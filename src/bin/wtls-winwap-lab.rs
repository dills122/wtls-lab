//! Isolated, loopback-only WAP 1.x GETs for WinWAP.

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::net::UdpSocket;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use wtls_lab::handshake::{CloseScope, Status};
use wtls_lab::wire::{
    DatagramBudget, WireAction, WirePeer, decode_client_hello, decode_server_hello,
};
use wtls_lab::{CipherSpec, RecordType, decode_datagram};

const REPLY_DELIVERY_INTERVAL: Duration = Duration::from_millis(250);

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let probe = probe_session_cache(&args)?;
    let socket = UdpSocket::bind("127.0.0.1:9202")?;
    socket.set_read_timeout(Some(Duration::from_secs(120)))?;
    eprintln!("listening udp=127.0.0.1:9202 profile=legacy-winwap");
    run_connection(&socket, probe.then_some(1))?;
    if probe {
        run_connection(&socket, Some(2))?;
    }
    Ok(())
}

fn probe_session_cache(args: &[OsString]) -> Result<bool, &'static str> {
    if args == ["--legacy-winwap"] {
        Ok(false)
    } else if args == ["--legacy-winwap", "--probe-session-cache"]
        || args == ["--probe-session-cache", "--legacy-winwap"]
    {
        Ok(true)
    } else {
        Err("usage: wtls-winwap-lab --legacy-winwap [--probe-session-cache]")
    }
}

fn run_connection(socket: &UdpSocket, probe_connection: Option<u8>) -> Result<(), Box<dyn Error>> {
    let mut gateway = WirePeer::legacy_winwap_server(u32::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)?;
    let probe = probe_connection.is_some();
    let log_prefix = probe_connection
        .map(|number| format!("connection={number} "))
        .unwrap_or_default();
    let mut peer = None;
    let start = Instant::now();
    let mut datagram = vec![0u8; usize::from(u16::MAX)];
    let budget = DatagramBudget::new(1200);
    loop {
        let (len, addr) = socket.recv_from(&mut datagram)?;
        if peer.is_some_and(|selected| selected != addr) || budget.check_size(len).is_err() {
            continue;
        }
        let incoming = &datagram[..len];
        if probe {
            if let Some(session_id) = client_session_id(incoming) {
                eprintln!("{log_prefix}wtls=client-hello peer={addr} session-id={session_id:02x?}");
            } else if peer.is_none() {
                // Only a clear ClientHello can claim a fresh peer, even on a reused port.
                continue;
            }
        }
        let elapsed_ms = u64::try_from(start.elapsed().as_millis())?;
        let actions = match gateway.receive(incoming, elapsed_ms) {
            Ok(actions) => actions,
            Err(error) => {
                eprintln!(
                    "{log_prefix}wtls=rejected status={:?} error={error}",
                    gateway.status()
                );
                if gateway.status() == Status::Closed {
                    return Err(error.into());
                }
                continue;
            }
        };
        peer = Some(addr);
        for action in actions {
            match action {
                WireAction::Send(bytes) => {
                    budget.check(&bytes)?;
                    socket.send_to(&bytes, addr)?;
                    if probe && let Some(session_id) = server_session_id(&bytes) {
                        eprintln!(
                            "{log_prefix}wtls=server-hello peer={addr} session-id={session_id:02x?}"
                        );
                    }
                    eprintln!("{log_prefix}wtls=flight-sent bytes={}", bytes.len());
                }
                WireAction::Established(_) => {
                    let info = gateway
                        .connection_info()
                        .ok_or("missing WTLS connection info")?;
                    let p = info.parameters;
                    eprintln!(
                        "{log_prefix}wtls=established key-exchange={} cipher={} mac={} refresh={} peer-authentication={:?}",
                        p.key_exchange,
                        p.bulk_cipher,
                        p.mac,
                        p.key_refresh,
                        info.peer_authentication
                    );
                }
                WireAction::Deliver(payload) => {
                    let Some(tid) = connectionless_get(&payload) else {
                        eprintln!(
                            "{log_prefix}wsp=unsupported-request bytes={}",
                            payload.len()
                        );
                        continue;
                    };
                    eprintln!(
                        "{log_prefix}wsp=get-received tid={tid} bytes={}",
                        payload.len()
                    );
                    let mut replies = gateway.send_application(wsp_reply(tid, probe))?;
                    let Some(WireAction::Send(bytes)) = replies.pop() else {
                        return Err("expected a protected WSP reply".into());
                    };
                    budget.check(&bytes)?;
                    socket.send_to(&bytes, addr)?;
                    eprintln!(
                        "{log_prefix}wsp=reply-sent tid={tid} status=200 bytes={}",
                        bytes.len()
                    );
                    if probe_connection == Some(1) {
                        thread::sleep(REPLY_DELIVERY_INTERVAL);
                        let actions = gateway.close(CloseScope::Connection)?;
                        let [
                            WireAction::Send(bytes),
                            WireAction::Closed(CloseScope::Connection),
                        ] = actions.as_slice()
                        else {
                            return Err("expected a protected WTLS connection close".into());
                        };
                        budget.check(bytes)?;
                        socket.send_to(bytes, addr)?;
                        eprintln!(
                            "{log_prefix}wtls=connection-close-sent bytes={}",
                            bytes.len()
                        );
                    }
                    return Ok(());
                }
                WireAction::Closed(_) | WireAction::TimedOut => {
                    return Err(io::Error::other("WTLS ended before the WSP exchange").into());
                }
            }
        }
    }
}

fn clear_handshakes(datagram: &[u8]) -> impl Iterator<Item = &[u8]> {
    decode_datagram(datagram)
        .unwrap_or_default()
        .into_iter()
        .filter(|record| {
            record.content_type == RecordType::Handshake && record.cipher_spec == CipherSpec::Null
        })
        .map(|record| record.fragment)
}

fn client_session_id(datagram: &[u8]) -> Option<&[u8]> {
    clear_handshakes(datagram).find_map(|fragment| {
        decode_client_hello(fragment)
            .ok()
            .map(|hello| hello.session_id)
    })
}

fn server_session_id(datagram: &[u8]) -> Option<&[u8]> {
    clear_handshakes(datagram).find_map(|fragment| {
        decode_server_hello(fragment)
            .ok()
            .map(|hello| hello.session_id)
    })
}

fn connectionless_get(payload: &[u8]) -> Option<u8> {
    let [tid, 0x40, uri_length @ ..] = payload else {
        return None;
    };
    let mut length = 0u32;
    for (index, &byte) in uri_length.iter().take(5).enumerate() {
        length = length
            .checked_mul(128)?
            .checked_add(u32::from(byte & 127))?;
        if byte & 128 == 0 {
            let available = uri_length.len() - index - 1;
            return (length != 0 && usize::try_from(length).ok()? <= available).then_some(*tid);
        }
    }
    None
}

fn wsp_reply(tid: u8, probe: bool) -> Vec<u8> {
    // Reply, OK, HeadersLen, application/vnd.wap.wmlc.
    let mut reply = vec![tid, 0x04, 0x20, if probe { 3 } else { 1 }, 0x94];
    if probe {
        // WSP well-known Cache-Control field and no-cache directive.
        reply.extend_from_slice(&[0x88, 0x80]);
    }
    // WBXML 1.1, WML 1.1, UTF-8, empty string table, <wml><card><p> and STR_I.
    reply.extend_from_slice(&[0x01, 0x04, 0x6a, 0, 0x7f, 0x67, 0x60, 0x03]);
    reply.extend_from_slice(b"WTLS lab protected reply");
    reply.extend_from_slice(&[0, 1, 1, 1]);
    reply
}

#[cfg(test)]
mod tests {
    use super::*;
    use wtls_lab::handshake::{Message, SessionId};
    use wtls_lab::wire::{WireError, encode_handshake};
    use wtls_lab::{LengthForm, Record, encode_datagram};

    #[test]
    fn probe_requires_legacy_winwap_and_rejects_extra_flags() {
        let parse = |args: &[&str]| {
            probe_session_cache(&args.iter().map(OsString::from).collect::<Vec<_>>())
        };
        assert_eq!(parse(&["--legacy-winwap"]), Ok(false));
        assert_eq!(
            parse(&["--legacy-winwap", "--probe-session-cache"]),
            Ok(true)
        );
        assert_eq!(
            parse(&["--probe-session-cache", "--legacy-winwap"]),
            Ok(true)
        );
        for args in [
            &[][..],
            &["--probe-session-cache"][..],
            &["--legacy-winwap", "--legacy-winwap"][..],
            &["--legacy-winwap", "--probe-session-cache", "--extra"][..],
        ] {
            assert!(parse(args).is_err());
        }
    }

    #[test]
    fn observes_clear_offers_even_when_legacy_negotiation_rejects_them() {
        let raw_id = [0, 0xff, 0x80, 1, 0, 2, 0xfe, 3];
        for (resume, expected) in [(None, &[][..]), (Some(SessionId(raw_id)), &raw_id)] {
            let hello = encode_handshake(&Message::ClientHello {
                random: [1; 16],
                resume,
            })
            .unwrap();
            let record = Record {
                cipher_spec: CipherSpec::Null,
                content_type: RecordType::Handshake,
                sequence: 0,
                length_form: LengthForm::Explicit,
                fragment: &hello,
            };
            let clear = encode_datagram(&[record]).unwrap();
            assert_eq!(client_session_id(&clear), Some(expected));

            let protected = encode_datagram(&[Record {
                cipher_spec: CipherSpec::Current,
                ..record
            }])
            .unwrap();
            assert_eq!(client_session_id(&protected), None);
            assert_eq!(client_session_id(&clear[..clear.len() - 1]), None);

            let mut gateway = WirePeer::legacy_winwap_server(1_730_000_000).unwrap();
            assert_eq!(
                gateway.receive(&clear, 0),
                Err(WireError::UnsupportedProfile)
            );
            assert_eq!(gateway.status(), Status::Idle);
        }
    }

    #[test]
    fn observes_the_selected_id_in_the_full_server_flight() {
        let offer: Vec<_> = include_str!("../../fixtures/winwap-client-hello.hex")
            .lines()
            .filter(|line| !line.starts_with('#'))
            .flat_map(str::split_whitespace)
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect();
        assert_eq!(client_session_id(&offer), Some(&[][..]));
        let mut gateway = WirePeer::legacy_winwap_server(1_730_000_000).unwrap();
        let actions = gateway.receive(&offer, 0).unwrap();
        let [WireAction::Send(flight)] = actions.as_slice() else {
            panic!("expected a full server handshake flight");
        };
        let records = decode_datagram(flight).unwrap();
        let selected = decode_server_hello(records[0].fragment).unwrap();
        assert_eq!(server_session_id(flight), Some(selected.session_id));
        assert_eq!(selected.session_id.len(), 8);
        assert_eq!(gateway.status(), Status::Negotiating);
    }

    #[test]
    fn probe_reply_encodes_wsp_cache_control_no_cache() {
        let reply = wsp_reply(0x33, true);
        // WAP-230 Reply header block: Content-Type followed by Cache-Control (§8.4.2.15).
        assert_eq!(&reply[..7], &[0x33, 0x04, 0x20, 3, 0x94, 0x88, 0x80]);
        assert_eq!(&reply[7..11], &[0x01, 0x04, 0x6a, 0]);
        assert_eq!(&reply[7..], &wsp_reply(0x33, false)[5..]);
    }

    #[test]
    fn matches_a_complete_get_and_preserves_the_transaction_id() {
        assert_eq!(connectionless_get(&[0x33, 0x40, 2, b'/', b'x']), Some(0x33));
        assert_eq!(connectionless_get(&[0x33, 0x40, 2, b'/']), None);
        assert_eq!(connectionless_get(&[0x33, 0x41, 1, b'/']), None);
        assert_eq!(connectionless_get(&[0x33, 0x40, 0x80]), None);
        assert_eq!(&wsp_reply(0x33, false)[..5], &[0x33, 0x04, 0x20, 1, 0x94]);
    }
}
