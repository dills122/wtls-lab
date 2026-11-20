//! One isolated, loopback-only WAP 1.x GET for WinWAP.

use std::env;
use std::error::Error;
use std::io;
use std::net::UdpSocket;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use wtls_lab::wire::{DatagramBudget, WireAction, WirePeer};

fn main() -> Result<(), Box<dyn Error>> {
    if !env::args_os().skip(1).eq(["--legacy-winwap"]) {
        return Err("usage: wtls-winwap-lab --legacy-winwap".into());
    }
    let socket = UdpSocket::bind("127.0.0.1:9202")?;
    socket.set_read_timeout(Some(Duration::from_secs(120)))?;
    eprintln!("listening udp=127.0.0.1:9202 profile=legacy-winwap");
    run(&socket)
}

fn run(socket: &UdpSocket) -> Result<(), Box<dyn Error>> {
    let mut gateway = WirePeer::legacy_winwap_server(u32::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)?;
    let mut peer = None;
    let start = Instant::now();
    let mut datagram = vec![0u8; usize::from(u16::MAX)];
    let budget = DatagramBudget::new(1200);
    loop {
        let (len, addr) = socket.recv_from(&mut datagram)?;
        if peer.is_some_and(|selected| selected != addr) || budget.check_size(len).is_err() {
            continue;
        }
        let elapsed_ms = u64::try_from(start.elapsed().as_millis())?;
        let actions = match gateway.receive(&datagram[..len], elapsed_ms) {
            Ok(actions) => actions,
            Err(error) => {
                eprintln!("wtls=rejected status={:?} error={error}", gateway.status());
                if gateway.status() == wtls_lab::handshake::Status::Closed {
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
                    eprintln!("wtls=flight-sent bytes={}", bytes.len());
                }
                WireAction::Established(_) => {
                    let info = gateway
                        .connection_info()
                        .ok_or("missing WTLS connection info")?;
                    let p = info.parameters;
                    eprintln!(
                        "wtls=established key-exchange={} cipher={} mac={} refresh={} peer-authentication={:?}",
                        p.key_exchange,
                        p.bulk_cipher,
                        p.mac,
                        p.key_refresh,
                        info.peer_authentication
                    );
                }
                WireAction::Deliver(payload) => {
                    let Some(tid) = connectionless_get(&payload) else {
                        eprintln!("wsp=unsupported-request bytes={}", payload.len());
                        continue;
                    };
                    eprintln!("wsp=get-received tid={tid} bytes={}", payload.len());
                    let mut replies = gateway.send_application(wsp_reply(tid))?;
                    let Some(WireAction::Send(bytes)) = replies.pop() else {
                        return Err("expected a protected WSP reply".into());
                    };
                    budget.check(&bytes)?;
                    socket.send_to(&bytes, addr)?;
                    eprintln!("wsp=reply-sent tid={tid} status=200 bytes={}", bytes.len());
                    return Ok(());
                }
                WireAction::Closed(_) | WireAction::TimedOut => {
                    return Err(io::Error::other("WTLS ended before the WSP exchange").into());
                }
            }
        }
    }
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

fn wsp_reply(tid: u8) -> Vec<u8> {
    // Reply, OK, one header byte, application/vnd.wap.wmlc.
    let mut reply = vec![tid, 0x04, 0x20, 1, 0x94];
    // WBXML 1.1, WML 1.1, UTF-8, empty string table, <wml><card><p> and STR_I.
    reply.extend_from_slice(&[0x01, 0x04, 0x6a, 0, 0x7f, 0x67, 0x60, 0x03]);
    reply.extend_from_slice(b"WTLS lab protected reply");
    reply.extend_from_slice(&[0, 1, 1, 1]);
    reply
}

#[cfg(test)]
mod tests {
    use super::{connectionless_get, wsp_reply};

    #[test]
    fn matches_a_complete_get_and_preserves_the_transaction_id() {
        assert_eq!(connectionless_get(&[0x33, 0x40, 2, b'/', b'x']), Some(0x33));
        assert_eq!(connectionless_get(&[0x33, 0x40, 2, b'/']), None);
        assert_eq!(connectionless_get(&[0x33, 0x41, 1, b'/']), None);
        assert_eq!(connectionless_get(&[0x33, 0x40, 0x80]), None);
        assert_eq!(&wsp_reply(0x33)[..5], &[0x33, 0x04, 0x20, 1, 0x94]);
    }
}
