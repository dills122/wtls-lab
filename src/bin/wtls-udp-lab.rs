//! Isolated BlackBerry WTP/WSP smoke server over authenticated WTLS.

#[path = "wtls-udp-lab/wsp.rs"]
mod wsp;

use std::collections::BTreeMap;
use std::error::Error;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::mpsc::{Receiver, sync_channel};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use openssl::rsa::Rsa;
use openssl::sha::{sha1, sha256};
use wtls_lab::handshake::CloseScope;
use wtls_lab::udp::{Adapter, Event, SocketTransport};
use wtls_lab::wire::{DatagramBudget, ResumableServer, ServerIdentity, issue_certificate};

const LISTEN: &str = "127.0.0.1:9203";
const ISSUER: &str = "WTLS Lab CA; WAP Labs; CA";
const SUBJECT: &str = "WTLS Lab Gateway; WAP Labs; CA; 10.0.2.2";
const CERTIFICATE_LIFETIME_SECS: u32 = 24 * 60 * 60;
const CACHE_LIFETIME_MS: u64 = 30 * 60 * 1000;
const CERTIFICATE_REVIEW_TIMEOUT_MS: NonZeroU64 = NonZeroU64::new(5 * 60 * 1000).unwrap();
const CAPACITY: NonZeroUsize = NonZeroUsize::new(32).unwrap();
const CONTROL_POLL_MS: u64 = 100;
const USAGE: &str = "Usage: wtls-udp-lab [--help]\n\
    Listens on 127.0.0.1:9203 for the isolated BlackBerry lab.\n\
    Compare the printed leaf fingerprint before accepting the certificate.\n\
    The handshake expires five minutes after the first accepted ClientHello.\n\
    Enter connection-close or session-close on stdin to close the most recently\n\
    established connection. Refresh the Browser after the logged close.";

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args == ["--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    if !args.is_empty() {
        return Err(USAGE.into());
    }

    let socket = UdpSocket::bind(LISTEN)?;
    let identity = lab_identity()?;
    let server = ResumableServer::new(
        identity,
        CAPACITY,
        NonZeroU64::new(CACHE_LIFETIME_MS).unwrap(),
    );
    let mut lab = Lab {
        adapter: Adapter::new(Some(server), DatagramBudget::new(1200), CAPACITY)
            .with_pending_handshake_timeout_ms(CERTIFICATE_REVIEW_TIMEOUT_MS),
        transport: SocketTransport::new(socket),
        applications: BTreeMap::new(),
        current: None,
    };

    eprintln!("listening udp={LISTEN} profile=authenticated-wtls");
    eprintln!("stdin commands: connection-close, session-close");
    lab.run(&operator_commands())
}

fn lab_identity() -> Result<ServerIdentity, Box<dyn Error>> {
    let now = unix_seconds()?;
    let ca = Rsa::generate(2048)?;
    let key = Rsa::generate(2048)?;
    let public = Rsa::from_public_components(key.n().to_owned()?, key.e().to_owned()?)?;
    let certificate = issue_certificate(
        ISSUER,
        SUBJECT,
        now.saturating_sub(60)..=now.saturating_add(CERTIFICATE_LIFETIME_SECS),
        &ca,
        &public,
    )?;
    eprintln!("leaf sha1={}", hex(&sha1(&certificate)));
    eprintln!("leaf sha256={}", hex(&sha256(&certificate)));
    Ok(ServerIdentity::new(certificate, key)?)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unix_seconds() -> Result<u32, Box<dyn Error>> {
    Ok(u32::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)
}

fn operator_commands() -> Receiver<CloseScope> {
    let (sender, receiver) = sync_channel(1);
    thread::spawn(move || {
        for line in io::stdin().lines() {
            let scope = match line.as_deref() {
                Ok("connection-close") => CloseScope::Connection,
                Ok("session-close") => CloseScope::Session,
                Ok("") => continue,
                Ok(_) => {
                    eprintln!("stdin commands: connection-close, session-close");
                    continue;
                }
                Err(error) => {
                    eprintln!("stdin error={error}");
                    break;
                }
            };
            if sender.send(scope).is_err() {
                break;
            }
        }
    });
    receiver
}

struct Lab {
    adapter: Adapter,
    transport: SocketTransport,
    applications: BTreeMap<SocketAddr, wsp::Session>,
    current: Option<SocketAddr>,
}

impl Lab {
    fn run(&mut self, commands: &Receiver<CloseScope>) -> Result<(), Box<dyn Error>> {
        let start = Instant::now();
        loop {
            if let Ok(scope) = commands.try_recv() {
                if let Some(remote) = self.current {
                    eprintln!("wtls=close-requested remote={remote} scope={scope:?}");
                    let events = self.adapter.close(remote, scope);
                    self.dispatch(events)?;
                } else {
                    eprintln!("wtls=close-skipped scope={scope:?} reason=no-current-connection");
                }
            }

            let now = u64::try_from(start.elapsed().as_millis())?;
            let events = self.adapter.tick(now);
            self.dispatch(events)?;
            let wait = self.adapter.deadline().map_or(CONTROL_POLL_MS, |deadline| {
                deadline.saturating_sub(now).clamp(1, CONTROL_POLL_MS)
            });
            self.transport
                .socket()
                .set_read_timeout(Some(Duration::from_millis(wait)))?;
            let (remote, bytes) = match self.transport.receive() {
                Ok(datagram) => datagram,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let now = u64::try_from(start.elapsed().as_millis())?;
            let events = self.adapter.receive(remote, bytes, unix_seconds()?, now);
            self.dispatch(events)?;
        }
    }

    fn dispatch(&mut self, events: Vec<Event>) -> io::Result<()> {
        for event in events {
            match event {
                Event::Send { remote, bytes } => self.transport.send(remote, &bytes)?,
                Event::Established { remote, kind } => {
                    eprintln!(
                        "wtls=established remote={remote} handshake={kind:?} finished=verified"
                    );
                    self.applications.insert(remote, wsp::Session::default());
                    self.current = Some(remote);
                }
                Event::Deliver { remote, payload } => self.application(remote, &payload)?,
                Event::Closed { remote, scope } => {
                    self.remove(remote);
                    eprintln!("wtls=closed remote={remote} scope={scope:?}");
                }
                Event::TimedOut { remote } => {
                    self.remove(remote);
                    eprintln!("wtls=timed-out remote={remote}");
                }
                Event::Diagnostic { remote, reason } => {
                    eprintln!("wtls=diagnostic remote={remote} reason={reason}");
                    if self.adapter.status(remote).is_none() {
                        self.remove(remote);
                    }
                }
            }
        }
        Ok(())
    }

    fn application(&mut self, remote: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let Some(session) = self.applications.get_mut(&remote) else {
            return Ok(());
        };
        match session.receive(payload) {
            wsp::Request::Reply { bytes, page_tid } => {
                let events = self.adapter.send_application(remote, bytes);
                if let [Event::Send { remote, bytes }] = events.as_slice() {
                    self.transport.send(*remote, bytes)?;
                    if let Some(tid) = page_tid {
                        session.page_sent(tid);
                        eprintln!("wsp=page-sent remote={remote} tid={tid:04x}");
                    }
                } else {
                    self.dispatch(events)?;
                }
            }
            wsp::Request::PageAck(tid) => {
                eprintln!("wsp=page-ack remote={remote} tid={tid:04x} protection=verified");
            }
            wsp::Request::Ignore => {}
        }
        Ok(())
    }

    fn remove(&mut self, remote: SocketAddr) {
        self.applications.remove(&remote);
        if self.current == Some(remote) {
            self.current = None;
        }
    }
}
