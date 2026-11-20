use std::collections::VecDeque;
use std::net::SocketAddr;
use std::num::{NonZeroU64, NonZeroUsize};

use openssl::rsa::Rsa;
use wtls_lab::handshake::{HandshakeKind, RetryPolicy, Status};
use wtls_lab::udp::{Adapter, Diagnostic, Event};
use wtls_lab::wire::{
    DatagramBudget, ResumableClient, ResumableServer, ServerIdentity, TrustAnchor,
    issue_certificate,
};

const WALL: u32 = 1_730_000_000;
const ISSUER: &str = "WTLS Lab CA; WTLS Lab; CA";
const SUBJECT: &str = "Echo; WTLS Lab; CA; echo.lab.invalid";
const PAYLOAD: &[u8] = b"protected UDP echo";

fn contexts() -> (ResumableClient, ResumableServer) {
    let ca = Rsa::generate(2048).unwrap();
    let leaf = Rsa::generate(2048).unwrap();
    let leaf_public =
        Rsa::from_public_components(leaf.n().to_owned().unwrap(), leaf.e().to_owned().unwrap())
            .unwrap();
    let ca_public =
        Rsa::from_public_components(ca.n().to_owned().unwrap(), ca.e().to_owned().unwrap())
            .unwrap();
    let certificate =
        issue_certificate(ISSUER, SUBJECT, (WALL - 1)..=(WALL + 1), &ca, &leaf_public).unwrap();
    let identity = ServerIdentity::new(certificate, leaf).unwrap();
    let trust = TrustAnchor::new(ISSUER, SUBJECT, ca_public).unwrap();
    let lifetime = NonZeroU64::new(1_000).unwrap();
    (
        ResumableClient::new(
            RetryPolicy {
                timeout_ms: NonZeroU64::new(10).unwrap(),
                max_retries: 2,
            },
            trust,
            lifetime,
        ),
        ResumableServer::new(identity, NonZeroUsize::new(8).unwrap(), lifetime),
    )
}

fn adapter(server: Option<ResumableServer>, capacity: usize) -> Adapter {
    Adapter::new(
        server,
        DatagramBudget::new(1200),
        NonZeroUsize::new(capacity).unwrap(),
    )
}

#[derive(Default)]
struct Link {
    pending: VecDeque<(SocketAddr, Vec<u8>)>,
}

impl Link {
    fn send(&mut self, events: Vec<Event>) {
        for event in events {
            if let Event::Send { remote, bytes } = event {
                self.pending.push_back((remote, bytes));
            }
        }
    }

    fn take(&mut self, destination: SocketAddr) -> Vec<u8> {
        let (remote, bytes) = self.pending.pop_front().expect("one queued datagram");
        assert_eq!(remote, destination);
        assert!(self.pending.is_empty());
        bytes
    }
}

fn established(events: &[Event], expected: SocketAddr, kind: HandshakeKind) -> bool {
    events.iter().any(|event| {
        matches!(event, Event::Established { remote, kind: actual }
            if *remote == expected && *actual == kind)
    })
}

#[test]
fn lost_server_flight_retries_at_exact_deadline_and_echoes_protected_data() {
    // WAP-199 §§9.2.3.1 and 10.4. Drop the normal ServerHello flight.
    // The client resends its original ClientHello and the peer repeats its flight.
    let (clients, servers) = contexts();
    let client_addr = "127.0.0.1:49152".parse().unwrap();
    let server_addr = "127.0.0.1:9203".parse().unwrap();
    let mut client = adapter(None, 1);
    let mut server = adapter(Some(servers), 1);
    let mut link = Link::default();

    link.send(client.connect(server_addr, &clients, WALL, 100));
    let hello = link.take(server_addr);
    link.send(server.receive(client_addr, &hello, WALL, 101));
    let lost_flight = link.take(client_addr);
    assert_eq!(client.deadline(), Some(110));
    assert!(client.tick(109).is_empty());
    link.send(client.tick(110));
    let retry = link.take(server_addr);
    assert_eq!(retry, hello);
    link.send(server.receive(client_addr, &retry, WALL, 110));
    let repeated_flight = link.take(client_addr);
    assert_eq!(repeated_flight, lost_flight);

    link.send(client.receive(server_addr, &repeated_flight, WALL, 111));
    let commit = link.take(server_addr);
    let events = server.receive(client_addr, &commit, WALL, 112);
    assert!(established(&events, client_addr, HandshakeKind::Full));
    link.send(events);
    let commit = link.take(client_addr);
    let events = client.receive(server_addr, &commit, WALL, 113);
    assert!(established(&events, server_addr, HandshakeKind::Full));
    assert_eq!(client.status(server_addr), Some(Status::Open));
    assert_eq!(client.deadline(), None);

    link.send(client.send_application(server_addr, PAYLOAD.to_vec()));
    let request = link.take(server_addr);
    let events = server.receive(client_addr, &request, WALL, 114);
    let [Event::Deliver { remote, payload }] = events.as_slice() else {
        panic!("expected authenticated request");
    };
    assert_eq!((*remote, payload.as_slice()), (client_addr, PAYLOAD));
    link.send(server.send_application(*remote, payload.clone()));
    let response = link.take(client_addr);
    assert!(matches!(
        client.receive(server_addr, &response, WALL, 115).as_slice(),
        [Event::Deliver { remote, payload }] if *remote == server_addr && payload == PAYLOAD
    ));
}

fn session_id(datagram: &[u8]) -> Vec<u8> {
    let records = wtls_lab::decode_datagram(datagram).unwrap();
    match records[0].fragment[0] {
        1 => wtls_lab::wire::decode_client_hello(records[0].fragment)
            .unwrap()
            .session_id
            .to_vec(),
        2 => wtls_lab::wire::decode_server_hello(records[0].fragment)
            .unwrap()
            .session_id
            .to_vec(),
        _ => panic!("expected a hello"),
    }
}

#[test]
fn admission_routing_and_close_scope_control_reconnects() {
    use wtls_lab::handshake::CloseScope;

    let (clients, servers) = contexts();
    let client_addr = "127.0.0.1:49152".parse().unwrap();
    let other_addr = "127.0.0.1:49153".parse().unwrap();
    let server_addr = "127.0.0.1:9203".parse().unwrap();
    let mut client = adapter(None, 1);
    let mut server = adapter(Some(servers), 1);
    let mut link = Link::default();

    link.send(client.connect(server_addr, &clients, WALL, 10));
    let first_hello = link.take(server_addr);
    let mut combined = first_hello.clone();
    combined.extend_from_slice(&first_hello);
    assert!(matches!(
        server.receive(other_addr, &combined, WALL, 11).as_slice(),
        [Event::Diagnostic { remote, reason: Diagnostic::Protocol(_) }] if *remote == other_addr
    ));
    assert_eq!(server.status(other_addr), None);

    link.send(server.receive(client_addr, &first_hello, WALL, 12));
    let flight = link.take(client_addr);
    let initial_id = session_id(&flight);
    assert_eq!(initial_id.len(), 8);
    let mut contender = adapter(None, 1);
    link.send(contender.connect(server_addr, &clients, WALL, 13));
    let other_hello = link.take(server_addr);
    assert!(matches!(
        server.receive(other_addr, &other_hello, WALL, 13).as_slice(),
        [Event::Diagnostic { remote, reason: Diagnostic::AtCapacity }] if *remote == other_addr
    ));
    assert!(matches!(
        server.receive(client_addr, &other_hello, WALL, 13).as_slice(),
        [Event::Diagnostic { remote, reason: Diagnostic::Protocol(_) }] if *remote == client_addr
    ));

    link.send(client.receive(server_addr, &flight, WALL, 14));
    let commit = link.take(server_addr);
    let events = server.receive(client_addr, &commit, WALL, 15);
    assert!(established(&events, client_addr, HandshakeKind::Full));
    link.send(events);
    let commit = link.take(client_addr);
    assert!(established(
        &client.receive(server_addr, &commit, WALL, 16),
        server_addr,
        HandshakeKind::Full
    ));

    link.send(client.send_application(server_addr, PAYLOAD.to_vec()));
    let request = link.take(server_addr);
    assert!(matches!(
        server.receive(other_addr, &request, WALL, 17).as_slice(),
        [Event::Diagnostic { remote, reason: Diagnostic::Protocol(_) }] if *remote == other_addr
    ));
    assert!(matches!(
        server.receive(client_addr, &request, WALL, 17).as_slice(),
        [Event::Deliver { remote, payload }] if *remote == client_addr && payload == PAYLOAD
    ));

    let closed =
        |events: &[Event], address, expected| {
            events.iter().any(|event| matches!(
            event, Event::Closed { remote, scope } if *remote == address && *scope == expected
        ))
        };
    let events = server.close(client_addr, CloseScope::Connection);
    assert!(closed(&events, client_addr, CloseScope::Connection));
    link.send(events);
    let notify = link.take(client_addr);
    let events = client.receive(server_addr, &notify, WALL, 18);
    assert!(closed(&events, server_addr, CloseScope::Connection));
    link.send(events);
    let reply = link.take(server_addr);
    assert_eq!(server.status(client_addr), None);
    assert!(
        server
            .receive(client_addr, &reply, WALL, 19)
            .iter()
            .all(|event| matches!(event, Event::Diagnostic { .. }))
    );
    assert!(matches!(
        server
            .receive(client_addr, &first_hello, WALL, 20)
            .as_slice(),
        [Event::Diagnostic {
            reason: Diagnostic::PreviousClientHello,
            ..
        }]
    ));
    assert_eq!(server.status(client_addr), None);

    link.send(client.connect(server_addr, &clients, WALL, 21));
    let second_hello = link.take(server_addr);
    assert_eq!(session_id(&second_hello), initial_id);
    link.send(server.receive(client_addr, &second_hello, WALL, 22));
    let resumed = link.take(client_addr);
    assert_eq!(session_id(&resumed), initial_id);
    let events = client.receive(server_addr, &resumed, WALL, 23);
    assert!(established(&events, server_addr, HandshakeKind::Resumed));
    link.send(events);
    let commit = link.take(server_addr);
    let events = server.receive(client_addr, &commit, WALL, 24);
    assert!(established(&events, client_addr, HandshakeKind::Resumed));

    let events = server.close(client_addr, CloseScope::Session);
    assert!(closed(&events, client_addr, CloseScope::Session));
    link.send(events);
    // Drop this notification so the reconnecting client still offers the old ID.
    link.take(client_addr);
    assert_eq!(server.status(client_addr), None);

    let mut client = adapter(None, 1);
    link.send(client.connect(server_addr, &clients, WALL, 25));
    let third_hello = link.take(server_addr);
    assert_eq!(session_id(&third_hello), initial_id);
    link.send(server.receive(other_addr, &third_hello, WALL, 26));
    let fallback = link.take(other_addr);
    assert_ne!(session_id(&fallback), initial_id);
    link.send(client.receive(server_addr, &fallback, WALL, 27));
    let commit = link.take(server_addr);
    let events = server.receive(other_addr, &commit, WALL, 28);
    assert!(established(&events, other_addr, HandshakeKind::Full));
    assert_eq!(server.status(client_addr), None);
}

#[test]
fn delayed_full_handshake_finishes_during_certificate_review_window() {
    let (clients, servers) = contexts();
    let client_addr = "127.0.0.1:49152".parse().unwrap();
    let server_addr = "127.0.0.1:9203".parse().unwrap();
    let mut client = adapter(None, 1);
    let mut server = adapter(Some(servers), 1)
        .with_pending_handshake_timeout_ms(NonZeroU64::new(300_000).unwrap());
    let mut link = Link::default();

    link.send(client.connect(server_addr, &clients, WALL, 100));
    let hello = link.take(server_addr);
    link.send(server.receive(client_addr, &hello, WALL, 101));
    let flight = link.take(client_addr);
    link.send(client.receive(server_addr, &flight, WALL, 102));
    let commit = link.take(server_addr);

    // Hold the client's key exchange and Finished while the operator reviews
    // the certificate. The captured stock client took about 151 seconds.
    let approved_at = 101 + 151_000;
    assert!(
        server.tick(approved_at).is_empty(),
        "certificate review timed out"
    );
    let events = server.receive(client_addr, &commit, WALL, approved_at);
    assert!(established(&events, client_addr, HandshakeKind::Full));
    assert_eq!(server.status(client_addr), Some(Status::Open));
    assert_eq!(server.deadline(), None);
    link.send(events);
    let commit = link.take(client_addr);
    assert!(established(
        &client.receive(server_addr, &commit, WALL, approved_at + 1),
        server_addr,
        HandshakeKind::Full,
    ));
}

#[test]
fn abandoned_server_handshakes_expire_without_disturbing_open_associations() {
    let (clients, servers) = contexts();
    let server_addr = "127.0.0.1:9203".parse().unwrap();
    let open_addr = "127.0.0.1:49152".parse().unwrap();
    let pending_addr = "127.0.0.1:49153".parse().unwrap();
    let other_addr = "127.0.0.1:49154".parse().unwrap();
    let timeout_ms = NonZeroU64::new(45_000).unwrap();
    let mut server = adapter(Some(servers), 2).with_pending_handshake_timeout_ms(timeout_ms);
    let mut client = adapter(None, 1);
    let mut link = Link::default();

    link.send(client.connect(server_addr, &clients, WALL, 1));
    let hello = link.take(server_addr);
    link.send(server.receive(open_addr, &hello, WALL, 2));
    let flight = link.take(open_addr);
    link.send(client.receive(server_addr, &flight, WALL, 3));
    let commit = link.take(server_addr);
    link.send(server.receive(open_addr, &commit, WALL, 4));
    let commit = link.take(open_addr);
    assert!(established(
        &client.receive(server_addr, &commit, WALL, 5),
        server_addr,
        HandshakeKind::Full
    ));
    assert_eq!(server.deadline(), None);

    let mut abandoned = adapter(None, 1);
    link.send(abandoned.connect(server_addr, &clients, WALL, 10));
    let abandoned_hello = link.take(server_addr);
    link.send(server.receive(pending_addr, &abandoned_hello, WALL, 10));
    let abandoned_flight = link.take(pending_addr);
    let deadline = 10 + timeout_ms.get();
    let before_deadline = deadline - 1;
    assert_eq!(server.deadline(), Some(deadline));

    let mut fresh = adapter(None, 1);
    link.send(fresh.connect(server_addr, &clients, WALL, before_deadline));
    let fresh_hello = link.take(server_addr);
    assert!(matches!(
        server.receive(other_addr, &fresh_hello, WALL, before_deadline).as_slice(),
        [Event::Diagnostic { remote, reason: Diagnostic::AtCapacity }] if *remote == other_addr
    ));
    assert!(server.tick(before_deadline).is_empty());
    link.send(server.receive(pending_addr, &abandoned_hello, WALL, before_deadline));
    assert_eq!(link.take(pending_addr), abandoned_flight);
    assert_eq!(server.deadline(), Some(deadline));
    assert!(matches!(
        server.tick(deadline).as_slice(),
        [Event::TimedOut { remote }] if *remote == pending_addr
    ));
    assert_eq!(server.status(pending_addr), None);
    assert_eq!(server.deadline(), None);
    assert!(matches!(
        server.receive(pending_addr, &abandoned_hello, WALL, deadline).as_slice(),
        [Event::Diagnostic { remote, reason: Diagnostic::PreviousClientHello }] if *remote == pending_addr
    ));

    link.send(server.receive(pending_addr, &fresh_hello, WALL, deadline));
    link.take(pending_addr);
    assert_eq!(server.status(pending_addr), Some(Status::Negotiating));
    let next_deadline = deadline + timeout_ms.get();
    assert_eq!(server.deadline(), Some(next_deadline));

    let mut other = adapter(None, 1);
    link.send(other.connect(server_addr, &clients, WALL, next_deadline));
    let other_hello = link.take(server_addr);
    assert!(matches!(
        server.receive(other_addr, &other_hello, WALL, next_deadline).as_slice(),
        [Event::TimedOut { remote: expired }, Event::Send { remote: accepted, .. }]
            if *expired == pending_addr && *accepted == other_addr
    ));
    assert_eq!(server.status(pending_addr), None);
    assert_eq!(server.status(other_addr), Some(Status::Negotiating));
    assert_eq!(server.status(open_addr), Some(Status::Open));
    link.send(client.send_application(server_addr, PAYLOAD.to_vec()));
    let request = link.take(server_addr);
    assert!(matches!(
        server.receive(open_addr, &request, WALL, next_deadline + 1).as_slice(),
        [Event::Deliver { remote, payload }] if *remote == open_addr && payload == PAYLOAD
    ));
}

#[test]
fn adapter_budget_rejects_whole_datagrams_on_both_paths() {
    use wtls_lab::wire::DatagramTooLarge;

    let server_addr = "127.0.0.1:9203".parse().unwrap();
    let (clients, servers) = contexts();
    let mut gateway = adapter(Some(servers), 1);
    let oversized = vec![7; 12_000];
    assert!(matches!(
        gateway.receive(server_addr, &oversized, WALL, 1).as_slice(),
        [Event::Diagnostic {
            reason: Diagnostic::InboundTooLarge(DatagramTooLarge {
                size: 12_000,
                limit: 1200
            }),
            ..
        }]
    ));
    assert_eq!(gateway.status(server_addr), None);

    let mut constrained = Adapter::new(None, DatagramBudget::new(1), NonZeroUsize::MIN);
    assert!(matches!(
        constrained
            .connect(server_addr, &clients, WALL, 1)
            .as_slice(),
        [Event::Diagnostic {
            reason: Diagnostic::OutboundTooLarge(_),
            ..
        }]
    ));
    assert_eq!(constrained.status(server_addr), None);
    assert_eq!(constrained.deadline(), None);
}

#[test]
fn udp_socket_preserves_whole_datagrams_and_source_addresses() {
    use std::io::ErrorKind;
    use std::net::UdpSocket;
    use std::time::Duration;
    use wtls_lab::udp::SocketTransport;
    use wtls_lab::wire::DatagramTooLarge;

    let client_socket = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == ErrorKind::PermissionDenied => {
            eprintln!("loopback UDP smoke skipped: bind denied ({error})");
            return;
        }
        Err(error) => panic!("loopback UDP bind failed: {error}"),
    };
    let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    for socket in [&client_socket, &server_socket] {
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
    }
    let mut client = SocketTransport::new(client_socket);
    let mut server = SocketTransport::new(server_socket);
    let client_addr = client.socket().local_addr().unwrap();
    let server_addr = server.socket().local_addr().unwrap();
    let (clients, servers) = contexts();
    let mut gateway = adapter(Some(servers), 1);

    let mut lab = adapter(None, 1);
    let mut link = Link::default();
    link.send(lab.connect(server_addr, &clients, WALL, 2));
    let hello = link.take(server_addr);

    let mut oversized = hello.clone();
    oversized.resize(2048, 7);
    client.send(server_addr, &oversized).unwrap();
    let (remote, datagram) = server.receive().unwrap();
    assert_eq!((remote, datagram), (client_addr, oversized.as_slice()));
    assert!(matches!(
        gateway.receive(remote, datagram, WALL, 2).as_slice(),
        [Event::Diagnostic {
            remote,
            reason: Diagnostic::InboundTooLarge(DatagramTooLarge { size: 2048, limit: 1200 })
        }] if *remote == client_addr
    ));
    assert_eq!(gateway.status(client_addr), None);

    client.send(server_addr, &hello).unwrap();
    let (remote, received) = server.receive().unwrap();
    assert_eq!((remote, received), (client_addr, hello.as_slice()));
    link.send(gateway.receive(remote, received, WALL, 3));
    let flight = link.take(client_addr);
    server.send(remote, &flight).unwrap();
    let (remote, received) = client.receive().unwrap();
    assert_eq!((remote, received), (server_addr, flight.as_slice()));
    link.send(lab.receive(remote, received, WALL, 4));
    assert!(!link.take(server_addr).is_empty());
}

#[test]
fn captured_blackberry_hello_fits_the_udp_lab_budget() {
    // The stock WTLS ClientHello from fixtures/HISTORICAL_PEERS.md exercises
    // admission and the initial response through the same adapter as the lab.
    let offer: Vec<_> = include_str!("../fixtures/blackberry-7290-client-hello.hex")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .flat_map(str::split_whitespace)
        .map(|octet| u8::from_str_radix(octet, 16).unwrap())
        .collect();
    let (_, servers) = contexts();
    let mut gateway = adapter(Some(servers), 1);
    let remote = "127.0.0.1:49152".parse().unwrap();
    let events = gateway.receive(remote, &offer, WALL, 1);
    let [
        Event::Send {
            remote: destination,
            bytes,
        },
    ] = events.as_slice()
    else {
        panic!("expected one server flight for the captured ClientHello");
    };
    assert_eq!(*destination, remote);
    assert_eq!(gateway.status(remote), Some(Status::Negotiating));
    assert_eq!(wtls_lab::decode_datagram(bytes).unwrap().len(), 3);
}
