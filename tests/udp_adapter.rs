use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::{NonZeroU64, NonZeroUsize};

use openssl::rsa::Rsa;
use wtls_lab::handshake::{CloseScope, HandshakeKind, RetryPolicy, Status};
use wtls_lab::udp::{Adapter, Diagnostic, Event};
use wtls_lab::wire::{
    DatagramBudget, ResumableClient, ResumableServer, ServerIdentity, TrustAnchor,
    decode_client_hello, decode_server_hello, issue_certificate,
};
use wtls_lab::{CipherSpec, RecordType, decode_datagram};

const WALL: u32 = 1_730_000_000;
const ISSUER: &str = "WTLS Lab CA; WTLS Lab; CA";
const SUBJECT: &str = "Echo; WTLS Lab; CA; echo.lab.invalid";
const PAYLOAD: &[u8] = b"protected UDP echo";
const CLIENT_ADDR: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152));
const SERVER_ADDR: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9203));

fn contexts() -> (ResumableClient, ResumableServer) {
    contexts_with_authority(false)
}

fn contexts_with_authority(require_authority: bool) -> (ResumableClient, ResumableServer) {
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
    let identity = if require_authority {
        ServerIdentity::provisioned(certificate, leaf, ISSUER, ca_public.clone()).unwrap()
    } else {
        ServerIdentity::new(certificate, leaf).unwrap()
    };
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

fn assert_client_hello_time(datagram: &[u8], unix_seconds: u32) -> &[u8] {
    let records = decode_datagram(datagram).unwrap();
    let [record] = records.as_slice() else {
        panic!("expected one ClientHello record: {records:?}");
    };
    assert_eq!(record.content_type, RecordType::Handshake);
    assert_eq!(record.cipher_spec, CipherSpec::Null);
    let hello = decode_client_hello(record.fragment).unwrap();
    assert_eq!(
        hello.random[..4],
        unix_seconds.to_be_bytes(),
        "ClientHello Random time prefix"
    );
    hello.session_id
}

fn assert_server_hello_time(datagram: &[u8], unix_seconds: u32) -> &[u8] {
    let records = decode_datagram(datagram).unwrap();
    let record = records.first().expect("expected a ServerHello record");
    assert_eq!(record.content_type, RecordType::Handshake);
    assert_eq!(record.cipher_spec, CipherSpec::Null);
    let hello = decode_server_hello(record.fragment).unwrap();
    assert_eq!(
        hello.random[..4],
        unix_seconds.to_be_bytes(),
        "ServerHello Random time prefix"
    );
    hello.session_id
}

fn full_handshake_with_hello_times(
    link: &mut Link,
    client: &mut Adapter,
    server: &mut Adapter,
    clients: &ResumableClient,
) -> [u8; 8] {
    let client_wall = WALL - 1;
    let server_wall = WALL;
    link.send(client.connect(SERVER_ADDR, clients, client_wall, 100));
    let hello = link.take(SERVER_ADDR);
    assert!(assert_client_hello_time(&hello, client_wall).is_empty());

    link.send(server.receive(CLIENT_ADDR, &hello, server_wall, 101));
    let flight = link.take(CLIENT_ADDR);
    let session = assert_server_hello_time(&flight, server_wall)
        .try_into()
        .expect("expected an eight-byte session ID");

    link.send(client.receive(SERVER_ADDR, &flight, client_wall, 102));
    let commit = link.take(SERVER_ADDR);
    let events = server.receive(CLIENT_ADDR, &commit, server_wall, 103);
    assert!(established(&events, CLIENT_ADDR, HandshakeKind::Full));
    link.send(events);
    let commit = link.take(CLIENT_ADDR);
    let events = client.receive(SERVER_ADDR, &commit, client_wall, 104);
    assert!(established(&events, SERVER_ADDR, HandshakeKind::Full));
    session
}

#[test]
fn full_handshake_hellos_encode_supplied_unix_time() {
    let (clients, servers) = contexts();
    let mut client = adapter(None, 1);
    let mut server = adapter(Some(servers), 1);
    let mut link = Link::default();

    full_handshake_with_hello_times(&mut link, &mut client, &mut server, &clients);
}

#[test]
fn resumed_handshake_hellos_encode_supplied_unix_time() {
    let (clients, servers) = contexts();
    let mut client = adapter(None, 1);
    let mut server = adapter(Some(servers), 1);
    let mut link = Link::default();
    let session = full_handshake_with_hello_times(&mut link, &mut client, &mut server, &clients);

    link.send(server.close(CLIENT_ADDR, CloseScope::Connection));
    let notify = link.take(CLIENT_ADDR);
    link.send(client.receive(SERVER_ADDR, &notify, WALL - 1, 105));
    let reply = link.take(SERVER_ADDR);
    server.receive(CLIENT_ADDR, &reply, WALL, 106);
    assert_eq!(client.status(SERVER_ADDR), None);
    assert_eq!(server.status(CLIENT_ADDR), None);

    let client_wall = WALL;
    let server_wall = WALL + 1;
    link.send(client.connect(SERVER_ADDR, &clients, client_wall, 107));
    let hello = link.take(SERVER_ADDR);
    assert_eq!(assert_client_hello_time(&hello, client_wall), session);

    link.send(server.receive(CLIENT_ADDR, &hello, server_wall, 108));
    let flight = link.take(CLIENT_ADDR);
    assert_eq!(assert_server_hello_time(&flight, server_wall), session);

    let events = client.receive(SERVER_ADDR, &flight, client_wall, 109);
    assert!(established(&events, SERVER_ADDR, HandshakeKind::Resumed));
    link.send(events);
    let commit = link.take(SERVER_ADDR);
    let events = server.receive(CLIENT_ADDR, &commit, server_wall, 110);
    assert!(established(&events, CLIENT_ADDR, HandshakeKind::Resumed));
}

fn open_protected_association(link: &mut Link) -> (Adapter, Adapter) {
    let (clients, servers) = contexts();
    let mut client = adapter(None, 1);
    let mut server = adapter(Some(servers), 1);

    link.send(client.connect(SERVER_ADDR, &clients, WALL, 0));
    let hello = link.take(SERVER_ADDR);
    link.send(server.receive(CLIENT_ADDR, &hello, WALL, 1));
    let flight = link.take(CLIENT_ADDR);
    let records = decode_datagram(&flight).unwrap();
    let selection = decode_server_hello(records[0].fragment).unwrap();
    assert_eq!(selection.sequence_mode, 2);
    assert_eq!(selection.key_refresh, 3); // 2^3 = 8 protected records per key block.

    link.send(client.receive(SERVER_ADDR, &flight, WALL, 2));
    let commit = link.take(SERVER_ADDR);
    let events = server.receive(CLIENT_ADDR, &commit, WALL, 3);
    assert!(established(&events, CLIENT_ADDR, HandshakeKind::Full));
    link.send(events);
    let commit = link.take(CLIENT_ADDR);
    let events = client.receive(SERVER_ADDR, &commit, WALL, 4);
    assert!(established(&events, SERVER_ADDR, HandshakeKind::Full));
    assert_eq!(client.status(SERVER_ADDR), Some(Status::Open));
    assert_eq!(server.status(CLIENT_ADDR), Some(Status::Open));
    (client, server)
}

fn protected_application(
    link: &mut Link,
    sender: &mut Adapter,
    destination: SocketAddr,
    sequence: u16,
) -> Vec<u8> {
    link.send(sender.send_application(destination, sequence.to_be_bytes().to_vec()));
    let datagram = link.take(destination);
    let records = decode_datagram(&datagram).unwrap();
    let [record] = records.as_slice() else {
        panic!("expected one protected application record: {records:?}");
    };
    assert_eq!(record.content_type, RecordType::ApplicationData);
    assert_eq!(record.cipher_spec, CipherSpec::Current);
    assert_eq!(record.sequence, sequence);
    datagram
}

fn assert_application_delivery(events: Vec<Event>, source: SocketAddr, sequence: u16) {
    let [Event::Deliver { remote, payload }] = events.as_slice() else {
        panic!("expected one delivery of record {sequence} from {source}");
    };
    assert_eq!(*remote, source);
    assert_eq!(payload.as_slice(), sequence.to_be_bytes());
}

// WAP-199-WTLS-20000218-a, §§9.2.3.1, 11.2 and Appendix B.3.
// Explicit record sequences select the key block. WTLS leaves reliable,
// ordered application delivery to the upper layer.
#[test]
fn protected_udp_reordering_and_duplicates_across_key_refresh() {
    let mut link = Link::default();
    let (mut client, mut server) = open_protected_association(&mut link);
    let mut now = 10;

    for (source, destination) in [(CLIENT_ADDR, SERVER_ADDR), (SERVER_ADDR, CLIENT_ADDR)] {
        let (sender, receiver) = if source == CLIENT_ADDR {
            (&mut client, &mut server)
        } else {
            (&mut server, &mut client)
        };
        for sequence in 1..=6 {
            let datagram = protected_application(&mut link, sender, destination, sequence);
            assert_application_delivery(
                receiver.receive(source, &datagram, WALL, now),
                source,
                sequence,
            );
            now += 1;
        }

        let older = protected_application(&mut link, sender, destination, 7);
        let newer = protected_application(&mut link, sender, destination, 8);
        assert_application_delivery(receiver.receive(source, &newer, WALL, now), source, 8);
        assert_application_delivery(receiver.receive(source, &older, WALL, now + 1), source, 7);
        now += 2;
        for (sequence, duplicate) in [(8, newer), (7, older)] {
            let events = receiver.receive(source, &duplicate, WALL, now);
            assert!(
                events.is_empty(),
                "duplicate record {sequence} from {source} produced {} events",
                events.len()
            );
            now += 1;
        }
    }
}

#[test]
fn protected_udp_loss_of_first_refreshed_record_does_not_block_delivery() {
    let mut link = Link::default();
    let (mut client, mut server) = open_protected_association(&mut link);
    let mut now = 10;

    for (source, destination) in [(CLIENT_ADDR, SERVER_ADDR), (SERVER_ADDR, CLIENT_ADDR)] {
        let (sender, receiver) = if source == CLIENT_ADDR {
            (&mut client, &mut server)
        } else {
            (&mut server, &mut client)
        };
        for sequence in 1..=7 {
            let datagram = protected_application(&mut link, sender, destination, sequence);
            assert_application_delivery(
                receiver.receive(source, &datagram, WALL, now),
                source,
                sequence,
            );
            now += 1;
        }

        drop(protected_application(&mut link, sender, destination, 8));
        assert_eq!(sender.deadline(), None);
        assert_eq!(receiver.deadline(), None);
        now += 100; // Advance past the handshake retry interval with record 8 lost.
        assert!(sender.tick(now).is_empty());
        assert!(receiver.tick(now).is_empty());

        let later = protected_application(&mut link, sender, destination, 9);
        assert_application_delivery(receiver.receive(source, &later, WALL, now), source, 9);
        // Check for a timer while the gap is visible and before any further delivery.
        assert_eq!(sender.deadline(), None);
        assert_eq!(receiver.deadline(), None);
        now += 100;
        assert!(sender.tick(now).is_empty());
        assert!(receiver.tick(now).is_empty());

        let subsequent = protected_application(&mut link, sender, destination, 10);
        assert_application_delivery(
            receiver.receive(source, &subsequent, WALL, now + 1),
            source,
            10,
        );
        now += 2;
        assert_eq!(sender.deadline(), None);
        assert_eq!(receiver.deadline(), None);
    }
}

fn assert_protected_echo(link: &mut Link, client: &mut Adapter, server: &mut Adapter, now: u64) {
    link.send(client.send_application(SERVER_ADDR, PAYLOAD.to_vec()));
    let request = link.take(SERVER_ADDR);
    assert!(matches!(
        server.receive(CLIENT_ADDR, &request, WALL, now).as_slice(),
        [Event::Deliver { remote, payload }] if *remote == CLIENT_ADDR && payload == PAYLOAD
    ));
    link.send(server.send_application(CLIENT_ADDR, PAYLOAD.to_vec()));
    let response = link.take(CLIENT_ADDR);
    assert!(matches!(
        client.receive(SERVER_ADDR, &response, WALL, now + 1).as_slice(),
        [Event::Deliver { remote, payload }] if *remote == SERVER_ADDR && payload == PAYLOAD
    ));
}

#[test]
fn pending_client_hello_replaces_full_handshake_at_capacity() {
    let (clients, servers) = contexts();
    let mut a = adapter(None, 1);
    let mut b = adapter(None, 1);
    let mut server = adapter(Some(servers), 1);
    let mut link = Link::default();

    link.send(a.connect(SERVER_ADDR, &clients, WALL - 1, 100));
    let hello_a = link.take(SERVER_ADDR);
    assert!(assert_client_hello_time(&hello_a, WALL - 1).is_empty());
    link.send(server.receive(CLIENT_ADDR, &hello_a, WALL, 101));
    let flight_a = link.take(CLIENT_ADDR);
    let deadline = server.deadline();
    link.send(server.receive(CLIENT_ADDR, &hello_a, WALL, 102));
    assert_eq!(link.take(CLIENT_ADDR), flight_a);
    link.send(a.receive(SERVER_ADDR, &flight_a, WALL - 1, 103));
    let commit_a = link.take(SERVER_ADDR);

    link.send(b.connect(SERVER_ADDR, &clients, WALL + 1, 103));
    let hello_b = link.take(SERVER_ADDR);
    assert!(assert_client_hello_time(&hello_b, WALL + 1).is_empty());
    let events = server.receive(CLIENT_ADDR, &hello_b, WALL + 1, 104);
    assert!(
        matches!(events.as_slice(), [Event::Send { remote, .. }] if *remote == CLIENT_ADDR),
        "fresh B must start a handshake in the occupied slot"
    );
    link.send(events);
    let flight_b = link.take(CLIENT_ADDR);
    assert_server_hello_time(&flight_b, WALL + 1);
    assert_eq!(server.status(CLIENT_ADDR), Some(Status::Negotiating));
    assert_eq!(server.deadline(), deadline);
    link.send(server.receive(CLIENT_ADDR, &hello_b, WALL + 1, 105));
    assert_eq!(link.take(CLIENT_ADDR), flight_b);

    let other_addr = SocketAddr::new(CLIENT_ADDR.ip(), CLIENT_ADDR.port() + 1);
    let mut c = adapter(None, 1);
    link.send(c.connect(SERVER_ADDR, &clients, WALL, 106));
    let hello_c = link.take(SERVER_ADDR);
    assert!(matches!(
        server.receive(other_addr, &hello_c, WALL, 106).as_slice(),
        [Event::Diagnostic { remote, reason: Diagnostic::AtCapacity }] if *remote == other_addr
    ));
    assert!(matches!(
        server.receive(CLIENT_ADDR, &hello_a, WALL, 107).as_slice(),
        [Event::Diagnostic { remote, reason: Diagnostic::PreviousClientHello }] if *remote == CLIENT_ADDR
    ));
    assert!(matches!(
        server.receive(CLIENT_ADDR, &commit_a, WALL, 108).as_slice(),
        [Event::Diagnostic {
            reason: Diagnostic::Protocol(_),
            ..
        }]
    ));
    assert_eq!(server.status(CLIENT_ADDR), Some(Status::Negotiating));
    assert_eq!(server.deadline(), deadline);
    link.send(server.receive(CLIENT_ADDR, &hello_b, WALL + 1, 109));
    assert_eq!(link.take(CLIENT_ADDR), flight_b);

    link.send(b.receive(SERVER_ADDR, &flight_b, WALL + 1, 110));
    let commit_b = link.take(SERVER_ADDR);
    let events = server.receive(CLIENT_ADDR, &commit_b, WALL, 111);
    assert!(established(&events, CLIENT_ADDR, HandshakeKind::Full));
    link.send(events);
    let finished = link.take(CLIENT_ADDR);
    assert!(matches!(
        server.receive(CLIENT_ADDR, &commit_b, WALL, 112).as_slice(),
        [Event::Send { remote, bytes }] if *remote == CLIENT_ADDR && *bytes == finished
    ));
    assert!(established(
        &b.receive(SERVER_ADDR, &finished, WALL, 113),
        SERVER_ADDR,
        HandshakeKind::Full
    ));
    assert!(matches!(
        server.receive(CLIENT_ADDR, &hello_c, WALL, 114).as_slice(),
        [Event::Diagnostic { remote, reason: Diagnostic::Protocol(_) }] if *remote == CLIENT_ADDR
    ));
    assert_eq!(server.status(CLIENT_ADDR), Some(Status::Open));
    assert_eq!(server.deadline(), None);
    assert_protected_echo(&mut link, &mut b, &mut server, 115);
}

#[test]
fn pending_client_hello_rejects_candidates_and_keeps_original_flight() {
    let (clients, servers) = contexts_with_authority(true);
    let mut a = adapter(None, 1);
    let mut b = adapter(None, 1);
    let mut server = adapter(Some(servers), 1);
    let mut link = Link::default();

    link.send(a.connect(SERVER_ADDR, &clients, WALL - 1, 100));
    let hello_a = link.take(SERVER_ADDR);
    link.send(server.receive(CLIENT_ADDR, &hello_a, WALL, 101));
    let flight_a = link.take(CLIENT_ADDR);
    let deadline = server.deadline();

    let unrelated = Rsa::generate(2048).unwrap();
    let unrelated = Rsa::from_public_components(
        unrelated.n().to_owned().unwrap(),
        unrelated.e().to_owned().unwrap(),
    )
    .unwrap();
    let foreign_clients = ResumableClient::provisioned(
        RetryPolicy {
            timeout_ms: NonZeroU64::new(10).unwrap(),
            max_retries: 2,
        },
        TrustAnchor::new(ISSUER, SUBJECT, unrelated).unwrap(),
        NonZeroU64::new(1_000).unwrap(),
    );
    link.send(b.connect(SERVER_ADDR, &foreign_clients, WALL + 1, 102));
    let hello_b = link.take(SERVER_ADDR);
    assert!(assert_client_hello_time(&hello_b, WALL + 1).is_empty());

    // A truncated fresh offer and a validly framed change to A's key refresh.
    let mut conflict = hello_a.clone();
    *conflict.last_mut().unwrap() ^= 1;
    assert_client_hello_time(&conflict, WALL - 1);
    for (at, rejected) in [(103, &hello_b[..hello_b.len() - 1]), (104, &conflict[..])] {
        assert!(matches!(
            server.receive(CLIENT_ADDR, rejected, WALL, at).as_slice(),
            [Event::Diagnostic {
                reason: Diagnostic::Protocol(_),
                ..
            }]
        ));
        assert_eq!(server.status(CLIENT_ADDR), Some(Status::Negotiating));
        assert_eq!(server.deadline(), deadline);
    }

    // The provisioned server sends a clear alert for B's unrelated authority.
    link.send(server.receive(CLIENT_ADDR, &hello_b, WALL, 105));
    let alert = link.take(CLIENT_ADDR);
    let records = decode_datagram(&alert).unwrap();
    assert!(matches!(records.as_slice(), [record]
        if record.content_type == RecordType::Alert && record.cipher_spec == CipherSpec::Null));
    assert_eq!(server.status(CLIENT_ADDR), Some(Status::Negotiating));
    assert_eq!(server.deadline(), deadline);

    link.send(server.receive(CLIENT_ADDR, &hello_a, WALL, 106));
    assert_eq!(link.take(CLIENT_ADDR), flight_a);
    link.send(a.receive(SERVER_ADDR, &flight_a, WALL, 107));
    let commit_a = link.take(SERVER_ADDR);
    let events = server.receive(CLIENT_ADDR, &commit_a, WALL, 108);
    assert!(established(&events, CLIENT_ADDR, HandshakeKind::Full));
}

#[test]
fn pending_client_hello_replacement_expires_at_original_deadline() {
    let (clients, servers) = contexts();
    let mut a = adapter(None, 1);
    let mut b = adapter(None, 1);
    let mut c = adapter(None, 1);
    let mut server =
        adapter(Some(servers), 1).with_pending_handshake_timeout_ms(NonZeroU64::new(10).unwrap());
    let mut link = Link::default();

    link.send(a.connect(SERVER_ADDR, &clients, WALL - 1, 99));
    let hello_a = link.take(SERVER_ADDR);
    link.send(server.receive(CLIENT_ADDR, &hello_a, WALL, 100));
    let flight_a = link.take(CLIENT_ADDR);
    link.send(server.receive(CLIENT_ADDR, &hello_a, WALL, 108));
    assert_eq!(link.take(CLIENT_ADDR), flight_a);
    assert_eq!(server.deadline(), Some(110));

    link.send(b.connect(SERVER_ADDR, &clients, WALL + 1, 109));
    let hello_b = link.take(SERVER_ADDR);
    link.send(server.receive(CLIENT_ADDR, &hello_b, WALL + 1, 109));
    let flight_b = link.take(CLIENT_ADDR);
    assert_server_hello_time(&flight_b, WALL + 1);
    assert_eq!(server.deadline(), Some(110));
    assert!(server.tick(109).is_empty());

    let other_addr = SocketAddr::new(CLIENT_ADDR.ip(), CLIENT_ADDR.port() + 1);
    link.send(c.connect(SERVER_ADDR, &clients, WALL, 110));
    let hello_c = link.take(SERVER_ADDR);
    assert!(matches!(
        server.receive(other_addr, &hello_c, WALL, 110).as_slice(),
        [Event::TimedOut { remote: expired }, Event::Send { remote: admitted, .. }]
            if *expired == CLIENT_ADDR && *admitted == other_addr
    ));
    assert_eq!(server.status(CLIENT_ADDR), None);
    assert_eq!(server.status(other_addr), Some(Status::Negotiating));
    assert_eq!(server.deadline(), Some(120));
    assert!(matches!(
        server.receive(CLIENT_ADDR, &hello_b, WALL, 110).as_slice(),
        [Event::Diagnostic {
            reason: Diagnostic::PreviousClientHello,
            ..
        }]
    ));
}

#[test]
fn pending_client_hello_replaces_abbreviated_handshake_for_same_session() {
    let (clients, servers) = contexts();
    let mut a = adapter(None, 1);
    let mut b = adapter(None, 1);
    let mut server = adapter(Some(servers), 1);
    let mut link = Link::default();
    let session = full_handshake_with_hello_times(&mut link, &mut a, &mut server, &clients);

    link.send(server.close(CLIENT_ADDR, CloseScope::Connection));
    let close = link.take(CLIENT_ADDR);
    link.send(a.receive(SERVER_ADDR, &close, WALL, 105));
    let reply = link.take(SERVER_ADDR);
    server.receive(CLIENT_ADDR, &reply, WALL, 106);
    assert_eq!(a.status(SERVER_ADDR), None);
    assert_eq!(server.status(CLIENT_ADDR), None);

    link.send(a.connect(SERVER_ADDR, &clients, WALL - 1, 107));
    let hello_a = link.take(SERVER_ADDR);
    assert_eq!(assert_client_hello_time(&hello_a, WALL - 1), session);
    link.send(server.receive(CLIENT_ADDR, &hello_a, WALL, 108));
    let flight_a = link.take(CLIENT_ADDR);
    assert_eq!(assert_server_hello_time(&flight_a, WALL), session);
    let events = a.receive(SERVER_ADDR, &flight_a, WALL, 109);
    assert!(established(&events, SERVER_ADDR, HandshakeKind::Resumed));
    link.send(events);
    let commit_a = link.take(SERVER_ADDR);

    link.send(b.connect(SERVER_ADDR, &clients, WALL + 1, 110));
    let hello_b = link.take(SERVER_ADDR);
    assert_eq!(assert_client_hello_time(&hello_b, WALL + 1), session);
    link.send(server.receive(CLIENT_ADDR, &hello_b, WALL + 1, 111));
    let flight_b = link.take(CLIENT_ADDR);
    assert_eq!(assert_server_hello_time(&flight_b, WALL + 1), session);
    let records = decode_datagram(&flight_b).unwrap();
    let [hello, ccs, finished] = records.as_slice() else {
        panic!("expected an abbreviated ServerHello, CCS and Finished flight");
    };
    assert_eq!(hello.content_type, RecordType::Handshake);
    assert_eq!(ccs.content_type, RecordType::ChangeCipherSpec);
    assert_eq!(finished.content_type, RecordType::Handshake);
    assert_eq!(finished.cipher_spec, CipherSpec::Current);

    assert!(matches!(
        server.receive(CLIENT_ADDR, &commit_a, WALL, 112).as_slice(),
        [Event::Diagnostic {
            reason: Diagnostic::Protocol(_),
            ..
        }]
    ));
    assert_eq!(server.status(CLIENT_ADDR), Some(Status::Negotiating));
    link.send(server.receive(CLIENT_ADDR, &hello_b, WALL, 113));
    assert_eq!(link.take(CLIENT_ADDR), flight_b);
    let events = b.receive(SERVER_ADDR, &flight_b, WALL, 114);
    assert!(established(&events, SERVER_ADDR, HandshakeKind::Resumed));
    link.send(events);
    let commit_b = link.take(SERVER_ADDR);
    let events = server.receive(CLIENT_ADDR, &commit_b, WALL, 115);
    assert!(established(&events, CLIENT_ADDR, HandshakeKind::Resumed));
    let events = server.receive(CLIENT_ADDR, &commit_b, WALL, 116);
    assert!(matches!(events.as_slice(), [Event::Send { remote, .. }] if *remote == CLIENT_ADDR));
    link.send(events);
    let confirmation = link.take(CLIENT_ADDR);
    assert!(b.receive(SERVER_ADDR, &confirmation, WALL, 117).is_empty());
    assert_eq!(b.status(SERVER_ADDR), Some(Status::Open));
    assert_protected_echo(&mut link, &mut b, &mut server, 118);

    link.send(server.close(CLIENT_ADDR, CloseScope::Connection));
    let close = link.take(CLIENT_ADDR);
    link.send(b.receive(SERVER_ADDR, &close, WALL, 120));
    let reply = link.take(SERVER_ADDR);
    server.receive(CLIENT_ADDR, &reply, WALL, 121);

    // The server seeded the cache at 103. The client still offers that ID
    // when the server reaches its original expiration at 103 + 1,000.
    link.send(b.connect(SERVER_ADDR, &clients, WALL, 1102));
    let hello = link.take(SERVER_ADDR);
    assert_eq!(assert_client_hello_time(&hello, WALL), session);
    link.send(server.receive(CLIENT_ADDR, &hello, WALL, 1103));
    let fallback = link.take(CLIENT_ADDR);
    assert_ne!(assert_server_hello_time(&fallback, WALL), session);
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

#[test]
fn lost_final_server_finished_flight_retries_and_echoes_protected_data() {
    // WAP-199 §10.4. Drop the final server CCS/Finished datagram.
    let (clients, servers) = contexts();
    let mut client = adapter(None, 1);
    let mut server = adapter(Some(servers), 1);
    let mut link = Link::default();

    link.send(client.connect(SERVER_ADDR, &clients, WALL, 100));
    let hello = link.take(SERVER_ADDR);
    link.send(server.receive(CLIENT_ADDR, &hello, WALL, 101));
    let server_hello_flight = link.take(CLIENT_ADDR);
    link.send(client.receive(SERVER_ADDR, &server_hello_flight, WALL, 102));
    let client_commit = link.take(SERVER_ADDR);

    let events = server.receive(CLIENT_ADDR, &client_commit, WALL, 103);
    assert_eq!(events.len(), 2);
    assert!(established(&events, CLIENT_ADDR, HandshakeKind::Full));
    link.send(events);
    let lost_flight = link.take(CLIENT_ADDR);
    let records = decode_datagram(&lost_flight).unwrap();
    let [ccs, finished] = records.as_slice() else {
        panic!("expected CCS and protected Finished: {records:?}");
    };
    assert_eq!(ccs.content_type, RecordType::ChangeCipherSpec);
    assert_eq!(ccs.cipher_spec, CipherSpec::Null);
    assert_eq!(ccs.sequence, 3);
    assert_eq!(ccs.fragment, &[1]);
    assert_eq!(finished.content_type, RecordType::Handshake);
    assert_eq!(finished.cipher_spec, CipherSpec::Current);
    assert_eq!(finished.sequence, 0);
    assert_eq!(server.status(CLIENT_ADDR), Some(Status::Open));
    assert_eq!(client.status(SERVER_ADDR), Some(Status::Negotiating));

    assert_eq!(client.deadline(), Some(112));
    assert!(client.tick(111).is_empty());
    let events = client.tick(112);
    assert_eq!(events.len(), 1);
    link.send(events);
    let retried_commit = link.take(SERVER_ADDR);
    assert_eq!(retried_commit, client_commit);

    let events = server.receive(CLIENT_ADDR, &retried_commit, WALL, 113);
    assert!(matches!(events.as_slice(), [Event::Send { .. }]));
    link.send(events);
    let repeated_flight = link.take(CLIENT_ADDR);
    assert_eq!(repeated_flight, lost_flight);

    let events = client.receive(SERVER_ADDR, &repeated_flight, WALL, 114);
    assert!(matches!(
        events.as_slice(),
        [Event::Established { remote, kind: HandshakeKind::Full }] if *remote == SERVER_ADDR
    ));
    assert_eq!(client.status(SERVER_ADDR), Some(Status::Open));
    assert_eq!(server.status(CLIENT_ADDR), Some(Status::Open));
    assert_eq!(client.deadline(), None);

    link.send(client.send_application(SERVER_ADDR, PAYLOAD.to_vec()));
    let request = link.take(SERVER_ADDR);
    let events = server.receive(CLIENT_ADDR, &request, WALL, 115);
    let [Event::Deliver { remote, payload }] = events.as_slice() else {
        panic!("expected authenticated request");
    };
    assert_eq!((*remote, payload.as_slice()), (CLIENT_ADDR, PAYLOAD));

    link.send(server.send_application(*remote, payload.clone()));
    let response = link.take(CLIENT_ADDR);
    assert!(matches!(
        client.receive(SERVER_ADDR, &response, WALL, 116).as_slice(),
        [Event::Deliver { remote, payload }] if *remote == SERVER_ADDR && payload == PAYLOAD
    ));
    for datagram in [&request, &response] {
        let records = decode_datagram(datagram).unwrap();
        let [record] = records.as_slice() else {
            panic!("expected one protected application record: {records:?}");
        };
        assert_eq!(record.content_type, RecordType::ApplicationData);
        assert_eq!(record.cipher_spec, CipherSpec::Current);
    }
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
    assert!(matches!(
        server.receive(client_addr, &other_hello, WALL, 16).as_slice(),
        [Event::Diagnostic { remote, reason: Diagnostic::Protocol(_) }] if *remote == client_addr
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
