use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::{NonZeroU64, NonZeroUsize};

use openssl::rsa::Rsa;
use wtls_lab::handshake::{CloseScope, HandshakeKind, RetryPolicy, Status};
use wtls_lab::udp::{Adapter, Diagnostic, Event};
use wtls_lab::wire::{
    AlertFields, AlertProtection, DatagramBudget, ResumableClient, ResumableServer, ServerIdentity,
    TrustAnchor, WireAction, WireError, decode_client_hello, decode_server_hello,
    issue_certificate,
};
use wtls_lab::{CipherSpec, RecordType, decode_datagram};

const WALL: u32 = 1_730_000_000;
const ISSUER: &str = "WTLS Lab CA; WTLS Lab; CA";
const SUBJECT: &str = "Echo; WTLS Lab; CA; echo.lab.invalid";
const PAYLOAD: &[u8] = b"protected UDP echo";
const CLIENT_ADDR: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152));
const ALT_CLIENT_ADDR: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49153));
const SERVER_ADDR: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9203));

fn contexts() -> (ResumableClient, ResumableServer) {
    contexts_with_authority(false)
}

fn contexts_with_authority(require_authority: bool) -> (ResumableClient, ResumableServer) {
    let (trust, servers) = credentials(require_authority);
    (client_context(trust), servers)
}

fn credentials(require_authority: bool) -> (TrustAnchor, ResumableServer) {
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
    (
        trust,
        ResumableServer::new(identity, NonZeroUsize::new(8).unwrap(), CACHE_LIFETIME),
    )
}

const RETRY: RetryPolicy = RetryPolicy {
    timeout_ms: NonZeroU64::new(10).unwrap(),
    max_retries: 2,
};
const CACHE_LIFETIME: NonZeroU64 = NonZeroU64::new(1_000).unwrap();

fn client_context(trust: TrustAnchor) -> ResumableClient {
    ResumableClient::new(RETRY, trust, CACHE_LIFETIME)
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
    open_protected_association_with_budget(link, DatagramBudget::new(1200))
}

fn open_protected_association_with_budget(
    link: &mut Link,
    server_budget: DatagramBudget,
) -> (Adapter, Adapter) {
    let (clients, servers) = contexts();
    let mut client = adapter(None, 1);
    let mut server = Adapter::new(Some(servers), server_budget, NonZeroUsize::MIN);

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

fn assert_application_batch_delivery(events: &[Event], source: SocketAddr, sequences: &[u16]) {
    assert_eq!(events.len(), sequences.len());
    for (event, sequence) in events.iter().zip(sequences) {
        assert!(matches!(
            event,
            Event::Deliver { remote, payload }
                if *remote == source && payload.as_slice() == sequence.to_be_bytes()
        ));
    }
}

#[test]
fn application_batch_replay_is_per_record_across_key_refresh_and_window_cutoff() {
    let mut link = Link::default();
    let (mut client, mut server) = open_protected_association(&mut link);
    let records = (1..=39)
        .map(|sequence| protected_application(&mut link, &mut client, SERVER_ADDR, sequence))
        .collect::<Vec<_>>();
    let record = |sequence: usize| records[sequence - 1].as_slice();

    let reversed = [record(8), record(7)].concat();
    assert_application_batch_delivery(
        &server.receive(CLIENT_ADDR, &reversed, WALL, 5),
        CLIENT_ADDR,
        &[8, 7],
    );
    assert!(server.receive(CLIENT_ADDR, &reversed, WALL, 6).is_empty());

    let mixed = [record(8), record(9), record(9), record(10)].concat();
    assert_application_batch_delivery(
        &server.receive(CLIENT_ADDR, &mixed, WALL, 7),
        CLIENT_ADDR,
        &[9, 10],
    );
    assert!(server.receive(CLIENT_ADDR, &mixed, WALL, 8).is_empty());

    // Sequence 6 is fresh, but falls exactly outside the 32-record window
    // after accepting sequence 38. Sequence 11 is still inside it.
    let cutoff = [record(38), record(6), record(11), record(39)].concat();
    assert_application_batch_delivery(
        &server.receive(CLIENT_ADDR, &cutoff, WALL, 9),
        CLIENT_ADDR,
        &[38, 11, 39],
    );
    assert!(server.receive(CLIENT_ADDR, &cutoff, WALL, 10).is_empty());
}

#[test]
fn application_batch_udp_budget_accepts_the_limit_and_rejects_one_byte_over() {
    use wtls_lab::wire::DatagramTooLarge;

    // Each record has a 5-byte header and 544 bytes of protected content.
    const BATCH_LEN: usize = 2 * (5 + 544);
    for limit in [BATCH_LEN, BATCH_LEN - 1] {
        let mut link = Link::default();
        let (mut client, mut server) =
            open_protected_association_with_budget(&mut link, DatagramBudget::new(limit));
        let first = vec![0x11; 520];
        let second = vec![0x22; 520];
        link.send(client.send_application(SERVER_ADDR, first.clone()));
        let first_record = link.take(SERVER_ADDR);
        link.send(client.send_application(SERVER_ADDR, second.clone()));
        let second_record = link.take(SERVER_ADDR);
        let batch = [first_record.as_slice(), &second_record].concat();
        assert_eq!(batch.len(), BATCH_LEN);

        let events = server.receive(CLIENT_ADDR, &batch, WALL, 5);
        if limit == BATCH_LEN {
            assert!(matches!(
                events.as_slice(),
                [Event::Deliver { remote: a, payload: x }, Event::Deliver { remote: b, payload: y }]
                    if *a == CLIENT_ADDR && *b == CLIENT_ADDR && *x == first && *y == second
            ));
        } else {
            assert!(matches!(
                events.as_slice(),
                [Event::Diagnostic {
                    remote,
                    reason: Diagnostic::InboundTooLarge(DatagramTooLarge { size: BATCH_LEN, limit: actual }),
                }] if *remote == CLIENT_ADDR && *actual == limit
            ));
            assert_eq!(server.status(CLIENT_ADDR), Some(Status::Open));
            for (record, expected) in [(first_record, first), (second_record, second)] {
                assert!(matches!(
                    server.receive(CLIENT_ADDR, &record, WALL, 6).as_slice(),
                    [Event::Deliver { remote, payload }] if *remote == CLIENT_ADDR && *payload == expected
                ));
            }
        }
    }
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
fn matching_clear_alert_retires_a_pending_udp_slot_on_receive() {
    use wtls_lab::wire::{AlertFields, AlertProtection, WireError};
    use wtls_lab::{LengthForm, Record, encode_datagram};

    let (clients, servers) = contexts();
    let mut client = adapter(None, 1);
    let mut other = adapter(None, 1);
    let mut server = adapter(Some(servers), 1);
    let mut link = Link::default();
    let other_addr = SocketAddr::new(CLIENT_ADDR.ip(), CLIENT_ADDR.port() + 1);

    link.send(client.connect(SERVER_ADDR, &clients, WALL, 0));
    let offer = link.take(SERVER_ADDR);
    link.send(server.receive(CLIENT_ADDR, &offer, WALL, 1));
    let flight = link.take(CLIENT_ADDR);
    assert_eq!(server.status(CLIENT_ADDR), Some(Status::Negotiating));
    link.send(other.connect(SERVER_ADDR, &clients, WALL, 2));
    let other_offer = link.take(SERVER_ADDR);
    assert!(matches!(
        server.receive(other_addr, &other_offer, WALL, 2).as_slice(),
        [Event::Diagnostic { remote, reason: Diagnostic::AtCapacity }] if *remote == other_addr
    ));

    let first = decode_datagram(&flight).unwrap()[0];
    let mut checksum = [0; 4];
    for (index, &byte) in flight[..first.wire_len()].iter().enumerate() {
        checksum[index % 4] ^= byte;
    }
    let [a, b, c, d] = checksum;
    let alert = encode_datagram(&[Record {
        content_type: RecordType::Alert,
        cipher_spec: CipherSpec::Null,
        sequence: 1,
        length_form: LengthForm::Explicit,
        fragment: &[3, 40, a, b, c, d],
    }])
    .unwrap();
    assert!(matches!(
        server.receive(CLIENT_ADDR, &alert, WALL, 4).as_slice(),
        [Event::Diagnostic {
            remote,
            reason: Diagnostic::Protocol(WireError::PeerAlert {
                fields: AlertFields { level: 3, description: 40, checksum: reported },
                protection: AlertProtection::Clear,
            }),
        }] if *remote == CLIENT_ADDR && *reported == checksum
    ));
    assert_eq!(server.status(CLIENT_ADDR), None);
    assert_eq!(server.deadline(), None);
    let events = server.receive(other_addr, &other_offer, WALL, 4);
    assert!(matches!(events.as_slice(), [Event::Send { remote, .. }] if *remote == other_addr));
    assert_eq!(server.status(other_addr), Some(Status::Negotiating));
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
    let mut resume = adapter(None, 1);
    link.send(resume.connect(SERVER_ADDR, &clients, WALL, 114));
    let nonempty_offer = link.take(SERVER_ADDR);
    assert!(!session_id(&nonempty_offer).is_empty());
    let resumed = only_send(
        server.receive(CLIENT_ADDR, &nonempty_offer, WALL, 114),
        CLIENT_ADDR,
    );
    assert_eq!(session_id(&resumed), session_id(&nonempty_offer));
    assert_eq!(server.status(CLIENT_ADDR), Some(Status::Open));
    assert!(server.deadline().is_some());
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
fn algorithm_alert_keeps_a_pending_association_and_its_cached_session() {
    use wtls_lab::LengthForm;
    use wtls_lab::wire::DatagramTooLarge;

    let (clients, servers) = contexts();
    let mut a = adapter(None, 1);
    let mut b = adapter(None, 1);
    let mut server =
        adapter(Some(servers), 1).with_pending_handshake_timeout_ms(NonZeroU64::new(20).unwrap());
    let mut link = Link::default();
    let id = full_handshake_with_hello_times(&mut link, &mut a, &mut server, &clients);

    link.send(server.close(CLIENT_ADDR, CloseScope::Connection));
    let close = link.take(CLIENT_ADDR);
    link.send(a.receive(SERVER_ADDR, &close, WALL, 105));
    let reply = link.take(SERVER_ADDR);
    server.receive(CLIENT_ADDR, &reply, WALL, 106);
    assert_eq!(server.status(CLIENT_ADDR), None);

    link.send(b.connect(SERVER_ADDR, &clients, WALL + 1, 107));
    let mut hello_b = link.take(SERVER_ADDR);
    assert_eq!(assert_client_hello_time(&hello_b, WALL + 1), id);
    let suite = hello_b.len() - 6;
    assert_eq!(hello_b[suite..suite + 2], [6, 3]);
    hello_b[suite..suite + 2].copy_from_slice(&[5, 2]);
    let mut expected = vec![0xc2, 0, 0, 0, 6, 3, 40, 0, 0, 0, 0];
    for (index, byte) in hello_b.iter().enumerate() {
        expected[7 + index % 4] ^= byte;
    }
    let assert_alert = |events: Vec<Event>| {
        assert!(matches!(events.as_slice(),
            [Event::Send { remote, bytes }] if *remote == CLIENT_ADDR && *bytes == expected));
    };
    assert_alert(server.receive(CLIENT_ADDR, &hello_b, WALL, 107));
    assert_eq!(server.status(CLIENT_ADDR), None);
    assert_eq!(server.deadline(), None);
    assert!(server.tick(108).is_empty());

    link.send(a.connect(SERVER_ADDR, &clients, WALL - 1, 109));
    let hello_a = link.take(SERVER_ADDR);
    assert_eq!(assert_client_hello_time(&hello_a, WALL - 1), id);
    link.send(server.receive(CLIENT_ADDR, &hello_a, WALL, 110));
    let flight_a = link.take(CLIENT_ADDR);
    assert_eq!(assert_server_hello_time(&flight_a, WALL), id);
    assert_eq!(server.deadline(), Some(130));

    // A complete incompatible hello can still be stopped by the inbound budget.
    let mut fragment = decode_datagram(&hello_b).unwrap()[0].fragment.to_vec();
    let extra_keys = [7, 0, 0].repeat(400);
    let key_length = u16::try_from(3 + extra_keys.len()).unwrap();
    let key_offset = 3 + 1 + 16 + 1 + id.len();
    assert_eq!(fragment[key_offset..key_offset + 2], [0, 3]);
    fragment[key_offset..key_offset + 2].copy_from_slice(&key_length.to_be_bytes());
    fragment.splice(key_offset + 2..key_offset + 2, extra_keys);
    let body_length = u16::try_from(fragment.len() - 3).unwrap();
    fragment[1..3].copy_from_slice(&body_length.to_be_bytes());
    let oversized = wtls_lab::encode_datagram(&[wtls_lab::Record {
        length_form: LengthForm::Explicit,
        fragment: &fragment,
        ..decode_datagram(&hello_b).unwrap()[0]
    }])
    .unwrap();
    assert!(matches!(
        server.receive(CLIENT_ADDR, &oversized, WALL, 111).as_slice(),
        [Event::Diagnostic {
            remote,
            reason: Diagnostic::InboundTooLarge(DatagramTooLarge {
                size,
                limit: 1200,
            }),
        }] if *remote == CLIENT_ADDR && *size == oversized.len()
    ));

    assert_alert(server.receive(CLIENT_ADDR, &hello_b, WALL, 112));
    assert_alert(server.receive(CLIENT_ADDR, &hello_b, WALL, 113));
    let other = SocketAddr::new(CLIENT_ADDR.ip(), CLIENT_ADDR.port() + 1);
    assert!(matches!(
        server.receive(other, &hello_b, WALL, 114).as_slice(),
        [Event::Diagnostic { remote, reason: Diagnostic::AtCapacity }] if *remote == other
    ));
    let mut same_random = hello_a.clone();
    same_random[suite..suite + 2].copy_from_slice(&[5, 2]);
    assert!(matches!(
        server.receive(CLIENT_ADDR, &same_random, WALL, 115).as_slice(),
        [Event::Diagnostic { remote, reason: Diagnostic::Protocol(_) }] if *remote == CLIENT_ADDR
    ));
    assert_eq!(server.status(CLIENT_ADDR), Some(Status::Negotiating));
    assert_eq!(server.deadline(), Some(130));
    assert!(server.tick(116).is_empty());
    link.send(server.receive(CLIENT_ADDR, &hello_a, WALL, 117));
    assert_eq!(link.take(CLIENT_ADDR), flight_a);

    let events = a.receive(SERVER_ADDR, &flight_a, WALL, 118);
    assert!(established(&events, SERVER_ADDR, HandshakeKind::Resumed));
    link.send(events);
    let commit_a = link.take(SERVER_ADDR);
    let events = server.receive(CLIENT_ADDR, &commit_a, WALL, 119);
    assert!(established(&events, CLIENT_ADDR, HandshakeKind::Resumed));
    link.send(server.receive(CLIENT_ADDR, &commit_a, WALL, 119));
    let confirmation = link.take(CLIENT_ADDR);
    assert!(a.receive(SERVER_ADDR, &confirmation, WALL, 119).is_empty());
    assert_alert(server.receive(CLIENT_ADDR, &hello_b, WALL, 120));
    assert_eq!(server.status(CLIENT_ADDR), Some(Status::Open));
    assert_eq!(server.deadline(), None);
    assert_protected_echo(&mut link, &mut a, &mut server, 121);
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

fn only_send(events: Vec<Event>, destination: SocketAddr) -> Vec<u8> {
    let Ok([Event::Send { remote, bytes }]) = <[Event; 1]>::try_from(events) else {
        panic!("expected one Send event");
    };
    assert_eq!(remote, destination);
    bytes
}

fn recovery_hello(client: &mut Adapter, context: &ResumableClient, at: u64) -> Vec<u8> {
    only_send(
        client.connect(SERVER_ADDR, context, WALL + 1, at),
        SERVER_ADDR,
    )
}

fn recovery_flight(server: &mut Adapter, hello: &[u8], at: u64) -> Vec<u8> {
    only_send(server.receive(CLIENT_ADDR, hello, WALL, at), CLIENT_ADDR)
}

fn recovery_commit(client: &mut Adapter, flight: &[u8], at: u64) -> Vec<u8> {
    only_send(client.receive(SERVER_ADDR, flight, WALL, at), SERVER_ADDR)
}

fn assert_retired_hello(server: &mut Adapter, hello: &[u8], at: u64) {
    assert!(matches!(
        server.receive(CLIENT_ADDR, hello, WALL, at).as_slice(),
        [Event::Diagnostic { remote, reason: Diagnostic::PreviousClientHello }]
            if *remote == CLIENT_ADDR
    ));
}

#[test]
fn established_recovery_stages_at_capacity_and_keeps_incumbent_traffic() {
    let (trust, servers) = credentials(false);
    let clients_a = client_context(trust.clone());
    let clients_b = client_context(trust);
    let mut server =
        adapter(Some(servers), 1).with_pending_handshake_timeout_ms(NonZeroU64::new(20).unwrap());
    let mut a = adapter(None, 1);
    let mut b = adapter(None, 1);
    let mut link = Link::default();

    let hello_a = only_send(a.connect(SERVER_ADDR, &clients_a, WALL - 1, 0), SERVER_ADDR);
    let flight_a = recovery_flight(&mut server, &hello_a, 1);
    let commit_a = recovery_commit(&mut a, &flight_a, 2);
    link.send(server.receive(CLIENT_ADDR, &commit_a, WALL, 3));
    let final_a = link.take(CLIENT_ADDR);
    assert!(established(
        &a.receive(SERVER_ADDR, &final_a, WALL, 4),
        SERVER_ADDR,
        HandshakeKind::Full
    ));

    let hello_b = recovery_hello(&mut b, &clients_b, 10);
    assert!(assert_client_hello_time(&hello_b, WALL + 1).is_empty());
    let events = server.receive(CLIENT_ADDR, &hello_b, WALL, 11);
    assert!(
        matches!(events.as_slice(), [Event::Send { remote, .. }] if *remote == CLIENT_ADDR),
        "fresh full ClientHello on the established tuple must start a server flight"
    );
    let flight_b = only_send(events, CLIENT_ADDR);
    assert_eq!(server.status(CLIENT_ADDR), Some(Status::Open));
    assert_eq!(server.deadline(), Some(31));
    assert_protected_echo(&mut link, &mut a, &mut server, 12);

    assert_eq!(recovery_flight(&mut server, &hello_a, 14), flight_a);
    assert_eq!(recovery_flight(&mut server, &commit_a, 15), final_a);
    assert_eq!(recovery_flight(&mut server, &hello_b, 16), flight_b);
    for hello in [&hello_a, &hello_b] {
        let mut conflict = hello.clone();
        *conflict.last_mut().unwrap() ^= 1;
        assert!(matches!(
            server.receive(CLIENT_ADDR, &conflict, WALL, 17).as_slice(),
            [Event::Diagnostic {
                reason: Diagnostic::Protocol(WireError::InvalidRecord),
                ..
            }]
        ));
    }

    let mut c = adapter(None, 1);
    let hello_c = only_send(c.connect(SERVER_ADDR, &clients_b, WALL, 18), SERVER_ADDR);
    let other = SocketAddr::new(CLIENT_ADDR.ip(), CLIENT_ADDR.port() + 1);
    assert!(matches!(
        server.receive(other, &hello_c, WALL, 18).as_slice(),
        [Event::Diagnostic { remote, reason: Diagnostic::AtCapacity }] if *remote == other
    ));
    assert!(matches!(
        server.receive(CLIENT_ADDR, &hello_c, WALL, 19).as_slice(),
        [Event::Diagnostic { remote, reason: Diagnostic::AddressInUse }] if *remote == CLIENT_ADDR
    ));
    assert_eq!(recovery_flight(&mut server, &hello_b, 20), flight_b);
    assert_eq!(server.deadline(), Some(31));
    assert_eq!(server.status(CLIENT_ADDR), Some(Status::Open));
}

#[test]
fn established_recovery_keeps_both_peers_on_incomplete_commit_input() {
    let (trust, servers) = credentials(false);
    let clients_a = client_context(trust.clone());
    let clients_b = client_context(trust);
    let mut server =
        adapter(Some(servers), 1).with_pending_handshake_timeout_ms(NonZeroU64::new(20).unwrap());
    let mut a = adapter(None, 1);
    let mut b = adapter(None, 1);
    let mut link = Link::default();
    full_handshake_with_hello_times(&mut link, &mut a, &mut server, &clients_a);

    let hello_b = recovery_hello(&mut b, &clients_b, 105);
    let flight_b = recovery_flight(&mut server, &hello_b, 106);
    let commit_b = recovery_commit(&mut b, &flight_b, 107);
    let records = decode_datagram(&commit_b).unwrap();
    let [key_exchange, ccs, _] = records.as_slice() else {
        panic!("expected a three-record full client commit");
    };
    let key_exchange_end = key_exchange.wire_len();
    let ccs_end = key_exchange_end + ccs.wire_len();

    for (at, end) in [(108, 0), (110, key_exchange_end), (112, ccs_end)] {
        assert!(matches!(
            server.receive(CLIENT_ADDR, &commit_b[..end], WALL, at).as_slice(),
            [Event::Diagnostic { remote, reason: Diagnostic::Protocol(_) }]
                if *remote == CLIENT_ADDR
        ));
        assert_eq!(server.status(CLIENT_ADDR), Some(Status::Open));
        assert_eq!(server.deadline(), Some(126));
        assert_protected_echo(&mut link, &mut a, &mut server, at + 1);
    }
    assert_eq!(recovery_flight(&mut server, &hello_b, 114), flight_b);
    assert_eq!(server.deadline(), Some(126));
}

#[test]
fn established_recovery_promotes_and_replays_lost_final_before_delayed_incumbent_close() {
    let (trust, servers) = credentials(false);
    let clients_a = client_context(trust.clone());
    let clients_b = client_context(trust);
    let mut a = adapter(None, 1);
    let mut b = adapter(None, 1);
    let mut server = adapter(Some(servers), 1);
    let mut link = Link::default();
    let id_a = full_handshake_with_hello_times(&mut link, &mut a, &mut server, &clients_a);

    let hello_b = recovery_hello(&mut b, &clients_b, 105);
    let flight_b = recovery_flight(&mut server, &hello_b, 106);
    let commit_b = recovery_commit(&mut b, &flight_b, 107);
    let delayed_a = only_send(
        a.send_application(SERVER_ADDR, PAYLOAD.to_vec()),
        SERVER_ADDR,
    );
    let mut reconnect_a = adapter(None, 1);
    let resume_a = recovery_hello(&mut reconnect_a, &clients_a, 108);
    assert_eq!(session_id(&resume_a), id_a);
    link.send(a.close(SERVER_ADDR, CloseScope::Session));
    let delayed_close = link.take(SERVER_ADDR);

    let events = server.receive(CLIENT_ADDR, &commit_b, WALL, 109);
    assert!(matches!(
        events.as_slice(),
        [Event::Send { remote, .. }, Event::Established { remote: established, kind: HandshakeKind::Full }]
            if *remote == CLIENT_ADDR && *established == CLIENT_ADDR
    ));
    link.send(events);
    let lost_final = link.take(CLIENT_ADDR);
    assert_eq!(server.deadline(), None);
    for delayed in [&delayed_a, &delayed_close] {
        assert!(matches!(
            server.receive(CLIENT_ADDR, delayed, WALL, 110).as_slice(),
            [Event::Diagnostic {
                reason: Diagnostic::Protocol(_),
                ..
            }]
        ));
    }
    assert_eq!(server.status(CLIENT_ADDR), Some(Status::Open));

    let retry = only_send(b.tick(117), SERVER_ADDR);
    assert_eq!(retry, commit_b);
    assert_eq!(recovery_flight(&mut server, &retry, 118), lost_final);
    assert!(established(
        &b.receive(SERVER_ADDR, &lost_final, WALL, 119),
        SERVER_ADDR,
        HandshakeKind::Full
    ));
    assert_protected_echo(&mut link, &mut b, &mut server, 120);

    server.close(CLIENT_ADDR, CloseScope::Connection);
    let resumed = recovery_flight(&mut server, &resume_a, 122);
    assert_eq!(session_id(&resumed), id_a);
}

#[test]
fn established_recovery_expires_at_the_deadline_in_tick_and_receive() {
    for expire_by_tick in [true, false] {
        let (trust, servers) = credentials(false);
        let clients_a = client_context(trust.clone());
        let clients_b = client_context(trust);
        let mut server = adapter(Some(servers), 1)
            .with_pending_handshake_timeout_ms(NonZeroU64::new(10).unwrap());
        let mut a = adapter(None, 1);
        let mut b = adapter(None, 1);
        let mut link = Link::default();
        full_handshake_with_hello_times(&mut link, &mut a, &mut server, &clients_a);
        let hello_b = recovery_hello(&mut b, &clients_b, 105);
        let flight_b = recovery_flight(&mut server, &hello_b, 106);
        let commit_b = recovery_commit(&mut b, &flight_b, 107);
        assert_eq!(recovery_flight(&mut server, &hello_b, 115), flight_b);
        assert_eq!(server.deadline(), Some(116));
        if expire_by_tick {
            assert!(server.tick(116).is_empty());
            assert_eq!(server.deadline(), None);
        }
        assert!(matches!(
            server.receive(CLIENT_ADDR, &commit_b, WALL, 116).as_slice(),
            [Event::Diagnostic {
                reason: Diagnostic::Protocol(_),
                ..
            }]
        ));
        assert_eq!(server.deadline(), None);
        assert_retired_hello(&mut server, &hello_b, 117);
        assert_protected_echo(&mut link, &mut a, &mut server, 118);
        let hello_c = only_send(
            adapter(None, 1).connect(SERVER_ADDR, &clients_b, WALL - 1, 120),
            SERVER_ADDR,
        );
        recovery_flight(&mut server, &hello_c, 120);
    }
}

#[test]
fn established_recovery_retires_failed_finished_and_preserves_incumbent() {
    let (trust, servers) = credentials(false);
    let clients_a = client_context(trust.clone());
    let clients_b = client_context(trust);
    let mut a = adapter(None, 1);
    let mut b = adapter(None, 1);
    let mut c = adapter(None, 1);
    let mut server = adapter(Some(servers), 1);
    let mut link = Link::default();
    full_handshake_with_hello_times(&mut link, &mut a, &mut server, &clients_a);
    let mut hello_b = recovery_hello(&mut b, &clients_b, 105);
    // The gateway still selects refresh 3, but the peer's Finished covers
    // its original offer. The client generates the entire protected commit.
    assert_eq!(*hello_b.last().unwrap(), 3);
    *hello_b.last_mut().unwrap() = 4;
    let flight_b = recovery_flight(&mut server, &hello_b, 106);
    let commit_b = recovery_commit(&mut b, &flight_b, 107);
    let events = server.receive(CLIENT_ADDR, &commit_b, WALL, 108);
    let [Event::Diagnostic { reason, .. }] = events.as_slice() else {
        panic!("expected a Finished verification diagnostic");
    };
    assert_eq!(
        *reason,
        Diagnostic::Protocol(WireError::AuthenticationFailed)
    );
    assert_eq!(server.deadline(), None);
    assert_retired_hello(&mut server, &hello_b, 109);
    assert_protected_echo(&mut link, &mut a, &mut server, 110);

    let hello_c = only_send(
        c.connect(SERVER_ADDR, &clients_b, WALL - 1, 112),
        SERVER_ADDR,
    );
    let flight_c = recovery_flight(&mut server, &hello_c, 113);
    let deadline = server.deadline();
    assert!(matches!(
        server.receive(CLIENT_ADDR, &commit_b, WALL, 114).as_slice(),
        [Event::Diagnostic {
            reason: Diagnostic::Protocol(_),
            ..
        }]
    ));
    assert_eq!(server.deadline(), deadline);
    assert_protected_echo(&mut link, &mut a, &mut server, 115);
    let commit_c = recovery_commit(&mut c, &flight_c, 117);
    assert!(established(
        &server.receive(CLIENT_ADDR, &commit_c, WALL, 118),
        CLIENT_ADDR,
        HandshakeKind::Full
    ));
}

#[test]
fn established_recovery_initial_alert_and_clear_certificate_rejection_preserve_incumbent() {
    let (trust, servers) = credentials(false);
    let clients_a = client_context(trust.clone());
    let clients_b = ResumableClient::provisioned(RETRY, trust, CACHE_LIFETIME);
    let mut a = adapter(None, 1);
    let mut b = adapter(None, 1);
    let mut server = adapter(Some(servers), 1);
    let mut link = Link::default();
    let id_a = full_handshake_with_hello_times(&mut link, &mut a, &mut server, &clients_a);

    let hello_b = only_send(
        b.connect(SERVER_ADDR, &clients_b, WALL + 2, 105),
        SERVER_ADDR,
    );
    let mut incompatible = hello_b.clone();
    let suite = incompatible.len() - 6;
    assert_eq!(incompatible[suite..suite + 2], [6, 3]);
    incompatible[suite..suite + 2].copy_from_slice(&[5, 2]);
    let alert = recovery_flight(&mut server, &incompatible, 106);
    let records = decode_datagram(&alert).unwrap();
    assert!(matches!(records.as_slice(), [record]
        if record.content_type == RecordType::Alert
            && record.cipher_spec == CipherSpec::Null
            && record.fragment[..2] == [3, 40]));
    assert_eq!(server.deadline(), None);
    assert_protected_echo(&mut link, &mut a, &mut server, 107);

    let flight_b = recovery_flight(&mut server, &hello_b, 109);
    assert!(server.deadline().is_some());
    let events = b.receive(SERVER_ADDR, &flight_b, WALL + 2, 110);
    assert!(matches!(
        events.as_slice(),
        [
            Event::Diagnostic { reason: Diagnostic::Protocol(WireError::CertificateRejected), .. },
            Event::Send { remote, .. },
        ] if *remote == SERVER_ADDR
    ));
    link.send(events);
    let cert_alert = link.take(SERVER_ADDR);
    assert!(matches!(
        server.receive(CLIENT_ADDR, &cert_alert, WALL, 111).as_slice(),
        [Event::Diagnostic {
            remote,
            reason: Diagnostic::Protocol(WireError::PeerAlert {
                fields: AlertFields { level: 3, description: 45, .. },
                protection: AlertProtection::Clear,
            }),
        }] if *remote == CLIENT_ADDR
    ));
    assert_eq!(server.deadline(), None);
    assert_retired_hello(&mut server, &hello_b, 112);
    assert_protected_echo(&mut link, &mut a, &mut server, 113);
    server.close(CLIENT_ADDR, CloseScope::Connection);
    let resume_a = recovery_hello(&mut adapter(None, 1), &clients_a, 115);
    assert_eq!(
        session_id(&recovery_flight(&mut server, &resume_a, 116)),
        id_a
    );
}

#[test]
fn established_recovery_incumbent_close_cancels_staged_commit_and_honors_scope() {
    for (scope, close_from_client) in [
        (CloseScope::Connection, true),
        (CloseScope::Session, true),
        (CloseScope::Connection, false),
    ] {
        let (trust, servers) = credentials(false);
        let clients_a = client_context(trust.clone());
        let clients_b = client_context(trust);
        let mut a = adapter(None, 1);
        let mut b = adapter(None, 1);
        let mut server = adapter(Some(servers), 1);
        let mut link = Link::default();
        let id_a = full_handshake_with_hello_times(&mut link, &mut a, &mut server, &clients_a);
        let hello_b = recovery_hello(&mut b, &clients_b, 105);
        let flight_b = recovery_flight(&mut server, &hello_b, 106);
        let commit_b = recovery_commit(&mut b, &flight_b, 107);
        let resume_a = recovery_hello(&mut adapter(None, 1), &clients_a, 108);
        assert_eq!(session_id(&resume_a), id_a);
        let events = if close_from_client {
            link.send(a.close(SERVER_ADDR, scope));
            let close_a = link.take(SERVER_ADDR);
            server.receive(CLIENT_ADDR, &close_a, WALL, 109)
        } else {
            server.close(CLIENT_ADDR, scope)
        };
        assert!(matches!(
            events.as_slice(),
            [Event::Send { .. }, Event::Closed { remote, scope: actual }]
                if *remote == CLIENT_ADDR && *actual == scope
        ));
        if !close_from_client {
            link.send(events);
            let close_a = link.take(CLIENT_ADDR);
            assert!(
                a.receive(SERVER_ADDR, &close_a, WALL, 109)
                    .iter()
                    .any(|event| {
                        matches!(event, Event::Closed { remote, scope: actual }
                    if *remote == SERVER_ADDR && *actual == scope)
                    })
            );
        }
        assert_eq!(server.status(CLIENT_ADDR), None);
        assert_eq!(server.deadline(), None);
        assert!(matches!(
            server.receive(CLIENT_ADDR, &commit_b, WALL, 110).as_slice(),
            [Event::Diagnostic {
                reason: Diagnostic::Protocol(_),
                ..
            }]
        ));
        assert_retired_hello(&mut server, &hello_b, 111);
        let new_flight = recovery_flight(&mut server, &resume_a, 112);
        assert_eq!(
            session_id(&new_flight) == id_a,
            scope == CloseScope::Connection
        );
    }
}

fn seed_recovery_cache(clients: &ResumableClient, servers: &ResumableServer) -> Vec<u8> {
    fn sent(actions: Vec<WireAction>) -> Vec<u8> {
        actions
            .into_iter()
            .find_map(|action| match action {
                WireAction::Send(bytes) => Some(bytes),
                _ => None,
            })
            .expect("one wire flight")
    }

    let mut client = clients.peer(WALL).unwrap();
    let mut server = servers.peer(WALL).unwrap();
    let opening = sent(client.start(0).unwrap());
    let flight = sent(server.receive(&opening, 1).unwrap());
    let commit = sent(client.receive(&flight, 2).unwrap());
    let finished = sent(server.receive(&commit, 3).unwrap());
    assert_eq!(
        client.receive(&finished, 4).unwrap(),
        [WireAction::Established(HandshakeKind::Full)]
    );
    session_id(&flight)
}

#[test]
fn established_recovery_keeps_verified_abbreviated_prefix_with_incumbent() {
    let (trust, servers) = credentials(false);
    let clients_a = client_context(trust.clone());
    let clients_b = client_context(trust);
    let id = seed_recovery_cache(&clients_a, &servers);
    let mut server = adapter(Some(servers), 1);
    let mut a = adapter(None, 1);
    let mut b = adapter(None, 1);
    let mut link = Link::default();

    let hello_a = recovery_hello(&mut a, &clients_a, 10);
    let flight_a = recovery_flight(&mut server, &hello_a, 11);
    assert_eq!(session_id(&flight_a), id);
    link.send(a.receive(SERVER_ADDR, &flight_a, WALL, 12));
    let commit_a = link.take(SERVER_ADDR);
    assert!(established(
        &server.receive(CLIENT_ADDR, &commit_a, WALL, 13),
        CLIENT_ADDR,
        HandshakeKind::Resumed
    ));
    assert_eq!(a.status(SERVER_ADDR), Some(Status::AwaitingConfirmation));

    let hello_b = only_send(
        b.connect(SERVER_ADDR, &clients_b, WALL - 1, 14),
        SERVER_ADDR,
    );
    let flight_b = recovery_flight(&mut server, &hello_b, 15);
    let deadline = server.deadline();
    assert_eq!(recovery_flight(&mut server, &hello_a, 16), flight_a);
    let confirmation = recovery_flight(&mut server, &commit_a, 17);
    assert_eq!(
        decode_datagram(&confirmation).unwrap()[0].cipher_spec,
        CipherSpec::Current
    );

    let prefixed = only_send(
        a.send_application(SERVER_ADDR, PAYLOAD.to_vec()),
        SERVER_ADDR,
    );
    assert!(prefixed.starts_with(&commit_a));
    let events = server.receive(CLIENT_ADDR, &prefixed, WALL, 18);
    assert!(events.iter().any(|event| matches!(
        event, Event::Deliver { remote, payload } if *remote == CLIENT_ADDR && payload == PAYLOAD
    )));
    assert_eq!(recovery_flight(&mut server, &hello_b, 19), flight_b);
    assert_eq!(server.deadline(), deadline);
    let response = only_send(
        server.send_application(CLIENT_ADDR, PAYLOAD.to_vec()),
        CLIENT_ADDR,
    );
    assert!(matches!(
        a.receive(SERVER_ADDR, &response, WALL, 20).as_slice(),
        [Event::Deliver { remote, payload }] if *remote == SERVER_ADDR && payload == PAYLOAD
    ));
}

#[test]
fn resumed_recovery_first_flight_budget_refusal_leaves_candidate_slot_free() {
    let (trust, servers) = credentials(false);
    let clients_a = client_context(trust.clone());
    let clients_b = client_context(trust);
    let id = seed_recovery_cache(&clients_a, &servers);
    let mut server = Adapter::new(Some(servers), DatagramBudget::new(160), NonZeroUsize::MIN);
    let mut a = adapter(None, 1);
    let mut b = adapter(None, 1);
    let mut link = Link::default();

    let hello_a = recovery_hello(&mut a, &clients_a, 10);
    let flight_a = recovery_flight(&mut server, &hello_a, 11);
    assert_eq!(session_id(&flight_a), id);
    link.send(a.receive(SERVER_ADDR, &flight_a, WALL, 12));
    let commit_a = link.take(SERVER_ADDR);
    assert!(established(
        &server.receive(CLIENT_ADDR, &commit_a, WALL, 13),
        CLIENT_ADDR,
        HandshakeKind::Resumed
    ));
    let confirmation = recovery_flight(&mut server, &commit_a, 14);
    assert!(a.receive(SERVER_ADDR, &confirmation, WALL, 15).is_empty());

    let hello_b = only_send(
        b.connect(SERVER_ADDR, &clients_b, WALL - 1, 16),
        SERVER_ADDR,
    );
    for at in [17, 18] {
        assert!(matches!(
            server.receive(CLIENT_ADDR, &hello_b, WALL, at).as_slice(),
            [Event::Diagnostic { remote, reason: Diagnostic::OutboundTooLarge(_) }]
                if *remote == CLIENT_ADDR
        ));
        assert_eq!(server.deadline(), None);
    }
    assert_protected_echo(&mut link, &mut a, &mut server, 19);
    let resume_a = recovery_hello(&mut adapter(None, 1), &clients_a, 21);
    assert_eq!(session_id(&recovery_flight(&mut server, &resume_a, 22)), id);
    assert_eq!(server.status(CLIENT_ADDR), Some(Status::Open));
}

fn resumed_recovery_commit(client: &mut Adapter, flight: &[u8], at: u64) -> Vec<u8> {
    let events = client.receive(SERVER_ADDR, flight, WALL, at);
    assert!(established(&events, SERVER_ADDR, HandshakeKind::Resumed));
    let mut link = Link::default();
    link.send(events);
    link.take(SERVER_ADDR)
}

#[test]
fn resumed_recovery_standalone_commit_promotes_silently() {
    let (trust, servers) = credentials(false);
    let clients = client_context(trust);
    let id = seed_recovery_cache(&clients, &servers);
    let mut server = adapter(Some(servers), 1);
    let mut a = adapter(None, 1);
    let mut b = adapter(None, 1);

    let hello_a = recovery_hello(&mut a, &clients, 10);
    let flight_a = recovery_flight(&mut server, &hello_a, 11);
    let commit_a = resumed_recovery_commit(&mut a, &flight_a, 12);
    assert!(established(
        &server.receive(CLIENT_ADDR, &commit_a, WALL, 13),
        CLIENT_ADDR,
        HandshakeKind::Resumed,
    ));

    let hello_b = recovery_hello(&mut b, &clients, 14);
    assert_eq!(session_id(&hello_b), id);
    let flight_b = recovery_flight(&mut server, &hello_b, 15);
    assert_eq!(session_id(&flight_b), id);
    let commit_b = resumed_recovery_commit(&mut b, &flight_b, 16);
    let events = server.receive(CLIENT_ADDR, &commit_b, WALL, 17);
    assert!(matches!(
        events.as_slice(),
        [Event::Established { remote, kind: HandshakeKind::Resumed }] if *remote == CLIENT_ADDR
    ));
}

#[test]
fn resumed_recovery_routes_incumbent_prefix_and_promotes_on_first_application() {
    let (clients, servers) = contexts();
    let id = seed_recovery_cache(&clients, &servers);
    let mut server = adapter(Some(servers), 2);
    let mut a = adapter(None, 1);
    let mut b = adapter(None, 1);

    let hello_a = recovery_hello(&mut a, &clients, 10);
    let flight_a = recovery_flight(&mut server, &hello_a, 11);
    let commit_a = resumed_recovery_commit(&mut a, &flight_a, 12);
    assert!(established(
        &server.receive(CLIENT_ADDR, &commit_a, WALL, 13),
        CLIENT_ADDR,
        HandshakeKind::Resumed,
    ));

    let hello_b = recovery_hello(&mut b, &clients, 14);
    let flight_b = recovery_flight(&mut server, &hello_b, 15);
    assert_eq!(session_id(&flight_b), id);
    let deadline = server.deadline();
    let commit_b = resumed_recovery_commit(&mut b, &flight_b, 16);
    let hello_c = only_send(
        adapter(None, 1).connect(SERVER_ADDR, &clients, WALL - 1, 17),
        SERVER_ADDR,
    );
    assert!(matches!(
        server.receive(CLIENT_ADDR, &hello_c, WALL, 17).as_slice(),
        [Event::Diagnostic {
            reason: Diagnostic::AddressInUse,
            ..
        }]
    ));
    assert_eq!(recovery_flight(&mut server, &hello_a, 18), flight_a);
    assert_eq!(recovery_flight(&mut server, &hello_b, 19), flight_b);
    assert_eq!(server.deadline(), deadline);

    let incumbent = only_send(
        a.send_application(SERVER_ADDR, PAYLOAD.to_vec()),
        SERVER_ADDR,
    );
    assert!(incumbent.starts_with(&commit_a));
    assert!(matches!(
        server.receive(CLIENT_ADDR, &incumbent, WALL, 20).as_slice(),
        [Event::Send { remote: reply, .. }, Event::Deliver { remote, payload }]
            if *reply == CLIENT_ADDR && *remote == CLIENT_ADDR && payload == PAYLOAD
    ));
    let response = only_send(
        server.send_application(CLIENT_ADDR, PAYLOAD.to_vec()),
        CLIENT_ADDR,
    );
    assert!(matches!(
        a.receive(SERVER_ADDR, &response, WALL, 21).as_slice(),
        [Event::Deliver { remote, payload }] if *remote == SERVER_ADDR && payload == PAYLOAD
    ));
    let delayed_data = only_send(
        a.send_application(SERVER_ADDR, PAYLOAD.to_vec()),
        SERVER_ADDR,
    );
    let mut link = Link::default();
    link.send(a.close(SERVER_ADDR, CloseScope::Session));
    let delayed_close = link.take(SERVER_ADDR);

    let first_data = only_send(
        b.send_application(SERVER_ADDR, PAYLOAD.to_vec()),
        SERVER_ADDR,
    );
    assert!(first_data.starts_with(&commit_b));
    assert!(matches!(
        server.receive(CLIENT_ADDR, &first_data, WALL, 22).as_slice(),
        [
            Event::Established { remote, kind: HandshakeKind::Resumed },
            Event::Deliver { remote: delivery, payload }
        ] if *remote == CLIENT_ADDR && *delivery == CLIENT_ADDR && payload == PAYLOAD
    ));
    let ack = recovery_flight(&mut server, &commit_b, 23);
    assert!(b.receive(SERVER_ADDR, &ack, WALL, 24).is_empty());
    assert_eq!(b.status(SERVER_ADDR), Some(Status::Open));
    assert!(matches!(
        server.receive(CLIENT_ADDR, &first_data, WALL, 24).as_slice(),
        [Event::Send { remote, .. }] if *remote == CLIENT_ADDR
    ));
    for (at, delayed) in [(25, delayed_data), (26, delayed_close)] {
        assert!(matches!(
            server.receive(CLIENT_ADDR, &delayed, WALL, at).as_slice(),
            [Event::Diagnostic {
                reason: Diagnostic::Protocol(_),
                ..
            }]
        ));
    }
    assert_eq!(server.status(CLIENT_ADDR), Some(Status::Open));
    assert_protected_echo(&mut link, &mut b, &mut server, 27);
    assert_eq!(
        session_id(&only_send(
            server.receive(ALT_CLIENT_ADDR, &hello_c, WALL, 30),
            ALT_CLIENT_ADDR,
        )),
        id
    );
}

#[test]
fn resumed_recovery_fixed_deadline_expires_before_receive_and_tick() {
    let (clients, servers) = contexts();
    let id = seed_recovery_cache(&clients, &servers);
    let mut server =
        adapter(Some(servers), 1).with_pending_handshake_timeout_ms(NonZeroU64::new(10).unwrap());
    let mut a = adapter(None, 1);
    let hello_a = recovery_hello(&mut a, &clients, 10);
    let flight_a = recovery_flight(&mut server, &hello_a, 11);
    let commit_a = resumed_recovery_commit(&mut a, &flight_a, 12);
    assert!(established(
        &server.receive(CLIENT_ADDR, &commit_a, WALL, 13),
        CLIENT_ADDR,
        HandshakeKind::Resumed,
    ));
    let ack = recovery_flight(&mut server, &commit_a, 14);
    assert!(a.receive(SERVER_ADDR, &ack, WALL, 14).is_empty());

    let mut link = Link::default();
    for (tick_first, at) in [(false, 20), (true, 40)] {
        let mut b = adapter(None, 1);
        let hello_b = recovery_hello(&mut b, &clients, at);
        let flight_b = recovery_flight(&mut server, &hello_b, at + 1);
        assert_eq!(session_id(&flight_b), id);
        let commit_b = resumed_recovery_commit(&mut b, &flight_b, at + 2);
        let deadline = at + 11;
        assert_eq!(
            recovery_flight(&mut server, &hello_b, deadline - 1),
            flight_b
        );
        assert_eq!(server.deadline(), Some(deadline));
        if tick_first {
            assert!(server.tick(deadline).is_empty());
            assert_eq!(server.deadline(), None);
        }
        assert!(matches!(
            server
                .receive(CLIENT_ADDR, &commit_b, WALL, deadline)
                .as_slice(),
            [Event::Diagnostic {
                reason: Diagnostic::Protocol(_),
                ..
            }]
        ));
        assert_eq!(server.deadline(), None);
        assert_retired_hello(&mut server, &hello_b, deadline + 1);
        assert_protected_echo(&mut link, &mut a, &mut server, deadline + 2);
    }
}

#[test]
fn resumed_recovery_rechecks_cache_at_finished_and_falls_back_for_stale_id() {
    let (clients, servers) = contexts();
    let id = seed_recovery_cache(&clients, &servers);
    let mut server = adapter(Some(servers), 2);
    let mut a = adapter(None, 1);
    let mut b = adapter(None, 1);
    let mut c = adapter(None, 1);

    let hello_a = recovery_hello(&mut a, &clients, 10);
    let flight_a = recovery_flight(&mut server, &hello_a, 11);
    let commit_a = resumed_recovery_commit(&mut a, &flight_a, 12);
    assert!(established(
        &server.receive(CLIENT_ADDR, &commit_a, WALL, 13),
        CLIENT_ADDR,
        HandshakeKind::Resumed,
    ));
    let ack = recovery_flight(&mut server, &commit_a, 14);
    assert!(a.receive(SERVER_ADDR, &ack, WALL, 14).is_empty());

    let hello_b = recovery_hello(&mut b, &clients, 14);
    let flight_b = only_send(
        server.receive(ALT_CLIENT_ADDR, &hello_b, WALL, 15),
        ALT_CLIENT_ADDR,
    );
    let commit_b = resumed_recovery_commit(&mut b, &flight_b, 16);
    assert!(established(
        &server.receive(ALT_CLIENT_ADDR, &commit_b, WALL, 17),
        ALT_CLIENT_ADDR,
        HandshakeKind::Resumed,
    ));

    let hello_c = recovery_hello(&mut c, &clients, 18);
    let flight_c = recovery_flight(&mut server, &hello_c, 19);
    assert_eq!(session_id(&flight_c), id);
    let commit_c = resumed_recovery_commit(&mut c, &flight_c, 20);
    assert!(matches!(
        server
            .close(ALT_CLIENT_ADDR, CloseScope::Session)
            .as_slice(),
        [
            Event::Send { .. },
            Event::Closed {
                scope: CloseScope::Session,
                ..
            }
        ]
    ));
    assert!(matches!(
        server.receive(CLIENT_ADDR, &commit_c, WALL, 21).as_slice(),
        [Event::Diagnostic {
            reason: Diagnostic::Protocol(WireError::InvalidMessage),
            ..
        }]
    ));
    assert_retired_hello(&mut server, &hello_c, 22);
    let mut link = Link::default();
    assert_protected_echo(&mut link, &mut a, &mut server, 23);

    let mut d = adapter(None, 1);
    let stale_hello = recovery_hello(&mut d, &clients, 25);
    assert_eq!(session_id(&stale_hello), id);
    let fallback = recovery_flight(&mut server, &stale_hello, 26);
    assert_ne!(session_id(&fallback), id);
    let full_commit = recovery_commit(&mut d, &fallback, 27);
    let events = server.receive(CLIENT_ADDR, &full_commit, WALL, 28);
    assert!(matches!(
        events.as_slice(),
        [Event::Send { remote, .. }, Event::Established { remote: established, kind: HandshakeKind::Full }]
            if *remote == CLIENT_ADDR && *established == CLIENT_ADDR
    ));
    link.send(events);
    let final_flight = link.take(CLIENT_ADDR);
    assert!(established(
        &d.receive(SERVER_ADDR, &final_flight, WALL, 29),
        SERVER_ADDR,
        HandshakeKind::Full,
    ));
    assert_protected_echo(&mut link, &mut d, &mut server, 30);

    let mut e = adapter(None, 1);
    // The fallback session was inserted by the server at 28. Resume must
    // still use that expiry, even though the client received it at 29.
    let expiry = 28 + CACHE_LIFETIME.get();
    let hello_e = recovery_hello(&mut e, &clients, expiry - 3);
    let flight_e = recovery_flight(&mut server, &hello_e, expiry - 2);
    assert_eq!(session_id(&flight_e), session_id(&fallback));
    let commit_e = resumed_recovery_commit(&mut e, &flight_e, expiry - 1);
    assert!(matches!(
        server
            .receive(CLIENT_ADDR, &commit_e, WALL, expiry)
            .as_slice(),
        [Event::Diagnostic {
            reason: Diagnostic::Protocol(WireError::InvalidMessage),
            ..
        }]
    ));
    assert_retired_hello(&mut server, &hello_e, expiry + 1);
    assert_protected_echo(&mut link, &mut d, &mut server, expiry + 2);
}

#[test]
fn resumed_recovery_candidate_close_preserves_incumbent_and_applies_exact_scope() {
    let (trust, servers) = credentials(false);
    let distinct_clients = client_context(trust.clone());
    let distinct_id = seed_recovery_cache(&distinct_clients, &servers);
    let incumbent_clients = client_context(trust);
    let mut server =
        adapter(Some(servers), 2).with_pending_handshake_timeout_ms(NonZeroU64::new(10).unwrap());
    let mut a = adapter(None, 1);
    let mut link = Link::default();
    let incumbent_id =
        full_handshake_with_hello_times(&mut link, &mut a, &mut server, &incumbent_clients);

    // Check both scopes against each entry. Run the preserving closes first
    // so the same entry can then be used to test invalidation.
    for (clients, id, scope, at) in [
        (
            &distinct_clients,
            distinct_id.as_slice(),
            CloseScope::Connection,
            110,
        ),
        (
            &incumbent_clients,
            incumbent_id.as_slice(),
            CloseScope::Connection,
            130,
        ),
        (
            &distinct_clients,
            distinct_id.as_slice(),
            CloseScope::Session,
            150,
        ),
        (
            &incumbent_clients,
            incumbent_id.as_slice(),
            CloseScope::Session,
            170,
        ),
    ] {
        let mut b = adapter(None, 1);
        let hello_b = recovery_hello(&mut b, clients, at);
        assert_eq!(session_id(&hello_b), id);
        let flight_b = recovery_flight(&mut server, &hello_b, at + 1);
        assert_eq!(session_id(&flight_b), id);
        let commit_b = resumed_recovery_commit(&mut b, &flight_b, at + 2);
        let probe = recovery_hello(&mut adapter(None, 1), clients, at + 3);
        assert_eq!(session_id(&probe), id);
        let events = b.close(SERVER_ADDR, scope);
        assert!(matches!(
            events.as_slice(),
            [Event::Send { .. }, Event::Closed { scope: actual, .. }] if *actual == scope
        ));
        link.send(events);
        let close_b = link.take(SERVER_ADDR);
        assert!(close_b.starts_with(&commit_b));

        let events = server.receive(CLIENT_ADDR, &close_b, WALL, at + 4);
        assert!(matches!(
            events.as_slice(),
            [Event::Send { remote, bytes }, Event::Diagnostic { remote: diagnostic, reason: Diagnostic::CandidateClosed(actual) }]
                if *remote == CLIENT_ADDR && *diagnostic == CLIENT_ADDR && *actual == scope
                    && matches!(
                        decode_datagram(bytes).unwrap().as_slice(),
                        [record] if record.content_type == RecordType::Alert
                            && record.cipher_spec == CipherSpec::Current && record.sequence == 1
                    )
        ));
        assert_eq!(server.deadline(), None);
        assert_retired_hello(&mut server, &hello_b, at + 5);
        assert_protected_echo(&mut link, &mut a, &mut server, at + 6);

        let probe_flight = only_send(
            server.receive(ALT_CLIENT_ADDR, &probe, WALL, at + 8),
            ALT_CLIENT_ADDR,
        );
        assert_eq!(
            session_id(&probe_flight) == id,
            scope == CloseScope::Connection
        );
        // Free the probe tuple without completing the handshake or touching the cache.
        assert!(matches!(
            server.tick(at + 18).as_slice(),
            [Event::TimedOut { remote }] if *remote == ALT_CLIENT_ADDR
        ));
    }
}

#[test]
fn resumed_recovery_incumbent_prefixed_close_cancels_candidate() {
    for scope in [CloseScope::Connection, CloseScope::Session] {
        let (clients, servers) = contexts();
        let id = seed_recovery_cache(&clients, &servers);
        let mut server = adapter(Some(servers), 1);
        let mut a = adapter(None, 1);
        let mut b = adapter(None, 1);

        let hello_a = recovery_hello(&mut a, &clients, 10);
        let flight_a = recovery_flight(&mut server, &hello_a, 11);
        let commit_a = resumed_recovery_commit(&mut a, &flight_a, 12);
        server.receive(CLIENT_ADDR, &commit_a, WALL, 13);

        let hello_b = recovery_hello(&mut b, &clients, 14);
        let flight_b = recovery_flight(&mut server, &hello_b, 15);
        assert_eq!(session_id(&flight_b), id);
        let commit_b = resumed_recovery_commit(&mut b, &flight_b, 16);
        let probe = recovery_hello(&mut adapter(None, 1), &clients, 17);
        let mut link = Link::default();
        link.send(a.close(SERVER_ADDR, scope));
        let close_a = link.take(SERVER_ADDR);
        assert!(close_a.starts_with(&commit_a));

        assert!(matches!(
            server.receive(CLIENT_ADDR, &close_a, WALL, 18).as_slice(),
            [Event::Send { .. }, Event::Closed { remote, scope: actual }]
                if *remote == CLIENT_ADDR && *actual == scope
        ));
        assert_eq!(server.status(CLIENT_ADDR), None);
        assert_eq!(server.deadline(), None);
        assert!(matches!(
            server.receive(CLIENT_ADDR, &commit_b, WALL, 19).as_slice(),
            [Event::Diagnostic {
                reason: Diagnostic::Protocol(_),
                ..
            }]
        ));
        assert_retired_hello(&mut server, &hello_b, 20);
        let next_flight = recovery_flight(&mut server, &probe, 21);
        assert_eq!(
            session_id(&next_flight) == id,
            scope == CloseScope::Connection
        );
    }
}
