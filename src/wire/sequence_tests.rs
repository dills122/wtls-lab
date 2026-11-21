use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::OnceLock;

use openssl::pkey::Public;

use super::*;

pub(crate) const NOW: u32 = 1_730_000_000;
const LIFETIME_MS: u64 = 1_000;
const ISSUER: &str = "WTLS Lab CA; WTLS Lab; CA";
const SUBJECT: &str = "Echo; WTLS Lab; CA; echo.lab.invalid";
pub(crate) const EXHAUSTED: WireError = WireError::Handshake(HandshakeError::SequenceExhausted);

fn public(key: &Rsa<Private>) -> Rsa<Public> {
    Rsa::from_public_components(key.n().to_owned().unwrap(), key.e().to_owned().unwrap()).unwrap()
}

pub(crate) fn contexts() -> (ResumableClient, ResumableServer) {
    static KEYS: OnceLock<(Rsa<Private>, Rsa<Private>)> = OnceLock::new();
    let (ca, leaf) =
        KEYS.get_or_init(|| (Rsa::generate(2048).unwrap(), Rsa::generate(2048).unwrap()));
    let certificate =
        issue_certificate(ISSUER, SUBJECT, (NOW - 1)..=(NOW + 1), ca, &public(leaf)).unwrap();
    let identity =
        ServerIdentity::provisioned(certificate, leaf.clone(), ISSUER, public(ca)).unwrap();
    let trust = TrustAnchor::new(ISSUER, SUBJECT, public(ca)).unwrap();
    let lifetime = NonZeroU64::new(LIFETIME_MS).unwrap();
    let retry = RetryPolicy {
        timeout_ms: NonZeroU64::new(10).unwrap(),
        max_retries: 2,
    };
    (
        ResumableClient::provisioned(retry, trust, lifetime),
        ResumableServer::new(identity, NonZeroUsize::new(4).unwrap(), lifetime),
    )
}

pub(crate) fn seed_last_write(peer: &mut WirePeer) {
    assert!(peer.write.protected);
    peer.write.sequence = u32::from(u16::MAX);
}

fn send(actions: &[WireAction]) -> &[u8] {
    let mut sends = actions.iter().filter_map(|action| match action {
        WireAction::Send(bytes) => Some(bytes.as_slice()),
        _ => None,
    });
    let bytes = sends.next().expect("one outbound datagram");
    assert!(sends.next().is_none());
    bytes
}

fn full(clients: &ResumableClient, servers: &ResumableServer, at: u64) -> (WirePeer, WirePeer) {
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let offer = client.start(at).unwrap();
    let hello = server.receive(send(&offer), at + 1).unwrap();
    let commit = client.receive(send(&hello), at + 2).unwrap();
    let server_commit = server.receive(send(&commit), at + 3).unwrap();
    assert!(server_commit.contains(&WireAction::Established(HandshakeKind::Full)));
    assert_eq!(
        client.receive(send(&server_commit), at + 4).unwrap(),
        [WireAction::Established(HandshakeKind::Full)]
    );
    (client, server)
}

fn sender_and_receiver<'a>(
    client: &'a mut WirePeer,
    server: &'a mut WirePeer,
    role: Role,
) -> (&'a mut WirePeer, &'a mut WirePeer) {
    match role {
        Role::Client => (client, server),
        Role::Server => (server, client),
    }
}

fn resume(
    clients: &ResumableClient,
    servers: &ResumableServer,
    id: SessionId,
    at: u64,
) -> (WirePeer, WirePeer, Vec<u8>, Vec<u8>) {
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let offer = client.start(at).unwrap();
    let records = crate::decode_datagram(send(&offer)).unwrap();
    assert_eq!(
        decode_client_hello(records[0].fragment).unwrap().session_id,
        id.0
    );
    let flight = server.receive(send(&offer), at + 1).unwrap();
    let records = crate::decode_datagram(send(&flight)).unwrap();
    assert_eq!(
        decode_server_hello(records[0].fragment).unwrap().session_id,
        id.0
    );
    let actions = client.receive(send(&flight), at + 2).unwrap();
    assert!(actions.contains(&WireAction::Established(HandshakeKind::Resumed)));
    let commit = send(&actions);
    let records = crate::decode_datagram(commit).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].content_type, RecordType::ChangeCipherSpec);
    assert_eq!(records[1].cipher_spec, CipherSpec::Current);
    assert_eq!(records[1].sequence, 0);
    (client, server, send(&flight).to_vec(), commit.to_vec())
}

fn assert_released(peer: &mut WirePeer) {
    assert_eq!(peer.status(), Status::Closed);
    assert_eq!(peer.deadline(), None);
    assert!(peer.session.is_none());
    assert!(peer.traffic.is_none());
    assert!(peer.random.is_none());
    assert!(peer.peer_random.is_none());
    assert!(peer.selection.is_none());
    assert!(peer.received_flights.is_empty());
    assert!(peer.sent_flights.is_empty());
    assert!(peer.verified_commit.is_none());
    assert_eq!(peer.sent_checksums.capacity(), 0);
    assert_eq!(peer.last_received, [0; 4]);
    assert_eq!(peer.highest_received_sequence, None);
    for direction in [peer.read, peer.write] {
        assert!(!direction.protected);
        assert_eq!(direction.sequence, 0);
    }
    assert_eq!(peer.tick(900).unwrap(), []);
    assert_eq!(
        peer.send_application(vec![3]),
        Err(HandshakeError::InvalidState.into())
    );
}

#[test]
fn sequence_exhaustion_last_application_preserves_exact_session_for_both_roles() {
    for role in [Role::Client, Role::Server] {
        let (clients, servers) = contexts();
        let (mut client, mut server) = full(&clients, &servers, 0);
        let (sender, receiver) = sender_and_receiver(&mut client, &mut server, role);
        let id = sender.handshake.cached_session().unwrap();
        let entry = sender.find_session(Some(id), 4).unwrap().unwrap();
        let expiry = entry.established_ms + LIFETIME_MS;

        seed_last_write(sender);
        let actions = sender.send_application(vec![1]).unwrap();
        let bytes = send(&actions);
        let records = crate::decode_datagram(bytes).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].cipher_spec, CipherSpec::Current);
        assert_eq!(records[0].sequence, u16::MAX);
        assert_eq!(
            receiver.receive(bytes, 5).unwrap(),
            [WireAction::Deliver(vec![1])]
        );
        assert_eq!(
            sender.send_application(vec![]),
            Err(WireError::InvalidRecord)
        );
        assert_eq!(sender.status(), Status::Open);
        assert_eq!(sender.send_application(vec![2]), Err(EXHAUSTED), "{role:?}");
        assert_released(sender);
        assert!(Arc::ptr_eq(
            &entry,
            &sender.find_session(Some(id), 6).unwrap().unwrap()
        ));

        let (mut resumed_client, mut resumed_server, _, commit) =
            resume(&clients, &servers, id, 90);
        assert_eq!(
            resumed_server.receive(&commit, 93).unwrap(),
            [WireAction::Established(HandshakeKind::Resumed)]
        );
        let old_traffic = receiver.traffic.as_ref().unwrap();
        // Server application confirms the commit before the client sends.
        for role in [Role::Server, Role::Client] {
            let (from, to) = sender_and_receiver(&mut resumed_client, &mut resumed_server, role);
            let actions = from.send_application(vec![7]).unwrap();
            let bytes = send(&actions);
            let records = crate::decode_datagram(bytes).unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].cipher_spec, CipherSpec::Current);
            assert_eq!(records[0].sequence, 1);
            assert_eq!(
                old_traffic.open(role, records[0]),
                Err(WireError::AuthenticationFailed)
            );
            assert_eq!(
                to.receive(bytes, 94).unwrap(),
                [WireAction::Deliver(vec![7])]
            );
        }
        assert!(Arc::ptr_eq(
            &entry,
            &sender.find_session(Some(id), expiry - 1).unwrap().unwrap()
        ));
        assert!(sender.find_session(Some(id), expiry).unwrap().is_none());
    }
}

#[test]
fn sequence_exhaustion_cached_commit_retransmits_but_fresh_suffix_is_atomic() {
    let (clients, servers) = contexts();
    let (client, _) = full(&clients, &servers, 0);
    let id = client.handshake.cached_session().unwrap();
    for (at, session_close) in [(10, false), (20, true)] {
        let (mut client, mut server, flight, commit) = resume(&clients, &servers, id, at);
        seed_last_write(&mut client);
        let final_send = client.send_application(vec![1]).unwrap();
        let bytes = send(&final_send);
        let suffix = bytes.strip_prefix(commit.as_slice()).unwrap();
        assert_eq!(
            crate::decode_datagram(suffix).unwrap()[0].sequence,
            u16::MAX
        );
        assert_eq!(
            server.receive(bytes, at + 3).unwrap(),
            [
                WireAction::Established(HandshakeKind::Resumed),
                WireAction::Deliver(vec![1])
            ]
        );
        assert_eq!(send(&client.receive(&flight, at + 4).unwrap()), commit);
        assert_eq!(client.status(), Status::AwaitingConfirmation);
        let failed_send = if session_close {
            client.close(CloseScope::Session)
        } else {
            client.send_application(vec![2])
        };
        assert_eq!(failed_send, Err(EXHAUSTED));
        assert_released(&mut client);
        assert_eq!(client.receive(&flight, at + 5).unwrap(), []);
        assert_eq!(
            client.find_session(Some(id), at + 5).unwrap().is_none(),
            session_close
        );
        assert!(server.find_session(Some(id), at + 5).unwrap().is_some());
    }
}

#[test]
fn sequence_exhaustion_fresh_acknowledgment_uses_the_same_counter_as_application() {
    for final_operation_is_ack in [true, false] {
        let (clients, servers) = contexts();
        let (client, _) = full(&clients, &servers, 0);
        let id = client.handshake.cached_session().unwrap();
        let (mut client, mut server, _, commit) = resume(&clients, &servers, id, 10);
        assert_eq!(
            server.receive(&commit, 13).unwrap(),
            [WireAction::Established(HandshakeKind::Resumed)]
        );
        seed_last_write(&mut server);
        if final_operation_is_ack {
            let ack = server.receive(&commit, 14).unwrap();
            let bytes = send(&ack);
            let records = crate::decode_datagram(bytes).unwrap();
            assert_eq!(records[0].content_type, RecordType::Alert);
            assert_eq!(records[0].sequence, u16::MAX);
            assert_eq!(client.receive(bytes, 15).unwrap(), []);
            assert_eq!(client.status(), Status::Open);
            assert_eq!(server.send_application(vec![2]), Err(EXHAUSTED));
        } else {
            server.send_application(vec![1]).unwrap();
            assert_eq!(server.receive(&commit, 14), Err(EXHAUSTED));
        }
        assert_released(&mut server);
        assert!(server.find_session(Some(id), 16).unwrap().is_some());
    }
}

#[test]
fn sequence_exhaustion_session_close_invalidates_locally_even_without_output() {
    for role in [Role::Client, Role::Server] {
        let (clients, servers) = contexts();
        let (other_clients, _) = contexts();
        let (other_client, _) = full(&other_clients, &servers, 0);
        let other_id = other_client.handshake.cached_session().unwrap();
        let (mut client, mut server) = full(&clients, &servers, 10);
        let (sender, receiver) = sender_and_receiver(&mut client, &mut server, role);
        let id = sender.handshake.cached_session().unwrap();
        seed_last_write(sender);
        sender.send_application(vec![1]).unwrap();

        assert_eq!(sender.close(CloseScope::Session), Err(EXHAUSTED));
        assert_released(sender);
        assert!(sender.find_session(Some(id), 15).unwrap().is_none());
        assert!(receiver.find_session(Some(id), 15).unwrap().is_some());
        let server = match role {
            Role::Client => receiver,
            Role::Server => sender,
        };
        assert!(server.find_session(Some(other_id), 15).unwrap().is_some());
    }
}

#[test]
fn sequence_exhaustion_authenticated_session_close_invalidates_even_without_ack() {
    for role in [Role::Client, Role::Server] {
        let (clients, servers) = contexts();
        let (mut client, mut server) = full(&clients, &servers, 0);
        let (receiver, sender) = sender_and_receiver(&mut client, &mut server, role);
        let id = sender.handshake.cached_session().unwrap();
        seed_last_write(receiver);
        receiver.send_application(vec![1]).unwrap();
        seed_last_write(sender);
        let close = sender.close(CloseScope::Session).unwrap();
        assert!(close.contains(&WireAction::Closed(CloseScope::Session)));
        let bytes = send(&close);
        let records = crate::decode_datagram(bytes).unwrap();
        assert_eq!(records[0].content_type, RecordType::Alert);
        assert_eq!(records[0].sequence, u16::MAX);
        assert_eq!(receiver.receive(bytes, 5), Err(EXHAUSTED));
        assert_released(receiver);
        assert!(receiver.find_session(Some(id), 5).unwrap().is_none());
        assert!(sender.find_session(Some(id), 5).unwrap().is_none());
    }
}
