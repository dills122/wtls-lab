use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::OnceLock;

use openssl::pkey::{Private, Public};
use openssl::rsa::Rsa;
use wtls_lab::handshake::{CloseScope, HandshakeKind, RetryPolicy, Status};
use wtls_lab::wire::{
    ResumableClient, ResumableServer, ServerIdentity, TrustAnchor, WireAction, WireError, WirePeer,
    decode_client_hello, decode_server_hello, issue_certificate,
};
use wtls_lab::{CipherSpec, LengthForm, Record, RecordType, decode_datagram, encode_datagram};

const NOW: u32 = 1_730_000_000;
const ISSUER: &str = "WTLS Lab CA; WTLS Lab; CA";
const SUBJECT: &str = "Echo; WTLS Lab; CA; echo.lab.invalid";

fn keys() -> &'static (Rsa<Private>, Rsa<Private>) {
    static KEYS: OnceLock<(Rsa<Private>, Rsa<Private>)> = OnceLock::new();
    KEYS.get_or_init(|| (Rsa::generate(2048).unwrap(), Rsa::generate(2048).unwrap()))
}

fn public(key: &Rsa<Private>) -> Rsa<Public> {
    Rsa::from_public_components(key.n().to_owned().unwrap(), key.e().to_owned().unwrap()).unwrap()
}

fn identity() -> ServerIdentity {
    let (ca, key) = keys();
    let leaf = issue_certificate(ISSUER, SUBJECT, (NOW - 1)..=(NOW + 1), ca, &public(key)).unwrap();
    ServerIdentity::new(leaf, key.clone()).unwrap()
}

fn server(capacity: usize, lifetime_ms: u64) -> ResumableServer {
    ResumableServer::new(
        identity(),
        NonZeroUsize::new(capacity).unwrap(),
        NonZeroU64::new(lifetime_ms).unwrap(),
    )
}

fn client(subject: &str, lifetime_ms: u64) -> ResumableClient {
    let trust = TrustAnchor::new(ISSUER, subject, public(&keys().0)).unwrap();
    ResumableClient::new(
        RetryPolicy {
            timeout_ms: NonZeroU64::new(10).unwrap(),
            max_retries: 2,
        },
        trust,
        NonZeroU64::new(lifetime_ms).unwrap(),
    )
}

fn send(actions: &[WireAction]) -> Vec<u8> {
    let mut sent = actions.iter().filter_map(|action| match action {
        WireAction::Send(bytes) => Some(bytes.clone()),
        _ => None,
    });
    let bytes = sent.next().expect("one outbound flight");
    assert!(sent.next().is_none());
    bytes
}

fn client_id(bytes: &[u8]) -> Vec<u8> {
    let records = decode_datagram(bytes).unwrap();
    decode_client_hello(records[0].fragment)
        .unwrap()
        .session_id
        .to_vec()
}

fn server_id(bytes: &[u8]) -> [u8; 8] {
    let records = decode_datagram(bytes).unwrap();
    decode_server_hello(records[0].fragment)
        .unwrap()
        .session_id
        .try_into()
        .unwrap()
}

fn full_commit(
    client: &mut WirePeer,
    server: &mut WirePeer,
    at: u64,
) -> ([u8; 8], Vec<u8>, Vec<u8>) {
    let offer = send(&client.start(at).unwrap());
    let flight = send(&server.receive(&offer, at + 1).unwrap());
    let records = decode_datagram(&flight).unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(records[1].fragment[0], 11); // Certificate
    assert_eq!(records[2].fragment[0], 14); // ServerHelloDone
    let id = server_id(&flight);
    assert_ne!(client_id(&offer), id);
    let commit = send(&client.receive(&flight, at + 2).unwrap());
    (id, offer, commit)
}

fn finish_full(client: &mut WirePeer, server: &mut WirePeer, commit: &[u8], at: u64) {
    let actions = server.receive(commit, at).unwrap();
    assert!(actions.contains(&WireAction::Established(HandshakeKind::Full)));
    assert_eq!(
        client.receive(&send(&actions), at + 1).unwrap(),
        [WireAction::Established(HandshakeKind::Full)]
    );
}

fn full(client: &mut WirePeer, server: &mut WirePeer, at: u64) -> [u8; 8] {
    let (id, _, commit) = full_commit(client, server, at);
    finish_full(client, server, &commit, at + 3);
    id
}

fn close(client: &mut WirePeer, server: &mut WirePeer, scope: CloseScope, at: u64) {
    let actions = client.close(scope).unwrap();
    assert!(actions.contains(&WireAction::Closed(scope)));
    let data = send(&actions);
    assert_eq!(
        decode_datagram(&data).unwrap()[0].cipher_spec,
        CipherSpec::Current
    );
    let actions = server.receive(&data, at).unwrap();
    assert!(actions.contains(&WireAction::Closed(scope)));
    assert_eq!(client.receive(&send(&actions), at + 1).unwrap(), []);
}

fn resumed_commit(
    client: &mut WirePeer,
    server: &mut WirePeer,
    id: [u8; 8],
    at: u64,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let offer = send(&client.start(at).unwrap());
    assert_eq!(client_id(&offer), id);
    let actions = server.receive(&offer, at + 1).unwrap();
    let flight = send(&actions);
    assert_eq!(actions.len(), 1);
    assert_eq!(server.status(), Status::Negotiating);
    assert_eq!(server_id(&flight), id);

    let records = decode_datagram(&flight).unwrap();
    assert_eq!(
        records
            .iter()
            .map(|r| (r.content_type, r.cipher_spec, r.sequence))
            .collect::<Vec<_>>(),
        [
            (RecordType::Handshake, CipherSpec::Null, 0),
            (RecordType::ChangeCipherSpec, CipherSpec::Null, 1),
            (RecordType::Handshake, CipherSpec::Current, 0),
        ]
    );
    assert_eq!(
        decode_server_hello(records[0].fragment)
            .unwrap()
            .key_exchange_index,
        0
    );
    assert_eq!(records[1].fragment, [1]);

    let actions = client.receive(&flight, at + 2).unwrap();
    assert!(actions.contains(&WireAction::Established(HandshakeKind::Resumed)));
    assert_eq!(client.status(), Status::AwaitingConfirmation);
    let commit = send(&actions);
    let records = decode_datagram(&commit).unwrap();
    assert_eq!(
        records
            .iter()
            .map(|r| (r.content_type, r.cipher_spec, r.sequence))
            .collect::<Vec<_>>(),
        [
            (RecordType::ChangeCipherSpec, CipherSpec::Null, 1),
            (RecordType::Handshake, CipherSpec::Current, 0),
        ]
    );
    assert_eq!(records[0].fragment, [1]);
    (offer, flight, commit)
}

fn resumption_only_offer(id: [u8; 8]) -> Vec<u8> {
    // WAP-199 §10.5.1.2 permits empty key and trusted-key vectors for resumption.
    let mut hello = vec![1, 0, 37, 1];
    hello.extend(1..=16);
    hello.push(8);
    hello.extend(id);
    hello.extend([0, 0, 0, 0, 2, 6, 3, 1, 0, 2, 3]);
    encode_datagram(&[Record {
        content_type: RecordType::Handshake,
        cipher_spec: CipherSpec::Null,
        sequence: 0,
        length_form: LengthForm::Explicit,
        fragment: &hello,
    }])
    .unwrap()
}

fn assert_unknown_key_id(peer: &mut WirePeer, id: [u8; 8], at: u64) {
    let offer = resumption_only_offer(id);
    let reply = send(&peer.receive(&offer, at).unwrap());
    let records = decode_datagram(&reply).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].content_type, RecordType::Alert);
    assert_eq!(records[0].cipher_spec, CipherSpec::Null);
    assert_eq!(records[0].sequence, 0);
    // WAP-199 §10.2 defines unknown_key_id as critical, description 52.
    let checksum = offer
        .iter()
        .enumerate()
        .fold([0; 4], |mut checksum, (i, byte)| {
            checksum[i % 4] ^= byte;
            checksum
        });
    assert_eq!(records[0].fragment, [&[2, 52][..], &checksum].concat());
    assert_eq!(peer.status(), Status::Idle);
}

#[test]
fn wap_199_resumption_only_miss_returns_clear_unknown_key_id() {
    assert_unknown_key_id(&mut server(1, 100).peer(NOW).unwrap(), *b"old-id!!", 1);
}

#[test]
fn full_only_authenticated_server_returns_clear_unknown_key_id() {
    let mut server = WirePeer::server(identity(), NOW).unwrap();
    assert_unknown_key_id(&mut server, *b"old-id!!", 1);
    full(&mut client(SUBJECT, 100).peer(NOW).unwrap(), &mut server, 2);
}

#[test]
fn connection_close_preserves_id_and_resume_uses_fresh_record_keys() {
    let clients = client(SUBJECT, 100);
    let servers = server(2, 100);
    let mut previous_client = clients.peer(NOW).unwrap();
    let mut previous_server = servers.peer(NOW).unwrap();
    let (id, first_offer, commit) = full_commit(&mut previous_client, &mut previous_server, 0);
    finish_full(&mut previous_client, &mut previous_server, &commit, 3);
    let old_data = send(&previous_client.send_application(b"echo".to_vec()).unwrap());
    assert_eq!(
        previous_server.receive(&old_data, 5).unwrap(),
        [WireAction::Deliver(b"echo".to_vec())]
    );
    close(
        &mut previous_client,
        &mut previous_server,
        CloseScope::Connection,
        6,
    );

    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let (offer, _, commit) = resumed_commit(&mut client, &mut server, id, 10);
    let hello_random = |bytes: &[u8]| {
        let records = decode_datagram(bytes).unwrap();
        decode_client_hello(records[0].fragment).unwrap().random
    };
    assert_ne!(hello_random(&first_offer), hello_random(&offer));
    assert_eq!(
        server.receive(&commit, 13).unwrap(),
        [WireAction::Established(HandshakeKind::Resumed)]
    );
    assert_eq!(
        server.receive(&old_data, 14),
        Err(WireError::AuthenticationFailed)
    );

    let with_prefix = send(&client.send_application(b"echo".to_vec()).unwrap());
    let new_data = with_prefix.strip_prefix(commit.as_slice()).unwrap();
    let old = decode_datagram(&old_data).unwrap()[0];
    let new = decode_datagram(new_data).unwrap()[0];
    assert_eq!(old.sequence, new.sequence);
    assert_eq!(new.sequence, 1);
    assert_ne!(old.fragment, new.fragment);

    let mut records = decode_datagram(&with_prefix).unwrap();
    records[0].sequence += 1;
    assert_eq!(
        server.receive(&encode_datagram(&records).unwrap(), 15),
        Err(WireError::InvalidRecord)
    );
    let mut tampered = with_prefix.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert_eq!(
        server.receive(&tampered, 16),
        Err(WireError::AuthenticationFailed)
    );

    let actions = server.receive(&with_prefix, 17).unwrap();
    assert!(actions.contains(&WireAction::Deliver(b"echo".to_vec())));
    let confirmation = send(&actions);
    let replay = server.receive(&with_prefix, 18).unwrap();
    assert!(matches!(replay.as_slice(), [WireAction::Send(_)]));
    assert_eq!(client.receive(&confirmation, 19).unwrap(), []);
    assert_eq!(client.status(), Status::Open);

    let subsequent = send(&client.send_application(b"next".to_vec()).unwrap());
    let records = decode_datagram(&subsequent).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].content_type, RecordType::ApplicationData);
    assert_eq!(records[0].sequence, 2);
    assert_eq!(
        server.receive(&subsequent, 20).unwrap(),
        [WireAction::Deliver(b"next".to_vec())]
    );
    assert_eq!(server.receive(&subsequent, 21).unwrap(), []);
}

#[test]
fn prefixed_application_recovers_lost_commit_and_server_data_confirms() {
    let clients = client(SUBJECT, 100);
    let servers = server(1, 100);
    let id = full(
        &mut clients.peer(NOW).unwrap(),
        &mut servers.peer(NOW).unwrap(),
        0,
    );
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let (offer, flight, commit) = resumed_commit(&mut client, &mut server, id, 10);
    assert_eq!(
        server.receive(&offer, 13).unwrap(),
        [WireAction::Send(flight.clone())]
    );
    assert_eq!(
        client.receive(&flight, 14).unwrap(),
        [WireAction::Send(commit.clone())]
    );
    let first = send(&client.send_application(b"first".to_vec()).unwrap());
    let second = send(&client.send_application(b"second".to_vec()).unwrap());
    assert!(first.starts_with(&commit) && second.starts_with(&commit));
    assert_eq!(
        server.receive(&second, 15).unwrap(),
        [
            WireAction::Established(HandshakeKind::Resumed),
            WireAction::Deliver(b"second".to_vec())
        ]
    );
    assert!(matches!(
        server.receive(&commit, 16).unwrap().as_slice(),
        [WireAction::Send(_)]
    ));
    let actions = server.receive(&first, 17).unwrap();
    assert!(actions.contains(&WireAction::Deliver(b"first".to_vec())));
    assert!(matches!(
        server.receive(&second, 18).unwrap().as_slice(),
        [WireAction::Send(_)]
    ));

    let reply = send(&server.send_application(b"reply".to_vec()).unwrap());
    let records = decode_datagram(&reply).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].sequence, 4); // Three authenticated alerts used sequences 1–3.
    assert_eq!(
        client.receive(&reply, 19).unwrap(),
        [WireAction::Deliver(b"reply".to_vec())]
    );
    assert_eq!(client.status(), Status::Open);
    assert_eq!(client.receive(&flight, 20).unwrap(), []);
}

#[test]
fn caches_install_after_full_finished_and_resume_does_not_extend_ttl() {
    let clients = client(SUBJECT, 100);
    let servers = server(1, 12);
    let mut first_client = clients.peer(NOW).unwrap();
    let mut first_server = servers.peer(NOW).unwrap();
    let (id, _, commit) = full_commit(&mut first_client, &mut first_server, 0);
    assert!(client_id(&send(&clients.peer(NOW).unwrap().start(2).unwrap())).is_empty());
    assert_unknown_key_id(&mut servers.peer(NOW).unwrap(), id, 2);
    finish_full(&mut first_client, &mut first_server, &commit, 3);
    let mut resumed_client = clients.peer(NOW).unwrap();
    let mut resumed_server = servers.peer(NOW).unwrap();
    let (_, _, commit) = resumed_commit(&mut resumed_client, &mut resumed_server, id, 8);
    assert_eq!(
        resumed_server.receive(&commit, 11).unwrap(),
        [WireAction::Established(HandshakeKind::Resumed)]
    );

    assert_unknown_key_id(&mut servers.peer(NOW).unwrap(), id, 15);
    let mut fallback_client = clients.peer(NOW).unwrap();
    let mut fallback_server = servers.peer(NOW).unwrap();
    let (fresh, offer, commit) = full_commit(&mut fallback_client, &mut fallback_server, 16);
    assert_eq!(client_id(&offer), id);
    assert_ne!(fresh, id);
    finish_full(&mut fallback_client, &mut fallback_server, &commit, 19);
}

#[test]
fn capacity_evicts_oldest_and_closing_evicted_session_preserves_newer_sessions() {
    let servers = server(2, 100);
    let first_clients = client(SUBJECT, 100);
    let mut first_client = first_clients.peer(NOW).unwrap();
    let mut first_server = servers.peer(NOW).unwrap();
    let oldest = full(&mut first_client, &mut first_server, 0);
    let middle_clients = client(SUBJECT, 100);
    let middle = full(
        &mut middle_clients.peer(NOW).unwrap(),
        &mut servers.peer(NOW).unwrap(),
        5,
    );
    let newest_clients = client(SUBJECT, 100);
    let newest = full(
        &mut newest_clients.peer(NOW).unwrap(),
        &mut servers.peer(NOW).unwrap(),
        10,
    );
    assert_ne!(oldest, middle);
    assert_ne!(middle, newest);
    assert_unknown_key_id(&mut servers.peer(NOW).unwrap(), oldest, 15);
    close(
        &mut first_client,
        &mut first_server,
        CloseScope::Session,
        16,
    );

    for (clients, id, at) in [(middle_clients, middle, 20), (newest_clients, newest, 25)] {
        let mut client = clients.peer(NOW).unwrap();
        let mut server = servers.peer(NOW).unwrap();
        let (_, _, commit) = resumed_commit(&mut client, &mut server, id, at);
        assert_eq!(
            server.receive(&commit, at + 3).unwrap(),
            [WireAction::Established(HandshakeKind::Resumed)]
        );
    }
}

#[test]
fn authenticated_session_close_invalidates_only_the_current_session() {
    let clients = client(SUBJECT, 100);
    let servers = server(1, 100);
    let id = full(
        &mut clients.peer(NOW).unwrap(),
        &mut servers.peer(NOW).unwrap(),
        0,
    );
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let (_, _, commit) = resumed_commit(&mut client, &mut server, id, 10);
    server.receive(&commit, 13).unwrap();

    let mut forged_close = send(&client.close(CloseScope::Session).unwrap());
    let authentic_close = forged_close.clone();
    *forged_close.last_mut().unwrap() ^= 1;
    assert_eq!(
        server.receive(&forged_close, 14),
        Err(WireError::AuthenticationFailed)
    );
    assert_eq!(server.status(), Status::Open);
    assert_eq!(
        server_id(&send(
            &servers
                .peer(NOW)
                .unwrap()
                .receive(&resumption_only_offer(id), 15)
                .unwrap()
        )),
        id
    );
    assert!(client_id(&send(&clients.peer(NOW).unwrap().start(15).unwrap())).is_empty());
    assert!(
        server
            .receive(&authentic_close, 16)
            .unwrap()
            .contains(&WireAction::Closed(CloseScope::Session))
    );
    assert_unknown_key_id(&mut servers.peer(NOW).unwrap(), id, 17);
}

#[test]
fn matching_id_requires_an_abbreviated_flight_and_unverified_finished_keeps_cache() {
    let clients = client(SUBJECT, 100);
    let servers = server(1, 100);
    let id = full(
        &mut clients.peer(NOW).unwrap(),
        &mut servers.peer(NOW).unwrap(),
        0,
    );
    let mut client = clients.peer(NOW).unwrap();
    let offer = send(&client.start(10).unwrap());

    let full_reply = send(
        &server(1, 100)
            .peer(NOW)
            .unwrap()
            .receive(&offer, 11)
            .unwrap(),
    );
    let mut full_records = decode_datagram(&full_reply).unwrap();
    let mut hello = full_records[0].fragment.to_vec();
    hello[21..29].copy_from_slice(&id);
    full_records[0].fragment = &hello;
    let forged_full = encode_datagram(&full_records).unwrap();
    assert!(matches!(
        client.receive(&forged_full, 12),
        Err(WireError::Handshake(_))
    ));
    assert_eq!(client.status(), Status::Negotiating);

    let valid = send(&servers.peer(NOW).unwrap().receive(&offer, 13).unwrap());
    let mut records = decode_datagram(&valid).unwrap();
    let mut hello = records[0].fragment.to_vec();
    hello[29] = 1; // A valid key ID, but distinct ServerHello transcript bytes.
    records[0].fragment = &hello;
    let tampered = encode_datagram(&records).unwrap();
    assert_eq!(
        client.receive(&tampered, 14),
        Err(WireError::AuthenticationFailed)
    );
    assert_eq!(client.status(), Status::Closed);

    let mut next = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let (_, _, commit) = resumed_commit(&mut next, &mut server, id, 15);
    assert_eq!(
        server.receive(&commit, 18).unwrap(),
        [WireAction::Established(HandshakeKind::Resumed)]
    );
}

#[test]
fn credential_wall_clock_and_monotonic_lifetime_both_bound_use() {
    let clients = client(SUBJECT, 10);
    let servers = server(1, 100);
    let id = full(
        &mut clients.peer(NOW).unwrap(),
        &mut servers.peer(NOW).unwrap(),
        0,
    );
    for outside_validity in [NOW - 2, NOW + 2] {
        assert_unknown_key_id(&mut servers.peer(outside_validity).unwrap(), id, 5);
        assert!(
            client_id(&send(
                &clients.peer(outside_validity).unwrap().start(5).unwrap()
            ))
            .is_empty()
        );
    }
    assert_eq!(
        client_id(&send(&clients.peer(NOW + 1).unwrap().start(13).unwrap())),
        id
    );
    assert!(client_id(&send(&clients.peer(NOW + 1).unwrap().start(14).unwrap())).is_empty());

    let mut untrusted = client("Other; WTLS Lab; CA; other.lab.invalid", 100)
        .peer(NOW)
        .unwrap();
    let offer = send(&untrusted.start(15).unwrap());
    assert!(client_id(&offer).is_empty());
    let flight = send(&servers.peer(NOW).unwrap().receive(&offer, 16).unwrap());
    assert_eq!(
        untrusted.receive(&flight, 17),
        Err(WireError::CertificateRejected)
    );
    assert_eq!(untrusted.status(), Status::Closed);
    let matching = send(
        &servers
            .peer(NOW)
            .unwrap()
            .receive(&resumption_only_offer(id), 18)
            .unwrap(),
    );
    assert_eq!(server_id(&matching), id);
}

#[test]
fn delayed_prefixed_application_confirms_after_later_sends() {
    let clients = client(SUBJECT, 100);
    let servers = server(1, 100);
    let id = full(
        &mut clients.peer(NOW).unwrap(),
        &mut servers.peer(NOW).unwrap(),
        0,
    );
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let (_, _, commit) = resumed_commit(&mut client, &mut server, id, 10);
    server.receive(&commit, 13).unwrap();
    let payload = b"delayed".to_vec();
    let delayed = send(&client.send_application(payload.clone()).unwrap());
    assert!(delayed.starts_with(&commit));
    for i in 0..33 {
        let datagram = send(&client.send_application(vec![i]).unwrap());
        assert!(datagram.starts_with(&commit));
    }
    let actions = server.receive(&delayed, 14).unwrap();
    assert!(actions.contains(&WireAction::Deliver(payload)));
    let confirmation = send(&actions);
    assert_eq!(client.receive(&confirmation, 15).unwrap(), []);
    assert_eq!(client.status(), Status::Open);
    let second_confirmation = send(&server.receive(&commit, 16).unwrap());
    assert_eq!(client.receive(&second_confirmation, 17).unwrap(), []);
    assert_eq!(client.status(), Status::Open);
}

#[test]
fn server_session_close_after_prefixed_application_invalidates_both_caches() {
    let clients = client(SUBJECT, 100);
    let servers = server(1, 100);
    let id = full(
        &mut clients.peer(NOW).unwrap(),
        &mut servers.peer(NOW).unwrap(),
        0,
    );
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let (_, _, commit) = resumed_commit(&mut client, &mut server, id, 10);
    server.receive(&commit, 13).unwrap();

    let delayed = send(&client.send_application(vec![0]).unwrap());
    for i in 1..32 {
        client.send_application(vec![i]).unwrap();
    }
    let latest = send(&client.send_application(vec![32]).unwrap());
    assert!(latest.starts_with(&commit));

    let actions = server.receive(&delayed, 14).unwrap();
    assert!(actions.contains(&WireAction::Deliver(vec![0])));
    let actions = server.receive(&latest, 15).unwrap();
    assert!(actions.contains(&WireAction::Deliver(vec![32])));
    assert!(
        !server
            .receive(&delayed, 16)
            .unwrap()
            .iter()
            .any(|action| matches!(action, WireAction::Deliver(_)))
    );
    assert_eq!(client.status(), Status::AwaitingConfirmation);

    close(&mut server, &mut client, CloseScope::Session, 17);
    assert!(client_id(&send(&clients.peer(NOW).unwrap().start(19).unwrap())).is_empty());
    assert_unknown_key_id(&mut servers.peer(NOW).unwrap(), id, 19);
}

#[test]
fn client_session_close_keeps_latest_checksum_after_reordering() {
    let clients = client(SUBJECT, 100);
    let servers = server(1, 100);
    let id = full(
        &mut clients.peer(NOW).unwrap(),
        &mut servers.peer(NOW).unwrap(),
        0,
    );
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let (_, _, commit) = resumed_commit(&mut client, &mut server, id, 10);
    server.receive(&commit, 13).unwrap();

    let payload = b"delayed server data".to_vec();
    let delayed = send(&server.send_application(payload.clone()).unwrap());
    let first_ack = send(&server.receive(&commit, 14).unwrap());
    assert_eq!(client.receive(&first_ack, 15).unwrap(), []);
    for at in 16..48 {
        let ack = send(&server.receive(&commit, at).unwrap());
        assert_eq!(client.receive(&ack, at).unwrap(), []);
    }
    // An older acknowledgment must not replace the recent close checksum.
    assert_eq!(client.receive(&first_ack, 48).unwrap(), []);
    assert_eq!(
        client.receive(&delayed, 48).unwrap(),
        [WireAction::Deliver(payload)]
    );
    assert_eq!(client.receive(&delayed, 48).unwrap(), []);

    close(&mut client, &mut server, CloseScope::Session, 49);
    assert!(client_id(&send(&clients.peer(NOW).unwrap().start(51).unwrap())).is_empty());
    assert_unknown_key_id(&mut servers.peer(NOW).unwrap(), id, 51);
}

#[test]
fn pending_client_resume_cannot_complete_after_session_close_or_expiry() {
    for invalidate in [true, false] {
        let clients = client(SUBJECT, 20);
        let servers = server(1, 100);
        let mut original_client = clients.peer(NOW).unwrap();
        let mut original_server = servers.peer(NOW).unwrap();
        let id = full(&mut original_client, &mut original_server, 0);
        let mut client = clients.peer(NOW).unwrap();
        let mut server = servers.peer(NOW).unwrap();
        let offer = send(&client.start(10).unwrap());
        assert_eq!(client_id(&offer), id);
        let flight = send(&server.receive(&offer, 11).unwrap());
        assert_eq!(server_id(&flight), id);

        let at = if invalidate {
            // A locally closed client session is invalid even if its close is lost.
            assert!(
                original_client
                    .close(CloseScope::Session)
                    .unwrap()
                    .contains(&WireAction::Closed(CloseScope::Session))
            );
            12
        } else {
            24
        };
        assert!(client.receive(&flight, at).is_err());
        assert!(client.connection_info().is_none());
        assert!(client_id(&send(&clients.peer(NOW).unwrap().start(at + 1).unwrap())).is_empty());
    }
}

#[test]
fn client_session_close_carries_the_commit_until_confirmed() {
    client_close_carries_commit_until_confirmed(CloseScope::Session);
}

#[test]
fn client_connection_close_carries_the_commit_until_confirmed() {
    client_close_carries_commit_until_confirmed(CloseScope::Connection);
}

fn client_close_carries_commit_until_confirmed(scope: CloseScope) {
    for (deliver_commit, delivered_ack) in [
        (false, None),
        (true, None),
        (true, Some(14)),
        (true, Some(46)),
    ] {
        let clients = client(SUBJECT, 100);
        let servers = server(1, 100);
        let id = full(
            &mut clients.peer(NOW).unwrap(),
            &mut servers.peer(NOW).unwrap(),
            0,
        );
        let mut client = clients.peer(NOW).unwrap();
        let mut server = servers.peer(NOW).unwrap();
        let (_, _, commit) = resumed_commit(&mut client, &mut server, id, 10);
        if deliver_commit {
            server.receive(&commit, 13).unwrap();
            // Deliver no acknowledgment, only the first, or only the latest.
            for at in 14..47 {
                let ack = send(&server.receive(&commit, at).unwrap());
                if delivered_ack == Some(at) {
                    assert_eq!(client.receive(&ack, at).unwrap(), []);
                }
            }
        }

        let confirmed = delivered_ack.is_some();
        assert_eq!(
            client.status(),
            if confirmed {
                Status::Open
            } else {
                Status::AwaitingConfirmation
            }
        );
        let actions = client.close(scope).unwrap();
        assert!(actions.contains(&WireAction::Closed(scope)));
        let datagram = send(&actions);
        let tail = if confirmed {
            assert!(!datagram.starts_with(&commit));
            datagram.as_slice()
        } else {
            let tail = datagram.strip_prefix(commit.as_slice()).unwrap();
            let mut altered = decode_datagram(&datagram).unwrap();
            altered[0].sequence += 1;
            assert_eq!(
                server.receive(&encode_datagram(&altered).unwrap(), 47),
                Err(WireError::InvalidRecord)
            );
            tail
        };
        let records = decode_datagram(tail).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].content_type, RecordType::Alert);
        assert_eq!(records[0].cipher_spec, CipherSpec::Current);
        assert_eq!(records[0].sequence, 1);

        let actions = server.receive(&datagram, 47).unwrap();
        assert_eq!(
            actions.contains(&WireAction::Established(HandshakeKind::Resumed)),
            !deliver_commit
        );
        assert!(actions.contains(&WireAction::Closed(scope)));
        assert_eq!(client.receive(&send(&actions), 48).unwrap(), []);
        assert_eq!(server.receive(&datagram, 49).unwrap(), []);
        assert_close_cache_effect(&clients, &servers, id, scope, 50);
    }
}

#[test]
fn server_session_close_accepts_an_early_client_record_checksum() {
    server_close_references_early_record(CloseScope::Session);
}

#[test]
fn server_connection_close_accepts_an_early_client_record_checksum() {
    server_close_references_early_record(CloseScope::Connection);
}

fn server_close_references_early_record(scope: CloseScope) {
    for (confirmed, deliver_application) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let clients = client(SUBJECT, 100);
        let servers = server(1, 100);
        let id = full(
            &mut clients.peer(NOW).unwrap(),
            &mut servers.peer(NOW).unwrap(),
            0,
        );
        let mut client = clients.peer(NOW).unwrap();
        let mut server = servers.peer(NOW).unwrap();
        let (_, _, commit) = resumed_commit(&mut client, &mut server, id, 10);
        server.receive(&commit, 13).unwrap();
        if confirmed {
            let data = send(&server.send_application(vec![0]).unwrap());
            assert_eq!(
                client.receive(&data, 14).unwrap(),
                [WireAction::Deliver(vec![0])]
            );
            assert_eq!(client.status(), Status::Open);
        } else {
            assert_eq!(client.status(), Status::AwaitingConfirmation);
        }

        if deliver_application {
            let data = send(&client.send_application(vec![0]).unwrap());
            assert!(
                server
                    .receive(&data, 15)
                    .unwrap()
                    .contains(&WireAction::Deliver(vec![0]))
            );
        }
        // Lose these records so the server references Finished or the first
        // application record, whichever it received most recently.
        for i in 1..=32 {
            client.send_application(vec![i]).unwrap();
        }
        let actions = server.close(scope).unwrap();
        assert!(actions.contains(&WireAction::Closed(scope)));
        let datagram = send(&actions);
        let records = decode_datagram(&datagram).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].content_type, RecordType::Alert);
        assert_eq!(records[0].cipher_spec, CipherSpec::Current);
        let actions = client.receive(&datagram, 16).unwrap();
        assert!(actions.contains(&WireAction::Closed(scope)));
        assert_eq!(server.receive(&send(&actions), 17).unwrap(), []);
        assert_close_cache_effect(&clients, &servers, id, scope, 18);
    }
}

fn assert_close_cache_effect(
    clients: &ResumableClient,
    servers: &ResumableServer,
    id: [u8; 8],
    scope: CloseScope,
    at: u64,
) {
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    match scope {
        CloseScope::Session => {
            assert!(client_id(&send(&client.start(at).unwrap())).is_empty());
            assert_unknown_key_id(&mut server, id, at);
        }
        CloseScope::Connection => {
            let (_, _, commit) = resumed_commit(&mut client, &mut server, id, at);
            assert_eq!(
                server.receive(&commit, at + 3).unwrap(),
                [WireAction::Established(HandshakeKind::Resumed)]
            );
        }
    }
}

#[test]
fn pending_resume_cannot_complete_after_session_close_or_expiry() {
    for invalidate in [true, false] {
        let clients = client(SUBJECT, 100);
        let servers = server(1, 20);
        let mut original_client = clients.peer(NOW).unwrap();
        let mut original_server = servers.peer(NOW).unwrap();
        let id = full(&mut original_client, &mut original_server, 0);
        let mut client = clients.peer(NOW).unwrap();
        let mut server = servers.peer(NOW).unwrap();
        let (_, _, commit) = resumed_commit(&mut client, &mut server, id, 10);
        let at = if invalidate {
            close(
                &mut original_client,
                &mut original_server,
                CloseScope::Session,
                13,
            );
            15
        } else {
            23
        };

        assert!(server.receive(&commit, at).is_err());
        assert_eq!(server.status(), Status::Closed);
        assert_unknown_key_id(&mut servers.peer(NOW).unwrap(), id, at + 1);
    }
}
