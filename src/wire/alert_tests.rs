use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::OnceLock;

use openssl::pkey::Public;

use super::*;

pub(super) const NOW: u32 = 1_730_000_000;
const ISSUER: &str = "WTLS Alert CA; WTLS Lab; CA";
const SUBJECT: &str = "Echo; WTLS Lab; CA; echo.lab.invalid";
const WARNING: u8 = 1;
const CRITICAL: u8 = 2;
const FATAL: u8 = 3;
const HANDSHAKE_FAILURE: u8 = 40;
const UNKNOWN_KEY_ID: u8 = 52;
const NO_RENEGOTIATION: u8 = 100;
// A protected alert header with a sequence and a length, missing both fields.
const TRUNCATED_ALERT: [u8; 1] = [0xe2];

fn public(key: &Rsa<Private>) -> Rsa<Public> {
    Rsa::from_public_components(key.n().to_owned().unwrap(), key.e().to_owned().unwrap()).unwrap()
}

pub(super) fn contexts() -> (ResumableClient, ResumableServer) {
    static KEYS: OnceLock<(Rsa<Private>, Rsa<Private>)> = OnceLock::new();
    let (ca, key) =
        KEYS.get_or_init(|| (Rsa::generate(2048).unwrap(), Rsa::generate(2048).unwrap()));
    let cert = issue_certificate(ISSUER, SUBJECT, (NOW - 1)..=(NOW + 1), ca, &public(key)).unwrap();
    let identity = ServerIdentity::new(cert, key.clone()).unwrap();
    let trust = TrustAnchor::new(ISSUER, SUBJECT, public(ca)).unwrap();
    let lifetime = NonZeroU64::new(1_000).unwrap();
    let retry = RetryPolicy {
        timeout_ms: NonZeroU64::new(10).unwrap(),
        max_retries: 2,
    };
    (
        ResumableClient::new(retry, trust, lifetime),
        ResumableServer::new(identity, NonZeroUsize::new(4).unwrap(), lifetime),
    )
}

pub(super) fn send(actions: &[WireAction]) -> Vec<u8> {
    let mut sends = actions.iter().filter_map(|action| match action {
        WireAction::Send(bytes) => Some(bytes),
        _ => None,
    });
    let bytes = sends.next().expect("outbound datagram");
    assert!(sends.next().is_none());
    bytes.clone()
}

fn offered_id(offer: &[u8]) -> &[u8] {
    let records = crate::decode_datagram(offer).unwrap();
    decode_client_hello(records[0].fragment).unwrap().session_id
}

fn establish_full(
    client: &mut WirePeer,
    server: &mut WirePeer,
    offer: &[u8],
    at: u64,
) -> SessionId {
    let hello = send(&server.receive(offer, at + 1).unwrap());
    let records = crate::decode_datagram(&hello).unwrap();
    assert_eq!(records.len(), 3);
    let id = decode_server_hello(records[0].fragment).unwrap().session_id;
    assert_ne!(id, offered_id(offer));
    let commit = send(&client.receive(&hello, at + 2).unwrap());
    let actions = server.receive(&commit, at + 3).unwrap();
    assert!(actions.contains(&WireAction::Established(HandshakeKind::Full)));
    assert_eq!(
        client.receive(&send(&actions), at + 4).unwrap(),
        [WireAction::Established(HandshakeKind::Full)]
    );
    SessionId(id.try_into().unwrap())
}

pub(super) fn full(client: &mut WirePeer, server: &mut WirePeer, at: u64) -> SessionId {
    let offer = send(&client.start(at).unwrap());
    establish_full(client, server, &offer, at)
}

pub(super) fn begin_resume(
    client: &mut WirePeer,
    server: &mut WirePeer,
    id: SessionId,
    at: u64,
) -> Vec<u8> {
    let offer = send(&client.start(at).unwrap());
    assert_eq!(offered_id(&offer), id.0);
    let response = send(&server.receive(&offer, at + 1).unwrap());
    assert_eq!(server.status(), Status::Negotiating);
    let actions = client.receive(&response, at + 2).unwrap();
    assert!(actions.contains(&WireAction::Established(HandshakeKind::Resumed)));
    assert_eq!(client.status(), Status::AwaitingConfirmation);
    send(&actions)
}

fn seal(peer: &WirePeer, kind: RecordType, sequence: u16, fragment: &[u8]) -> Vec<u8> {
    let mut record = Record {
        content_type: kind,
        cipher_spec: CipherSpec::Current,
        sequence,
        length_form: LengthForm::Explicit,
        fragment,
    };
    let ciphertext = peer
        .traffic
        .as_ref()
        .unwrap()
        .seal(peer.local_role(), record)
        .unwrap();
    record.fragment = &ciphertext;
    crate::encode_datagram(&[record]).unwrap()
}

fn alert_fields(level: u8, description: u8, checksum: [u8; 4]) -> [u8; 6] {
    let [a, b, c, d] = checksum;
    [level, description, a, b, c, d]
}

fn clear_alert(sequence: u16, fragment: &[u8]) -> Vec<u8> {
    crate::encode_datagram(&[Record {
        content_type: RecordType::Alert,
        cipher_spec: CipherSpec::Null,
        sequence,
        length_form: LengthForm::Explicit,
        fragment,
    }])
    .unwrap()
}

fn first_record_checksum(datagram: &[u8]) -> [u8; 4] {
    let records = crate::decode_datagram(datagram).unwrap();
    assert!(records.len() > 1);
    datagram[..records[0].wire_len()]
        .chunks(4)
        .fold(0u32, |checksum, chunk| {
            let mut word = [0; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            checksum ^ u32::from_be_bytes(word)
        })
        .to_be_bytes()
}

pub(super) fn protected_alert(peer: &mut WirePeer, fragment: &[u8]) -> Vec<u8> {
    assert!(peer.write.protected);
    let sequence = peer.write.next().unwrap();
    seal(peer, RecordType::Alert, sequence, fragment)
}

fn alert_error(fragment: &[u8], protection: AlertProtection) -> WireError {
    WireError::PeerAlert {
        fields: decode_alert_fields(fragment).unwrap(),
        protection,
    }
}

fn assert_delivers(from: &mut WirePeer, to: &mut WirePeer, at: u64) {
    let data = b"still open";
    let bytes = send(&from.send_application(data.to_vec()).unwrap());
    let actions = to.receive(&bytes, at).unwrap();
    assert!(actions.contains(&WireAction::Deliver(data.to_vec())));
}

#[test]
fn clear_alert_critical_can_reference_the_first_record_of_a_full_server_flight() {
    let (clients, servers) = contexts();
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let offer = send(&client.start(0).unwrap());
    let flight = send(&server.receive(&offer, 1).unwrap());
    let fragment = alert_fields(CRITICAL, HANDSHAKE_FAILURE, first_record_checksum(&flight));
    let commit = send(&client.receive(&flight, 2).unwrap());

    assert_eq!(
        server.receive(&clear_alert(1, &fragment), 3),
        Err(alert_error(&fragment, AlertProtection::Clear))
    );
    assert_eq!(server.status(), Status::Closed);
    assert_eq!(server.deadline(), None);
    assert!(server.receive(&commit, 4).unwrap().is_empty());
    assert!(server.tick(30).unwrap().is_empty());
}

#[test]
fn clear_alert_rejections_leave_the_expected_full_flight_usable() {
    let (clients, servers) = contexts();
    // Fixed, distinct ClientHello randoms give two valid attempts with
    // different, nonzero complete-record checksums.
    let fixed_offer = |peer: &mut WirePeer, last_byte| {
        let mut random = [0; 16];
        random[..4].copy_from_slice(&NOW.to_be_bytes());
        random[15] = last_byte;
        let actions = peer.handshake.start(random, 0).unwrap();
        peer.random = Some(random);
        send(&peer.apply(actions).unwrap())
    };
    let previous_offer = fixed_offer(&mut clients.peer(NOW).unwrap(), 1);
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let offer = fixed_offer(&mut client, 2);
    let checksum = record_checksum(&offer);
    let previous = record_checksum(&previous_offer);
    assert_ne!(checksum, previous);
    assert_ne!(checksum, [0; 4]);
    let mut wrong = checksum;
    wrong[0] ^= 1;
    let flight = send(&server.receive(&offer, 1).unwrap());
    let fragment = alert_fields(FATAL, HANDSHAKE_FAILURE, checksum);
    let clear = clear_alert(0, &fragment);

    for (received, expected) in [
        (
            clear_alert(0, &alert_fields(FATAL, HANDSHAKE_FAILURE, wrong)),
            WireError::AuthenticationFailed,
        ),
        (
            clear_alert(0, &alert_fields(FATAL, HANDSHAKE_FAILURE, previous)),
            WireError::AuthenticationFailed,
        ),
        (
            clear_alert(0, &alert_fields(FATAL, HANDSHAKE_FAILURE, [0; 4])),
            WireError::AuthenticationFailed,
        ),
        (clear_alert(1, &fragment), WireError::InvalidRecord),
        (clear_alert(0, &fragment[..5]), WireError::InvalidMessage),
        (
            [clear.as_slice(), &flight].concat(),
            WireError::InvalidRecord,
        ),
        (
            [flight.as_slice(), &clear].concat(),
            WireError::InvalidRecord,
        ),
    ] {
        assert_eq!(client.receive(&received, 2), Err(expected));
        assert_eq!(client.status(), Status::Negotiating);
        assert_eq!(client.deadline(), Some(10));
    }
    let malformed = [clear.as_slice(), &TRUNCATED_ALERT].concat();
    assert_eq!(
        client.receive(&malformed, 2),
        Err(WireError::Decode(
            crate::decode_datagram(&malformed).unwrap_err()
        ))
    );

    assert_eq!(client.tick(10).unwrap(), [WireAction::Send(offer)]);
    let commit = send(&client.receive(&flight, 11).unwrap());
    let reply = send(&server.receive(&commit, 12).unwrap());
    assert_eq!(
        client.receive(&reply, 13).unwrap(),
        [WireAction::Established(HandshakeKind::Full)]
    );
    assert_delivers(&mut client, &mut server, 14);
}

#[test]
fn clear_alert_no_connection_checks_the_checksum_before_exempting_sequence() {
    let (clients, _) = contexts();
    for (level, sequence) in [(FATAL, u16::MAX), (CRITICAL, 42)] {
        let mut client = clients.peer(NOW).unwrap();
        let offer = send(&client.start(0).unwrap());
        let checksum = record_checksum(&offer);
        let mut wrong = checksum;
        wrong[0] ^= 1;
        assert_eq!(
            client.receive(&clear_alert(sequence, &alert_fields(level, 5, wrong)), 1),
            Err(WireError::AuthenticationFailed)
        );
        assert_eq!(client.status(), Status::Negotiating);
        assert_eq!(client.deadline(), Some(10));
        let fragment = alert_fields(level, 5, checksum);
        assert_eq!(
            client.receive(&clear_alert(sequence, &fragment), 2),
            Err(alert_error(&fragment, AlertProtection::Clear))
        );
        assert_eq!(client.status(), Status::Closed);
        assert_eq!(client.deadline(), None);
        assert!(client.tick(10).unwrap().is_empty());
    }
}

#[test]
fn clear_alert_aborts_both_pending_resumption_roles_and_preserves_original_expiry() {
    let (clients, servers) = contexts();
    let id = full(
        &mut clients.peer(NOW).unwrap(),
        &mut servers.peer(NOW).unwrap(),
        0,
    );
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let offer = send(&client.start(10).unwrap());
    assert_eq!(offered_id(&offer), id.0);
    let flight = send(&server.receive(&offer, 11).unwrap());
    assert_eq!(crate::decode_datagram(&flight).unwrap().len(), 3);
    assert!(server.traffic.is_some());
    assert!(server.session.is_some());
    assert!(client.session.is_some());

    let fatal = alert_fields(FATAL, HANDSHAKE_FAILURE, record_checksum(&offer));
    let critical = alert_fields(CRITICAL, UNKNOWN_KEY_ID, first_record_checksum(&flight));
    for (peer, sequence, fragment) in [(&mut client, 0, fatal), (&mut server, 1, critical)] {
        assert_eq!(
            peer.receive(&clear_alert(sequence, &fragment), 12),
            Err(alert_error(&fragment, AlertProtection::Clear))
        );
        assert_eq!(peer.status(), Status::Closed);
        assert_eq!(peer.deadline(), None);
        assert!(peer.tick(30).unwrap().is_empty());
        assert!(peer.traffic.is_none());
        assert!(peer.session.is_none());
    }

    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let commit = begin_resume(&mut client, &mut server, id, 40);
    assert!(
        server
            .receive(&commit, 43)
            .unwrap()
            .contains(&WireAction::Established(HandshakeKind::Resumed))
    );
    assert_delivers(&mut server, &mut client, 44);
    assert_delivers(&mut client, &mut server, 45);
    assert!(server.find_session(Some(id), 1002).unwrap().is_some());
    assert!(server.find_session(Some(id), 1003).unwrap().is_none());
    assert!(client.find_session(Some(id), 1003).unwrap().is_some());
    assert!(client.find_session(Some(id), 1004).unwrap().is_none());
}

#[test]
fn clear_alert_advisories_preserve_deadline_cache_and_confirmation() {
    let (clients, servers) = contexts();
    let id = full(
        &mut clients.peer(NOW).unwrap(),
        &mut servers.peer(NOW).unwrap(),
        0,
    );
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let offer = send(&client.start(10).unwrap());
    let checksum = record_checksum(&offer);
    for (level, description) in [(WARNING, 11), (CRITICAL, 0), (FATAL, 1), (WARNING, 57)] {
        let advisory = alert_fields(level, description, checksum);
        assert_eq!(
            client.receive(&clear_alert(0, &advisory), 11),
            Err(alert_error(&advisory, AlertProtection::Clear))
        );
        assert_eq!(client.status(), Status::Negotiating);
        assert_eq!(client.deadline(), Some(20));
        assert!(client.find_session(Some(id), 11).unwrap().is_some());
    }
    for (level, description) in [
        (FATAL, 0),
        (WARNING, 0),
        (CRITICAL, 1),
        (WARNING, 1),
        (0, 40),
        (4, 40),
    ] {
        let invalid = alert_fields(level, description, checksum);
        assert_eq!(
            client.receive(&clear_alert(0, &invalid), 11),
            Err(WireError::InvalidMessage)
        );
    }
    let warning = alert_fields(WARNING, 5, checksum);
    assert_eq!(
        client.receive(&clear_alert(42, &warning), 11),
        Err(WireError::InvalidRecord)
    );
    assert_eq!(client.tick(20).unwrap(), [WireAction::Send(offer.clone())]);
    let resumed = send(&server.receive(&offer, 21).unwrap());
    let actions = client.receive(&resumed, 22).unwrap();
    assert!(actions.contains(&WireAction::Established(HandshakeKind::Resumed)));
    let commit = send(&actions);
    assert_eq!(client.status(), Status::AwaitingConfirmation);
    let deadline = client.deadline();
    for (level, description, sequence) in [(WARNING, 57, 1), (FATAL, 1, 1), (FATAL, 5, u16::MAX)] {
        let fragment = alert_fields(level, description, checksum);
        assert_eq!(
            client.receive(&clear_alert(sequence, &fragment), 23),
            Err(WireError::InvalidRecord)
        );
        assert_eq!(client.status(), Status::AwaitingConfirmation);
        assert_eq!(client.deadline(), deadline);
        assert!(client.find_session(Some(id), 23).unwrap().is_some());
    }
    assert!(
        server
            .receive(&commit, 24)
            .unwrap()
            .contains(&WireAction::Established(HandshakeKind::Resumed))
    );
    assert_delivers(&mut server, &mut client, 25);
    assert_eq!(client.status(), Status::Open);
    assert_delivers(&mut client, &mut server, 26);
}

#[test]
fn clear_alert_is_rejected_in_a_committed_full_receive_epoch() {
    let (clients, servers) = contexts();
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let id = full(&mut client, &mut server, 0);

    let fragment = alert_fields(FATAL, 5, server.last_received);
    assert_eq!(
        client.receive(&clear_alert(u16::MAX, &fragment), 5),
        Err(WireError::InvalidRecord)
    );
    assert_eq!(client.status(), Status::Open);
    assert!(client.find_session(Some(id), 5).unwrap().is_some());
    assert_delivers(&mut server, &mut client, 6);
    assert_delivers(&mut client, &mut server, 7);
}

#[test]
fn clear_alert_is_rejected_but_protected_generic_critical_closes_the_server() {
    let (clients, servers) = contexts();
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let id = full(&mut client, &mut server, 0);
    let fragment = alert_fields(CRITICAL, HANDSHAKE_FAILURE, client.last_received);
    assert_eq!(
        server.receive(&clear_alert(0, &fragment), 5),
        Err(WireError::InvalidRecord)
    );
    assert_eq!(server.status(), Status::Open);
    let alert = protected_alert(&mut client, &fragment);
    assert_eq!(
        server.receive(&alert, 5),
        Err(alert_error(&fragment, AlertProtection::Authenticated))
    );
    assert_eq!(server.status(), Status::Closed);
    assert!(server.traffic.is_none());
    assert!(server.session.is_none());
    assert!(server.find_session(Some(id), 5).unwrap().is_some());
    assert_eq!(client.status(), Status::Open);
    let mut new_server = servers.peer(NOW).unwrap();
    let commit = begin_resume(&mut clients.peer(NOW).unwrap(), &mut new_server, id, 10);
    assert!(
        new_server
            .receive(&commit, 13)
            .unwrap()
            .contains(&WireAction::Established(HandshakeKind::Resumed))
    );
}

#[test]
fn application_batch_fatal_alert_revokes_the_session_and_disengages_only_its_receiver() {
    let (clients, servers) = contexts();
    let (other_clients, _) = contexts();
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let id = full(&mut client, &mut server, 0);
    let other_id = full(
        &mut other_clients.peer(NOW).unwrap(),
        &mut servers.peer(NOW).unwrap(),
        5,
    );

    let mut sibling_client = clients.peer(NOW).unwrap();
    let mut sibling_server = servers.peer(NOW).unwrap();
    let commit = begin_resume(&mut sibling_client, &mut sibling_server, id, 10);
    let actions = sibling_server.receive(&commit, 13).unwrap();
    assert!(actions.contains(&WireAction::Established(HandshakeKind::Resumed)));
    assert_delivers(&mut sibling_server, &mut sibling_client, 14);

    let mut pending_server = servers.peer(NOW).unwrap();
    let pending = begin_resume(&mut clients.peer(NOW).unwrap(), &mut pending_server, id, 15);

    // WAP-199 §§10.1 and 10.2: correlate the fatal handshake_failure with
    // a record this peer received. Neither a prior warning nor application
    // data on either side of the fatal alert may mask the terminal outcome.
    let fragment = alert_fields(FATAL, HANDSHAKE_FAILURE, client.last_received);
    let warning = alert_fields(WARNING, NO_RENEGOTIATION, client.last_received);
    let before = send(&client.send_application(b"before alert".to_vec()).unwrap());
    let more = send(
        &client
            .send_application(b"also before alert".to_vec())
            .unwrap(),
    );
    let warning = protected_alert(&mut client, &warning);
    let alert = protected_alert(&mut client, &fragment);
    let after = send(&client.send_application(b"after alert".to_vec()).unwrap());
    let datagram = [
        before.as_slice(),
        &more,
        &warning,
        &alert,
        &after,
        &TRUNCATED_ALERT,
    ]
    .concat();
    let sent_count = server.sent_checksums.len();
    assert_eq!(
        server.receive(&datagram, 18),
        Err(alert_error(&fragment, AlertProtection::Authenticated))
    );
    assert_eq!(server.status(), Status::Closed);
    assert!(server.traffic.is_none());
    assert!(server.session.is_none());
    assert_eq!(server.sent_checksums.len(), sent_count);
    assert_eq!(server.receive(&after, 19).unwrap(), []);
    assert_eq!(
        pending_server.receive(&pending, 19),
        Err(WireError::InvalidMessage)
    );
    assert_eq!(pending_server.status(), Status::Closed);

    assert_delivers(&mut sibling_client, &mut sibling_server, 20);
    assert_delivers(&mut sibling_server, &mut sibling_client, 21);

    let mut other_server = servers.peer(NOW).unwrap();
    let commit = begin_resume(
        &mut other_clients.peer(NOW).unwrap(),
        &mut other_server,
        other_id,
        22,
    );
    assert!(
        other_server
            .receive(&commit, 25)
            .unwrap()
            .contains(&WireAction::Established(HandshakeKind::Resumed))
    );

    let mut stale_client = clients.peer(NOW).unwrap();
    let offer = send(&stale_client.start(30).unwrap());
    assert_eq!(offered_id(&offer), id.0);
    assert_ne!(
        establish_full(
            &mut stale_client,
            &mut servers.peer(NOW).unwrap(),
            &offer,
            30
        ),
        id
    );
}

#[test]
fn fatal_alert_closes_a_resumed_client_awaiting_confirmation() {
    let (clients, servers) = contexts();
    let id = full(
        &mut clients.peer(NOW).unwrap(),
        &mut servers.peer(NOW).unwrap(),
        0,
    );
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let commit = begin_resume(&mut client, &mut server, id, 10);
    server.receive(&commit, 13).unwrap();

    let fragment = alert_fields(FATAL, HANDSHAKE_FAILURE, server.last_received);
    let terminal = protected_alert(&mut server, &fragment);
    assert_eq!(
        client.receive(&terminal, 14),
        Err(alert_error(&fragment, AlertProtection::Authenticated))
    );
    assert_eq!(client.status(), Status::Closed);
    assert_eq!(client.deadline(), None);
    assert!(client.tick(30).unwrap().is_empty());
    assert!(client.traffic.is_none());
    assert!(client.session.is_none());
    assert!(offered_id(&send(&clients.peer(NOW).unwrap().start(31).unwrap())).is_empty());
    assert!(server.find_session(Some(id), 31).unwrap().is_some());
    assert_eq!(server.status(), Status::Open);
}

#[test]
fn application_batch_critical_alert_preserves_the_session_after_warnings_and_unverified_alerts() {
    let (clients, servers) = contexts();
    let id = full(
        &mut clients.peer(NOW).unwrap(),
        &mut servers.peer(NOW).unwrap(),
        0,
    );
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let commit = begin_resume(&mut client, &mut server, id, 11);
    assert!(
        server
            .receive(&commit, 14)
            .unwrap()
            .contains(&WireAction::Established(HandshakeKind::Resumed))
    );
    assert_delivers(&mut server, &mut client, 15);
    assert_eq!(client.status(), Status::Open);

    let checksum = server.last_received;
    let warning = alert_fields(WARNING, NO_RENEGOTIATION, checksum);
    let warning_record = protected_alert(&mut server, &warning);
    assert_eq!(
        client.receive(&warning_record, 17),
        Err(alert_error(&warning, AlertProtection::Authenticated))
    );
    let malformed = [warning_record.as_slice(), &TRUNCATED_ALERT].concat();
    assert_eq!(
        client.receive(&malformed, 17),
        Err(WireError::Decode(
            crate::decode_datagram(&malformed).unwrap_err()
        ))
    );
    let incorrect = (0u32..)
        .map(u32::to_be_bytes)
        .find(|sum| !client.sent_checksums.contains(sum))
        .unwrap();
    let uncorrelated = alert_fields(FATAL, HANDSHAKE_FAILURE, incorrect);
    assert_eq!(
        client.receive(&protected_alert(&mut server, &uncorrelated), 18),
        Err(WireError::AuthenticationFailed)
    );
    let fatal = alert_fields(FATAL, HANDSHAKE_FAILURE, checksum);
    assert_eq!(
        client.receive(&protected_alert(&mut server, &fatal[..5]), 19),
        Err(WireError::InvalidMessage)
    );
    let authentic = protected_alert(&mut server, &fatal);
    let mut unauthenticated = crate::decode_datagram(&authentic).unwrap()[0];
    unauthenticated.sequence += 1;
    let unauthenticated = crate::encode_datagram(&[unauthenticated]).unwrap();
    assert_eq!(
        client.receive(&unauthenticated, 20),
        Err(WireError::AuthenticationFailed)
    );
    for (level, description) in [(FATAL, 0), (WARNING, 0), (CRITICAL, 1), (WARNING, 1)] {
        let malformed = alert_fields(level, description, checksum);
        assert_eq!(
            client.receive(&protected_alert(&mut server, &malformed), 20),
            Err(WireError::InvalidMessage)
        );
        assert_eq!(client.status(), Status::Open);
        assert!(client.find_session(Some(id), 20).unwrap().is_some());
    }
    assert_delivers(&mut server, &mut client, 21);
    let critical = alert_fields(CRITICAL, UNKNOWN_KEY_ID, checksum);
    let sent_count = client.sent_checksums.len();
    let datagram = [
        send(&server.send_application(b"first".to_vec()).unwrap()),
        send(&server.send_application(b"second".to_vec()).unwrap()),
        protected_alert(&mut server, &critical),
        protected_alert(&mut server, &fatal),
    ]
    .concat();
    assert_eq!(
        client.receive(&datagram, 22),
        Err(alert_error(&critical, AlertProtection::Authenticated))
    );
    assert_eq!(client.status(), Status::Closed);
    assert!(client.traffic.is_none());
    assert_eq!(client.sent_checksums.len(), sent_count);

    let mut server = servers.peer(NOW).unwrap();
    let commit = begin_resume(&mut clients.peer(NOW).unwrap(), &mut server, id, 25);
    assert!(
        server
            .receive(&commit, 28)
            .unwrap()
            .contains(&WireAction::Established(HandshakeKind::Resumed))
    );
}

#[test]
fn application_batch_prefixed_close_takes_priority_over_warning_and_data() {
    for scope in [CloseScope::Connection, CloseScope::Session] {
        let (clients, servers) = contexts();
        let id = full(
            &mut clients.peer(NOW).unwrap(),
            &mut servers.peer(NOW).unwrap(),
            0,
        );
        let mut client = clients.peer(NOW).unwrap();
        let mut server = servers.peer(NOW).unwrap();
        let commit = begin_resume(&mut client, &mut server, id, 10);
        server.receive(&commit, 13).unwrap();

        let checksum = client.last_received;
        let first = send(&client.send_application(b"first".to_vec()).unwrap());
        let second = send(&client.send_application(b"second".to_vec()).unwrap());
        let warning = alert_fields(WARNING, NO_RENEGOTIATION, checksum);
        let warning = protected_alert(&mut client, &warning);
        let close = protected_alert(
            &mut client,
            &encode_alert(Alert::CloseNotify(scope), checksum),
        );
        let first = first.strip_prefix(commit.as_slice()).unwrap();
        let second = second.strip_prefix(commit.as_slice()).unwrap();
        let mut datagram = [commit.as_slice(), first, second, &warning, &close].concat();
        if scope == CloseScope::Connection {
            let fatal = alert_fields(FATAL, HANDSHAKE_FAILURE, checksum);
            datagram.extend(protected_alert(&mut client, &fatal));
        }
        datagram.extend(TRUNCATED_ALERT);

        let actions = server.receive(&datagram, 14).unwrap();
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[1], WireAction::Closed(scope));
        assert_eq!(server.status(), Status::Closed);
        let reply = send(&actions);
        let records = crate::decode_datagram(&reply).unwrap();
        assert_eq!(records.len(), 1);
        let plaintext = client
            .traffic
            .as_ref()
            .unwrap()
            .open(Role::Server, records[0])
            .unwrap();
        assert_eq!(
            plaintext.as_slice(),
            encode_alert(Alert::CloseNotify(scope), record_checksum(&close))
        );
        assert_eq!(
            server.find_session(Some(id), 15).unwrap().is_some(),
            scope == CloseScope::Connection,
        );
    }
}

#[test]
fn application_batch_cannot_follow_a_cached_lengthless_finished() {
    let (clients, servers) = contexts();
    let id = full(
        &mut clients.peer(NOW).unwrap(),
        &mut servers.peer(NOW).unwrap(),
        0,
    );
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let explicit_commit = begin_resume(&mut client, &mut server, id, 10);
    let mut records = crate::decode_datagram(&explicit_commit).unwrap();
    let keys = client.traffic.as_ref().unwrap();
    let finished = keys.open(Role::Client, records[1]).unwrap();
    records[1].length_form = LengthForm::DatagramRemainder;
    let ciphertext = keys
        .seal(
            Role::Client,
            Record {
                fragment: &finished,
                ..records[1]
            },
        )
        .unwrap();
    records[1].fragment = &ciphertext;
    let commit = crate::encode_datagram(&records).unwrap();
    assert!(
        server
            .receive(&commit, 13)
            .unwrap()
            .contains(&WireAction::Established(HandshakeKind::Resumed))
    );

    let first = send(&client.send_application(b"first".to_vec()).unwrap());
    let second = send(&client.send_application(b"second".to_vec()).unwrap());
    let suffix = [
        first.strip_prefix(explicit_commit.as_slice()).unwrap(),
        second.strip_prefix(explicit_commit.as_slice()).unwrap(),
    ]
    .concat();
    assert_eq!(
        server.receive(&[commit.as_slice(), &suffix].concat(), 14),
        Err(WireError::InvalidRecord)
    );
    assert_eq!(
        server.receive(&suffix, 14).unwrap(),
        [
            WireAction::Deliver(b"first".to_vec()),
            WireAction::Deliver(b"second".to_vec())
        ]
    );

    let fatal = alert_fields(FATAL, HANDSHAKE_FAILURE, client.last_received);
    let alert = protected_alert(&mut client, &fatal);
    assert_eq!(
        server.receive(&[commit.as_slice(), &alert].concat(), 14),
        Err(WireError::InvalidRecord)
    );
    assert_eq!(server.status(), Status::Open);
    assert!(server.find_session(Some(id), 14).unwrap().is_some());
    assert_eq!(
        server.receive(&alert, 15),
        Err(alert_error(&fatal, AlertProtection::Authenticated))
    );
    assert_eq!(server.status(), Status::Closed);
    assert!(server.find_session(Some(id), 15).unwrap().is_none());
}

#[test]
fn application_batch_failed_finished_closes_the_pending_epoch_and_preserves_the_cache() {
    let (clients, servers) = contexts();
    let id = full(
        &mut clients.peer(NOW).unwrap(),
        &mut servers.peer(NOW).unwrap(),
        0,
    );
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let commit = begin_resume(&mut client, &mut server, id, 10);

    let fragment = alert_fields(FATAL, HANDSHAKE_FAILURE, client.last_received);
    let alert = protected_alert(&mut client, &fragment);
    assert_eq!(server.receive(&alert, 13), Err(WireError::InvalidRecord));
    assert_eq!(
        server.receive(&[commit.as_slice(), &alert].concat(), 14),
        Err(alert_error(&fragment, AlertProtection::Authenticated))
    );
    assert_eq!(server.status(), Status::Negotiating);

    let records = crate::decode_datagram(&commit).unwrap();
    let (ccs, finished) = (records[0], records[1]);
    let mut bad_proof = client
        .traffic
        .as_ref()
        .unwrap()
        .open(Role::Client, finished)
        .unwrap();
    *bad_proof.last_mut().unwrap() ^= 1;
    let authenticated_bad_finished = seal(&client, RecordType::Handshake, 0, &bad_proof);
    let first = send(&client.send_application(b"first".to_vec()).unwrap());
    let second = send(&client.send_application(b"second".to_vec()).unwrap());
    let bad_commit = [
        &commit[..ccs.wire_len()],
        &authenticated_bad_finished,
        first.strip_prefix(commit.as_slice()).unwrap(),
        second.strip_prefix(commit.as_slice()).unwrap(),
    ]
    .concat();
    assert_eq!(
        server.receive(&bad_commit, 15),
        Err(WireError::AuthenticationFailed)
    );
    assert_eq!(server.status(), Status::Closed);
    assert!(server.verified_commit.is_none());
    assert_eq!(server.receive(&first, 16).unwrap(), []);

    let mut retry_server = servers.peer(NOW).unwrap();
    let retry = begin_resume(&mut clients.peer(NOW).unwrap(), &mut retry_server, id, 20);
    assert!(
        retry_server
            .receive(&retry, 23)
            .unwrap()
            .contains(&WireAction::Established(HandshakeKind::Resumed))
    );
}
