use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::OnceLock;

use openssl::pkey::Public;

use super::*;

const NOW: u32 = 1_730_000_000;
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

fn contexts() -> (ResumableClient, ResumableServer) {
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

fn send(actions: &[WireAction]) -> Vec<u8> {
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

fn full(client: &mut WirePeer, server: &mut WirePeer, at: u64) -> SessionId {
    let offer = send(&client.start(at).unwrap());
    establish_full(client, server, &offer, at)
}

fn begin_resume(client: &mut WirePeer, server: &mut WirePeer, id: SessionId, at: u64) -> Vec<u8> {
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

fn protected_alert(peer: &mut WirePeer, fragment: &[u8]) -> Vec<u8> {
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
fn fatal_alert_revokes_the_session_and_disengages_only_its_receiver() {
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
    let warning = protected_alert(&mut client, &warning);
    let alert = protected_alert(&mut client, &fragment);
    let after = send(&client.send_application(b"after alert".to_vec()).unwrap());
    let datagram = [
        before.as_slice(),
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
fn warning_and_unverified_alerts_preserve_the_association_and_critical_preserves_the_session() {
    let (clients, servers) = contexts();
    let id = full(
        &mut clients.peer(NOW).unwrap(),
        &mut servers.peer(NOW).unwrap(),
        0,
    );
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let offer = send(&client.start(10).unwrap());
    let clear_fragment = alert_fields(FATAL, HANDSHAKE_FAILURE, record_checksum(&offer));
    let clear = crate::encode_datagram(&[Record {
        content_type: RecordType::Alert,
        cipher_spec: CipherSpec::Null,
        sequence: 0,
        length_form: LengthForm::Explicit,
        fragment: &clear_fragment,
    }])
    .unwrap();
    assert_eq!(
        client.receive(&clear, 11),
        Err(alert_error(&clear_fragment, AlertProtection::Clear))
    );
    assert_eq!(client.status(), Status::Negotiating);
    let malformed = [clear.as_slice(), &TRUNCATED_ALERT].concat();
    assert_eq!(
        client.receive(&malformed, 11),
        Err(WireError::Decode(
            crate::decode_datagram(&malformed).unwrap_err()
        ))
    );

    let hello = send(&server.receive(&offer, 12).unwrap());
    let commit = send(&client.receive(&hello, 13).unwrap());
    assert!(
        server
            .receive(&commit, 14)
            .unwrap()
            .contains(&WireAction::Established(HandshakeKind::Resumed))
    );
    assert_delivers(&mut server, &mut client, 15);
    assert_eq!(client.status(), Status::Open);
    assert_eq!(client.receive(&clear, 16), Err(WireError::InvalidRecord));

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
fn warning_does_not_mask_a_prefixed_close_or_change_its_acknowledgment() {
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
        let warning = alert_fields(WARNING, NO_RENEGOTIATION, checksum);
        let warning = protected_alert(&mut client, &warning);
        let close = protected_alert(
            &mut client,
            &encode_alert(Alert::CloseNotify(scope), checksum),
        );
        let mut datagram = [commit.as_slice(), &warning, &close].concat();
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
fn an_omitted_length_in_a_cached_commit_still_consumes_the_sdu() {
    let (clients, servers) = contexts();
    let id = full(
        &mut clients.peer(NOW).unwrap(),
        &mut servers.peer(NOW).unwrap(),
        0,
    );
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let commit = begin_resume(&mut client, &mut server, id, 10);
    let mut records = crate::decode_datagram(&commit).unwrap();
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
fn an_uncommitted_receive_epoch_and_a_failed_resume_preserve_the_cache() {
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
    let bad_commit = [&commit[..ccs.wire_len()], &authenticated_bad_finished].concat();
    assert_eq!(
        server.receive(&bad_commit, 15),
        Err(WireError::AuthenticationFailed)
    );
    assert_eq!(server.status(), Status::Closed);

    let mut retry_server = servers.peer(NOW).unwrap();
    let retry = begin_resume(&mut clients.peer(NOW).unwrap(), &mut retry_server, id, 20);
    assert!(
        retry_server
            .receive(&retry, 23)
            .unwrap()
            .contains(&WireAction::Established(HandshakeKind::Resumed))
    );
}
