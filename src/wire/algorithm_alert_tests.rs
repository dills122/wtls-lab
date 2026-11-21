use super::sequence_tests::{NOW, contexts};
use super::*;

fn opening(fragment: &[u8]) -> Vec<u8> {
    crate::encode_datagram(&[Record {
        content_type: RecordType::Handshake,
        cipher_spec: CipherSpec::Null,
        sequence: 0,
        length_form: LengthForm::Explicit,
        fragment,
    }])
    .unwrap()
}

#[test]
fn algorithm_alert_leaves_the_idle_candidate_uncommitted() {
    let (_, servers) = contexts();
    let mut server = servers.peer(NOW).unwrap();
    let candidate_id = *server.handshake.idle_server_session().unwrap();
    let mut fragment = encode_handshake(&Message::ClientHello {
        random: [1; 16],
        resume: Some(candidate_id),
    })
    .unwrap();
    let bulk_cipher = fragment.len() - 6;
    fragment[bulk_cipher] = 5;
    let actions = server.receive_with_reply(&opening(&fragment), 1).unwrap();
    assert!(matches!(actions.as_slice(), [WireAction::Send(_)]));
    assert_eq!(server.status(), Status::Idle);
    assert_eq!(
        *server.handshake.idle_server_session().unwrap(),
        candidate_id
    );
    assert_eq!(server.read.sequence, 0);
    assert_eq!(server.write.sequence, 0);
    assert!(!server.read.protected && !server.write.protected);
    assert!(server.selection.is_none() && server.traffic.is_none());
    assert!(server.session.is_none() && server.peer_random.is_none());
    assert!(server.received_flights.is_empty() && server.sent_flights.is_empty());
    assert!(server.sent_checksums.is_empty());
    assert!(server.find_session(None, 1).unwrap().is_none());
}

#[test]
fn algorithm_alert_checks_admission_before_cache_access() {
    let (_, servers) = contexts();
    let mut server = servers.peer(NOW).unwrap();
    let cache = server.cache.as_ref().unwrap();
    let _ = std::panic::catch_unwind(|| {
        let _guard = cache.lock().unwrap();
        panic!("poison the test cache");
    });
    let mut fragment = encode_handshake(&Message::ClientHello {
        random: [1; 16],
        resume: Some(SessionId(*b"old-id!!")),
    })
    .unwrap();
    fragment[3] = 2;
    let error = server
        .receive_with_reply(&opening(&fragment), 1)
        .unwrap_err();
    assert_eq!(error.diagnostic, WireError::UnsupportedProfile);
    assert_eq!(error.reply, None);

    fragment[3] = 1;
    let error = server
        .receive_with_reply(&opening(&fragment), 2)
        .unwrap_err();
    assert_eq!(error.diagnostic, WireError::Provider);
    assert_eq!(error.reply, None);
    assert_eq!(server.status(), Status::Idle);
}
