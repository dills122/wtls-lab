use super::alert_tests::{NOW, begin_resume, contexts, full, send};
use super::*;

fn application(peer: &mut WirePeer, payload: &[u8]) -> Vec<u8> {
    send(&peer.send_application(payload.to_vec()).unwrap())
}

fn delivery(payload: &[u8]) -> WireAction {
    WireAction::Deliver(payload.to_vec())
}

fn record(bytes: &[u8]) -> Record<'_> {
    let record = crate::decode_record(bytes).unwrap();
    assert_eq!(record.wire_len(), bytes.len());
    record
}

fn omit_length(sender: &WirePeer, explicit: &[u8]) -> Vec<u8> {
    let keys = sender.traffic.as_ref().unwrap();
    let role = sender.local_role();
    let mut record = record(explicit);
    let plaintext = keys.open(role, record).unwrap();
    record.length_form = LengthForm::DatagramRemainder;
    record.fragment = &plaintext;
    let ciphertext = keys.seal(role, record).unwrap();
    record.fragment = &ciphertext;
    crate::encode_datagram(&[record]).unwrap()
}

fn invalid_integrity(bytes: &[u8]) -> Vec<u8> {
    let mut record = record(bytes);
    // Keep the explicit framing valid and make the protected fragment one byte
    // short of a complete block.
    record.fragment = &record.fragment[..record.fragment.len() - 1];
    crate::encode_datagram(&[record]).unwrap()
}

fn open_alert(sender: &WirePeer, bytes: &[u8]) -> AlertFields {
    let record = record(bytes);
    assert_eq!(record.content_type, RecordType::Alert);
    let plaintext = sender
        .traffic
        .as_ref()
        .unwrap()
        .open(sender.remote_role(), record)
        .unwrap();
    decode_alert_fields(&plaintext).unwrap()
}

#[test]
fn application_batch_accepts_a_protected_final_omitted_length_in_both_directions() {
    for role in [Role::Client, Role::Server] {
        let (clients, servers) = contexts();
        let mut client = clients.peer(NOW).unwrap();
        let mut server = servers.peer(NOW).unwrap();
        full(&mut client, &mut server, 0);
        let (sender, receiver) = match role {
            Role::Client => (&mut client, &mut server),
            Role::Server => (&mut server, &mut client),
        };
        let first = application(sender, b"explicit");
        let last = application(sender, b"omitted");
        let last = omit_length(sender, &last);
        let batch = [first.as_slice(), &last].concat();
        let records = crate::decode_datagram(&batch).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].length_form, LengthForm::Explicit);
        assert_eq!(records[1].length_form, LengthForm::DatagramRemainder);
        assert_eq!(
            receiver.receive(&batch, 5).unwrap(),
            [delivery(b"explicit"), delivery(b"omitted")]
        );

        let close = send(&receiver.close(CloseScope::Connection).unwrap());
        let alert = open_alert(sender, &close);
        assert_eq!(alert.checksum, record_checksum(&last));
    }
}

#[test]
fn application_batch_close_checksum_uses_the_highest_admitted_record() {
    let (clients, servers) = contexts();
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    full(&mut client, &mut server, 0);

    let older = application(&mut client, b"older");
    let newer = application(&mut client, b"newer");
    // This duplicate has a different authenticated header and framed checksum.
    let duplicate = omit_length(&client, &newer);
    assert_eq!(record(&newer).sequence, record(&duplicate).sequence);
    let reference = record_checksum(&newer);
    assert_ne!(reference, record_checksum(&duplicate));
    let batch = [newer.as_slice(), &older, &duplicate].concat();
    assert_eq!(
        server.receive(&batch, 5).unwrap(),
        [delivery(b"newer"), delivery(b"older")]
    );
    assert_eq!(server.last_received, reference);
    assert_eq!(
        server
            .receive(&[older.as_slice(), &duplicate].concat(), 6)
            .unwrap(),
        []
    );

    let candidate = application(&mut client, b"would replace the reference");
    let malformed = [candidate.as_slice(), &[0xe3]].concat();
    assert_eq!(
        server.receive(&malformed, 7),
        Err(WireError::Decode(
            crate::decode_datagram(&malformed).unwrap_err()
        ))
    );
    let close = send(&server.close(CloseScope::Connection).unwrap());
    assert_eq!(open_alert(&client, &close).checksum, reference);
    assert!(matches!(
        client.receive(&close, 8).unwrap().as_slice(),
        [
            WireAction::Send(_),
            WireAction::Closed(CloseScope::Connection)
        ]
    ));
}

#[test]
fn application_batch_rejects_late_framing_integrity_and_message_type_before_admission() {
    let (clients, servers) = contexts();
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    full(&mut client, &mut server, 0);

    let first = application(&mut client, b"first");
    let last = application(&mut client, b"last");
    let reference = server.last_received;
    let truncated = [first.as_slice(), &last[..last.len() - 1]].concat();
    assert_eq!(
        server.receive(&truncated, 5),
        Err(WireError::Decode(
            crate::decode_datagram(&truncated).unwrap_err()
        ))
    );
    let invalid = [first.as_slice(), &invalid_integrity(&last)].concat();
    assert_eq!(
        server.receive(&invalid, 6),
        Err(WireError::AuthenticationFailed)
    );
    let fragment = encode_alert(Alert::DuplicateFinishedReceived, client.last_received);
    let warning = super::alert_tests::protected_alert(&mut client, &fragment);
    let wrong_type = [first.as_slice(), &last, &warning].concat();
    assert_eq!(
        server.receive(&wrong_type, 7),
        Err(WireError::Handshake(HandshakeError::UnexpectedDatagram))
    );
    assert_eq!(server.status(), Status::Open);
    assert_eq!(server.last_received, reference);

    let valid = [first, last].concat();
    assert_eq!(
        server.receive(&valid, 8).unwrap(),
        [delivery(b"first"), delivery(b"last")]
    );
    assert_eq!(server.receive(&valid, 9).unwrap(), []);
}

#[test]
fn application_batch_abbreviated_commit_and_exact_prefix_retry() {
    let (clients, servers) = contexts();
    let id = full(
        &mut clients.peer(NOW).unwrap(),
        &mut servers.peer(NOW).unwrap(),
        0,
    );
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let commit = begin_resume(&mut client, &mut server, id, 10);
    let finished_offset = crate::decode_record(&commit).unwrap().wire_len();
    let finished_checksum = record_checksum(&commit[finished_offset..]);
    let first = application(&mut client, b"first");
    let second = application(&mut client, b"second");
    let second = second.strip_prefix(commit.as_slice()).unwrap();

    let invalid = [first.as_slice(), &invalid_integrity(second)].concat();
    assert_eq!(
        server.receive(&invalid, 13),
        Err(WireError::AuthenticationFailed)
    );
    assert_eq!(server.status(), Status::Negotiating);
    assert!(!server.read.protected);
    assert!(server.verified_commit.is_none());
    assert!(server.find_session(Some(id), 13).unwrap().is_some());

    let batch = [first.as_slice(), second].concat();
    assert_eq!(
        server.receive(&batch, 14).unwrap(),
        [
            WireAction::Established(HandshakeKind::Resumed),
            delivery(b"first"),
            delivery(b"second")
        ]
    );
    assert_eq!(server.last_received, record_checksum(second));

    let third = application(&mut client, b"third");
    let fourth = application(&mut client, b"fourth");
    let third = third.strip_prefix(commit.as_slice()).unwrap();
    let fourth = fourth.strip_prefix(commit.as_slice()).unwrap();
    let invalid = [first.as_slice(), third, &invalid_integrity(fourth)].concat();
    assert_eq!(
        server.receive(&invalid, 15),
        Err(WireError::AuthenticationFailed)
    );
    assert_eq!(server.status(), Status::Open);
    assert_eq!(server.last_received, record_checksum(second));

    let retry = [first.as_slice(), fourth, third, second].concat();
    let actions = server.receive(&retry, 16).unwrap();
    let [WireAction::Send(warning), fourth_delivery, third_delivery] = actions.as_slice() else {
        panic!("expected a warning and two fresh deliveries: {actions:?}");
    };
    assert_eq!(*fourth_delivery, delivery(b"fourth"));
    assert_eq!(*third_delivery, delivery(b"third"));
    assert_eq!(record(warning).sequence, 1);
    assert_eq!(
        open_alert(&client, warning),
        decode_alert_fields(&encode_alert(
            Alert::DuplicateFinishedReceived,
            finished_checksum
        ))
        .unwrap()
    );
    assert_eq!(client.receive(warning, 17).unwrap(), []);
    assert_eq!(client.status(), Status::Open);
    assert_eq!(server.last_received, record_checksum(fourth));

    let actions = server.receive(&retry, 18).unwrap();
    assert!(matches!(actions.as_slice(), [WireAction::Send(_)]));
    assert_eq!(server.last_received, record_checksum(fourth));
}
