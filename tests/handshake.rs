use std::num::NonZeroU64;
use wtls_lab::handshake::{
    Action, Alert, CloseScope, Datagram, FinishedData, FinishedProvider, Handshake, HandshakeError,
    HandshakeKind, Message, RetryPolicy, Role, SessionId, Status,
};

const FIRST: SessionId = SessionId(*b"first-id");
const SECOND: SessionId = SessionId(*b"other-id");
const CLIENT_RANDOM: [u8; 16] = [1; 16];
const SERVER_RANDOM: [u8; 16] = [2; 16];

struct FixtureFinished;

impl FinishedProvider for FixtureFinished {
    fn create(&self, sender: Role, transcript: &[Message]) -> Option<FinishedData> {
        // An in-memory fixture token, with different values for each sender and transcript.
        let input = format!("{sender:?} {transcript:?}");
        let mut token = [0u8; 12];
        for (index, byte) in input.bytes().enumerate() {
            token[index % 12] = token[index % 12].wrapping_mul(31).wrapping_add(byte);
        }
        Some(token)
    }

    fn verify(&self, sender: Role, transcript: &[Message], value: &FinishedData) -> bool {
        self.create(sender, transcript) == Some(*value)
    }
}

fn client(cached: Option<SessionId>) -> Handshake {
    let retry = RetryPolicy {
        timeout_ms: NonZeroU64::new(10).unwrap(),
        max_retries: 2,
    };
    Handshake::client(retry, vec![0x21], cached)
}

fn server(fresh_id: SessionId, cached: Option<SessionId>) -> Handshake {
    Handshake::server(fresh_id, SERVER_RANDOM, vec![0x42], cached)
}

fn sent(actions: &[Action]) -> Datagram {
    let sends: Vec<_> = actions
        .iter()
        .filter_map(|action| match action {
            Action::Send(datagram) => Some(datagram),
            _ => None,
        })
        .collect();
    assert_eq!(sends.len(), 1, "{actions:?}");
    sends[0].clone()
}

fn deliver(peer: &mut Handshake, datagram: &[Message], now_ms: u64) -> Vec<Action> {
    peer.receive(datagram, now_ms, &FixtureFinished).unwrap()
}

fn full_exchange() -> (Handshake, Handshake) {
    let mut client = client(None);
    let mut server = server(FIRST, None);
    let hello = sent(&client.start(CLIENT_RANDOM, 0).unwrap());
    let server_hello = sent(&deliver(&mut server, &hello, 1));
    let client_commit = sent(&deliver(&mut client, &server_hello, 2));
    let server_commit = sent(&deliver(&mut server, &client_commit, 3));
    deliver(&mut client, &server_commit, 4);
    (client, server)
}

#[test]
fn full_handshake_commits_client_write_first_and_opens_both_roles() {
    let mut client = client(None);
    let mut server = server(FIRST, None);
    let hello = sent(&client.start(CLIENT_RANDOM, 0).unwrap());
    assert!(matches!(
        &hello[..],
        [Message::ClientHello { resume: None, .. }]
    ));

    let server_hello = sent(&deliver(&mut server, &hello, 1));
    assert!(matches!(
        &server_hello[..],
        [
            Message::ServerHello { session: FIRST, .. },
            Message::Certificate(_),
            Message::ServerHelloDone
        ]
    ));
    let client_commit = sent(&deliver(&mut client, &server_hello, 2));
    assert!(matches!(
        &client_commit[..],
        [
            Message::ClientKeyExchange(_),
            Message::ChangeCipherSpec,
            Message::Finished(_)
        ]
    ));
    assert_eq!(client.status(), Status::Negotiating);

    let server_actions = deliver(&mut server, &client_commit, 3);
    let server_commit = sent(&server_actions);
    assert!(matches!(
        &server_commit[..],
        [Message::ChangeCipherSpec, Message::Finished(_)]
    ));
    assert_eq!(
        server_actions,
        [
            Action::Send(server_commit.clone()),
            Action::Established {
                kind: HandshakeKind::Full,
                session: FIRST
            }
        ]
    );
    assert_eq!(
        deliver(&mut client, &server_commit, 4),
        [Action::Established {
            kind: HandshakeKind::Full,
            session: FIRST
        }]
    );
    assert_eq!(client.status(), Status::Open);
    assert_eq!(server.status(), Status::Open);
}

#[test]
fn resumed_handshake_uses_the_saved_session_and_commits_server_write_first() {
    let (old_client, old_server) = full_exchange();
    let mut client = client(old_client.cached_session());
    let mut server = server(SECOND, old_server.cached_session());

    let hello = sent(&client.start([3; 16], 0).unwrap());
    assert!(matches!(
        &hello[..],
        [Message::ClientHello {
            resume: Some(FIRST),
            ..
        }]
    ));
    let server_flight = sent(&deliver(&mut server, &hello, 1));
    assert!(matches!(
        &server_flight[..],
        [
            Message::ServerHello { session: FIRST, .. },
            Message::ChangeCipherSpec,
            Message::Finished(_)
        ]
    ));
    let client_flight = sent(&deliver(&mut client, &server_flight, 2));
    assert!(matches!(
        &client_flight[..],
        [Message::ChangeCipherSpec, Message::Finished(_)]
    ));
    assert_eq!(client.status(), Status::AwaitingConfirmation);
    assert_eq!(
        deliver(&mut server, &client_flight, 3),
        [Action::Established {
            kind: HandshakeKind::Resumed,
            session: FIRST
        }]
    );
    let application = sent(&server.send_application(b"ready".to_vec()).unwrap());
    assert_eq!(
        deliver(&mut client, &application, 4),
        [Action::Deliver(b"ready".to_vec())]
    );
    assert_eq!(client.status(), Status::Open);
    assert_eq!(client.cached_session(), Some(FIRST));
}

#[test]
fn lost_full_flights_are_recovered_with_identical_retransmissions() {
    let mut client = client(None);
    let mut server = server(FIRST, None);

    let hello = sent(&client.start(CLIENT_RANDOM, 0).unwrap());
    let server_hello = sent(&deliver(&mut server, &hello, 1));
    // Drop the first server flight. A client timer resends the same ClientHello.
    assert!(client.tick(9).is_empty());
    assert_eq!(sent(&client.tick(10)), hello);
    let recovered_server_hello = sent(&deliver(&mut server, &hello, 11));
    assert_eq!(recovered_server_hello, server_hello);

    let client_commit = sent(&deliver(&mut client, &recovered_server_hello, 12));
    let server_commit = sent(&deliver(&mut server, &client_commit, 13));
    // Drop the server commit. The server already committed locally.
    assert_eq!(server.status(), Status::Open);
    assert!(client.tick(21).is_empty());
    assert_eq!(sent(&client.tick(22)), client_commit);
    assert_eq!(
        deliver(&mut server, &client_commit, 23),
        [Action::Send(server_commit.clone())]
    );
    deliver(&mut client, &server_commit, 24);
    assert!(deliver(&mut client, &server_commit, 25).is_empty());
    assert!(client.tick(100).is_empty());
    assert_eq!(client.status(), Status::Open);
}

#[test]
fn lost_resumed_client_commit_is_prepended_and_duplicate_data_is_delivered_once() {
    let mut client = client(Some(FIRST));
    let mut server = server(SECOND, Some(FIRST));
    let hello = sent(&client.start(CLIENT_RANDOM, 0).unwrap());
    let reply = sent(&deliver(&mut server, &hello, 1));
    let client_commit = sent(&deliver(&mut client, &reply, 2));
    // Drop the initial CCS/Finished flight. The next application datagram carries it.
    let app = sent(&client.send_application(b"message".to_vec()).unwrap());
    assert_eq!(&app[..2], client_commit);
    assert_eq!(
        deliver(&mut server, &app, 3),
        [
            Action::Established {
                kind: HandshakeKind::Resumed,
                session: FIRST
            },
            Action::Deliver(b"message".to_vec())
        ]
    );
    let second = sent(&client.send_application(b"another".to_vec()).unwrap());
    assert_eq!(&second[..2], client_commit);
    let confirmation = vec![Message::Alert(Alert::DuplicateFinishedReceived)];
    assert_eq!(
        deliver(&mut server, &second, 4),
        [
            Action::Send(confirmation.clone()),
            Action::Deliver(b"another".to_vec())
        ]
    );
    assert_eq!(
        deliver(&mut server, &app, 5),
        [Action::Send(confirmation.clone())]
    );
    assert!(deliver(&mut client, &confirmation, 6).is_empty());
    assert_eq!(client.status(), Status::Open);
    let app = sent(&client.send_application(b"confirmed".to_vec()).unwrap());
    assert!(matches!(&app[..], [Message::ApplicationData { .. }]));
}

#[test]
fn a_missing_server_cache_entry_takes_the_full_handshake_path() {
    let mut client = client(Some(FIRST));
    let mut server = server(SECOND, None);
    let hello = sent(&client.start(CLIENT_RANDOM, 0).unwrap());
    let reply = sent(&deliver(&mut server, &hello, 1));
    assert!(matches!(
        &reply[..],
        [
            Message::ServerHello {
                session: SECOND,
                ..
            },
            Message::Certificate(_),
            Message::ServerHelloDone
        ]
    ));
    let commit = sent(&deliver(&mut client, &reply, 2));
    let done = sent(&deliver(&mut server, &commit, 3));
    assert_eq!(
        deliver(&mut client, &done, 4),
        [Action::Established {
            kind: HandshakeKind::Full,
            session: SECOND
        }]
    );
}

#[test]
fn lost_client_hello_retries_stop_at_the_configured_limit() {
    let mut client = client(None);
    let hello = sent(&client.start(CLIENT_RANDOM, 0).unwrap());
    assert_eq!(client.deadline(), Some(10));
    assert_eq!(sent(&client.tick(10)), hello);
    assert_eq!(sent(&client.tick(20)), hello);
    assert_eq!(client.tick(30), [Action::TimedOut]);
    assert_eq!(client.status(), Status::Closed);
    assert_eq!(client.deadline(), None);
    assert!(client.tick(40).is_empty());
}

#[test]
fn connection_close_replies_once_and_preserves_the_session() {
    let (mut client, mut server) = full_exchange();
    let close = client.close(CloseScope::Connection).unwrap();
    let notify = vec![Message::Alert(Alert::CloseNotify(CloseScope::Connection))];
    assert_eq!(
        close,
        [
            Action::Send(notify.clone()),
            Action::Closed(CloseScope::Connection)
        ]
    );
    assert_eq!(
        deliver(&mut server, &notify, 5),
        [
            Action::Send(notify.clone()),
            Action::Closed(CloseScope::Connection)
        ]
    );
    assert!(deliver(&mut client, &notify, 6).is_empty());
    assert!(deliver(&mut server, &notify, 7).is_empty());
    assert_eq!(client.cached_session(), Some(FIRST));
    assert_eq!(server.cached_session(), Some(FIRST));
    assert_eq!(client.status(), Status::Closed);
    assert_eq!(server.status(), Status::Closed);
}

#[test]
fn server_session_close_invalidates_both_caches_and_ignores_late_data() {
    let (mut client, mut server) = full_exchange();
    let pending = sent(&server.send_application(vec![3]).unwrap());
    let notify = sent(&server.close(CloseScope::Session).unwrap());
    let reply = sent(&deliver(&mut client, &notify, 5));

    assert!(deliver(&mut server, &reply, 6).is_empty());
    assert!(deliver(&mut client, &pending, 7).is_empty());
    assert_eq!(client.cached_session(), None);
    assert_eq!(server.cached_session(), None);
    assert_eq!(
        client.send_application(vec![3]),
        Err(HandshakeError::InvalidState)
    );
}

#[test]
fn missing_ccs_or_failed_finished_verification_prevents_opening() {
    let mut client = client(None);
    let mut server = server(FIRST, None);
    let hello = sent(&client.start(CLIENT_RANDOM, 0).unwrap());
    let reply = sent(&deliver(&mut server, &hello, 1));
    let commit = sent(&deliver(&mut client, &reply, 2));

    let missing_ccs = [commit[0].clone(), commit[2].clone()];
    assert_eq!(
        server.receive(&missing_ccs, 3, &FixtureFinished),
        Err(HandshakeError::UnexpectedDatagram)
    );
    assert_eq!(server.status(), Status::Negotiating);

    let mut changed_proof = commit;
    let Message::Finished(proof) = &mut changed_proof[2] else {
        panic!("missing Finished")
    };
    proof[0] ^= 1;
    assert_eq!(
        server.receive(&changed_proof, 3, &FixtureFinished),
        Err(HandshakeError::FinishedVerificationFailed)
    );
    assert_eq!(server.status(), Status::Closed);
    assert_eq!(server.cached_session(), None);
}

#[test]
fn resumed_confirmation_requires_accepted_application_data() {
    let mut client = client(Some(FIRST));
    let mut server = server(SECOND, Some(FIRST));
    let hello = sent(&client.start(CLIENT_RANDOM, 0).unwrap());
    let reply = sent(&deliver(&mut server, &hello, 1));
    let commit = sent(&deliver(&mut client, &reply, 2));
    deliver(&mut server, &commit, 3);

    let reserved_sequence = [Message::ApplicationData {
        sequence: 0,
        payload: b"unexpected application sequence".to_vec(),
    }];
    assert!(deliver(&mut client, &reserved_sequence, 4).is_empty());
    assert_eq!(client.status(), Status::AwaitingConfirmation);
}

#[test]
fn delayed_datagrams_within_the_receive_window_are_delivered_once() {
    let (mut client, mut server) = full_exchange();
    let first = sent(&client.send_application(b"first".to_vec()).unwrap());
    let second = sent(&client.send_application(b"second".to_vec()).unwrap());

    assert_eq!(
        deliver(&mut server, &second, 5),
        [Action::Deliver(b"second".to_vec())]
    );
    assert_eq!(
        deliver(&mut server, &first, 6),
        [Action::Deliver(b"first".to_vec())]
    );
    assert!(deliver(&mut server, &first, 7).is_empty());

    for now in 8..40 {
        let data = sent(&client.send_application(vec![0]).unwrap());
        assert_eq!(deliver(&mut server, &data, now), [Action::Deliver(vec![0])]);
    }
    assert!(deliver(&mut server, &second, 40).is_empty());
}
