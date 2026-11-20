use std::num::NonZeroU64;
use std::sync::OnceLock;

use openssl::pkey::{Private, Public};
use openssl::rsa::Rsa;
use wtls_lab::handshake::{CloseScope, HandshakeKind, Message, RetryPolicy, SessionId, Status};
use wtls_lab::wire::{
    ServerIdentity, TrustAnchor, WireAction, WireError, WirePeer, decode_handshake,
    encode_handshake, issue_certificate,
};
use wtls_lab::{CipherSpec, RecordType, decode_datagram};

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

fn peers(expected_subject: &str) -> (WirePeer, WirePeer) {
    let (ca, server_key) = keys();
    let leaf = issue_certificate(
        ISSUER,
        SUBJECT,
        (NOW - 1)..=(NOW + 1),
        ca,
        &public(server_key),
    )
    .unwrap();
    let identity = ServerIdentity::new(leaf, server_key.clone()).unwrap();
    let trust = TrustAnchor::new(ISSUER, expected_subject, public(ca)).unwrap();
    let retry = RetryPolicy {
        timeout_ms: NonZeroU64::new(10).unwrap(),
        max_retries: 2,
    };
    (
        WirePeer::client(retry, trust, NOW),
        WirePeer::server(identity, NOW).unwrap(),
    )
}

fn send(actions: &[WireAction]) -> Vec<u8> {
    let mut datagrams = actions.iter().filter_map(|action| match action {
        WireAction::Send(bytes) => Some(bytes.clone()),
        _ => None,
    });
    let datagram = datagrams.next().expect("expected one outbound datagram");
    assert!(datagrams.next().is_none());
    datagram
}

fn establish(client: &mut WirePeer, server: &mut WirePeer) {
    let hello = send(&client.start(0).unwrap());
    let reply = send(&server.receive(&hello, 1).unwrap());

    let client_commit = send(&client.receive(&reply, 2).unwrap());
    let records = decode_datagram(&client_commit).unwrap();
    assert_eq!(
        records
            .iter()
            .map(|record| (record.content_type, record.cipher_spec, record.sequence))
            .collect::<Vec<_>>(),
        [
            (RecordType::Handshake, CipherSpec::Null, 1),
            (RecordType::ChangeCipherSpec, CipherSpec::Null, 2),
            (RecordType::Handshake, CipherSpec::Current, 0),
        ]
    );
    let server_actions = server.receive(&client_commit, 3).unwrap();
    assert!(server_actions.contains(&WireAction::Established(HandshakeKind::Full)));
    let server_commit = send(&server_actions);
    let records = decode_datagram(&server_commit).unwrap();
    assert_eq!(records[0].sequence, 3);
    assert_eq!(records[1].sequence, 0);
    assert_eq!(records[1].cipher_spec, CipherSpec::Current);

    // Simulate loss of the server's final flight. The record bytes are reused.
    assert_eq!(client.tick(11).unwrap(), []);
    assert_eq!(
        client.tick(12).unwrap(),
        [WireAction::Send(client_commit.clone())]
    );
    assert_eq!(
        server.receive(&client_commit, 13).unwrap(),
        [WireAction::Send(server_commit.clone())]
    );
    assert_eq!(
        client.receive(&server_commit, 14).unwrap(),
        [WireAction::Established(HandshakeKind::Full)]
    );
}

#[test]
fn fixed_profile_client_hello_matches_the_spec_derived_bytes() {
    let expected = [
        1, 0, 32, // ClientHello type and body length
        1,  // WTLS version
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, // Empty session ID
        0, 3, 8, 0, 0, // RSA, default parameters, null identifier
        0, 0, // Empty trusted key ID vector
        2, 6, 3, // One 3DES-CBC-EDE / SHA suite
        1, 0, // Null compression
        2, 3, // Explicit datagram sequence numbers, key refresh every 8 records
    ];
    let hello = Message::ClientHello {
        random: std::array::from_fn(|i| i as u8),
        resume: None,
    };
    assert_eq!(encode_handshake(&hello).unwrap(), expected);
    assert_eq!(decode_handshake(&expected).unwrap(), hello);
}

#[test]
fn handshake_codec_preserves_the_session_id_and_finished_bytes() {
    for message in [
        Message::ServerHello {
            random: [1; 16],
            session: SessionId(*b"echo-lab"),
        },
        Message::Finished([0xd2; 12]),
        Message::ServerHelloDone,
    ] {
        let encoded = encode_handshake(&message).unwrap();
        assert_eq!(decode_handshake(&encoded).unwrap(), message);
        assert!(decode_handshake(&encoded[..encoded.len() - 1]).is_err());
    }
}

#[test]
fn protected_echo_survives_key_refresh_and_closes_cleanly() {
    let (mut client, mut server) = peers(SUBJECT);
    establish(&mut client, &mut server);
    let message = b"WTLS authenticated echo".to_vec();

    for sequence in 1..=9 {
        let outgoing = send(&client.send_application(message.clone()).unwrap());
        let records = decode_datagram(&outgoing).unwrap();
        assert_eq!(records[0].sequence, sequence);
        assert_eq!(records[0].cipher_spec, CipherSpec::Current);
        assert!(
            !records[0]
                .fragment
                .windows(message.len())
                .any(|bytes| bytes == message)
        );

        assert_eq!(
            server.receive(&outgoing, 20).unwrap(),
            [WireAction::Deliver(message.clone())]
        );
        assert!(server.receive(&outgoing, 20).unwrap().is_empty());
        let reply = send(&server.send_application(message.clone()).unwrap());
        assert_eq!(
            client.receive(&reply, 21).unwrap(),
            [WireAction::Deliver(message.clone())]
        );
    }

    let notify = send(&client.close(CloseScope::Session).unwrap());
    let actions = server.receive(&notify, 22).unwrap();
    assert!(actions.contains(&WireAction::Closed(CloseScope::Session)));
    assert!(client.receive(&send(&actions), 23).unwrap().is_empty());
    assert_eq!(client.status(), Status::Closed);
    assert_eq!(server.status(), Status::Closed);
}

#[test]
fn mismatched_certificate_identity_cannot_open_the_wire_handshake() {
    let (mut client, mut server) = peers("Echo; WTLS Lab; CA; other.lab.invalid");
    let hello = send(&client.start(0).unwrap());
    let reply = send(&server.receive(&hello, 1).unwrap());

    assert_eq!(
        client.receive(&reply, 2).unwrap_err(),
        WireError::CertificateRejected
    );
    assert_eq!(client.status(), Status::Closed);
    assert!(client.send_application(b"must not leave".to_vec()).is_err());
}

#[test]
fn unprotected_application_data_is_rejected_after_the_handshake() {
    use wtls_lab::{LengthForm, Record, encode_datagram};

    let (mut client, mut server) = peers(SUBJECT);
    establish(&mut client, &mut server);
    let clear_datagram = encode_datagram(&[Record {
        content_type: RecordType::ApplicationData,
        cipher_spec: CipherSpec::Null,
        sequence: 1,
        length_form: LengthForm::Explicit,
        fragment: b"clear",
    }])
    .unwrap();
    assert_eq!(
        server.receive(&clear_datagram, 20).unwrap_err(),
        WireError::InvalidRecord
    );
    let outgoing = send(&client.send_application(b"encrypted".to_vec()).unwrap());
    assert_eq!(
        server.receive(&outgoing, 21).unwrap(),
        [WireAction::Deliver(b"encrypted".to_vec())]
    );
}

#[test]
fn ciphertext_integrity_failure_releases_no_application_data() {
    let (mut client, mut server) = peers(SUBJECT);
    establish(&mut client, &mut server);
    let message = b"integrity check".to_vec();
    let valid = send(&client.send_application(message.clone()).unwrap());

    let mut damaged = valid.clone();
    *damaged.last_mut().unwrap() ^= 1;
    assert_eq!(
        server.receive(&damaged, 20).unwrap_err(),
        WireError::AuthenticationFailed
    );
    assert_eq!(
        server.receive(&valid, 21).unwrap(),
        [WireAction::Deliver(message)]
    );
}

#[test]
fn connection_reports_the_negotiated_profile_and_each_peers_authentication() {
    use wtls_lab::wire::PeerAuthentication;

    let (mut client, mut server) = peers(SUBJECT);
    assert!(client.connection_info().is_none());
    assert!(server.connection_info().is_none());
    establish(&mut client, &mut server);
    let client_info = client.connection_info().unwrap();
    let server_info = server.connection_info().unwrap();
    assert_eq!(client_info.parameters, server_info.parameters);
    assert_eq!(client_info.parameters.key_exchange, 8);
    assert_eq!(client_info.parameters.bulk_cipher, 6);
    assert_eq!(client_info.parameters.mac, 3);
    assert_eq!(client_info.parameters.sequence_mode, 2);
    assert_eq!(client_info.parameters.key_refresh, 3);
    assert_eq!(
        client_info.peer_authentication,
        PeerAuthentication::VerifiedServerCertificate
    );
    assert_eq!(server_info.peer_authentication, PeerAuthentication::None);
}

#[test]
fn datagram_budget_checks_the_encoded_flight_length() {
    use wtls_lab::wire::{DatagramBudget, DatagramTooLarge};

    let (mut client, mut server) = peers(SUBJECT);
    let hello = send(&client.start(0).unwrap());
    let flight = send(&server.receive(&hello, 1).unwrap());
    let size = flight.len();
    assert_eq!(DatagramBudget::new(size).check(&flight), Ok(()));
    assert_eq!(
        DatagramBudget::new(size - 1).check(&flight),
        Err(DatagramTooLarge {
            size,
            limit: size - 1
        })
    );
}

#[test]
fn a_clear_peer_alert_is_reported_without_trusting_or_closing_the_association() {
    use wtls_lab::wire::{AlertFields, AlertProtection};

    let (mut client, _) = peers(SUBJECT);
    client.start(0).unwrap();
    let alert = wtls_lab::encode_datagram(&[wtls_lab::Record {
        content_type: RecordType::Alert,
        cipher_spec: CipherSpec::Null,
        sequence: 0,
        length_form: wtls_lab::LengthForm::Explicit,
        fragment: &[3, 10, 0, 0, 0, 0],
    }])
    .unwrap();
    assert_eq!(
        client.receive(&alert, 1),
        Err(WireError::PeerAlert {
            fields: AlertFields {
                level: 3,
                description: 10,
                checksum: [0; 4]
            },
            protection: AlertProtection::Clear,
        })
    );
    assert_eq!(client.status(), Status::Negotiating);
    assert_eq!(client.deadline(), Some(10));
}
