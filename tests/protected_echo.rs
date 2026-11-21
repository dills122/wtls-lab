use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::OnceLock;

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::{Padding, Rsa};
use openssl::sha::sha1;
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};
use wtls_lab::handshake::{CloseScope, HandshakeKind, Message, RetryPolicy, SessionId, Status};
use wtls_lab::wire::{
    PeerAuthentication, ResumableServer, ServerIdentity, TrustAnchor, WireAction, WireError,
    WirePeer, decode_client_hello, decode_handshake, decode_server_hello, encode_handshake,
    issue_certificate,
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
    let (ca, server_key) = keys();
    let leaf = issue_certificate(
        ISSUER,
        SUBJECT,
        (NOW - 1)..=(NOW + 1),
        ca,
        &public(server_key),
    )
    .unwrap();
    ServerIdentity::new(leaf, server_key.clone()).unwrap()
}

fn peers(expected_subject: &str) -> (WirePeer, WirePeer) {
    let (ca, _) = keys();
    let trust = TrustAnchor::new(ISSUER, expected_subject, public(ca)).unwrap();
    let retry = RetryPolicy {
        timeout_ms: NonZeroU64::new(10).unwrap(),
        max_retries: 2,
    };
    (
        WirePeer::client(retry, trust, NOW),
        WirePeer::server(identity(), NOW).unwrap(),
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
fn authenticated_server_selects_from_the_captured_blackberry_hello() {
    let (_, mut server) = peers(SUBJECT);
    let captured = include_str!("../fixtures/blackberry-7290-client-hello.hex")
        .lines()
        .flat_map(|line| line.split('#').next().unwrap().split_whitespace())
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect::<Vec<_>>();
    let records = decode_datagram(&captured).unwrap();
    let offer = decode_client_hello(records[0].fragment).unwrap();
    assert_eq!(offer.key_refresh, 5);
    assert!(!offer.trusted_keys.is_empty());

    let flight = send(&server.receive(&captured, 1).unwrap());
    let records = decode_datagram(&flight).unwrap();
    let selected = decode_server_hello(records[0].fragment).unwrap();
    assert_eq!(selected.key_exchange_index, 1);
    assert_eq!(selected.cipher_suite, [6, 3]);
    assert_eq!(selected.compression, 0);
    assert_eq!(selected.sequence_mode, 2);
    assert_eq!(selected.key_refresh, 3);
    assert_eq!(records.len(), 3);
    assert!(matches!(
        decode_handshake(records[1].fragment).unwrap(),
        Message::Certificate(_)
    ));
    assert_eq!(
        decode_handshake(records[2].fragment).unwrap(),
        Message::ServerHelloDone
    );
    assert_eq!(
        server.receive(&captured, 2).unwrap(),
        [WireAction::Send(flight)]
    );
}

fn handshake_fragment(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![kind];
    bytes.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

const NONCANONICAL_RANDOM: [u8; 16] = [0xa1; 16];
const OFFERED_SESSION: &[u8; 8] = b"old-id!!";
const NONCANONICAL_OFFER: &[u8] = &[
    0, 9, 8, 1, 0, 8, 0, 2, 2, 0xaa,
    0xbb, // RSA with index 1, then default RSA with a binary ID
    0, 6, 8, 0, 2, 2, 0xcc, 0xdd, // An unrelated server trust hint
    4, 5, 3, 6, 3, // DES/SHA, then 3DES/SHA
    2, 1, 0, // Another compression method, then null
    2, 1, // Explicit sequences, refresh every two records
];

fn offered_hello(session: &[u8], offer: &[u8]) -> Vec<u8> {
    let mut body = vec![1];
    body.extend_from_slice(&NONCANONICAL_RANDOM);
    body.push(u8::try_from(session.len()).unwrap());
    body.extend_from_slice(session);
    body.extend_from_slice(offer);
    handshake_fragment(1, &body)
}

fn clear_record(content_type: RecordType, sequence: u16, fragment: &[u8]) -> Record<'_> {
    Record {
        content_type,
        cipher_spec: CipherSpec::Null,
        sequence,
        length_form: LengthForm::Explicit,
        fragment,
    }
}

fn hmac_sha1(key: &[u8], bytes: &[u8]) -> Vec<u8> {
    let key = PKey::hmac(key).unwrap();
    let mut signer = Signer::new(MessageDigest::sha1(), &key).unwrap();
    signer.sign_oneshot_to_vec(bytes).unwrap()
}

// WAP-199 P_SHA-1 over the label and seed, with the seed already concatenated.
fn expected_prf(key: &[u8], label: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    let seed = [label, seed].concat();
    let mut a = seed.clone();
    let mut output = Vec::new();
    while output.len() < length {
        a = hmac_sha1(key, &a);
        output.extend(hmac_sha1(key, &[a.as_slice(), &seed].concat()));
    }
    output.truncate(length);
    output
}

fn expected_ciphertext(
    record: Record<'_>,
    master: &[u8],
    label: &[u8],
    client_random: &[u8; 16],
    server_random: &[u8; 16],
    epoch_start: u16,
) -> Vec<u8> {
    let sequence = record.sequence.to_be_bytes();
    let seed = [&epoch_start.to_be_bytes()[..], server_random, client_random].concat();
    let keys = expected_prf(master, label, &seed, 52);
    let plaintext = record.fragment;
    let mac_input = [
        &sequence[..],
        &[record.header_byte()],
        &(plaintext.len() as u16).to_be_bytes(),
        plaintext,
    ]
    .concat();
    let mut padded = [plaintext, &hmac_sha1(&keys[..20], &mac_input)].concat();
    let padding = 8 - padded.len() % 8;
    padded.resize(padded.len() + padding, (padding - 1) as u8);
    let iv = std::array::from_fn::<_, 8, _>(|i| keys[44 + i] ^ sequence[i % 2]);
    let mut cipher = Crypter::new(
        Cipher::des_ede3_cbc(),
        Mode::Encrypt,
        &keys[20..44],
        Some(&iv),
    )
    .unwrap();
    cipher.pad(false);
    let mut encrypted = vec![0; padded.len() + 8];
    let len = cipher.update(&padded, &mut encrypted).unwrap();
    let tail = cipher.finalize(&mut encrypted[len..]).unwrap();
    encrypted.truncate(len + tail);
    encrypted
}

#[test]
fn noncanonical_authenticated_exchange_uses_the_wire_transcript_and_selected_refresh() {
    let (_, mut server) = peers(SUBJECT);
    let client_hello = offered_hello(OFFERED_SESSION, NONCANONICAL_OFFER);
    let hello = encode_datagram(&[clear_record(RecordType::Handshake, 0, &client_hello)]).unwrap();
    let flight = send(&server.receive(&hello, 1).unwrap());
    assert_eq!(
        server.receive(&hello, 2).unwrap(),
        [WireAction::Send(flight.clone())]
    );
    let records = decode_datagram(&flight).unwrap();
    let [server_hello, certificate, done] = records.as_slice() else {
        panic!("expected a full authenticated server flight");
    };
    let selected = decode_server_hello(server_hello.fragment).unwrap();
    assert_eq!(selected.key_exchange_index, 2);
    assert_eq!(selected.key_refresh, 1);
    assert_eq!(selected.session_id.len(), 8);
    assert_ne!(selected.session_id, OFFERED_SESSION);

    let key = &keys().1;
    let secret = [1u8; 20];
    let mut encrypted = vec![0; key.size() as usize];
    let len = key
        .public_encrypt(&secret, &mut encrypted, Padding::PKCS1)
        .unwrap();
    encrypted.truncate(len);
    let master = fixture_master(&secret, &NONCANONICAL_RANDOM, &selected.random);
    let exchange = encode_handshake(&Message::ClientKeyExchange(encrypted)).unwrap();
    let mut transcript = [
        client_hello.as_slice(),
        server_hello.fragment,
        certificate.fragment,
        done.fragment,
        &exchange,
    ]
    .concat();
    let client_finished = handshake_fragment(
        20,
        &expected_prf(&master, b"client finished", &sha1(&transcript), 12),
    );
    let mut protected = Record {
        cipher_spec: CipherSpec::Current,
        ..clear_record(RecordType::Handshake, 0, &client_finished)
    };
    let ciphertext = expected_ciphertext(
        protected,
        &master,
        b"client expansion",
        &NONCANONICAL_RANDOM,
        &selected.random,
        0,
    );
    protected.fragment = &ciphertext;
    let commit = encode_datagram(&[
        clear_record(RecordType::Handshake, 1, &exchange),
        clear_record(RecordType::ChangeCipherSpec, 2, &[1]),
        protected,
    ])
    .unwrap();

    let actions = server.receive(&commit, 3).unwrap();
    assert!(actions.contains(&WireAction::Established(HandshakeKind::Full)));
    let final_flight = send(&actions);
    let records = decode_datagram(&final_flight).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].content_type, RecordType::ChangeCipherSpec);
    transcript.extend_from_slice(&client_finished);
    let server_finished = handshake_fragment(
        20,
        &expected_prf(&master, b"server finished", &sha1(&transcript), 12),
    );
    assert_eq!(
        records[1].fragment,
        expected_ciphertext(
            Record {
                fragment: &server_finished,
                ..records[1]
            },
            &master,
            b"server expansion",
            &NONCANONICAL_RANDOM,
            &selected.random,
            0,
        )
    );
    assert_eq!(
        server.receive(&commit, 4).unwrap(),
        [WireAction::Send(final_flight)]
    );
    let info = server.connection_info().unwrap();
    assert_eq!(info.parameters.key_refresh, 1);
    assert_eq!(info.peer_authentication, PeerAuthentication::None);

    let mut application = Record {
        cipher_spec: CipherSpec::Current,
        ..clear_record(RecordType::ApplicationData, 2, b"new epoch")
    };
    let ciphertext = expected_ciphertext(
        application,
        &master,
        b"client expansion",
        &NONCANONICAL_RANDOM,
        &selected.random,
        2,
    );
    application.fragment = &ciphertext;
    let datagram = encode_datagram(&[application]).unwrap();
    assert_eq!(
        server.receive(&datagram, 5).unwrap(),
        [WireAction::Deliver(b"new epoch".to_vec())]
    );
}

fn fixture_master(secret: &[u8], client_random: &[u8; 16], server_random: &[u8; 16]) -> Vec<u8> {
    let key = &keys().1;
    let mut premaster = secret.to_vec();
    for component in [key.e(), key.n()] {
        let bytes = component.to_vec();
        premaster.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        premaster.extend(bytes);
    }
    expected_prf(
        &premaster,
        b"master secret",
        &[client_random.as_slice(), server_random].concat(),
        20,
    )
}

#[test]
fn abbreviated_exchange_with_empty_vectors_matches_independent_wap_199_finished() {
    let servers =
        ResumableServer::new(identity(), NonZeroUsize::MIN, NonZeroU64::new(100).unwrap());
    let (mut client, _) = peers(SUBJECT);
    let mut server = servers.peer(NOW).unwrap();
    let offer = send(&client.start(0).unwrap());
    let offer_records = decode_datagram(&offer).unwrap();
    let full_offer = decode_client_hello(offer_records[0].fragment).unwrap();
    let reply = send(&server.receive(&offer, 1).unwrap());
    let reply_records = decode_datagram(&reply).unwrap();
    let full_selection = decode_server_hello(reply_records[0].fragment).unwrap();
    let commit = send(&client.receive(&reply, 2).unwrap());

    // Unwrap the full handshake's premaster with this fixture's private key.
    let commit_records = decode_datagram(&commit).unwrap();
    let Message::ClientKeyExchange(exchange) =
        decode_handshake(commit_records[0].fragment).unwrap()
    else {
        panic!("expected RSA key exchange")
    };
    let key = &keys().1;
    let mut secret = vec![0; key.size() as usize];
    let length = key
        .private_decrypt(&exchange, &mut secret, Padding::PKCS1)
        .unwrap();
    assert_eq!(length, 20);
    let master = fixture_master(
        &secret[..length],
        &full_offer.random,
        &full_selection.random,
    );
    let actions = server.receive(&commit, 3).unwrap();
    assert!(actions.contains(&WireAction::Established(HandshakeKind::Full)));
    client.receive(&send(&actions), 4).unwrap();
    let closing = send(&client.close(CloseScope::Connection).unwrap());
    assert!(
        server
            .receive(&closing, 5)
            .unwrap()
            .contains(&WireAction::Closed(CloseScope::Connection))
    );

    // The remote client changes the hello and offers no key exchange or trust IDs.
    // It also proposes key refresh at every record.
    let client_hello = offered_hello(
        full_selection.session_id,
        &[0, 0, 0, 0, 2, 6, 3, 1, 0, 2, 0],
    );
    let offer = encode_datagram(&[clear_record(RecordType::Handshake, 0, &client_hello)]).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let reply = send(&server.receive(&offer, 10).unwrap());
    let records = decode_datagram(&reply).unwrap();
    let [server_hello, ccs, ciphertext] = records.as_slice() else {
        panic!("expected ServerHello, CCS, Finished")
    };
    let selected = decode_server_hello(server_hello.fragment).unwrap();
    assert_eq!(selected.session_id, full_selection.session_id);
    assert_ne!(selected.random, full_selection.random);
    assert_ne!(NONCANONICAL_RANDOM, full_offer.random);
    assert_eq!(selected.key_exchange_index, 0);
    assert_eq!(selected.key_refresh, 0);
    assert_eq!(ccs.content_type, RecordType::ChangeCipherSpec);
    assert_eq!(
        (ciphertext.cipher_spec, ciphertext.sequence),
        (CipherSpec::Current, 0)
    );

    let mut transcript = [client_hello.as_slice(), server_hello.fragment].concat();
    let server_finished = handshake_fragment(
        20,
        &expected_prf(&master, b"server finished", &sha1(&transcript), 12),
    );
    assert_eq!(
        ciphertext.fragment,
        expected_ciphertext(
            Record {
                fragment: &server_finished,
                ..*ciphertext
            },
            &master,
            b"server expansion",
            &NONCANONICAL_RANDOM,
            &selected.random,
            0,
        ),
    );
    transcript.extend_from_slice(&server_finished);
    let client_finished = handshake_fragment(
        20,
        &expected_prf(&master, b"client finished", &sha1(&transcript), 12),
    );
    let mut finished = Record {
        cipher_spec: CipherSpec::Current,
        ..clear_record(RecordType::Handshake, 0, &client_finished)
    };
    let sealed = expected_ciphertext(
        finished,
        &master,
        b"client expansion",
        &NONCANONICAL_RANDOM,
        &selected.random,
        0,
    );
    finished.fragment = &sealed;
    let commit = encode_datagram(&[
        clear_record(RecordType::ChangeCipherSpec, 1, &[1]),
        finished,
    ])
    .unwrap();
    assert_eq!(
        server.receive(&commit, 11).unwrap(),
        [WireAction::Established(HandshakeKind::Resumed)]
    );

    let data = send(&server.send_application(b"reply".to_vec()).unwrap());
    let records = decode_datagram(&data).unwrap();
    assert_eq!(records[0].sequence, 1);
    assert_eq!(
        records[0].fragment,
        expected_ciphertext(
            Record {
                fragment: b"reply",
                ..records[0]
            },
            &master,
            b"server expansion",
            &NONCANONICAL_RANDOM,
            &selected.random,
            1,
        ),
    );
}

#[test]
fn authenticated_server_rejects_offers_without_a_required_choice() {
    let (_, mut server) = peers(SUBJECT);
    for (index, value) in [
        (6, 255), // Malformed explicit RSA parameters
        (6, 1),   // Neither RSA offer specifies default parameters
        (5, 5),   // No unrestricted RSA with default parameters
        (22, 5),  // No 3DES
        (23, 2),  // No full SHA with 3DES
        (26, 1),  // No null compression
        (27, 1),  // No explicit sequence numbering
    ] {
        let mut offer = NONCANONICAL_OFFER.to_vec();
        offer[index] = value;
        let fragment = offered_hello(OFFERED_SESSION, &offer);
        let hello = encode_datagram(&[clear_record(RecordType::Handshake, 0, &fragment)]).unwrap();
        let expected = if value == 255 {
            WireError::InvalidMessage
        } else {
            WireError::UnsupportedProfile
        };
        assert_eq!(
            server.receive(&hello, 1),
            Err(expected),
            "offer byte {index}"
        );
        assert_eq!(server.status(), Status::Idle);
    }
    let valid = offered_hello(b"old", NONCANONICAL_OFFER);
    let hello = encode_datagram(&[clear_record(RecordType::Handshake, 0, &valid)]).unwrap();
    let flight = send(&server.receive(&hello, 2).unwrap());
    let records = decode_datagram(&flight).unwrap();
    assert_eq!(
        decode_server_hello(records[0].fragment)
            .unwrap()
            .session_id
            .len(),
        8
    );
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
fn matching_clear_alert_fatal_ends_pending_client_negotiation() {
    use wtls_lab::wire::{AlertFields, AlertProtection};

    let (mut client, _) = peers(SUBJECT);
    let hello = send(&client.start(0).unwrap());
    let checksum = hello
        .chunks(4)
        .fold(0u32, |sum, chunk| {
            let mut word = [0; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            sum ^ u32::from_be_bytes(word)
        })
        .to_be_bytes();
    let fragment = [vec![3, 10], checksum.to_vec()].concat();
    let alert = wtls_lab::encode_datagram(&[wtls_lab::Record {
        content_type: RecordType::Alert,
        cipher_spec: CipherSpec::Null,
        sequence: 0,
        length_form: wtls_lab::LengthForm::Explicit,
        fragment: &fragment,
    }])
    .unwrap();
    assert_eq!(
        client.receive(&alert, 1),
        Err(WireError::PeerAlert {
            fields: AlertFields {
                level: 3,
                description: 10,
                checksum,
            },
            protection: AlertProtection::Clear,
        })
    );
    assert_eq!(client.status(), Status::Closed);
    assert_eq!(client.deadline(), None);
    assert!(client.tick(10).unwrap().is_empty());
}

#[test]
fn application_batch_delivers_distinct_records_in_both_directions() {
    let (mut client, mut server) = peers(SUBJECT);
    establish(&mut client, &mut server);

    for client_sends in [true, false] {
        let (sender, receiver) = if client_sends {
            (&mut client, &mut server)
        } else {
            (&mut server, &mut client)
        };
        let first = send(&sender.send_application(b"first".to_vec()).unwrap());
        let second = send(&sender.send_application(b"second".to_vec()).unwrap());
        assert_eq!(
            receiver.receive(&[first, second].concat(), 15).unwrap(),
            [
                WireAction::Deliver(b"first".to_vec()),
                WireAction::Deliver(b"second".to_vec()),
            ]
        );
    }
}
