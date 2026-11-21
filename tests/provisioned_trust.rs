use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::{NonZeroU64, NonZeroUsize};
use std::ops::RangeInclusive;
use std::sync::OnceLock;

use openssl::bn::BigNum;
use openssl::pkey::{Private, Public};
use openssl::rsa::Rsa;
use openssl::sha::sha1;
use wtls_lab::handshake::{HandshakeKind, Message, RetryPolicy, Status};
use wtls_lab::udp::{Adapter, Event};
use wtls_lab::wire::{
    AlertFields, DatagramBudget, KeyExchangeOffer, KeyIdentifier, PeerAuthentication,
    ResumableClient, ResumableServer, ServerIdentity, TrustAnchor, WireAction, WireError, WirePeer,
    decode_alert_fields, decode_client_hello, decode_handshake, decode_server_hello,
    issue_certificate,
};
use wtls_lab::{CipherSpec, LengthForm, Record, RecordType, decode_datagram, encode_datagram};

const NOW: u32 = 1_730_000_000;
const ISSUER: &str = "Test WTLS CA";
const SUBJECT: &str = "echo.lab.invalid";
const VALID: RangeInclusive<u32> = NOW - 1..=NOW + 1;
const RETRY: RetryPolicy = RetryPolicy {
    timeout_ms: NonZeroU64::new(10).unwrap(),
    max_retries: 2,
};
const TTL: NonZeroU64 = NonZeroU64::new(100).unwrap();

struct Keys {
    ca: Rsa<Private>,
    other_ca: Rsa<Private>,
    gateway: Rsa<Private>,
}

fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| Keys {
        ca: Rsa::generate(1024).unwrap(),
        other_ca: Rsa::generate(1024).unwrap(),
        gateway: Rsa::generate(1024).unwrap(),
    })
}

fn public(key: &Rsa<Private>) -> Rsa<Public> {
    Rsa::from_public_components(key.n().to_owned().unwrap(), key.e().to_owned().unwrap()).unwrap()
}

fn leaf(
    signer: &Rsa<Private>,
    issuer: &str,
    subject: &str,
    validity: RangeInclusive<u32>,
) -> Vec<u8> {
    issue_certificate(issuer, subject, validity, signer, &public(&keys().gateway)).unwrap()
}

fn trust(ca: &Rsa<Private>) -> TrustAnchor {
    TrustAnchor::new(ISSUER, SUBJECT, public(ca)).unwrap()
}

fn server_identity(ca: &Rsa<Private>, subject: &str) -> ServerIdentity {
    ServerIdentity::provisioned(
        leaf(ca, ISSUER, subject, VALID),
        keys().gateway.clone(),
        ISSUER,
        public(ca),
    )
    .unwrap()
}

fn server_context(identity: ServerIdentity) -> ResumableServer {
    ResumableServer::new(identity, NonZeroUsize::MIN, TTL)
}

fn sends(actions: &[WireAction]) -> &[u8] {
    let mut sends = actions.iter().filter_map(|action| match action {
        WireAction::Send(bytes) => Some(bytes.as_slice()),
        _ => None,
    });
    let bytes = sends.next().expect("one outbound datagram");
    assert!(sends.next().is_none());
    bytes
}

fn receive(peer: &mut WirePeer, bytes: &[u8], at: u64) -> Vec<u8> {
    sends(&peer.receive(bytes, at).unwrap()).to_vec()
}

fn start(peer: &mut WirePeer, at: u64) -> Vec<u8> {
    sends(&peer.start(at).unwrap()).to_vec()
}

fn client_hello(bytes: &[u8]) -> &[u8] {
    let records = decode_datagram(bytes).unwrap();
    assert_eq!(records.len(), 1);
    records[0].fragment
}

fn server_id(bytes: &[u8]) -> [u8; 8] {
    decode_server_hello(decode_datagram(bytes).unwrap()[0].fragment)
        .unwrap()
        .session_id
        .try_into()
        .unwrap()
}

const RSA_OFFER: [u8; 3] = [8, 0, 0];

fn rsa_hash(hash: [u8; 20]) -> Vec<u8> {
    [[8, 0, 254].as_slice(), &hash].concat()
}

fn hash(key: &Rsa<Private>) -> [u8; 20] {
    sha1(&key.n().to_vec())
}

fn vector(bytes: &[u8]) -> Vec<u8> {
    [
        u16::try_from(bytes.len()).unwrap().to_be_bytes().as_slice(),
        bytes,
    ]
    .concat()
}

fn offered_hello(session: &[u8], exchanges: &[u8], authorities: &[u8]) -> Vec<u8> {
    // WAP-199 §10.5.1.2: two independently length-delimited KeyExchangeId vectors.
    let body = [
        &[1][..],
        &[0xa1; 16],
        &[u8::try_from(session.len()).unwrap()],
        session,
        &vector(exchanges),
        &vector(authorities),
        &[2, 6, 3, 1, 0, 2, 3],
    ]
    .concat();
    let hello = [&[1][..], &vector(&body)].concat();
    encode_datagram(&[Record {
        content_type: RecordType::Handshake,
        cipher_spec: CipherSpec::Null,
        sequence: 0,
        length_form: LengthForm::Explicit,
        fragment: &hello,
    }])
    .unwrap()
}

fn assert_alert(server: &mut WirePeer, hello: &[u8], at: u64, level: u8, description: u8) {
    let actions = server.receive(hello, at).unwrap();
    let [WireAction::Send(reply)] = actions.as_slice() else {
        panic!("expected an alert-only response, got {actions:?}");
    };
    let records = decode_datagram(reply).unwrap();
    assert_eq!(records.len(), 1, "an initial rejection sends only an alert");
    let [record] = records.as_slice() else {
        unreachable!()
    };
    assert_eq!(record.content_type, RecordType::Alert);
    assert_eq!(record.cipher_spec, CipherSpec::Null);
    assert_eq!(record.sequence, 0);
    let mut checksum = [0; 4];
    for (i, byte) in hello.iter().enumerate() {
        checksum[i % 4] ^= byte;
    }
    assert_eq!(
        decode_alert_fields(record.fragment).unwrap(),
        AlertFields {
            level,
            description,
            checksum,
        }
    );
    assert!(matches!(server.status(), Status::Idle | Status::Closed));
    assert!(server.connection_info().is_none());
}

fn assert_full_flight(flight: &[u8], index: u8, certificate: &[u8]) {
    let records = decode_datagram(flight).unwrap();
    assert_eq!(records.len(), 3);
    assert!(
        records
            .iter()
            .all(|r| r.content_type == RecordType::Handshake && r.cipher_spec == CipherSpec::Null)
    );
    assert_eq!(
        decode_server_hello(records[0].fragment)
            .unwrap()
            .key_exchange_index,
        index
    );
    assert_eq!(
        decode_handshake(records[1].fragment).unwrap(),
        Message::Certificate(certificate.to_vec())
    );
    assert_eq!(
        decode_handshake(records[2].fragment).unwrap(),
        Message::ServerHelloDone
    );
}

fn assert_abbreviated(flight: &[u8], session: [u8; 8], index: u8) {
    assert_eq!(server_id(flight), session);
    let records = decode_datagram(flight).unwrap();
    assert_eq!(
        decode_server_hello(records[0].fragment)
            .unwrap()
            .key_exchange_index,
        index
    );
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
}

fn finish_full(client: &mut WirePeer, server: &mut WirePeer, flight: &[u8], at: u64) {
    let commit = receive(client, flight, at);
    let actions = server.receive(&commit, at + 1).unwrap();
    assert!(actions.contains(&WireAction::Established(HandshakeKind::Full)));
    assert_eq!(
        client.receive(sends(&actions), at + 2).unwrap(),
        [WireAction::Established(HandshakeKind::Full),]
    );
    assert_eq!(
        client.connection_info().unwrap().peer_authentication,
        PeerAuthentication::VerifiedServerCertificate
    );
}

#[test]
fn trust_01_unsigned_rsa_modulus_and_wire_vector() {
    // A modulus from a locally generated 1024-bit RSA key. Its high bit forces
    // a leading sign octet in the DER INTEGER. Both digests use Python hashlib.
    let modulus = BigNum::from_hex_str(concat!(
        "D8550F9D008C190847EE4286ED164E82EAD50E12156B4CA0F276A624CB272DF8922",
        "958EFF9F5089B27445E7AD3A923D7B59690F6A070353642CF5230889839F206C85",
        "FC970F4F438B6BDACA3AB3CE5BF98440D296BBB3CF52FC4D811497E0D80544BCD",
        "D0EB278F00C8D4F2EC688D134C14B4E37512593DED83C1FE00BCBCD79B"
    ))
    .unwrap();
    let expected =
        *b"\x39\xad\xe5\x36\x7f\xb5\x72\xd8\x67\xa8\x53\x75\x3c\x65\x1d\x66\xe6\x78\x66\x88";
    let padded =
        *b"\x2c\x25\x2a\x82\xdc\xa1\x1a\x49\x24\x20\x59\x46\x81\x6b\x52\x0e\xb0\x27\x52\x13";
    let key = Rsa::from_public_components(modulus, BigNum::from_u32(65537).unwrap()).unwrap();
    let der = key.public_key_to_der_pkcs1().unwrap();
    assert_eq!(&der[3..7], &[2, 0x81, 0x81, 0]);
    assert_eq!(sha1(&der[6..135]), padded);
    let mut client =
        WirePeer::provisioned_client(RETRY, TrustAnchor::new(ISSUER, SUBJECT, key).unwrap(), NOW);
    let offer = start(&mut client, 0);
    let fragment = client_hello(&offer);
    let hello = decode_client_hello(fragment).unwrap();
    let rsa = KeyExchangeOffer {
        suite: 8,
        parameter_index: 0,
        explicit_parameters: None,
        identifier: KeyIdentifier::Null,
    };
    assert_eq!(hello.key_exchanges, [rsa]);
    assert_eq!(
        hello.trusted_keys,
        [KeyExchangeOffer {
            identifier: KeyIdentifier::KeyHash(expected),
            ..rsa
        }]
    );
    assert_eq!(
        &fragment[26..51],
        [&[0, 23, 8, 0, 254][..], &expected].concat()
    );
    assert_eq!(client.tick(10).unwrap(), [WireAction::Send(offer)]);
}

#[test]
fn trust_02_matching_and_nonfirst_authority_finish_and_echo() {
    let ca = &keys().ca;
    let certificate = leaf(ca, ISSUER, SUBJECT, VALID);
    let identity = server_identity(ca, SUBJECT);
    let mut client = WirePeer::provisioned_client(RETRY, trust(ca), NOW);
    let mut server = WirePeer::server(identity.clone(), NOW).unwrap();
    let offer = start(&mut client, 0);
    assert_eq!(
        decode_client_hello(client_hello(&offer))
            .unwrap()
            .trusted_keys
            .len(),
        1
    );
    let flight = receive(&mut server, &offer, 1);
    assert_full_flight(&flight, 1, &certificate);
    assert_eq!(
        server.receive(&offer, 2).unwrap(),
        [WireAction::Send(flight.clone())]
    );
    finish_full(&mut client, &mut server, &flight, 3);
    let payload = b"authenticated echo".to_vec();
    let request = client.send_application(payload.clone()).unwrap();
    assert_eq!(
        decode_datagram(sends(&request)).unwrap()[0].cipher_spec,
        CipherSpec::Current
    );
    assert_eq!(
        server.receive(sends(&request), 6).unwrap(),
        [WireAction::Deliver(payload.clone())]
    );
    let reply = server.send_application(payload.clone()).unwrap();
    assert_eq!(
        decode_datagram(sends(&reply)).unwrap()[0].cipher_spec,
        CipherSpec::Current
    );
    assert_eq!(
        client.receive(sends(&reply), 7).unwrap(),
        [WireAction::Deliver(payload)]
    );

    let mut server = WirePeer::server(identity, NOW).unwrap();
    let wrong_parameters = [&[8, 1, 254][..], &hash(ca)].concat();
    let mix = [
        rsa_hash(hash(&keys().other_ca)),
        wrong_parameters,
        rsa_hash(hash(ca)),
    ]
    .concat();
    let exchanges = [&[8, 1, 0][..], &RSA_OFFER].concat();
    let flight = receive(&mut server, &offered_hello(&[], &exchanges, &mix), 10);
    assert_full_flight(&flight, 2, &certificate);

    check_udp_contexts(ca, &certificate);
}

fn check_udp_contexts(ca: &Rsa<Private>, certificate: &[u8]) {
    const CLIENT: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152));
    const SERVER: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9203));

    fn sent(events: &[Event], expected: SocketAddr) -> &[u8] {
        let mut sends = events.iter().filter_map(|event| match event {
            Event::Send { remote, bytes } => Some((remote, bytes)),
            _ => None,
        });
        let (remote, bytes) = sends.next().expect("one outbound datagram");
        assert_eq!(*remote, expected);
        assert!(sends.next().is_none());
        bytes
    }

    let clients = ResumableClient::provisioned(RETRY, trust(ca), TTL);
    let servers = server_context(server_identity(ca, SUBJECT));
    let budget = DatagramBudget::new(1200);
    let mut client = Adapter::new(None, budget, NonZeroUsize::MIN);
    let mut server = Adapter::new(Some(servers), budget, NonZeroUsize::MIN);

    let wrong_offer = offered_hello(&[], &RSA_OFFER, &rsa_hash(hash(&keys().other_ca)));
    let events = server.receive(CLIENT, &wrong_offer, NOW, 0);
    let records = decode_datagram(sent(&events, CLIENT)).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].content_type, RecordType::Alert);
    assert_eq!(server.status(CLIENT), None);

    let events = client.connect(SERVER, &clients, NOW, 1);
    let offer = sent(&events, SERVER);
    assert_eq!(
        decode_client_hello(client_hello(offer))
            .unwrap()
            .trusted_keys
            .len(),
        1
    );
    let events = server.receive(CLIENT, offer, NOW, 2);
    let flight = sent(&events, CLIENT);
    assert_full_flight(flight, 1, certificate);
    let events = client.receive(SERVER, flight, NOW, 3);
    let events = server.receive(CLIENT, sent(&events, SERVER), NOW, 4);
    assert!(events.iter().any(|event| matches!(
        event,
        Event::Established {
            remote: CLIENT,
            kind: HandshakeKind::Full
        }
    )));
    let events = client.receive(SERVER, sent(&events, CLIENT), NOW, 5);
    assert!(matches!(
        events.as_slice(),
        [Event::Established {
            remote: SERVER,
            kind: HandshakeKind::Full
        }]
    ));
}

#[test]
fn trust_03_wrong_leaf_or_misplaced_authority_gets_only_fatal_alert() {
    let ca = &keys().ca;
    let context = server_context(server_identity(ca, SUBJECT));
    let wrong = rsa_hash(hash(&keys().other_ca));
    let leaf = rsa_hash(hash(&keys().gateway));
    let wrong_parameters = [&[8, 1, 254][..], &hash(ca)].concat();
    let wrong_suite = [&[6, 0, 254][..], &hash(ca)].concat();
    let misplaced = rsa_hash(hash(ca));
    let includes_anonymous = [&[5, 0, 0][..], &RSA_OFFER].concat();
    for (exchanges, authorities) in [
        (RSA_OFFER.as_slice(), wrong.as_slice()),
        (&RSA_OFFER, &leaf),
        (&misplaced, &wrong),
        (&RSA_OFFER, &wrong_parameters),
        (&RSA_OFFER, &wrong_suite),
        (&includes_anonymous, &wrong),
    ] {
        let id = *b"stale-id";
        let offer = offered_hello(&id, exchanges, authorities);
        let mut server = context.peer(NOW).unwrap();
        assert_alert(&mut server, &offer, 1, 3, 40);
        assert!(server.send_application(vec![1]).is_err());
        assert_alert(
            &mut context.peer(NOW).unwrap(),
            &offered_hello(&id, &[], &[]),
            2,
            2,
            52,
        );
    }
}

#[test]
fn trust_04_empty_authority_list_still_verifies_the_leaf() {
    let ca = &keys().ca;
    let mut server = WirePeer::server(server_identity(ca, SUBJECT), NOW).unwrap();
    assert_eq!(
        server.receive(&offered_hello(&[], &[5, 0, 0], &[]), 0),
        Err(WireError::UnsupportedProfile)
    );
    let mut client = WirePeer::client(RETRY, trust(ca), NOW);
    let offer = start(&mut client, 0);
    assert!(
        decode_client_hello(client_hello(&offer))
            .unwrap()
            .trusted_keys
            .is_empty()
    );
    let flight = receive(&mut server, &offer, 1);
    assert_full_flight(&flight, 1, &leaf(ca, ISSUER, SUBJECT, VALID));
    finish_full(&mut client, &mut server, &flight, 2);
}

#[test]
fn trust_05_rejects_bad_provisioning_and_untrusted_leaves_before_key_transport() {
    let ca = &keys().ca;
    let gateway = &keys().gateway;
    let wrong_ca = &keys().other_ca;
    assert!(matches!(
        ServerIdentity::provisioned(
            leaf(ca, ISSUER, SUBJECT, VALID),
            gateway.clone(),
            ISSUER,
            public(wrong_ca)
        ),
        Err(WireError::CertificateRejected)
    ));
    assert!(matches!(
        ServerIdentity::provisioned(
            leaf(ca, "other issuer", SUBJECT, VALID),
            gateway.clone(),
            ISSUER,
            public(ca)
        ),
        Err(WireError::CertificateRejected)
    ));
    assert!(matches!(
        ServerIdentity::provisioned(
            leaf(ca, ISSUER, SUBJECT, VALID),
            wrong_ca.clone(),
            ISSUER,
            public(ca)
        ),
        Err(WireError::CertificateRejected)
    ));

    let client_context = ResumableClient::provisioned(RETRY, trust(ca), TTL);
    for certificate in [
        leaf(wrong_ca, ISSUER, SUBJECT, VALID),
        leaf(ca, "other issuer", SUBJECT, VALID),
        leaf(ca, ISSUER, "other.lab.invalid", VALID),
        leaf(ca, ISSUER, SUBJECT, NOW - 2..=NOW - 1),
    ] {
        // The manual gateway lets us exercise the client's independent checks.
        let server_context =
            server_context(ServerIdentity::new(certificate.clone(), gateway.clone()).unwrap());
        let mut server = server_context.peer(NOW).unwrap();
        let mut client = client_context.peer(NOW).unwrap();
        let offer = start(&mut client, 0);
        assert!(
            decode_client_hello(client_hello(&offer))
                .unwrap()
                .session_id
                .is_empty()
        );
        let flight = receive(&mut server, &offer, 1);
        assert_full_flight(&flight, 1, &certificate);
        assert_eq!(
            client.receive(&flight, 2),
            Err(WireError::CertificateRejected)
        );
        assert_eq!(client.status(), Status::Closed);
        assert_eq!(server.status(), Status::Negotiating);
        assert!(client.send_application(vec![1]).is_err());
        assert!(server.send_application(vec![1]).is_err());
        assert!(
            decode_client_hello(client_hello(&start(
                &mut client_context.peer(NOW).unwrap(),
                3
            )))
            .unwrap()
            .session_id
            .is_empty()
        );
        assert_alert(
            &mut server_context.peer(NOW).unwrap(),
            &offered_hello(&server_id(&flight), &[], &[]),
            3,
            2,
            52,
        );
    }
}

#[test]
fn trust_06_resumption_omission_mismatch_isolation_and_fallback() {
    let ca = &keys().ca;
    let other_ca = &keys().other_ca;
    let identity = server_identity(ca, SUBJECT);
    let server_context = server_context(identity.clone());
    let client_context = ResumableClient::provisioned(RETRY, trust(ca), TTL);
    let mut client = client_context.peer(NOW).unwrap();
    let mut server = server_context.peer(NOW).unwrap();
    let offer = start(&mut client, 0);
    let flight = receive(&mut server, &offer, 1);
    let id = server_id(&flight);
    finish_full(&mut client, &mut server, &flight, 2);

    let unknown = offered_hello(&id, &[], &[]);
    let mut server = server_context.peer(NOW).unwrap();
    let flight = receive(&mut server, &unknown, 10);
    assert_abbreviated(&flight, id, 0);

    let wrong = rsa_hash(hash(other_ca));
    let mismatched = offered_hello(&id, &RSA_OFFER, &wrong);
    assert_alert(
        &mut server_context.peer(NOW).unwrap(),
        &mismatched,
        11,
        3,
        40,
    );
    let mismatched_resume_only = offered_hello(&id, &[], &wrong);
    assert_alert(
        &mut server_context.peer(NOW).unwrap(),
        &mismatched_resume_only,
        12,
        3,
        40,
    );

    let mut client = client_context.peer(NOW).unwrap();
    let mut server = server_context.peer(NOW).unwrap();
    let retry = start(&mut client, 20);
    let hello = decode_client_hello(client_hello(&retry)).unwrap();
    assert_eq!(hello.session_id, id);
    assert_eq!(hello.trusted_keys.len(), 1);
    let flight = receive(&mut server, &retry, 21);
    assert_abbreviated(&flight, id, 1);
    let actions = client.receive(&flight, 22).unwrap();
    assert!(actions.contains(&WireAction::Established(HandshakeKind::Resumed)));
    let actions = server.receive(sends(&actions), 23).unwrap();
    assert!(actions.contains(&WireAction::Established(HandshakeKind::Resumed)));

    let new_trust = ResumableClient::provisioned(RETRY, trust(other_ca), TTL);
    let new_offer = start(&mut new_trust.peer(NOW).unwrap(), 24);
    assert!(
        decode_client_hello(client_hello(&new_offer))
            .unwrap()
            .session_id
            .is_empty()
    );
    let new_policy = ResumableClient::new(RETRY, trust(ca), TTL);
    let new_offer = start(&mut new_policy.peer(NOW).unwrap(), 24);
    let hello = decode_client_hello(client_hello(&new_offer)).unwrap();
    assert!(hello.session_id.is_empty());
    assert!(hello.trusted_keys.is_empty());

    for changed in [
        ResumableServer::new(server_identity(other_ca, SUBJECT), NonZeroUsize::MIN, TTL),
        ResumableServer::new(
            server_identity(ca, "other.lab.invalid"),
            NonZeroUsize::MIN,
            TTL,
        ),
        ResumableServer::new(
            ServerIdentity::new(leaf(ca, ISSUER, SUBJECT, VALID), keys().gateway.clone()).unwrap(),
            NonZeroUsize::MIN,
            TTL,
        ),
    ] {
        assert_alert(&mut changed.peer(NOW).unwrap(), &unknown, 25, 2, 52);
    }

    // A matching full offer can recover when the server lost its cache but the
    // client still holds the verified session.
    let restarted = ResumableServer::new(identity, NonZeroUsize::MIN, TTL);
    let mut server = restarted.peer(NOW).unwrap();
    let mut client = client_context.peer(NOW).unwrap();
    let offer = start(&mut client, 30);
    assert_eq!(
        decode_client_hello(client_hello(&offer))
            .unwrap()
            .session_id,
        id
    );
    let flight = receive(&mut server, &offer, 31);
    assert_ne!(server_id(&flight), id);
    assert_full_flight(&flight, 1, &leaf(ca, ISSUER, SUBJECT, VALID));
    finish_full(&mut client, &mut server, &flight, 32);

    let stale = offered_hello(&id, &RSA_OFFER, &[]);
    let wrong = offered_hello(&id, &RSA_OFFER, &wrong);
    assert_alert(&mut server_context.peer(NOW).unwrap(), &wrong, 103, 3, 40);
    assert_alert(&mut server_context.peer(NOW).unwrap(), &unknown, 104, 2, 52);
    let mut server = server_context.peer(NOW).unwrap();
    let flight = receive(&mut server, &stale, 105);
    assert_ne!(server_id(&flight), id);
    assert_full_flight(&flight, 1, &leaf(ca, ISSUER, SUBJECT, VALID));
}
