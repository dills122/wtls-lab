use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::{NonZeroU64, NonZeroUsize};
use std::ops::RangeInclusive;
use std::sync::OnceLock;

use openssl::bn::BigNum;
use openssl::pkey::{Private, Public};
use openssl::rsa::Rsa;
use openssl::sha::sha1;
use wtls_lab::handshake::{HandshakeKind, Message, RetryPolicy, Status};
use wtls_lab::udp::{Adapter, Diagnostic, Event};
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

#[test]
fn certificate_alert_trust_05_retires_pending_gateway() {
    use wtls_lab::wire::AlertProtection;

    let ca = &keys().ca;
    let wrong_ca = &keys().other_ca;
    let clients = ResumableClient::provisioned(RETRY, trust(ca), TTL);
    let servers = server_context(
        ServerIdentity::new(
            leaf(wrong_ca, ISSUER, SUBJECT, VALID),
            keys().gateway.clone(),
        )
        .unwrap(),
    );
    let mut client = Adapter::new(None, DatagramBudget::new(1200), NonZeroUsize::MIN);
    let mut server = Adapter::new(Some(servers), DatagramBudget::new(1200), NonZeroUsize::MIN);
    let client_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152).into();
    let server_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9203).into();
    let hello = udp_send(&client.connect(server_addr, &clients, NOW, 0), server_addr);
    let flight = udp_send(&server.receive(client_addr, &hello, NOW, 1), client_addr);
    assert_eq!(server.status(client_addr), Some(Status::Negotiating));

    let events = client.receive(server_addr, &flight, NOW, 2);
    assert!(matches!(
        events.first(),
        Some(Event::Diagnostic {
            reason: Diagnostic::Protocol(WireError::CertificateRejected),
            ..
        })
    ));
    assert_eq!(
        events.len(),
        2,
        "trust diagnostic must be followed by one alert"
    );
    let [
        Event::Diagnostic {
            remote,
            reason: Diagnostic::Protocol(WireError::CertificateRejected),
        },
        Event::Send {
            remote: destination,
            bytes,
        },
    ] = events.as_slice()
    else {
        panic!("expected trust diagnostic followed by one alert");
    };
    assert_eq!((*remote, *destination), (server_addr, server_addr));
    assert_eq!(bytes, &[0xc2, 0, 1, 0, 6, 3, 42, 0xc0, 0x0e, 2, 0]);
    assert_eq!(client.status(server_addr), None);
    assert!(client.tick(10).is_empty());
    let fresh_hello = udp_send(&client.connect(server_addr, &clients, NOW, 10), server_addr);
    assert!(
        matches!(server.receive(client_addr, bytes, NOW, 11).as_slice(), [Event::Diagnostic {
        remote,
        reason: Diagnostic::Protocol(WireError::PeerAlert {
            fields: AlertFields { level: 3, description: 42, checksum: [0xc0, 0x0e, 2, 0] },
            protection: AlertProtection::Clear,
        }),
    }] if *remote == client_addr)
    );
    assert_eq!(server.status(client_addr), None);
    let other_client = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49153).into();
    assert!(
        matches!(server.receive(other_client, &fresh_hello, NOW, 12).as_slice(), [Event::Send { remote, .. }] if *remote == other_client)
    );
}

fn certificate_fragment(format: u8, certificate: &[u8]) -> Vec<u8> {
    let mut list = vec![format];
    list.extend_from_slice(certificate);
    let mut handshake = vec![11];
    handshake.extend(vector(&vector(&list)));
    handshake
}

fn with_certificate(flight: &[u8], format: u8, certificate: &[u8]) -> Vec<u8> {
    let mut records = decode_datagram(flight).unwrap();
    let fragment = certificate_fragment(format, certificate);
    records[1].fragment = &fragment;
    encode_datagram(&records).unwrap()
}

fn certificate_alert_reply(
    client: &mut WirePeer,
    flight: &[u8],
    at: u64,
    description: u8,
) -> Vec<u8> {
    let error = client.receive_with_reply(flight, at).unwrap_err();
    assert_eq!(error.diagnostic, WireError::CertificateRejected);
    let reply = error.reply.expect("one certificate rejection alert");

    let records = decode_datagram(flight).unwrap();
    let done = records.last().unwrap();
    let done = &flight[flight.len() - done.wire_len()..];
    let checksum = done.chunks(4).fold(0u32, |sum, chunk| {
        let mut word = [0; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        sum ^ u32::from_be_bytes(word)
    });
    let mut expected = vec![0xc2, 0, 1, 0, 6, 3, description];
    expected.extend_from_slice(&checksum.to_be_bytes());
    assert_eq!(reply, expected);
    assert_eq!(client.status(), Status::Closed);
    assert_eq!(client.deadline(), None);
    assert!(client.connection_info().is_none());
    assert!(client.send_application(vec![1]).is_err());
    assert_eq!(client.receive_with_reply(flight, at + 1), Ok(vec![]));
    assert_eq!(client.tick(at + 30), Ok(vec![]));
    reply
}

#[test]
fn certificate_alert_classifies_native_leaves_in_order() {
    let ca = &keys().ca;
    let other_ca = &keys().other_ca;
    let valid = leaf(ca, ISSUER, SUBJECT, VALID);
    let mut invalid_interval = valid.clone();
    let start_offset = 2 + 4 + ISSUER.len();
    invalid_interval[start_offset..start_offset + 4].copy_from_slice(&(NOW + 2).to_be_bytes());
    let mut invalid_signature = valid.clone();
    let signature_offset = valid.len() - ca.size() as usize;
    invalid_signature[signature_offset..].fill(0);
    let short_rsa = Rsa::generate(768).unwrap();
    // issue_certificate enforces the offer profile. Rebuild the modulus and sign
    // the new certificate body to represent a complete smaller native RSA leaf.
    let mut short_leaf = valid[..start_offset + 8 + 4 + SUBJECT.len() + 2].to_vec();
    short_leaf.extend(vector(&short_rsa.e().to_vec()));
    short_leaf.extend(vector(&short_rsa.n().to_vec()));
    let mut signature = vec![0; ca.size() as usize];
    ca.private_encrypt(
        &sha1(&short_leaf),
        &mut signature,
        openssl::rsa::Padding::PKCS1,
    )
    .unwrap();
    short_leaf.extend(vector(&signature));

    let clients = ResumableClient::provisioned(RETRY, trust(ca), TTL);
    let servers = server_context(server_identity(ca, SUBJECT));
    for (name, certificate, description) in [
        ("truncated supported body", vec![1, 2, 1], 42),
        ("reversed dates", invalid_interval, 42),
        ("complete RSA leaf below the modulus limit", short_leaf, 43),
        (
            "issuer before signature",
            leaf(other_ca, "unknown CA", SUBJECT, VALID),
            48,
        ),
        (
            "claimed issuer with different key",
            leaf(other_ca, ISSUER, SUBJECT, VALID),
            42,
        ),
        ("invalid signature block", invalid_signature, 42),
        (
            "signature before subject",
            leaf(other_ca, ISSUER, "wrong subject", VALID),
            42,
        ),
        (
            "wrong subject",
            leaf(ca, ISSUER, "wrong subject", VALID),
            46,
        ),
        (
            "subject before time",
            leaf(ca, ISSUER, "wrong subject", NOW - 2..=NOW - 1),
            46,
        ),
        ("expired", leaf(ca, ISSUER, SUBJECT, NOW - 2..=NOW - 1), 45),
        (
            "not yet valid",
            leaf(ca, ISSUER, SUBJECT, NOW + 1..=NOW + 2),
            45,
        ),
    ] {
        let mut client = clients.peer(NOW).unwrap();
        let hello = start(&mut client, 0);
        let flight = receive(&mut servers.peer(NOW).unwrap(), &hello, 1);
        let flight = with_certificate(&flight, 1, &certificate);
        let reply = certificate_alert_reply(&mut client, &flight, 2, description);
        assert_eq!(
            reply,
            [0xc2, 0, 1, 0, 6, 3, description, 0xc0, 0x0e, 2, 0],
            "{name}"
        );
    }

    for now in [*VALID.start(), *VALID.end()] {
        let mut client = clients.peer(now).unwrap();
        let mut server = servers.peer(now).unwrap();
        let flight = receive(&mut server, &start(&mut client, 0), 1);
        finish_full(&mut client, &mut server, &flight, 2);
    }
}

#[test]
fn certificate_alert_uses_exact_lengthless_done_after_identical_retry() {
    let ca = &keys().ca;
    let clients = ResumableClient::provisioned(RETRY, trust(ca), TTL);
    let identity = ServerIdentity::new(
        leaf(&keys().other_ca, ISSUER, SUBJECT, VALID),
        keys().gateway.clone(),
    )
    .unwrap();
    let mut server = server_context(identity).peer(NOW).unwrap();
    let mut client = clients.peer(NOW).unwrap();
    let hello = start(&mut client, 0);
    let flight = receive(&mut server, &hello, 1);
    assert_eq!(client.tick(10), Ok(vec![WireAction::Send(hello.clone())]));
    assert_eq!(receive(&mut server, &hello, 11), flight);

    let mut records = decode_datagram(&flight).unwrap();
    records[2].length_form = LengthForm::DatagramRemainder;
    let flight = encode_datagram(&records).unwrap();
    assert!(flight.ends_with(&[0x43, 0, 2, 14, 0, 0]));
    assert_eq!(
        certificate_alert_reply(&mut client, &flight, 12, 42),
        [0xc2, 0, 1, 0, 6, 3, 42, 0x43, 0, 2, 14],
    );
}

#[test]
fn certificate_alert_is_scoped_to_ordered_well_framed_provisioned_flights() {
    use wtls_lab::handshake::HandshakeError;

    let ca = &keys().ca;
    let invalid = leaf(&keys().other_ca, ISSUER, SUBJECT, VALID);
    let clients = ResumableClient::provisioned(RETRY, trust(ca), TTL);
    let servers = server_context(server_identity(ca, SUBJECT));
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let flight = receive(&mut server, &start(&mut client, 0), 1);
    let invalid_flight = with_certificate(&flight, 1, &invalid);
    let mut records = decode_datagram(&invalid_flight).unwrap();
    let incomplete = encode_datagram(&records[..2]).unwrap();
    records.swap(1, 2);
    records[1].sequence = 1;
    records[2].sequence = 2;
    let unordered = encode_datagram(&records).unwrap();
    let mut malformed_handshake = records;
    malformed_handshake.swap(1, 2);
    malformed_handshake[1].sequence = 1;
    malformed_handshake[2].sequence = 2;
    malformed_handshake[2].fragment = &[14, 0, 1, 0];
    let malformed_handshake = encode_datagram(&malformed_handshake).unwrap();

    for (bytes, diagnostic) in [
        (incomplete, HandshakeError::UnexpectedDatagram.into()),
        (unordered, HandshakeError::UnexpectedDatagram.into()),
        (malformed_handshake, WireError::InvalidMessage),
        (
            with_certificate(&flight, 2, &invalid),
            WireError::UnsupportedProfile,
        ),
    ] {
        let error = client.receive_with_reply(&bytes, 2).unwrap_err();
        assert_eq!(error.diagnostic, diagnostic);
        assert_eq!(error.reply, None);
        assert_eq!(client.status(), Status::Negotiating);
    }
    let error = client
        .receive_with_reply(&invalid_flight[..invalid_flight.len() - 1], 2)
        .unwrap_err();
    assert!(matches!(error.diagnostic, WireError::Decode(_)));
    assert_eq!(error.reply, None);
    finish_full(&mut client, &mut server, &flight, 3);

    let mut unclassified = invalid.clone();
    unclassified[1] = 1; // a different native signature algorithm
    let mut provisioned = clients.peer(NOW).unwrap();
    let flight = receive(
        &mut servers.peer(NOW).unwrap(),
        &start(&mut provisioned, 0),
        1,
    );
    let error = provisioned
        .receive_with_reply(&with_certificate(&flight, 1, &unclassified), 2)
        .unwrap_err();
    assert_eq!(error.diagnostic, WireError::CertificateRejected);
    assert_eq!(error.reply, None);
    assert_eq!(provisioned.status(), Status::Closed);

    let mut manual = WirePeer::client(RETRY, trust(ca), NOW);
    let flight = receive(&mut servers.peer(NOW).unwrap(), &start(&mut manual, 0), 1);
    let error = manual
        .receive_with_reply(&with_certificate(&flight, 1, &invalid), 2)
        .unwrap_err();
    assert_eq!(error.diagnostic, WireError::CertificateRejected);
    assert_eq!(error.reply, None);
    assert_eq!(manual.status(), Status::Closed);
}

fn udp_send(events: &[Event], expected_remote: SocketAddr) -> Vec<u8> {
    let [Event::Send { remote, bytes }] = events else {
        panic!("expected exactly one UDP send");
    };
    assert_eq!(*remote, expected_remote);
    bytes.clone()
}

#[test]
fn certificate_alert_udp_drop_keeps_pending_deadline_and_inbound_budget() {
    use wtls_lab::wire::DatagramTooLarge;

    let clients = ResumableClient::provisioned(RETRY, trust(&keys().ca), TTL);
    let identity = ServerIdentity::new(
        leaf(&keys().other_ca, ISSUER, SUBJECT, VALID),
        keys().gateway.clone(),
    )
    .unwrap();
    let servers = server_context(identity.clone());
    let budget = DatagramBudget::new(1200);
    let client_addr = "127.0.0.1:49152".parse().unwrap();
    let other_client = "127.0.0.1:49153".parse().unwrap();
    let server_addr = "127.0.0.1:9203".parse().unwrap();
    let mut client = Adapter::new(None, budget, NonZeroUsize::MIN);
    let mut server = Adapter::new(Some(servers), budget, NonZeroUsize::MIN)
        .with_pending_handshake_timeout_ms(NonZeroU64::new(10).unwrap());

    let hello = udp_send(&client.connect(server_addr, &clients, NOW, 0), server_addr);
    let flight = udp_send(&server.receive(client_addr, &hello, NOW, 1), client_addr);
    let events = client.receive(server_addr, &flight, NOW, 2);
    assert!(matches!(
        events.as_slice(),
        [
            Event::Diagnostic { reason: Diagnostic::Protocol(WireError::CertificateRejected), .. },
            Event::Send { remote, bytes },
        ] if *remote == server_addr && bytes.len() < flight.len()
    ));
    assert_eq!(client.status(server_addr), None);
    assert_eq!(client.deadline(), None);
    let next_hello = udp_send(&client.connect(server_addr, &clients, NOW, 3), server_addr);

    // Drop the alert. A separate client cannot displace the occupied slot.
    assert!(matches!(
        server.receive(other_client, &next_hello, NOW, 4).as_slice(),
        [Event::Diagnostic {
            reason: Diagnostic::AtCapacity,
            ..
        }]
    ));
    assert_eq!(server.status(client_addr), Some(Status::Negotiating));
    assert_eq!(server.deadline(), Some(11));
    assert!(server.tick(10).is_empty());
    assert!(matches!(
        server.tick(11).as_slice(),
        [Event::TimedOut { remote }] if *remote == client_addr
    ));
    assert_eq!(server.status(client_addr), None);
    udp_send(
        &server.receive(other_client, &next_hello, NOW, 12),
        other_client,
    );

    let limit = 128;
    let mut client = Adapter::new(None, DatagramBudget::new(limit), NonZeroUsize::MIN);
    let hello = udp_send(&client.connect(server_addr, &clients, NOW, 13), server_addr);
    let flight = receive(&mut WirePeer::server(identity, NOW).unwrap(), &hello, 14);
    assert!(matches!(
        client.receive(server_addr, &flight, NOW, 15).as_slice(),
        [Event::Diagnostic {
            remote,
            reason: Diagnostic::InboundTooLarge(DatagramTooLarge { size, limit: observed_limit }),
        }] if *remote == server_addr && *size == flight.len() && *observed_limit == limit
    ));
    assert_eq!(client.status(server_addr), Some(Status::Negotiating));
    assert_eq!(client.deadline(), Some(23));
    assert_eq!(udp_send(&client.tick(23), server_addr), hello);
}

#[test]
fn certificate_alert_failed_fallback_preserves_original_cache_expiry() {
    let ca = &keys().ca;
    let clients = ResumableClient::provisioned(RETRY, trust(ca), TTL);
    let servers = server_context(server_identity(ca, SUBJECT));
    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let flight = receive(&mut server, &start(&mut client, 0), 1);
    let id = server_id(&flight);
    finish_full(&mut client, &mut server, &flight, 2);

    // Keep certificate wall time fixed. Only the retry/cache clock advances.
    let invalid = leaf(&keys().other_ca, ISSUER, SUBJECT, VALID);
    let restarted =
        server_context(ServerIdentity::new(invalid.clone(), keys().gateway.clone()).unwrap());
    let mut client = clients.peer(NOW).unwrap();
    let mut restarted = restarted.peer(NOW).unwrap();
    let offer = start(&mut client, 20);
    assert_eq!(
        decode_client_hello(client_hello(&offer))
            .unwrap()
            .session_id,
        id
    );

    let same_id_full = with_certificate(&flight, 1, &invalid);
    let error = client.receive_with_reply(&same_id_full, 21).unwrap_err();
    assert_eq!(
        error.diagnostic,
        wtls_lab::handshake::HandshakeError::UnexpectedDatagram.into()
    );
    assert_eq!(error.reply, None);

    let fallback = receive(&mut restarted, &offer, 22);
    assert_ne!(server_id(&fallback), id);
    assert_full_flight(&fallback, 1, &invalid);
    let reply = certificate_alert_reply(&mut client, &fallback, 23, 42);
    let error = restarted.receive_with_reply(&reply, 24).unwrap_err();
    assert!(matches!(error.diagnostic, WireError::PeerAlert { .. }));
    assert_eq!(error.reply, None);
    assert_eq!(restarted.status(), Status::Closed);

    let mut client = clients.peer(NOW).unwrap();
    let mut server = servers.peer(NOW).unwrap();
    let offer = start(&mut client, 99);
    assert_eq!(
        decode_client_hello(client_hello(&offer))
            .unwrap()
            .session_id,
        id
    );
    let response = receive(&mut server, &offer, 100);
    assert_abbreviated(&response, id, 1);
    let actions = client.receive_with_reply(&response, 101).unwrap();
    assert!(actions.contains(&WireAction::Established(HandshakeKind::Resumed)));
    let actions = server.receive_with_reply(sends(&actions), 102).unwrap();
    assert!(actions.contains(&WireAction::Established(HandshakeKind::Resumed)));

    // Original establishment was at t=3 on the gateway and t=4 on the client.
    assert_alert(
        &mut servers.peer(NOW).unwrap(),
        &offered_hello(&id, &[], &[]),
        103,
        2,
        52,
    );
    let before_expiry = start(&mut clients.peer(NOW).unwrap(), 103);
    assert_eq!(
        decode_client_hello(client_hello(&before_expiry))
            .unwrap()
            .session_id,
        id
    );
    let at_expiry = start(&mut clients.peer(NOW).unwrap(), 104);
    assert!(
        decode_client_hello(client_hello(&at_expiry))
            .unwrap()
            .session_id
            .is_empty()
    );
}
