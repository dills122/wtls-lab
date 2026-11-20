use wtls_lab::handshake::Status;
use wtls_lab::wire::{
    WireAction, WirePeer, decode_client_hello, decode_handshake, decode_server_hello,
};
use wtls_lab::{Record, RecordType, decode_datagram};

const WINWAP_HELLO: &str = include_str!("../fixtures/winwap-client-hello.hex");

fn datagram(fixture: &str) -> Vec<u8> {
    fixture
        .lines()
        .flat_map(|line| line.split('#').next().unwrap().split_whitespace())
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect()
}

fn winwap_offer_with_session_id(session_id: &[u8]) -> Vec<u8> {
    use wtls_lab::encode_datagram;

    let hello = datagram(WINWAP_HELLO);
    let records = decode_datagram(&hello).unwrap();
    let [record] = records.as_slice() else {
        panic!("expected one ClientHello record");
    };
    let mut fragment = record.fragment.to_vec();
    // After the handshake header, version, and random comes the Session ID vector.
    let session_length_offset = 3 + 1 + 16;
    assert_eq!(fragment[session_length_offset], 0);
    fragment[session_length_offset] = session_id.len().try_into().unwrap();
    let session_start = session_length_offset + 1;
    fragment.splice(session_start..session_start, session_id.iter().copied());
    let body_length = u16::try_from(fragment.len() - 3).unwrap();
    fragment[1..3].copy_from_slice(&body_length.to_be_bytes());
    assert_eq!(
        decode_client_hello(&fragment).unwrap().session_id,
        session_id
    );
    encode_datagram(&[Record {
        fragment: &fragment,
        ..*record
    }])
    .unwrap()
}

fn assert_full_handshake_and_retry(hello: &[u8], offered_id: &[u8]) {
    let mut server = WirePeer::legacy_winwap_server(1_730_000_000).unwrap();
    let first = server.receive(hello, 0).unwrap();
    let [WireAction::Send(flight)] = first.as_slice() else {
        panic!("expected a full server handshake flight");
    };
    let [selection, key, done]: [Record<'_>; 3] =
        decode_datagram(flight).unwrap().try_into().unwrap();
    let parameters = decode_server_hello(selection.fragment).unwrap();
    assert_eq!(parameters.session_id.len(), 8);
    assert_ne!(parameters.session_id, offered_id);
    assert_eq!(parameters.key_exchange_index, 1);
    assert_eq!(parameters.cipher_suite, [5, 3]);
    assert_eq!((parameters.sequence_mode, parameters.key_refresh), (2, 2));
    assert_eq!(key.content_type, RecordType::Handshake);
    assert_eq!(key.fragment[0], 12); // ServerKeyExchange
    assert_eq!(&key.fragment[3..7], &[0, 0, 3, 1]); // default parameters and length-prefixed exponent
    assert_eq!(done.content_type, RecordType::Handshake);
    assert_eq!(done.fragment, [14, 0, 0]); // ServerHelloDone
    assert_eq!(server.status(), Status::Negotiating);
    assert!(server.connection_info().is_none());
    assert_eq!(server.receive(hello, 5_000).unwrap(), first);
}

#[test]
fn anonymous_server_falls_back_when_an_eight_byte_session_id_misses() {
    let offered_id = b"old-sess";
    assert_full_handshake_and_retry(&winwap_offer_with_session_id(offered_id), offered_id);
}

#[test]
fn anonymous_server_falls_back_when_a_short_session_id_misses() {
    let offered_id = b"old";
    assert_full_handshake_and_retry(&winwap_offer_with_session_id(offered_id), offered_id);
}

#[test]
fn anonymous_server_accepts_the_winwap_offer_and_resends_the_exact_flight() {
    assert_full_handshake_and_retry(&datagram(WINWAP_HELLO), &[]);
}

#[test]
fn anonymous_server_requires_the_offered_legacy_suite() {
    use wtls_lab::handshake::{Message, SessionId};
    use wtls_lab::wire::{WireError, encode_handshake};
    use wtls_lab::{CipherSpec, LengthForm, encode_datagram};

    for resume in [None, Some(SessionId(*b"old-sess"))] {
        let offer = encode_handshake(&Message::ClientHello {
            random: [1; 16],
            resume,
        })
        .unwrap();
        assert!(decode_handshake(&offer).is_ok());
        let bytes = encode_datagram(&[Record {
            content_type: RecordType::Handshake,
            cipher_spec: CipherSpec::Null,
            sequence: 0,
            length_form: LengthForm::Explicit,
            fragment: &offer,
        }])
        .unwrap();
        let mut server = WirePeer::legacy_winwap_server(1_730_000_000).unwrap();
        assert_eq!(
            server.receive(&bytes, 0),
            Err(WireError::UnsupportedProfile)
        );
        assert_eq!(server.status(), Status::Idle);
    }
}
