use wtls_lab::handshake::Status;
use wtls_lab::wire::{WireAction, WirePeer, decode_handshake, decode_server_hello};
use wtls_lab::{Record, RecordType, decode_datagram};

const WINWAP_HELLO: &str = include_str!("../fixtures/winwap-client-hello.hex");

fn datagram(fixture: &str) -> Vec<u8> {
    fixture
        .lines()
        .flat_map(|line| line.split('#').next().unwrap().split_whitespace())
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect()
}

#[test]
fn anonymous_server_accepts_the_winwap_offer_and_resends_the_exact_flight() {
    let hello = datagram(WINWAP_HELLO);
    let mut server = WirePeer::legacy_winwap_server(1_730_000_000).unwrap();
    let first = server.receive(&hello, 0).unwrap();
    let [WireAction::Send(flight)] = first.as_slice() else {
        panic!("expected a server handshake flight");
    };
    let [selection, key, done]: [Record<'_>; 3] =
        decode_datagram(flight).unwrap().try_into().unwrap();
    let parameters = decode_server_hello(selection.fragment).unwrap();
    assert_eq!(parameters.key_exchange_index, 1);
    assert_eq!(parameters.cipher_suite, [5, 3]);
    assert_eq!((parameters.sequence_mode, parameters.key_refresh), (2, 2));
    assert_eq!(key.content_type, RecordType::Handshake);
    assert_eq!(&key.fragment[3..7], &[0, 0, 3, 1]); // default parameters and length-prefixed exponent
    assert_eq!(key.fragment[0], 12);
    assert_eq!(done.fragment, [14, 0, 0]);
    assert_eq!(server.status(), Status::Negotiating);
    assert!(server.connection_info().is_none());
    assert_eq!(server.receive(&hello, 5_000).unwrap(), first);
}

#[test]
fn anonymous_server_requires_the_offered_legacy_suite() {
    use wtls_lab::handshake::Message;
    use wtls_lab::wire::{WireError, encode_handshake};
    use wtls_lab::{CipherSpec, LengthForm, encode_datagram};

    let offer = encode_handshake(&Message::ClientHello {
        random: [1; 16],
        resume: None,
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
