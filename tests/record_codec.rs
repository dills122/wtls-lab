use wtls_lab::{
    CipherSpec, DecodeErrorKind, EncodeError, LengthForm, Record, RecordType, decode_datagram,
    encode_datagram,
};

#[test]
fn single_record_can_take_its_length_from_the_sdu() {
    let bytes = [0x43, 0, 0, 0, 0, 0];
    let records = decode_datagram(&bytes).unwrap();

    assert_eq!(
        records,
        [Record {
            content_type: RecordType::Handshake,
            cipher_spec: CipherSpec::Null,
            sequence: 0,
            length_form: LengthForm::DatagramRemainder,
            fragment: &[0, 0, 0],
        }]
    );
    assert_eq!(encode_datagram(&records).unwrap(), bytes);
}

#[test]
fn single_record_can_carry_its_length_explicitly() {
    let bytes = [0xc3, 0, 0, 0, 3, 0, 0, 0];
    let records = decode_datagram(&bytes).unwrap();

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].length_form, LengthForm::Explicit);
    assert_eq!(records[0].fragment, [0, 0, 0]);
    assert_eq!(encode_datagram(&records).unwrap(), bytes);
}

#[test]
fn concatenated_records_keep_their_order_and_wire_flags() {
    let bytes = [
        0xc3, 0x12, 0x34, 0, 3, 0, 0, 0, 0xe4, 0xab, 0xcd, 0, 3, 0xa1, 0xb2, 0xc3,
    ];
    let records = decode_datagram(&bytes).unwrap();

    assert_eq!(
        records,
        [
            Record {
                content_type: RecordType::Handshake,
                cipher_spec: CipherSpec::Null,
                sequence: 0x1234,
                length_form: LengthForm::Explicit,
                fragment: &[0, 0, 0],
            },
            Record {
                content_type: RecordType::ApplicationData,
                cipher_spec: CipherSpec::Current,
                sequence: 0xabcd,
                length_form: LengthForm::Explicit,
                fragment: &[0xa1, 0xb2, 0xc3],
            }
        ]
    );
    assert_eq!(encode_datagram(&records).unwrap(), bytes);
}

#[test]
fn a_lengthless_final_record_consumes_the_entire_remainder() {
    let bytes = [
        0xc3, 0, 0, 0, 3, 0, 0, 0, 0x64, 0, 1, 0xc3, 0, 2, 0, 1, 0xff,
    ];
    let records = decode_datagram(&bytes).unwrap();

    assert_eq!(records.len(), 2);
    assert_eq!(records[1].length_form, LengthForm::DatagramRemainder);
    assert_eq!(records[1].fragment, [0xc3, 0, 2, 0, 1, 0xff]);
    assert_eq!(encode_datagram(&records).unwrap(), bytes);
}

#[test]
fn an_encoder_cannot_put_a_lengthless_record_before_another_record() {
    let first = Record {
        content_type: RecordType::Handshake,
        cipher_spec: CipherSpec::Null,
        sequence: 0,
        length_form: LengthForm::DatagramRemainder,
        fragment: &[0, 0, 0],
    };
    let last = Record {
        length_form: LengthForm::Explicit,
        sequence: 1,
        ..first
    };

    assert_eq!(
        encode_datagram(&[first, last]),
        Err(EncodeError::LengthRequired { record_index: 0 })
    );
}

#[test]
fn decoder_rejects_a_record_without_a_datagram_sequence_field() {
    let error = decode_datagram(&[0x83, 0, 3, 0, 0, 0]).unwrap_err();
    assert_eq!(error.offset, 0);
    assert_eq!(error.kind, DecodeErrorKind::MissingSequence);
}

#[test]
fn decoder_reports_the_offset_of_a_truncated_following_header() {
    let error = decode_datagram(&[0xc3, 0, 0, 0, 3, 0, 0, 0, 0xc2, 0]).unwrap_err();
    assert_eq!(error.offset, 8);
    assert_eq!(
        error.kind,
        DecodeErrorKind::TruncatedHeader {
            expected: 5,
            available: 2,
        }
    );
}

#[test]
fn decoder_reports_truncated_fragments() {
    let error = decode_datagram(&[0xc3, 0, 0, 0, 3, 0]).unwrap_err();
    assert_eq!(
        error.kind,
        DecodeErrorKind::TruncatedFragment {
            declared: 3,
            available: 1,
        }
    );
}

#[test]
fn decoder_reports_empty_datagrams_and_fragments() {
    assert_eq!(
        decode_datagram(&[]).unwrap_err().kind,
        DecodeErrorKind::EmptyDatagram
    );
    for bytes in [&[0x43, 0, 0][..], &[0xc3, 0, 0, 0, 0][..]] {
        assert_eq!(
            decode_datagram(bytes).unwrap_err().kind,
            DecodeErrorKind::EmptyFragment
        );
    }
}

#[test]
fn decoder_reports_reserved_and_unknown_header_values() {
    assert_eq!(
        decode_datagram(&[0x53, 0, 0, 1]).unwrap_err().kind,
        DecodeErrorKind::ReservedBit
    );
    assert_eq!(
        decode_datagram(&[0x45, 0, 0, 1]).unwrap_err().kind,
        DecodeErrorKind::UnknownContentType(5)
    );
}

#[test]
fn fragment_size_is_checked_even_with_an_omitted_length() {
    let payload = vec![0; usize::from(u16::MAX) + 1];
    let fragment = Record {
        content_type: RecordType::ApplicationData,
        cipher_spec: CipherSpec::Current,
        sequence: 0,
        length_form: LengthForm::DatagramRemainder,
        fragment: &payload,
    };
    assert_eq!(
        encode_datagram(&[fragment]),
        Err(EncodeError::InvalidFragmentSize {
            record_index: 0,
            length: payload.len()
        })
    );
    let mut encoded = vec![0x64, 0, 0];
    encoded.extend_from_slice(&payload);
    assert_eq!(
        decode_datagram(&encoded).unwrap_err().kind,
        DecodeErrorKind::FragmentTooLarge {
            length: payload.len()
        }
    );
}

#[test]
fn explicit_length_accepts_the_full_u16_range() {
    let payload = vec![0xaa; usize::from(u16::MAX)];
    let record = Record {
        content_type: RecordType::ApplicationData,
        cipher_spec: CipherSpec::Current,
        sequence: u16::MAX,
        length_form: LengthForm::Explicit,
        fragment: &payload,
    };
    let bytes = encode_datagram(&[record]).unwrap();
    assert_eq!(&bytes[..5], &[0xe4, 0xff, 0xff, 0xff, 0xff]);
    assert_eq!(decode_datagram(&bytes).unwrap(), [record]);
}
