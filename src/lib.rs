//! WAP-199 WTLS record framing over a bounded transport SDU.
//!
//! Payloads are opaque. The codec preserves the cipher-spec bit and explicit
//! sequence field so a protocol state machine can interpret them later.

#![forbid(unsafe_code)]

pub mod handshake;
pub mod wire;

use std::error::Error;
use std::fmt;

const LENGTH_PRESENT: u8 = 0x80;
const SEQUENCE_PRESENT: u8 = 0x40;
const CURRENT_CIPHER_SPEC: u8 = 0x20;
const RESERVED: u8 = 0x10;
const CONTENT_TYPE: u8 = 0x0f;
const MAX_FRAGMENT_LENGTH: usize = u16::MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    ChangeCipherSpec = 1,
    Alert = 2,
    Handshake = 3,
    ApplicationData = 4,
}

impl RecordType {
    fn from_nibble(value: u8) -> Result<Self, DecodeErrorKind> {
        match value {
            1 => Ok(Self::ChangeCipherSpec),
            2 => Ok(Self::Alert),
            3 => Ok(Self::Handshake),
            4 => Ok(Self::ApplicationData),
            other => Err(DecodeErrorKind::UnknownContentType(other)),
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ChangeCipherSpec => "change-cipher-spec",
            Self::Alert => "alert",
            Self::Handshake => "handshake",
            Self::ApplicationData => "application-data",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSpec {
    Null,
    Current,
}

impl fmt::Display for CipherSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Null => "null",
            Self::Current => "current",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthForm {
    Explicit,
    DatagramRemainder,
}

impl LengthForm {
    fn header_len(self) -> usize {
        match self {
            Self::Explicit => 5,
            Self::DatagramRemainder => 3,
        }
    }
}

impl fmt::Display for LengthForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Explicit => "explicit",
            Self::DatagramRemainder => "datagram-remainder",
        })
    }
}

/// One WTLS record envelope. The immutable fragment is borrowed from the SDU
/// when decoding, or supplied by the caller when encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    pub content_type: RecordType,
    pub cipher_spec: CipherSpec,
    pub sequence: u16,
    pub length_form: LengthForm,
    pub fragment: &'a [u8],
}

impl Record<'_> {
    /// The WTLS record type octet, including the field presence flags.
    pub fn header_byte(&self) -> u8 {
        let mut header = SEQUENCE_PRESENT | self.content_type as u8;
        if self.length_form == LengthForm::Explicit {
            header |= LENGTH_PRESENT;
        }
        if self.cipher_spec == CipherSpec::Current {
            header |= CURRENT_CIPHER_SPEC;
        }
        header
    }

    /// Size of the record envelope and fragment on the wire.
    pub fn wire_len(&self) -> usize {
        self.length_form.header_len() + self.fragment.len()
    }
}

/// A framed WTLS record as observed on the wire, before datagram policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordEnvelope<'a> {
    header: u8,
    pub sequence: Option<u16>,
    pub length_form: LengthForm,
    pub fragment: &'a [u8],
}

impl RecordEnvelope<'_> {
    pub fn header_byte(&self) -> u8 {
        self.header
    }

    pub fn content_type(&self) -> Result<RecordType, DecodeErrorKind> {
        RecordType::from_nibble(self.header & CONTENT_TYPE)
    }

    pub fn cipher_spec(&self) -> CipherSpec {
        if self.header & CURRENT_CIPHER_SPEC == 0 {
            CipherSpec::Null
        } else {
            CipherSpec::Current
        }
    }

    pub fn wire_len(&self) -> usize {
        let implicit_header_len = 1 + 2 * usize::from(self.sequence.is_some());
        implicit_header_len
            + 2 * usize::from(self.length_form == LengthForm::Explicit)
            + self.fragment.len()
    }

    /// Check the header against the active datagram record profile.
    pub fn check_datagram_header(&self) -> Result<(), DecodeErrorKind> {
        check_datagram_header(self.header).map(|_| ())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError {
    /// Byte offset of the record whose decoding failed.
    pub offset: usize,
    pub kind: DecodeErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeErrorKind {
    EmptyDatagram,
    ReservedBit,
    MissingSequence,
    UnknownContentType(u8),
    TruncatedHeader { expected: usize, available: usize },
    EmptyFragment,
    FragmentTooLarge { length: usize },
    TruncatedFragment { declared: usize, available: usize },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "byte {}: ", self.offset)?;
        self.kind.fmt(f)
    }
}

impl fmt::Display for DecodeErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            DecodeErrorKind::EmptyDatagram => f.write_str("empty datagram"),
            DecodeErrorKind::ReservedBit => f.write_str("reserved record header bit is set"),
            DecodeErrorKind::MissingSequence => {
                f.write_str("datagram record is missing its explicit sequence field")
            }
            DecodeErrorKind::UnknownContentType(value) => {
                write!(f, "unknown record content type {value}")
            }
            DecodeErrorKind::TruncatedHeader {
                expected,
                available,
            } => write!(
                f,
                "truncated record header (needs {expected} bytes, has {available})"
            ),
            DecodeErrorKind::EmptyFragment => f.write_str("empty record fragment"),
            DecodeErrorKind::FragmentTooLarge { length } => write!(
                f,
                "record fragment has {length} bytes, maximum is {MAX_FRAGMENT_LENGTH}"
            ),
            DecodeErrorKind::TruncatedFragment {
                declared,
                available,
            } => write!(
                f,
                "truncated record fragment (declares {declared} bytes, has {available})"
            ),
        }
    }
}

impl Error for DecodeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    EmptyDatagram,
    LengthRequired { record_index: usize },
    InvalidFragmentSize { record_index: usize, length: usize },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDatagram => f.write_str("cannot encode an empty datagram"),
            Self::LengthRequired { record_index } => {
                write!(
                    f,
                    "record {record_index} needs a length before another record"
                )
            }
            Self::InvalidFragmentSize {
                record_index,
                length,
            } => write!(
                f,
                "record {record_index} has {length} fragment bytes, expected 1..={MAX_FRAGMENT_LENGTH}"
            ),
        }
    }
}

impl Error for EncodeError {}

/// Decode exactly one transport SDU.
///
/// An omitted length consumes the remainder of this SDU, following the
/// detailed flag rule of WAP-199 §9.2.1. Each earlier record needs a length.
pub fn decode_datagram(bytes: &[u8]) -> Result<Vec<Record<'_>>, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError {
            offset: 0,
            kind: DecodeErrorKind::EmptyDatagram,
        });
    }

    let mut records = Vec::new();
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let record = decode_record(remaining).map_err(|kind| DecodeError {
            offset: bytes.len() - remaining.len(),
            kind,
        })?;
        remaining = &remaining[record.wire_len()..];
        records.push(record);
    }
    Ok(records)
}

// The caller only passes a non-empty remainder of the SDU.
fn decode_record(bytes: &[u8]) -> Result<Record<'_>, DecodeErrorKind> {
    let content_type = check_datagram_header(bytes[0])?;
    let envelope = decode_record_envelope(bytes)?;
    Ok(Record {
        content_type,
        cipher_spec: envelope.cipher_spec(),
        sequence: envelope.sequence.ok_or(DecodeErrorKind::MissingSequence)?,
        length_form: envelope.length_form,
        fragment: envelope.fragment,
    })
}

fn check_datagram_header(header: u8) -> Result<RecordType, DecodeErrorKind> {
    if header & RESERVED != 0 {
        return Err(DecodeErrorKind::ReservedBit);
    }
    if header & SEQUENCE_PRESENT == 0 {
        return Err(DecodeErrorKind::MissingSequence);
    }
    RecordType::from_nibble(header & CONTENT_TYPE)
}

/// Frame the first record in one SDU remainder using its actual presence flags.
/// An omitted length consumes the remainder. Use [RecordEnvelope::wire_len]
/// to advance only after framing succeeds.
pub fn decode_record_envelope(bytes: &[u8]) -> Result<RecordEnvelope<'_>, DecodeErrorKind> {
    let header = *bytes.first().ok_or(DecodeErrorKind::EmptyDatagram)?;
    let sequence_present = header & SEQUENCE_PRESENT != 0;
    let length_present = header & LENGTH_PRESENT != 0;
    let length_at = 1 + 2 * usize::from(sequence_present);
    let header_len = length_at + 2 * usize::from(length_present);
    let payload = bytes
        .get(header_len..)
        .ok_or(DecodeErrorKind::TruncatedHeader {
            expected: header_len,
            available: bytes.len(),
        })?;
    let sequence = sequence_present.then(|| u16::from_be_bytes([bytes[1], bytes[2]]));
    let (length, length_form) = if length_present {
        (
            usize::from(u16::from_be_bytes([bytes[length_at], bytes[length_at + 1]])),
            LengthForm::Explicit,
        )
    } else {
        (payload.len(), LengthForm::DatagramRemainder)
    };
    if length == 0 {
        return Err(DecodeErrorKind::EmptyFragment);
    }
    if length > MAX_FRAGMENT_LENGTH {
        return Err(DecodeErrorKind::FragmentTooLarge { length });
    }
    let fragment = payload
        .get(..length)
        .ok_or(DecodeErrorKind::TruncatedFragment {
            declared: length,
            available: payload.len(),
        })?;
    Ok(RecordEnvelope {
        header,
        sequence,
        length_form,
        fragment,
    })
}

/// Encode records into one SDU and preserve the requested length forms.
pub fn encode_datagram(records: &[Record<'_>]) -> Result<Vec<u8>, EncodeError> {
    if records.is_empty() {
        return Err(EncodeError::EmptyDatagram);
    }

    let mut bytes = Vec::new();
    for (record_index, record) in records.iter().enumerate() {
        let length = record.fragment.len();
        let length_field = u16::try_from(length)
            .ok()
            .filter(|&length| length > 0)
            .ok_or(EncodeError::InvalidFragmentSize {
                record_index,
                length,
            })?;
        if record.length_form == LengthForm::DatagramRemainder && record_index + 1 < records.len() {
            return Err(EncodeError::LengthRequired { record_index });
        }

        bytes.push(record.header_byte());
        bytes.extend_from_slice(&record.sequence.to_be_bytes());
        if record.length_form == LengthForm::Explicit {
            bytes.extend_from_slice(&length_field.to_be_bytes());
        }
        bytes.extend_from_slice(record.fragment);
    }
    Ok(bytes)
}
