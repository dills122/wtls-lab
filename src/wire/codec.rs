use super::legacy::RSA_ANON;
use super::{NegotiatedParameters, WireError};
use crate::handshake::{Alert, CloseScope, Message, SessionId};

pub(crate) const VERSION: u8 = 1;
pub(crate) const KEY_REFRESH: u8 = 3;
const RSA: u8 = 8;
const TRIPLE_DES: u8 = 6;
const SHA: u8 = 3;
pub(super) const EXPLICIT_SEQUENCE: u8 = 2;
const WTLS_CERT: u8 = 1;
const KEY_HASH: u8 = 254;
const CLIENT_RECORD_CHOICES: &[u8] = &[
    2,
    TRIPLE_DES,
    SHA,
    1,
    0, // one cipher suite and null compression
    EXPLICIT_SEQUENCE,
    KEY_REFRESH,
];
const SERVER_PROFILE: &[u8] = &[TRIPLE_DES, SHA, 0, EXPLICIT_SEQUENCE, KEY_REFRESH];
pub(super) const FIXED_PARAMETERS: NegotiatedParameters = NegotiatedParameters {
    version: VERSION,
    key_exchange: RSA,
    bulk_cipher: TRIPLE_DES,
    mac: SHA,
    compression: 0,
    sequence_mode: EXPLICIT_SEQUENCE,
    key_refresh: KEY_REFRESH,
};

/// A WAP-199 ClientHello before selection of a connection profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello<'a> {
    pub version: u8,
    pub random: [u8; 16],
    pub session_id: &'a [u8],
    pub key_exchanges: Vec<KeyExchangeOffer<'a>>,
    pub trusted_keys: Vec<KeyExchangeOffer<'a>>,
    /// Each pair holds an Appendix A bulk cipher and MAC identifier.
    pub cipher_suites: Vec<[u8; 2]>,
    pub compression: &'a [u8],
    pub sequence_mode: u8,
    pub key_refresh: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyExchangeOffer<'a> {
    pub suite: u8,
    pub parameter_index: u8,
    pub explicit_parameters: Option<&'a [u8]>,
    pub identifier: KeyIdentifier<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyIdentifier<'a> {
    Null,
    Text { character_set: u16, name: &'a [u8] },
    Binary(&'a [u8]),
    KeyHash([u8; 20]),
    X509Name(&'a [u8]),
}

const RSA_OFFER: KeyExchangeOffer<'static> = KeyExchangeOffer {
    suite: RSA,
    parameter_index: 0,
    explicit_parameters: None,
    identifier: KeyIdentifier::Null,
};

impl ClientHello<'_> {
    /// Report the first reason the authenticated server cannot select this offer.
    pub fn profile_mismatch(&self) -> Option<&'static str> {
        self.select_key_exchange(FIXED_PARAMETERS).err()
    }

    fn select_key_exchange(&self, parameters: NegotiatedParameters) -> Result<u8, &'static str> {
        self.check_record_choices(parameters)?;
        // Treat key-exchange identifiers independently of trusted authorities.
        let index = self
            .key_exchanges
            .iter()
            .position(|key| key.suite == parameters.key_exchange && key.parameter_index == 0)
            .ok_or("no compatible default-parameter key exchange offered")?;
        u8::try_from(index + 1).map_err(|_| "selected key exchange index exceeds 255")
    }

    pub(super) fn allows_authority(&self, authority: [u8; 20]) -> bool {
        self.trusted_keys.is_empty()
            || self.trusted_keys.iter().any(|key| {
                key.suite == RSA
                    && key.parameter_index == 0
                    && key.identifier == KeyIdentifier::KeyHash(authority)
            })
    }

    pub(super) fn check_record_choices(
        &self,
        parameters: NegotiatedParameters,
    ) -> Result<(), &'static str> {
        if self.version != parameters.version {
            return Err("WTLS version 1 required");
        }
        if self.sequence_mode != parameters.sequence_mode {
            return Err("explicit sequence numbering required");
        }
        if !self
            .cipher_suites
            .contains(&[parameters.bulk_cipher, parameters.mac])
        {
            return Err("required cipher and MAC pair not offered");
        }
        if !self.compression.contains(&parameters.compression) {
            return Err("null compression not offered");
        }
        Ok(())
    }

    pub(super) fn offered_session(&self) -> Option<SessionId> {
        self.session_id.try_into().ok().map(SessionId)
    }
}

pub(super) struct ServerSelection {
    pub(super) parameters: NegotiatedParameters,
    key_exchange_index: u8,
    client_hello: Vec<u8>,
    received_server_hello: Option<Vec<u8>>,
}

impl ServerSelection {
    pub(super) fn choose(
        offer: &ClientHello<'_>,
        bytes: &[u8],
        mut parameters: NegotiatedParameters,
        abbreviated: bool,
    ) -> Result<Self, WireError> {
        let key_exchange_index = if abbreviated {
            offer
                .check_record_choices(parameters)
                .map_err(|_| WireError::UnsupportedProfile)?;
            offer.select_key_exchange(parameters).unwrap_or(0)
        } else {
            offer
                .select_key_exchange(parameters)
                .map_err(|_| WireError::UnsupportedProfile)?
        };
        parameters.key_refresh = offer.key_refresh.min(parameters.key_refresh);
        Ok(Self {
            parameters,
            key_exchange_index,
            client_hello: bytes.to_vec(),
            received_server_hello: None,
        })
    }

    pub(super) fn accept(
        hello: &ServerHello<'_>,
        server_hello: &[u8],
        client_hello: &[u8],
        cached: Option<NegotiatedParameters>,
    ) -> Result<Self, WireError> {
        // The native ClientHello offers only the fixed suite and explicit
        // sequences, with a maximum refresh setting of KEY_REFRESH.
        let mut parameters = cached.unwrap_or(FIXED_PARAMETERS);
        if hello.version != parameters.version
            || hello.cipher_suite != [parameters.bulk_cipher, parameters.mac]
            || hello.compression != parameters.compression
            || hello.sequence_mode != EXPLICIT_SEQUENCE
            || hello.key_refresh > KEY_REFRESH
            || (hello.key_exchange_index != 1
                && !(cached.is_some() && hello.key_exchange_index == 0))
        {
            return Err(WireError::UnsupportedProfile);
        }
        parameters.sequence_mode = hello.sequence_mode;
        parameters.key_refresh = hello.key_refresh;
        Ok(Self {
            parameters,
            key_exchange_index: hello.key_exchange_index,
            client_hello: client_hello.to_vec(),
            received_server_hello: Some(server_hello.to_vec()),
        })
    }

    pub(super) fn encode(&self, message: &Message) -> Result<Vec<u8>, WireError> {
        // Use the original wire hellos in Finished, including unused offers and IDs.
        match (message, &self.received_server_hello) {
            (Message::ClientHello { .. }, _) => Ok(self.client_hello.clone()),
            (Message::ServerHello { .. }, Some(bytes)) => Ok(bytes.clone()),
            _ => encode_handshake_with_selection(message, self.parameters, self.key_exchange_index),
        }
    }
}

fn handshake_body(bytes: &[u8]) -> Result<(u8, Reader<'_>), WireError> {
    let mut message = Reader::new(bytes);
    let kind = message.byte()?;
    let body = Reader::new(message.vector()?);
    message.end()?;
    Ok((kind, body))
}

/// Read one complete clear ClientHello, preserving the order and raw IDs of offers.
pub fn decode_client_hello(bytes: &[u8]) -> Result<ClientHello<'_>, WireError> {
    let (kind, body) = handshake_body(bytes)?;
    if kind != 1 {
        return Err(WireError::InvalidMessage);
    }
    parse_client_hello(body)
}

/// The selection advertised by a clear WAP-199 ServerHello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHello<'a> {
    pub version: u8,
    pub random: [u8; 16],
    pub session_id: &'a [u8],
    /// One-based index into the preceding ClientHello's key exchanges.
    /// Zero can indicate that the field is to be ignored during resumption.
    pub key_exchange_index: u8,
    pub cipher_suite: [u8; 2],
    pub compression: u8,
    pub sequence_mode: u8,
    pub key_refresh: u8,
}

/// Read one complete clear ServerHello without applying the engine's suite policy.
pub fn decode_server_hello(bytes: &[u8]) -> Result<ServerHello<'_>, WireError> {
    let (kind, body) = handshake_body(bytes)?;
    if kind != 2 {
        return Err(WireError::InvalidMessage);
    }
    parse_server_hello(body)
}

fn parse_server_hello(mut body: Reader<'_>) -> Result<ServerHello<'_>, WireError> {
    let version = body.byte()?;
    let random = body.array()?;
    let session_length = usize::from(body.byte()?);
    if session_length > 8 {
        return Err(WireError::UnsupportedProfile);
    }
    let hello = ServerHello {
        version,
        random,
        session_id: body.take(session_length)?,
        key_exchange_index: body.byte()?,
        cipher_suite: body.array()?,
        compression: body.byte()?,
        sequence_mode: body.byte()?,
        key_refresh: body.byte()?,
    };
    body.end()?;
    Ok(hello)
}

fn parse_client_hello(mut body: Reader<'_>) -> Result<ClientHello<'_>, WireError> {
    let version = body.byte()?;
    let random = body.array()?;
    let session_length = usize::from(body.byte()?);
    if session_length > 8 {
        return Err(WireError::UnsupportedProfile);
    }
    let session_id = body.take(session_length)?;
    let key_exchanges = parse_key_exchanges(body.vector()?)?;
    let trusted_keys = parse_key_exchanges(body.vector()?)?;
    let cipher_length = usize::from(body.byte()?);
    if cipher_length == 0 || !cipher_length.is_multiple_of(2) {
        return Err(WireError::InvalidMessage);
    }
    let cipher_suites = body.take(cipher_length)?.as_chunks::<2>().0.to_vec();
    let compression = body.nonempty_short_vector()?;
    let sequence_mode = body.byte()?;
    let key_refresh = body.byte()?;
    body.end()?;
    Ok(ClientHello {
        version,
        random,
        session_id,
        key_exchanges,
        trusted_keys,
        cipher_suites,
        compression,
        sequence_mode,
        key_refresh,
    })
}

fn parse_key_exchanges(bytes: &[u8]) -> Result<Vec<KeyExchangeOffer<'_>>, WireError> {
    let mut reader = Reader::new(bytes);
    let mut offers = Vec::new();
    while !reader.rest().is_empty() {
        let suite = reader.byte()?;
        let parameter_index = reader.byte()?;
        let explicit_parameters = (parameter_index == 255)
            .then(|| reader.vector())
            .transpose()?;
        let identifier = match reader.byte()? {
            0 => KeyIdentifier::Null,
            1 => KeyIdentifier::Text {
                character_set: u16::from_be_bytes(reader.array()?),
                name: reader.nonempty_short_vector()?,
            },
            2 => KeyIdentifier::Binary(reader.nonempty_short_vector()?),
            KEY_HASH => KeyIdentifier::KeyHash(reader.array()?),
            255 => KeyIdentifier::X509Name(reader.nonempty_short_vector()?),
            _ => return Err(WireError::InvalidMessage),
        };
        offers.push(KeyExchangeOffer {
            suite,
            parameter_index,
            explicit_parameters,
            identifier,
        });
    }
    Ok(offers)
}

/// Encode one complete WAP-199 handshake message for the fixed lab profile.
pub fn encode_handshake(message: &Message) -> Result<Vec<u8>, WireError> {
    encode_handshake_with_selection(message, FIXED_PARAMETERS, 1)
}

pub(super) fn encode_client_hello(
    random: &[u8; 16],
    resume: Option<SessionId>,
    authority: Option<[u8; 20]>,
) -> Result<Vec<u8>, WireError> {
    let mut body = vec![VERSION];
    body.extend_from_slice(random);
    write_session(&mut body, resume);
    write_vector(&mut body, &[RSA, 0, 0])?;
    if let Some(id) = authority {
        let mut entry = [0; 23];
        entry[..3].copy_from_slice(&[RSA, 0, KEY_HASH]);
        entry[3..].copy_from_slice(&id);
        write_vector(&mut body, &entry)?;
    } else {
        write_vector(&mut body, &[])?;
    }
    body.extend_from_slice(CLIENT_RECORD_CHOICES);
    let mut message = vec![1];
    write_vector(&mut message, &body)?;
    Ok(message)
}

fn encode_handshake_with_selection(
    message: &Message,
    parameters: NegotiatedParameters,
    key_exchange_index: u8,
) -> Result<Vec<u8>, WireError> {
    let mut body = Vec::new();
    let kind = match message {
        Message::ClientHello { random, resume } => {
            return encode_client_hello(random, *resume, None);
        }
        Message::ServerHello { random, session } => {
            body.push(parameters.version);
            body.extend_from_slice(random);
            write_session(&mut body, Some(*session));
            body.extend_from_slice(&[
                key_exchange_index,
                parameters.bulk_cipher,
                parameters.mac,
                parameters.compression,
                parameters.sequence_mode,
                parameters.key_refresh,
            ]);
            2
        }
        Message::Certificate(certificate) => {
            if certificate.is_empty() {
                return Err(WireError::InvalidMessage);
            }
            let size =
                u16::try_from(certificate.len() + 1).map_err(|_| WireError::InvalidMessage)?;
            body.extend_from_slice(&size.to_be_bytes());
            body.push(WTLS_CERT);
            body.extend_from_slice(certificate);
            11
        }
        Message::ServerKeyExchange(key) => {
            if parameters.key_exchange != RSA_ANON {
                return Err(WireError::UnsupportedProfile);
            }
            body.extend_from_slice(key);
            12
        }
        Message::ServerHelloDone => 14,
        Message::ClientKeyExchange(exchange) => {
            if exchange.is_empty() {
                return Err(WireError::InvalidMessage);
            }
            if parameters.key_exchange == RSA_ANON {
                body.extend_from_slice(exchange);
            } else {
                write_vector(&mut body, exchange)?;
            }
            16
        }
        Message::Finished(proof) => {
            body.extend_from_slice(proof);
            20
        }
        _ => return Err(WireError::InvalidMessage),
    };
    let mut message = vec![kind];
    write_vector(&mut message, &body)?;
    Ok(message)
}

/// Read one entire handshake fragment encoded for the fixed lab profile.
pub fn decode_handshake(bytes: &[u8]) -> Result<Message, WireError> {
    let (kind, mut body) = handshake_body(bytes)?;

    let decoded = match kind {
        1 => {
            let hello = parse_client_hello(body)?;
            if hello.version != VERSION
                || !matches!(hello.session_id.len(), 0 | 8)
                || hello.key_exchanges != [RSA_OFFER]
                || !hello.trusted_keys.is_empty()
                || hello.cipher_suites != [[TRIPLE_DES, SHA]]
                || hello.compression != [0]
                || hello.sequence_mode != EXPLICIT_SEQUENCE
                || hello.key_refresh != KEY_REFRESH
            {
                return Err(WireError::UnsupportedProfile);
            }
            let resume = hello.session_id.try_into().ok().map(SessionId);
            return Ok(Message::ClientHello {
                random: hello.random,
                resume,
            });
        }
        2 => {
            let hello = parse_server_hello(body)?;
            let session = SessionId(
                hello
                    .session_id
                    .try_into()
                    .map_err(|_| WireError::UnsupportedProfile)?,
            );
            let [bulk_cipher, mac] = hello.cipher_suite;
            if hello.version != VERSION
                || hello.key_exchange_index != 1
                || [
                    bulk_cipher,
                    mac,
                    hello.compression,
                    hello.sequence_mode,
                    hello.key_refresh,
                ] != SERVER_PROFILE
            {
                return Err(WireError::UnsupportedProfile);
            }
            return Ok(Message::ServerHello {
                random: hello.random,
                session,
            });
        }
        11 => {
            let mut list = Reader::new(body.vector()?);
            list.profile(&[WTLS_CERT])?;
            let certificate = list.rest();
            if certificate.is_empty() {
                return Err(WireError::InvalidMessage);
            }
            Message::Certificate(certificate.to_vec())
        }
        14 => Message::ServerHelloDone,
        16 => {
            let exchange = body.vector()?;
            if exchange.is_empty() {
                return Err(WireError::InvalidMessage);
            }
            Message::ClientKeyExchange(exchange.to_vec())
        }
        20 => Message::Finished(body.array()?),
        _ => return Err(WireError::UnsupportedProfile),
    };
    body.end()?;
    Ok(decoded)
}

/// WinWAP sends the modulus-sized RSA ciphertext directly inside the
/// ClientKeyExchange body. The record and handshake already have lengths.
pub(super) fn decode_legacy_client_key_exchange(
    bytes: &[u8],
    ciphertext_len: usize,
) -> Result<Message, WireError> {
    let (kind, mut body) = handshake_body(bytes)?;
    if kind != 16 {
        return Err(WireError::InvalidMessage);
    }
    let exchange = body.take(ciphertext_len)?.to_vec();
    body.end()?;
    Ok(Message::ClientKeyExchange(exchange))
}

fn write_session(out: &mut Vec<u8>, session: Option<SessionId>) {
    match session {
        Some(id) => {
            out.push(8);
            out.extend_from_slice(&id.0);
        }
        None => out.push(0),
    }
}

pub(super) enum InitialAlert {
    UnknownKeyId,
    HandshakeFailure,
}

impl InitialAlert {
    pub(super) fn encode(self, checksum: [u8; 4]) -> [u8; 6] {
        let (level, description) = match self {
            Self::UnknownKeyId => (2, 52),
            Self::HandshakeFailure => (3, 40),
        };
        AlertFields {
            level,
            description,
            checksum,
        }
        .encode()
    }
}

pub(super) fn encode_alert(alert: Alert, checksum: [u8; 4]) -> [u8; 6] {
    let (level, description) = match alert {
        Alert::CloseNotify(CloseScope::Connection) => (2, 0),
        Alert::CloseNotify(CloseScope::Session) => (3, 1),
        Alert::DuplicateFinishedReceived => (1, 57),
    };
    AlertFields {
        level,
        description,
        checksum,
    }
    .encode()
}

/// Raw fields from a complete clear or authenticated alert fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlertFields {
    pub level: u8,
    pub description: u8,
    pub checksum: [u8; 4],
}

pub fn decode_alert_fields(data: &[u8]) -> Result<AlertFields, WireError> {
    let [level, description, a, b, c, d] = *data else {
        return Err(WireError::InvalidMessage);
    };
    Ok(AlertFields {
        level,
        description,
        checksum: [a, b, c, d],
    })
}

impl AlertFields {
    pub(super) fn encode(self) -> [u8; 6] {
        let [a, b, c, d] = self.checksum;
        [self.level, self.description, a, b, c, d]
    }

    /// The WAP-199 §10.2 name for a recognized alert description.
    pub fn description_name(self) -> Option<&'static str> {
        Some(match self.description {
            0 => "connection-close-notify",
            1 => "session-close-notify",
            5 => "no-connection",
            10 => "unexpected-message",
            11 => "time-required",
            20 => "bad-record-mac",
            21 => "decryption-failed",
            22 => "record-overflow",
            30 => "decompression-failure",
            40 => "handshake-failure",
            42 => "bad-certificate",
            43 => "unsupported-certificate",
            44 => "certificate-revoked",
            45 => "certificate-expired",
            46 => "certificate-unknown",
            47 => "illegal-parameter",
            48 => "unknown-ca",
            49 => "access-denied",
            50 => "decode-error",
            51 => "decrypt-error",
            52 => "unknown-key-id",
            53 => "disabled-key-id",
            54 => "key-exchange-disabled",
            55 => "session-not-ready",
            56 => "unknown-parameter-index",
            57 => "duplicate-finished-received",
            60 => "export-restriction",
            70 => "protocol-version",
            71 => "insufficient-security",
            80 => "internal-error",
            90 => "user-canceled",
            100 => "no-renegotiation",
            _ => return None,
        })
    }

    pub(super) fn supported_alert(self) -> Result<Option<Alert>, WireError> {
        Ok(match (self.level, self.description) {
            (2, 0) => Some(Alert::CloseNotify(CloseScope::Connection)),
            (3, 1) => Some(Alert::CloseNotify(CloseScope::Session)),
            (_, 0 | 1) => return Err(WireError::InvalidMessage),
            (1, 57) => Some(Alert::DuplicateFinishedReceived),
            _ => None,
        })
    }
}

pub(super) fn write_vector(out: &mut Vec<u8>, data: &[u8]) -> Result<(), WireError> {
    let len = u16::try_from(data.len()).map_err(|_| WireError::InvalidMessage)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

pub(super) struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(super) fn new(data: &'a [u8]) -> Self {
        Self { remaining: data }
    }

    pub(super) fn take(&mut self, count: usize) -> Result<&'a [u8], WireError> {
        let (head, tail) = self
            .remaining
            .split_at_checked(count)
            .ok_or(WireError::InvalidMessage)?;
        self.remaining = tail;
        Ok(head)
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        self.take(N)?
            .try_into()
            .map_err(|_| WireError::InvalidMessage)
    }

    pub(super) fn byte(&mut self) -> Result<u8, WireError> {
        let [value] = self.array()?;
        Ok(value)
    }

    pub(super) fn vector(&mut self) -> Result<&'a [u8], WireError> {
        let count = u16::from_be_bytes(self.array()?);
        self.take(usize::from(count))
    }

    fn nonempty_short_vector(&mut self) -> Result<&'a [u8], WireError> {
        let len = usize::from(self.byte()?);
        if len == 0 {
            return Err(WireError::InvalidMessage);
        }
        self.take(len)
    }

    pub(super) fn profile(&mut self, expected: &[u8]) -> Result<(), WireError> {
        if self.take(expected.len())? != expected {
            return Err(WireError::UnsupportedProfile);
        }
        Ok(())
    }

    pub(super) fn rest(&self) -> &'a [u8] {
        self.remaining
    }

    pub(super) fn end(self) -> Result<(), WireError> {
        if !self.remaining.is_empty() {
            return Err(WireError::InvalidMessage);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_rsa_profile_cannot_encode_an_anonymous_server_key_exchange() {
        let exchange = Message::ServerKeyExchange(vec![0, 0, 1, 3, 0, 1, 1]);
        assert_eq!(
            encode_handshake(&exchange),
            Err(WireError::UnsupportedProfile)
        );
        let mut winwap = FIXED_PARAMETERS;
        winwap.key_exchange = RSA_ANON;
        assert_eq!(
            encode_handshake_with_selection(&exchange, winwap, 1).unwrap()[0],
            12
        );
    }

    #[test]
    fn winwap_rsa_ciphertext_uses_the_handshake_length_without_an_extra_vector() {
        let mut winwap = FIXED_PARAMETERS;
        winwap.key_exchange = RSA_ANON;
        let exchange = Message::ClientKeyExchange(vec![0xa5; 256]);
        let raw = encode_handshake_with_selection(&exchange, winwap, 1).unwrap();
        assert_eq!(&raw[..3], &[16, 1, 0]);
        assert_eq!(
            decode_legacy_client_key_exchange(&raw, 256).unwrap(),
            exchange
        );
        assert!(decode_legacy_client_key_exchange(&raw, 257).is_err());
        assert!(decode_legacy_client_key_exchange(&raw, 255).is_err());
        let vector = encode_handshake(&exchange).unwrap();
        assert_eq!(&vector[..5], &[16, 1, 2, 1, 0]);
        assert!(decode_legacy_client_key_exchange(&vector, 256).is_err());
    }
}
