//! In-memory wire peer for one authenticated WAP-199 profile.
//!
//! Uses RSA key transport, native RSA WTLS certificates, 3DES-CBC-EDE,
//! full HMAC-SHA-1, null compression and explicit datagram sequences.

mod certificate;
mod codec;
mod legacy;
mod protection;
mod report;

use std::collections::VecDeque;
use std::error::Error;
use std::fmt;

use openssl::error::ErrorStack;
use openssl::pkey::Private;
use openssl::rand::rand_bytes;
use openssl::rsa::Rsa;

pub use certificate::{ServerIdentity, TrustAnchor, issue_certificate};
pub use codec::{
    AlertFields, ClientHello, KeyExchangeOffer, KeyIdentifier, ServerHello, decode_alert_fields,
    decode_client_hello, decode_handshake, decode_server_hello, encode_handshake,
};

pub use report::{
    AlertProtection, ConnectionInfo, DatagramBudget, DatagramTooLarge, NegotiatedParameters,
    PeerAuthentication,
};

use codec::{FIXED_PARAMETERS, ServerSelection, decode_legacy_client_key_exchange, encode_alert};
use legacy::WINWAP_PARAMETERS;
use protection::{MAX_PLAINTEXT, Traffic, WireFinished};

use crate::handshake::{
    Action, CloseScope, Datagram, Handshake, HandshakeError, HandshakeKind, Message, RetryPolicy,
    Role, SessionId, Status,
};
use crate::{CipherSpec, DecodeError, EncodeError, LengthForm, Record, RecordType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    InvalidMessage,
    InvalidRecord,
    UnsupportedProfile,
    CertificateRejected,
    AuthenticationFailed,
    /// An alert that was observed but is not handled by the active engine profile.
    PeerAlert {
        fields: AlertFields,
        protection: AlertProtection,
    },
    Provider,
    Decode(DecodeError),
    Encode(EncodeError),
    Handshake(HandshakeError),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMessage => f.write_str("invalid WTLS message"),
            Self::InvalidRecord => f.write_str("record is invalid in the current WTLS state"),
            Self::UnsupportedProfile => f.write_str("unsupported WTLS lab profile"),
            Self::CertificateRejected => f.write_str("WTLS server certificate rejected"),
            Self::AuthenticationFailed => f.write_str("WTLS authentication failed"),
            Self::PeerAlert { fields, protection } => write!(
                f,
                "WTLS peer alert ({protection}, level {}, {} {})",
                fields.level,
                fields.description_name().unwrap_or("code"),
                fields.description,
            ),
            Self::Provider => f.write_str("WTLS cryptographic provider unavailable or failed"),
            Self::Decode(error) => error.fmt(f),
            Self::Encode(error) => error.fmt(f),
            Self::Handshake(error) => error.fmt(f),
        }
    }
}

impl Error for WireError {}

impl From<ErrorStack> for WireError {
    fn from(_: ErrorStack) -> Self {
        Self::Provider
    }
}

impl From<HandshakeError> for WireError {
    fn from(error: HandshakeError) -> Self {
        match error {
            HandshakeError::FinishedVerificationFailed => Self::AuthenticationFailed,
            HandshakeError::FinishedUnavailable => Self::Provider,
            _ => Self::Handshake(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireAction {
    Send(Vec<u8>),
    Established(HandshakeKind),
    Deliver(Vec<u8>),
    Closed(CloseScope),
    TimedOut,
}

enum Side {
    Client { trust: TrustAnchor, now: u32 },
    Server(Rsa<Private>),
    LegacyServer(Rsa<Private>),
}

#[derive(Clone, Copy, Default)]
struct Direction {
    protected: bool,
    sequence: u32,
}

impl Direction {
    fn next(&mut self) -> Result<u16, WireError> {
        let sequence = u16::try_from(self.sequence).map_err(|_| WireError::InvalidRecord)?;
        self.sequence += 1;
        Ok(sequence)
    }

    fn activate(&mut self) {
        self.protected = true;
        self.sequence = 0;
    }
}

struct Flight {
    messages: Datagram,
    bytes: Vec<u8>,
}

struct Incoming {
    messages: Datagram,
    read: Direction,
    traffic: Option<Traffic>,
    checksum: [u8; 4],
    selection: Option<ServerSelection>,
}

/// A full-handshake-only association driven by one in-memory datagram at a time.
/// The caller delivers the emitted bytes to the other peer and drives the clock.
pub struct WirePeer {
    side: Side,
    handshake: Handshake,
    random: Option<[u8; 16]>,
    peer_random: Option<[u8; 16]>,
    traffic: Option<Traffic>,
    read: Direction,
    write: Direction,
    received_flights: Vec<Flight>,
    sent_flights: Vec<Flight>,
    sent_checksums: VecDeque<[u8; 4]>,
    last_received: [u8; 4],
    selection: Option<ServerSelection>,
}

impl WirePeer {
    pub fn client(retry: RetryPolicy, trust: TrustAnchor, now: u32) -> Self {
        Self::new(
            Side::Client { trust, now },
            Handshake::client(retry, Vec::new(), None),
            None,
        )
    }

    pub fn server(identity: ServerIdentity, now: u32) -> Result<Self, WireError> {
        let (random, session) = server_parameters(now)?;
        let handshake = Handshake::server(session, random, identity.certificate, None);
        Ok(Self::new(
            Side::Server(identity.key),
            handshake,
            Some(random),
        ))
    }

    /// Opt into the anonymous RSA/DES-CBC profile observed in WinWAP.
    /// Use a dedicated ephemeral key and an isolated transport for this legacy profile.
    pub fn legacy_winwap_server(now: u32) -> Result<Self, WireError> {
        let (random, session) = server_parameters(now)?;
        let key = Rsa::generate(2048)?;
        let handshake = legacy_server_handshake(&key, session, random)?;
        Ok(Self::new(Side::LegacyServer(key), handshake, Some(random)))
    }

    fn new(side: Side, handshake: Handshake, random: Option<[u8; 16]>) -> Self {
        Self {
            side,
            handshake,
            random,
            peer_random: None,
            traffic: None,
            read: Direction::default(),
            write: Direction::default(),
            received_flights: Vec::new(),
            sent_flights: Vec::new(),
            sent_checksums: VecDeque::new(),
            last_received: [0; 4],
            selection: None,
        }
    }

    pub fn status(&self) -> Status {
        self.handshake.status()
    }

    /// Provide negotiated parameters only after the full handshake is established.
    pub fn connection_info(&self) -> Option<ConnectionInfo> {
        (self.status() == Status::Open).then_some(ConnectionInfo {
            parameters: self
                .selection
                .as_ref()
                .map_or(FIXED_PARAMETERS, |selection| selection.parameters),
            peer_authentication: match self.side {
                Side::Client { .. } => PeerAuthentication::VerifiedServerCertificate,
                Side::Server(_) | Side::LegacyServer(_) => PeerAuthentication::None,
            },
        })
    }

    pub fn deadline(&self) -> Option<u64> {
        self.handshake.deadline()
    }

    pub fn start(&mut self, monotonic_ms: u64) -> Result<Vec<WireAction>, WireError> {
        let Side::Client { now, .. } = self.side else {
            return Err(HandshakeError::InvalidState.into());
        };
        let random = random(now)?;
        let actions = self.handshake.start(random, monotonic_ms)?;
        self.random = Some(random);
        self.apply(actions)
    }

    pub fn tick(&mut self, monotonic_ms: u64) -> Result<Vec<WireAction>, WireError> {
        let actions = self.handshake.tick(monotonic_ms);
        self.apply(actions)
    }

    pub fn send_application(&mut self, payload: Vec<u8>) -> Result<Vec<WireAction>, WireError> {
        if payload.is_empty() || payload.len() > MAX_PLAINTEXT {
            return Err(WireError::InvalidRecord);
        }
        let actions = self.handshake.send_application(payload)?;
        self.apply(actions)
    }

    pub fn close(&mut self, scope: CloseScope) -> Result<Vec<WireAction>, WireError> {
        let actions = self.handshake.close(scope)?;
        self.apply(actions)
    }

    pub fn receive(
        &mut self,
        bytes: &[u8],
        monotonic_ms: u64,
    ) -> Result<Vec<WireAction>, WireError> {
        if self.status() == Status::Closed {
            return Ok(Vec::new());
        }

        // Only previously validated handshake SDUs bypass the current epoch's
        // sequence checks. A replay cannot install keys or rerun key exchange.
        if let Some(flight) = self
            .received_flights
            .iter()
            .find(|flight| flight.bytes == bytes)
        {
            let actions = self.handshake.receive(
                &flight.messages,
                monotonic_ms,
                &WireFinished(self.traffic.as_ref(), self.selection.as_ref()),
            )?;
            return self.apply(actions);
        }

        let mut incoming = self.decode(bytes)?;
        let has_handshake = carries_handshake(&incoming.messages);
        if let [
            Message::ServerHello { random: remote, .. },
            Message::Certificate(certificate),
            Message::ServerHelloDone,
        ] = incoming.messages.as_slice()
            && let Side::Client { trust, now } = &self.side
            && self.traffic.is_none()
        {
            let local = self.random.ok_or(WireError::InvalidMessage)?;
            if *remote == local {
                return Err(WireError::InvalidMessage);
            }
            let key = match trust.verify(certificate, *now) {
                Ok(key) => key,
                Err(error) => {
                    self.handshake.abort();
                    return Err(error);
                }
            };
            let (exchange, traffic) = Traffic::begin_client(&key, local, *remote)?;
            self.handshake.install_client_key_exchange(exchange)?;
            incoming.traffic = Some(traffic);
        }

        let context = WireFinished(
            incoming.traffic.as_ref().or(self.traffic.as_ref()),
            self.selection.as_ref(),
        );
        if let [Message::ClientHello { .. }] = incoming.messages.as_slice()
            && let Some(offered_id) = incoming
                .selection
                .as_ref()
                .and_then(|offer| offer.offered_session)
            && let Some(fresh_session) = self.handshake.idle_server_session()
            && *fresh_session == offered_id
        {
            let mut fresh = offered_id.0;
            while fresh == offered_id.0 {
                rand_bytes(&mut fresh)?;
            }
            *fresh_session = SessionId(fresh);
        }
        let actions = match self
            .handshake
            .receive(&incoming.messages, monotonic_ms, &context)
        {
            Ok(actions) => actions,
            Err(error) => {
                if self.status() == Status::Closed {
                    self.traffic = None;
                }
                return Err(error.into());
            }
        };

        self.read = incoming.read;
        if let Some(selection) = incoming.selection {
            self.selection = Some(selection);
        }
        if let Some(traffic) = incoming.traffic {
            self.traffic = Some(traffic);
        }
        if let [Message::ClientHello { random, .. }] = incoming.messages.as_slice() {
            self.peer_random = Some(*random);
        }
        if has_handshake || !actions.is_empty() {
            self.last_received = incoming.checksum;
        }
        if has_handshake {
            self.received_flights.push(Flight {
                messages: incoming.messages,
                bytes: bytes.to_vec(),
            });
        }
        self.apply(actions)
    }

    fn decode(&self, bytes: &[u8]) -> Result<Incoming, WireError> {
        let records = crate::decode_datagram(bytes).map_err(WireError::Decode)?;
        let last = records.last().ok_or(WireError::InvalidRecord)?;
        let checksum = record_checksum(&bytes[bytes.len() - last.wire_len()..]);
        let mut read = self.read;
        let mut traffic = None;
        let mut messages = Vec::new();
        let mut awaiting_finished = false;
        let mut selection = None;
        let server_profile = match self.side {
            Side::Server(_) => Some(FIXED_PARAMETERS),
            Side::LegacyServer(_) => Some(WINWAP_PARAMETERS),
            Side::Client { .. } => None,
        };

        for record in records {
            let message = match (read.protected, record.cipher_spec) {
                (false, CipherSpec::Null) if record.sequence == read.next()? => {
                    if record.content_type == RecordType::Alert
                        && self.status() == Status::Negotiating
                    {
                        return Err(WireError::PeerAlert {
                            fields: decode_alert_fields(record.fragment)?,
                            protection: AlertProtection::Clear,
                        });
                    }

                    if record.content_type == RecordType::ChangeCipherSpec && record.fragment == [1]
                    {
                        read.activate();
                        awaiting_finished = true;
                        Message::ChangeCipherSpec
                    } else if record.content_type == RecordType::Handshake {
                        let message = if record.fragment.first() == Some(&1)
                            && let Some(parameters) = server_profile
                        {
                            if self.status() != Status::Idle {
                                return Err(WireError::InvalidRecord);
                            }
                            let selected = ServerSelection::select(record.fragment, parameters)?;
                            let random = selected.client_random;
                            selection = Some(selected);
                            // Every offered ID is a cache miss for this full-handshake profile.
                            Message::ClientHello {
                                random,
                                resume: None,
                            }
                        } else if let Side::LegacyServer(key) = &self.side
                            && record.fragment.first() == Some(&16)
                        {
                            decode_legacy_client_key_exchange(record.fragment, key.size() as usize)?
                        } else {
                            decode_handshake(record.fragment)?
                        };
                        match &message {
                            Message::Finished(_) => return Err(WireError::InvalidRecord),
                            Message::ClientHello {
                                resume: Some(_), ..
                            } => {
                                return Err(WireError::UnsupportedProfile);
                            }
                            Message::ClientKeyExchange(exchange) => {
                                let key = match &self.side {
                                    Side::Server(key) | Side::LegacyServer(key) => key,
                                    Side::Client { .. } => return Err(WireError::InvalidRecord),
                                };
                                if !messages.is_empty() || self.traffic.is_some() {
                                    return Err(WireError::InvalidRecord);
                                }
                                let local = self.random.ok_or(WireError::InvalidRecord)?;
                                let remote = self.peer_random.ok_or(WireError::InvalidRecord)?;
                                let selected =
                                    self.selection.as_ref().ok_or(WireError::InvalidRecord)?;
                                traffic = Some(Traffic::begin_server(
                                    exchange,
                                    key,
                                    remote,
                                    local,
                                    selected.parameters,
                                )?);
                            }
                            _ => {}
                        }
                        message
                    } else {
                        return Err(WireError::InvalidRecord);
                    }
                }
                (true, CipherSpec::Current) => {
                    let keys = traffic
                        .as_ref()
                        .or(self.traffic.as_ref())
                        .ok_or(WireError::InvalidRecord)?;
                    let content = keys.open(self.remote_role(), record)?;
                    if awaiting_finished {
                        if record.sequence != 0 || record.content_type != RecordType::Handshake {
                            return Err(WireError::InvalidRecord);
                        }
                        let finished = decode_handshake(&content)?;
                        if !matches!(finished, Message::Finished(_)) {
                            return Err(WireError::InvalidRecord);
                        }
                        awaiting_finished = false;
                        finished
                    } else {
                        self.decode_open_record(record, &content)?
                    }
                }
                _ => return Err(WireError::InvalidRecord),
            };
            messages.push(message);
        }
        if awaiting_finished {
            return Err(WireError::InvalidRecord);
        }
        Ok(Incoming {
            messages,
            read,
            traffic,
            checksum,
            selection,
        })
    }

    fn decode_open_record(&self, record: Record<'_>, data: &[u8]) -> Result<Message, WireError> {
        if record.sequence == 0 {
            return Err(WireError::InvalidRecord);
        }
        match record.content_type {
            RecordType::ApplicationData => Ok(Message::ApplicationData {
                sequence: record.sequence,
                payload: data.to_vec(),
            }),
            RecordType::Alert => {
                let fields = decode_alert_fields(data)?;
                if !self.sent_checksums.contains(&fields.checksum) {
                    return Err(WireError::AuthenticationFailed);
                }
                fields
                    .supported_alert()
                    .map(Message::Alert)
                    .ok_or(WireError::PeerAlert {
                        fields,
                        protection: AlertProtection::Authenticated,
                    })
            }
            _ => Err(WireError::InvalidRecord),
        }
    }

    fn apply(&mut self, actions: Vec<Action>) -> Result<Vec<WireAction>, WireError> {
        let result = actions
            .into_iter()
            .map(|action| {
                Ok(match action {
                    Action::Send(messages) => WireAction::Send(self.encode(messages)?),
                    Action::Established { kind, .. } => WireAction::Established(kind),
                    Action::Deliver(data) => WireAction::Deliver(data),
                    Action::Closed(scope) => WireAction::Closed(scope),
                    Action::TimedOut => WireAction::TimedOut,
                })
            })
            .collect::<Result<Vec<_>, _>>();

        if result.is_err() {
            self.handshake.abort();
        }
        if self.status() == Status::Closed {
            self.traffic = None;
        }
        result
    }

    fn encode(&mut self, messages: Datagram) -> Result<Vec<u8>, WireError> {
        if let Some(flight) = self
            .sent_flights
            .iter()
            .find(|flight| flight.messages == messages)
        {
            return Ok(flight.bytes.clone());
        }
        let mut write = self.write;
        let mut datagram = Vec::new();
        let mut checksums = Vec::new();

        for message in &messages {
            let (content_type, plaintext) = match message {
                Message::ChangeCipherSpec => (RecordType::ChangeCipherSpec, vec![1]),
                Message::Alert(alert) => (
                    RecordType::Alert,
                    encode_alert(*alert, self.last_received).to_vec(),
                ),
                Message::ApplicationData { payload, .. } => {
                    (RecordType::ApplicationData, payload.clone())
                }
                _ => (
                    RecordType::Handshake,
                    match &self.selection {
                        Some(selection) => selection.encode(message)?,
                        None => encode_handshake(message)?,
                    },
                ),
            };
            let mut record = Record {
                content_type,
                cipher_spec: if write.protected {
                    CipherSpec::Current
                } else {
                    CipherSpec::Null
                },
                sequence: write.next()?,
                length_form: LengthForm::Explicit,
                fragment: &plaintext,
            };
            let protected;
            if write.protected {
                let traffic = self.traffic.as_ref().ok_or(WireError::InvalidRecord)?;
                protected = traffic.seal(self.local_role(), record)?;
                record.fragment = &protected;
            }
            let bytes = crate::encode_datagram(&[record]).map_err(WireError::Encode)?;
            checksums.push(record_checksum(&bytes));
            datagram.extend_from_slice(&bytes);
            if content_type == RecordType::ChangeCipherSpec {
                write.activate();
            }
        }

        self.write = write;
        for checksum in checksums {
            if self.sent_checksums.len() == 32 {
                self.sent_checksums.pop_front();
            }
            self.sent_checksums.push_back(checksum);
        }
        if carries_handshake(&messages) {
            self.sent_flights.push(Flight {
                messages,
                bytes: datagram.clone(),
            });
        }
        Ok(datagram)
    }

    fn local_role(&self) -> Role {
        match self.side {
            Side::Client { .. } => Role::Client,
            Side::Server(_) | Side::LegacyServer(_) => Role::Server,
        }
    }

    fn remote_role(&self) -> Role {
        match self.local_role() {
            Role::Client => Role::Server,
            Role::Server => Role::Client,
        }
    }
}

fn legacy_server_handshake(
    key: &Rsa<Private>,
    session: SessionId,
    random: [u8; 16],
) -> Result<Handshake, WireError> {
    let mut exchange = vec![0]; // parameter index, with no extra parameters
    certificate::write_rsa_key(&mut exchange, key)?;
    Ok(Handshake::anonymous_server(session, random, exchange))
}

fn server_parameters(now: u32) -> Result<([u8; 16], SessionId), WireError> {
    // The legacy profile uses the same default-provider RSA implicit rejection.
    if openssl::version::number() < 0x3020_0000
        || !openssl::version::version().starts_with("OpenSSL ")
    {
        return Err(WireError::Provider);
    }
    let mut session = [0; 8];
    rand_bytes(&mut session)?;
    Ok((random(now)?, SessionId(session)))
}

fn random(now: u32) -> Result<[u8; 16], WireError> {
    let mut value = [0; 16];
    value[..4].copy_from_slice(&now.to_be_bytes());
    rand_bytes(&mut value[4..])?;
    Ok(value)
}

fn carries_handshake(messages: &[Message]) -> bool {
    messages
        .iter()
        .any(|message| !matches!(message, Message::Alert(_) | Message::ApplicationData { .. }))
}

fn record_checksum(bytes: &[u8]) -> [u8; 4] {
    let mut checksum = [0; 4];
    for (index, byte) in bytes.iter().enumerate() {
        checksum[index % 4] ^= byte;
    }
    checksum
}
