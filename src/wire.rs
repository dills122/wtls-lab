//! In-memory wire peer for one authenticated WAP-199 profile.
//!
//! Uses RSA key transport, native RSA WTLS certificates, 3DES-CBC-EDE,
//! full HMAC-SHA-1, null compression and explicit datagram sequences.

mod certificate;
mod codec;
mod legacy;
mod protection;
mod report;
mod session;

#[cfg(test)]
mod alert_tests;
#[cfg(test)]
pub(crate) mod sequence_tests;

use std::error::Error;
use std::fmt;
use std::ops::RangeInclusive;
use std::sync::{Arc, MutexGuard, Weak};

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

pub use session::{ResumableClient, ResumableServer};

use codec::{
    FIXED_PARAMETERS, InitialAlert, ServerSelection, decode_legacy_client_key_exchange,
    encode_alert, encode_client_hello,
};
use legacy::WINWAP_PARAMETERS;
use protection::{MAX_PLAINTEXT, Traffic, WireFinished};
use session::{Session, SessionCache, SharedCache};

use crate::handshake::{
    Action, Alert, CloseScope, Datagram, Handshake, HandshakeError, HandshakeKind, Message,
    RetryPolicy, Role, SessionId, Status,
};
use crate::{
    CipherSpec, DecodeError, DecodeErrorKind, EncodeError, LengthForm, Record, RecordType,
};

const ALERT_WARNING: u8 = 1;
const ALERT_CRITICAL: u8 = 2;
const ALERT_FATAL: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    InvalidMessage,
    InvalidRecord,
    UnsupportedProfile,
    CertificateRejected,
    AuthenticationFailed,
    /// A peer alert reported outside the close and commit acknowledgment paths.
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
    Client(TrustAnchor),
    Server(Rsa<Private>),
    LegacyServer(Rsa<Private>),
}

#[derive(Clone, Copy, Default)]
struct Direction {
    protected: bool,
    sequence: u32,
}

impl Direction {
    fn next(&mut self) -> Option<u16> {
        let sequence = u16::try_from(self.sequence).ok()?;
        self.sequence += 1;
        Some(sequence)
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

struct VerifiedCommit {
    flight: Flight,
    finished_checksum: [u8; 4],
}

struct Incoming<'a> {
    messages: Datagram,
    read: Direction,
    traffic: Option<Traffic>,
    checksum: [u8; 4],
    protected_sequence: Option<u16>,
    selection: Option<ServerSelection>,
    client_hello: Option<(ClientHello<'a>, &'a [u8])>,
    commit_prefix: Option<(usize, [u8; 4])>,
}

/// An association driven by one in-memory datagram at a time.
/// The caller delivers the emitted bytes to the other peer and drives the clock.
pub struct WirePeer {
    side: Side,
    authority_id: Option<[u8; 20]>,
    handshake: Handshake,
    now: u32,
    credential_validity: Option<RangeInclusive<u32>>,
    cache: Option<SharedCache>,
    session: Option<Weak<Session>>,
    random: Option<[u8; 16]>,
    peer_random: Option<[u8; 16]>,
    traffic: Option<Traffic>,
    read: Direction,
    write: Direction,
    received_flights: Vec<Flight>,
    verified_commit: Option<VerifiedCommit>,
    sent_flights: Vec<Flight>,
    sent_checksums: Vec<[u8; 4]>,
    last_received: [u8; 4],
    highest_received_sequence: Option<u16>,
    selection: Option<ServerSelection>,
}

impl WirePeer {
    pub fn client(retry: RetryPolicy, trust: TrustAnchor, now: u32) -> Self {
        Self::new(
            Side::Client(trust),
            Handshake::client(retry, Vec::new(), None),
            now,
            None,
        )
    }

    /// Opt into the provisioned profile and advertise the same authority used
    /// to verify the gateway's native WTLS certificate.
    pub fn provisioned_client(retry: RetryPolicy, trust: TrustAnchor, now: u32) -> Self {
        let authority = trust.authority_id();
        let mut peer = Self::client(retry, trust, now);
        peer.authority_id = Some(authority);
        peer
    }

    pub fn server(identity: ServerIdentity, now: u32) -> Result<Self, WireError> {
        let (random, session) = server_parameters(now)?;
        let handshake = Handshake::server(session, random, identity.certificate, None);
        let mut peer = Self::new(Side::Server(identity.key), handshake, now, Some(random));
        peer.authority_id = identity.authority_id;
        peer.credential_validity = Some(identity.validity);
        Ok(peer)
    }

    /// Opt into the anonymous RSA/DES-CBC profile observed in WinWAP.
    /// Use a dedicated ephemeral key and an isolated transport for this legacy profile.
    pub fn legacy_winwap_server(now: u32) -> Result<Self, WireError> {
        let (random, session) = server_parameters(now)?;
        let key = Rsa::generate(2048)?;
        let handshake = legacy_server_handshake(&key, session, random)?;
        Ok(Self::new(
            Side::LegacyServer(key),
            handshake,
            now,
            Some(random),
        ))
    }

    fn new(side: Side, handshake: Handshake, now: u32, random: Option<[u8; 16]>) -> Self {
        Self {
            side,
            authority_id: None,
            handshake,
            now,
            credential_validity: None,
            cache: None,
            session: None,
            random,
            peer_random: None,
            traffic: None,
            read: Direction::default(),
            write: Direction::default(),
            received_flights: Vec::new(),
            verified_commit: None,
            sent_flights: Vec::new(),
            sent_checksums: Vec::new(),
            last_received: [0; 4],
            highest_received_sequence: None,
            selection: None,
        }
    }

    pub fn status(&self) -> Status {
        self.handshake.status()
    }

    /// Provide negotiated parameters after verifying the peer's Finished.
    pub fn connection_info(&self) -> Option<ConnectionInfo> {
        matches!(self.status(), Status::Open | Status::AwaitingConfirmation).then_some(
            ConnectionInfo {
                parameters: self
                    .selection
                    .as_ref()
                    .map_or(FIXED_PARAMETERS, |selection| selection.parameters),
                peer_authentication: match self.side {
                    Side::Client(_) => PeerAuthentication::VerifiedServerCertificate,
                    Side::Server(_) | Side::LegacyServer(_) => PeerAuthentication::None,
                },
            },
        )
    }

    pub fn deadline(&self) -> Option<u64> {
        self.handshake.deadline()
    }

    pub fn start(&mut self, monotonic_ms: u64) -> Result<Vec<WireAction>, WireError> {
        if !matches!(self.side, Side::Client(_)) || self.status() != Status::Idle {
            return Err(HandshakeError::InvalidState.into());
        }
        let random = random(self.now)?;
        let session = self.find_session(None, monotonic_ms)?;
        self.handshake
            .set_idle_cached_session(session.as_ref().map(|session| session.id))?;
        self.session = session.as_ref().map(Arc::downgrade);
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
        match self.handshake.send_application(payload) {
            Ok(actions) => self.apply(actions),
            Err(error @ HandshakeError::SequenceExhausted) => {
                self.finish_actions(Err(error.into()), false)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn close(&mut self, scope: CloseScope) -> Result<Vec<WireAction>, WireError> {
        let actions = self.handshake.close_actions(scope)?;
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
            let actions = self.handshake.receive_actions(
                &flight.messages,
                monotonic_ms,
                &WireFinished(self.traffic.as_ref(), self.selection.as_ref()),
            )?;
            return self.apply(actions);
        }

        let mut incoming = match self.decode(bytes, monotonic_ms) {
            Err(
                error @ WireError::PeerAlert {
                    fields,
                    protection: AlertProtection::Authenticated,
                },
            ) if self.has_committed_receive_epoch()
                && matches!(fields.level, ALERT_CRITICAL | ALERT_FATAL) =>
            {
                // Decode can authenticate records with provisional keys after a
                // ChangeCipherSpec. Only a previously committed epoch can close
                // the association here. Dropping the datagram also drops its data.
                self.handshake.abort();
                self.release_session(fields.level == ALERT_FATAL)?;
                return Err(error);
            }
            result => result?,
        };
        if let Some((offer, fragment)) = incoming.client_hello.take() {
            if !matches!(incoming.messages.as_slice(), [Message::ClientHello { .. }]) {
                return Err(HandshakeError::UnexpectedDatagram.into());
            }
            if let Some(alert) =
                self.prepare_server_hello(&mut incoming, &offer, fragment, monotonic_ms)?
            {
                let fragment = alert.encode(incoming.checksum);
                let reply = crate::encode_datagram(&[Record {
                    content_type: RecordType::Alert,
                    cipher_spec: CipherSpec::Null,
                    sequence: 0,
                    length_form: LengthForm::Explicit,
                    fragment: &fragment,
                }])
                .map_err(WireError::Encode)?;
                return Ok(vec![WireAction::Send(reply)]);
            }
        }

        if let [
            Message::ServerHello {
                random: remote,
                session,
            },
            Message::Certificate(certificate),
            Message::ServerHelloDone,
        ] = incoming.messages.as_slice()
            && let Side::Client(trust) = &self.side
            && self.traffic.is_none()
            && Some(*session) != self.handshake.cached_session()
        {
            let local = self.random.ok_or(WireError::InvalidMessage)?;
            let leaf = match trust.verify(certificate, self.now) {
                Ok(leaf) => leaf,
                Err(error) => {
                    self.handshake.abort();
                    self.session = None;
                    return Err(error);
                }
            };
            let selected = incoming
                .selection
                .as_ref()
                .ok_or(WireError::InvalidMessage)?;
            let (exchange, traffic) =
                Traffic::begin_client(&leaf.key, local, *remote, selected.parameters)?;
            self.handshake.install_client_key_exchange(exchange)?;
            self.credential_validity = Some(leaf.validity);
            incoming.traffic = Some(traffic);
        }

        // Hold the cache lock through Finished verification so a concurrent close
        // or eviction cannot remove this entry between the check and establishment.
        let cache = if self.status() == Status::Negotiating
            && let Some(id) = self.handshake.cached_session()
            && match &self.side {
                Side::Server(_) => incoming.commit_prefix.is_some(),
                Side::Client(_) => matches!(
                    incoming.messages.as_slice(),
                    [Message::ServerHello { session, .. }, Message::ChangeCipherSpec, Message::Finished(_)]
                        if *session == id
                ),
                Side::LegacyServer(_) => false,
            } {
            let mut cache = self
                .cache
                .as_ref()
                .ok_or(WireError::InvalidMessage)?
                .lock()
                .map_err(|_| WireError::Provider)?;
            let current = cache.find(Some(id), self.now, monotonic_ms);
            if !current.as_ref().is_some_and(|entry| {
                self.session
                    .as_ref()
                    .is_some_and(|session| session.ptr_eq(&Arc::downgrade(entry)))
            }) {
                self.handshake.abort();
                self.traffic = None;
                self.session = None;
                return Err(WireError::InvalidMessage);
            }
            Some(cache)
        } else {
            None
        };

        let context = WireFinished(
            incoming.traffic.as_ref().or(self.traffic.as_ref()),
            incoming.selection.as_ref().or(self.selection.as_ref()),
        );
        let actions = self
            .handshake
            .receive_actions(&incoming.messages, monotonic_ms, &context);
        drop(cache);
        let actions = match actions {
            Ok(actions) => actions,
            Err(error) => {
                if self.status() == Status::Closed {
                    self.traffic = None;
                    self.session = None;
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
        let has_handshake = carries_handshake(&incoming.messages);
        let accepted = if incoming.messages == [Message::Alert(Alert::DuplicateFinishedReceived)] {
            // Acknowledgments produce no action, even when they confirm a commit.
            true
        } else if has_handshake && self.verified_commit.is_some() {
            // A replayed commit or application record must not replace the close checksum.
            actions
                .iter()
                .any(|action| matches!(action, Action::Deliver(_) | Action::Closed(_)))
        } else {
            has_handshake || !actions.is_empty()
        };
        // Keep the newest accepted record as the close reference even when an
        // older record is delivered out of order.
        if accepted
            && self.highest_received_sequence.is_none_or(|highest| {
                incoming
                    .protected_sequence
                    .is_some_and(|sequence| sequence > highest)
            })
        {
            self.last_received = incoming.checksum;
            self.highest_received_sequence = incoming.protected_sequence;
        }
        let established = actions.iter().find_map(|action| match action {
            Action::Established { kind, session } => Some((*kind, *session)),
            _ => None,
        });
        if let Some((length, finished_checksum)) = incoming.commit_prefix
            && matches!(established, Some((HandshakeKind::Resumed, _)))
            && matches!(self.side, Side::Server(_))
        {
            self.verified_commit = Some(VerifiedCommit {
                flight: Flight {
                    messages: incoming.messages[..2].to_vec(),
                    bytes: bytes[..length].to_vec(),
                },
                finished_checksum,
            });
        } else if has_handshake && self.verified_commit.is_none() {
            self.received_flights.push(Flight {
                messages: incoming.messages,
                bytes: bytes.to_vec(),
            });
        }
        let result = self.apply(actions)?;
        if let Some((HandshakeKind::Full, id)) = established
            && let Err(error) = self.cache_full_session(id, monotonic_ms)
        {
            self.handshake.abort();
            self.traffic = None;
            self.session = None;
            return Err(error);
        }
        Ok(result)
    }

    fn lock_cache(&self) -> Result<Option<MutexGuard<'_, SessionCache>>, WireError> {
        self.cache
            .as_ref()
            .map(|cache| cache.lock().map_err(|_| WireError::Provider))
            .transpose()
    }

    fn find_session(
        &self,
        id: Option<SessionId>,
        monotonic_ms: u64,
    ) -> Result<Option<Arc<Session>>, WireError> {
        Ok(self
            .lock_cache()?
            .and_then(|mut cache| cache.find(id, self.now, monotonic_ms)))
    }

    fn prepare_server_hello(
        &mut self,
        incoming: &mut Incoming<'_>,
        offer: &ClientHello<'_>,
        fragment: &[u8],
        monotonic_ms: u64,
    ) -> Result<Option<InitialAlert>, WireError> {
        let offered = offer.offered_session();
        let cached = if let Some(id) = offered {
            self.find_session(Some(id), monotonic_ms)?
                .filter(|entry| offer.check_record_choices(entry.parameters).is_ok())
        } else {
            None
        };
        if cached.is_none()
            && matches!(self.side, Side::Server(_))
            && !offer.session_id.is_empty()
            && offer.key_exchanges.is_empty()
        {
            return Ok(Some(InitialAlert::UnknownKeyId));
        }
        // A conflicting list rejects a full offer or a cache hit before
        // installing traffic keys or assigning a new session ID.
        if self
            .authority_id
            .is_some_and(|authority| !offer.allows_authority(authority))
        {
            return Ok(Some(InitialAlert::HandshakeFailure));
        }
        let parameters = match (&self.side, &cached) {
            (_, Some(entry)) => entry.parameters,
            (Side::LegacyServer(_), None) => WINWAP_PARAMETERS,
            (_, None) => FIXED_PARAMETERS,
        };
        let selection = ServerSelection::choose(offer, fragment, parameters, cached.is_some())?;
        if let Some(session) = &cached {
            let local = self.random.ok_or(WireError::InvalidRecord)?;
            if local == offer.random {
                return Err(WireError::InvalidMessage);
            }
            incoming.traffic = Some(Traffic::from_master(
                session.master.clone(),
                offer.random,
                local,
                selection.parameters,
            ));
        } else {
            let mut fresh = *self
                .handshake
                .idle_server_session()
                .ok_or(HandshakeError::InvalidState)?;
            if let Some(mut cache) = self.lock_cache()? {
                fresh = cache.fresh_id(fresh, offered, monotonic_ms)?;
            } else {
                while Some(fresh) == offered {
                    rand_bytes(&mut fresh.0)?;
                }
            }
            *self
                .handshake
                .idle_server_session()
                .ok_or(HandshakeError::InvalidState)? = fresh;
        }
        self.handshake
            .set_idle_cached_session(cached.as_ref().map(|session| session.id))?;
        self.session = cached.as_ref().map(Arc::downgrade);
        incoming.selection = Some(selection);
        Ok(None)
    }

    fn cache_full_session(&mut self, id: SessionId, monotonic_ms: u64) -> Result<(), WireError> {
        let Some(mut cache) = self.lock_cache()? else {
            return Ok(());
        };
        let Some(validity) = self
            .credential_validity
            .as_ref()
            .filter(|validity| validity.contains(&self.now))
        else {
            return Ok(());
        };
        let traffic = self.traffic.as_ref().ok_or(WireError::InvalidRecord)?;
        let selection = self.selection.as_ref().ok_or(WireError::InvalidRecord)?;
        let session = Arc::new(Session {
            id,
            master: traffic.master(),
            parameters: selection.parameters,
            validity: validity.clone(),
            established_ms: monotonic_ms,
        });
        let current = Arc::downgrade(&session);
        cache.insert(session)?;
        drop(cache);
        self.session = Some(current);
        Ok(())
    }

    fn has_committed_receive_epoch(&self) -> bool {
        self.read.protected && !matches!(self.side, Side::LegacyServer(_))
    }

    fn decode<'a>(&self, bytes: &'a [u8], monotonic_ms: u64) -> Result<Incoming<'a>, WireError> {
        if bytes.is_empty() {
            return Err(WireError::Decode(DecodeError {
                offset: 0,
                kind: DecodeErrorKind::EmptyDatagram,
            }));
        }
        let committed = self.has_committed_receive_epoch();
        let mut offset = 0;
        let mut records = std::iter::from_fn(|| {
            if offset == bytes.len() {
                return None;
            }
            let start = offset;
            Some(match crate::decode_record(&bytes[start..]) {
                Ok(record) => {
                    offset += record.wire_len();
                    Ok((start, offset, record))
                }
                Err(kind) => {
                    offset = bytes.len();
                    Err(WireError::Decode(DecodeError {
                        offset: start,
                        kind,
                    }))
                }
            })
        });
        // Negotiation still validates the whole SDU's framing before interpreting
        // it. With committed keys, a verified terminal alert ends consumption.
        let negotiation_records = if committed {
            Vec::new()
        } else {
            records.by_ref().collect::<Result<Vec<_>, _>>()?
        };
        let mut records = negotiation_records.into_iter().map(Ok).chain(records);
        let mut read = self.read;
        let mut traffic = None;
        let prefix = self
            .verified_commit
            .as_ref()
            .map(|commit| &commit.flight)
            .filter(|flight| bytes.starts_with(&flight.bytes));
        let mut last_record = None;
        if let Some(flight) = prefix {
            for _ in &flight.messages {
                last_record = Some(records.next().ok_or(WireError::InvalidRecord)??);
            }
            // Frame against the full SDU so an omitted length cannot hide a suffix.
            if last_record.map(|(_, end, _)| end) != Some(flight.bytes.len()) {
                return Err(WireError::InvalidRecord);
            }
        }
        let mut messages = prefix.map_or_else(Vec::new, |flight| flight.messages.clone());
        let prefix_len = messages.len();
        let mut awaiting_finished = false;
        let mut selection = None;
        let mut client_hello = None;
        let mut commit_prefix = None;
        let mut warning = None;

        for framed in records {
            let (record_start, offset, record) = framed?;
            last_record = Some((record_start, offset, record));
            let message = match (read.protected, record.cipher_spec) {
                (false, CipherSpec::Null)
                    if record.sequence == read.next().ok_or(WireError::InvalidRecord)? =>
                {
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
                            && self.local_role() == Role::Server
                        {
                            if self.status() != Status::Idle || !messages.is_empty() {
                                return Err(WireError::InvalidRecord);
                            }
                            let offer = decode_client_hello(record.fragment)?;
                            let message = Message::ClientHello {
                                random: offer.random,
                                resume: offer.offered_session(),
                            };
                            client_hello = Some((offer, record.fragment));
                            message
                        } else if record.fragment.first() == Some(&2)
                            && self.local_role() == Role::Client
                        {
                            if self.status() != Status::Negotiating
                                || self.selection.is_some()
                                || !messages.is_empty()
                            {
                                return Err(WireError::InvalidRecord);
                            }
                            let (message, selected, keys) =
                                self.read_server_hello(record.fragment, monotonic_ms)?;
                            selection = Some(selected);
                            traffic = keys;
                            message
                        } else if let Side::LegacyServer(key) = &self.side
                            && record.fragment.first() == Some(&16)
                        {
                            decode_legacy_client_key_exchange(record.fragment, key.size() as usize)?
                        } else {
                            decode_handshake(record.fragment)?
                        };
                        match &message {
                            Message::Finished(_) => return Err(WireError::InvalidRecord),
                            Message::ClientKeyExchange(exchange) => {
                                let key = match &self.side {
                                    Side::Server(key) | Side::LegacyServer(key) => key,
                                    Side::Client(_) => return Err(WireError::InvalidRecord),
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
                        if messages.as_slice() == [Message::ChangeCipherSpec] {
                            commit_prefix =
                                Some((offset, record_checksum(&bytes[record_start..offset])));
                        }
                        finished
                    } else {
                        match self.decode_open_record(record, &content) {
                            Err(error @ WireError::PeerAlert { fields, .. })
                                if committed && fields.level == ALERT_WARNING =>
                            {
                                // Keep the first diagnostic unless a terminal alert follows.
                                warning.get_or_insert(error);
                                continue;
                            }
                            Ok(message @ Message::Alert(Alert::CloseNotify(_))) if committed => {
                                // Keep a verified commit prefix for the existing close path.
                                messages.truncate(prefix_len);
                                messages.push(message);
                                warning = None;
                                break;
                            }
                            result => result?,
                        }
                    }
                }
                _ => return Err(WireError::InvalidRecord),
            };
            messages.push(message);
        }
        if awaiting_finished {
            return Err(WireError::InvalidRecord);
        }
        if let Some(error) = warning {
            return Err(error);
        }
        let (start, end, last) = last_record.ok_or(WireError::InvalidRecord)?;
        Ok(Incoming {
            messages,
            read,
            traffic,
            checksum: record_checksum(&bytes[start..end]),
            protected_sequence: (last.cipher_spec == CipherSpec::Current).then_some(last.sequence),
            selection,
            client_hello,
            commit_prefix,
        })
    }

    fn read_server_hello(
        &self,
        fragment: &[u8],
        monotonic_ms: u64,
    ) -> Result<(Message, ServerSelection, Option<Traffic>), WireError> {
        let hello = decode_server_hello(fragment)?;
        let id = SessionId(
            hello
                .session_id
                .try_into()
                .map_err(|_| WireError::UnsupportedProfile)?,
        );
        let cached = if Some(id) == self.handshake.cached_session() {
            let offered = self.session.as_ref().and_then(Weak::upgrade);
            Some(
                self.find_session(Some(id), monotonic_ms)?
                    .filter(|current| {
                        offered
                            .as_ref()
                            .is_some_and(|offer| Arc::ptr_eq(offer, current))
                    })
                    .ok_or(WireError::InvalidMessage)?,
            )
        } else {
            None
        };
        // The initial flight is retained for retransmission. Use its actual
        // fragment for Finished, including the provisioned authority vector.
        let sent = self.sent_flights.first().ok_or(WireError::InvalidRecord)?;
        let client_hello = crate::decode_record(&sent.bytes)
            .map_err(|_| WireError::InvalidRecord)?
            .fragment;
        let selected = ServerSelection::accept(
            &hello,
            fragment,
            client_hello,
            cached.as_ref().map(|session| session.parameters),
        )?;
        let local = self.random.ok_or(WireError::InvalidRecord)?;
        if local == hello.random {
            return Err(WireError::InvalidMessage);
        }
        let traffic = cached.map(|session| {
            Traffic::from_master(
                session.master.clone(),
                local,
                hello.random,
                selected.parameters,
            )
        });
        Ok((
            Message::ServerHello {
                random: hello.random,
                session: id,
            },
            selected,
            traffic,
        ))
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
                    .supported_alert()?
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
        let invalidate = actions.contains(&Action::Closed(CloseScope::Session));
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
        self.finish_actions(result, invalidate)
    }

    fn finish_actions(
        &mut self,
        result: Result<Vec<WireAction>, WireError>,
        invalidate: bool,
    ) -> Result<Vec<WireAction>, WireError> {
        if result.is_err() {
            self.handshake.abort();
        }
        if matches!(
            result,
            Err(WireError::Handshake(HandshakeError::SequenceExhausted))
        ) {
            self.random = None;
            self.peer_random = None;
            self.selection = None;
            self.read = Direction::default();
            self.write = Direction::default();
            self.received_flights = Vec::new();
            self.verified_commit = None;
            self.sent_flights = Vec::new();
            self.sent_checksums = Vec::new();
            self.last_received = [0; 4];
            self.highest_received_sequence = None;
        }
        if self.status() == Status::Closed {
            self.release_session(invalidate)?;
        }
        result
    }

    fn release_session(&mut self, invalidate: bool) -> Result<(), WireError> {
        self.traffic = None;
        let session = self.session.take();
        if invalidate
            && let Some(session) = session
            && let Some(mut cache) = self.lock_cache()?
        {
            cache.invalidate(&session);
        }
        Ok(())
    }

    fn encode(&mut self, messages: Datagram) -> Result<Vec<u8>, WireError> {
        let prefix = self
            .sent_flights
            .iter()
            .find(|flight| messages.starts_with(&flight.messages));
        if let Some(flight) = prefix
            && flight.messages.len() == messages.len()
        {
            return Ok(flight.bytes.clone());
        }
        let mut write = self.write;
        let mut datagram = prefix.map_or_else(Vec::new, |flight| flight.bytes.clone());
        let mut checksums = Vec::new();

        for message in &messages[prefix.map_or(0, |flight| flight.messages.len())..] {
            let (content_type, plaintext) = match message {
                Message::ChangeCipherSpec => (RecordType::ChangeCipherSpec, vec![1]),
                Message::Alert(alert) => {
                    let checksum = if *alert == Alert::DuplicateFinishedReceived {
                        self.verified_commit
                            .as_ref()
                            .ok_or(WireError::InvalidRecord)?
                            .finished_checksum
                    } else {
                        self.last_received
                    };
                    (RecordType::Alert, encode_alert(*alert, checksum).to_vec())
                }
                Message::ApplicationData { payload, .. } => {
                    (RecordType::ApplicationData, payload.clone())
                }
                Message::ClientHello { random, resume } => (
                    RecordType::Handshake,
                    encode_client_hello(random, *resume, self.authority_id)?,
                ),
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
                sequence: write.next().ok_or(HandshakeError::SequenceExhausted)?,
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
        // A close may reference any earlier record that reached the peer.
        // Each new record uses a non-wrapping sequence in the clear or
        // protected epoch, and reused flight bytes add no entries.
        self.sent_checksums.extend(checksums);
        if prefix.is_none() && carries_handshake(&messages) {
            self.sent_flights.push(Flight {
                messages,
                bytes: datagram.clone(),
            });
        }
        Ok(datagram)
    }

    fn local_role(&self) -> Role {
        match self.side {
            Side::Client(_) => Role::Client,
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
