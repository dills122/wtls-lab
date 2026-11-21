//! Address routing for whole WTLS UDP datagrams. Feed one datagram and its
//! source at a time, send each [Event::Send] as a single datagram to its
//! indicated destination, and call [Adapter::tick] when its deadline is due.

mod socket;

#[cfg(test)]
mod certificate_alert_tests;
#[cfg(test)]
mod sequence_tests;

pub use socket::SocketTransport;

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::num::{NonZeroU64, NonZeroUsize};

use crate::handshake::{CloseScope, HandshakeKind, Status};
use crate::wire::{
    ClientHello, DatagramBudget, DatagramTooLarge, ReceiveError, RecoveryOutcome, ResumableClient,
    ResumableServer, WireAction, WireError, WirePeer, decode_client_hello,
};
use crate::{CipherSpec, RecordType, decode_record_envelope};

const DEFAULT_PENDING_HANDSHAKE_TIMEOUT_MS: NonZeroU64 = NonZeroU64::new(30_000).unwrap();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Diagnostic {
    NoAssociation,
    AddressInUse,
    AtCapacity,
    PreviousClientHello,
    /// A staged replacement verified Finished and closed in the same datagram.
    CandidateClosed(CloseScope),
    InboundTooLarge(DatagramTooLarge),
    OutboundTooLarge(DatagramTooLarge),
    Protocol(WireError),
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAssociation => f.write_str("no association for remote address"),
            Self::AddressInUse => f.write_str("remote address already has an association"),
            Self::AtCapacity => f.write_str("association table is full"),
            Self::PreviousClientHello => {
                f.write_str("ClientHello from a recently retired handshake")
            }
            Self::CandidateClosed(scope) => write!(f, "recovery candidate closed: {scope:?}"),
            Self::InboundTooLarge(error) => write!(f, "inbound {error}"),
            Self::OutboundTooLarge(error) => write!(f, "outbound {error}"),
            Self::Protocol(error) => error.fmt(f),
        }
    }
}

/// Ordered effects of one adapter operation. Socket failures are reported by
/// the transport separately. Delivery comes from WirePeer's protected path.
pub enum Event {
    Send {
        remote: SocketAddr,
        bytes: Vec<u8>,
    },
    Established {
        remote: SocketAddr,
        kind: HandshakeKind,
    },
    Deliver {
        remote: SocketAddr,
        payload: Vec<u8>,
    },
    Closed {
        remote: SocketAddr,
        scope: CloseScope,
    },
    TimedOut {
        remote: SocketAddr,
    },
    Diagnostic {
        remote: SocketAddr,
        reason: Diagnostic,
    },
}

struct Association {
    peer: WirePeer,
    client_random: Option<[u8; 16]>,
    pending_until_ms: Option<u64>,
    candidate: Option<RecoveryCandidate>,
}

struct RecoveryCandidate {
    peer: WirePeer,
    client_random: [u8; 16],
    deadline: u64,
}

/// A table of peers keyed by the full remote address (IP and port).
///
/// One capacity covers all live associations, including negotiations. A full
/// table refuses new associations. An inbound handshake gets a fixed deadline
/// from the slot's first accepted ClientHello, across retries and replacements.
/// An established inbound peer can stage one replacement with its own fixed
/// deadline. The incumbent serves the tuple until the replacement commits open.
/// Established and outbound peers follow WirePeer's lifecycle. The most recent
/// `capacity` server-side (address, ClientHello random) pairs from closed, expired,
/// or displaced handshakes are kept in FIFO order to reject stale hellos. The shared
/// server context handles resumption independently of this history.
///
/// Supply certificate time as Unix seconds and timers as nondecreasing
/// monotonic milliseconds. All peers using the same resumption context must
/// share a monotonic time base. The adapter owns no clock or socket.
pub struct Adapter {
    server: Option<ResumableServer>,
    budget: DatagramBudget,
    capacity: usize,
    pending_handshake_timeout_ms: NonZeroU64,
    associations: BTreeMap<SocketAddr, Association>,
    retired_hellos: VecDeque<(SocketAddr, [u8; 16])>,
}

impl Adapter {
    /// Pass a server context to accept inbound associations. Outbound client
    /// associations can be started with or without a server context. Inbound
    /// negotiations expire after 30 seconds by default.
    pub fn new(
        server: Option<ResumableServer>,
        budget: DatagramBudget,
        capacity: NonZeroUsize,
    ) -> Self {
        Self {
            server,
            budget,
            capacity: capacity.get(),
            pending_handshake_timeout_ms: DEFAULT_PENDING_HANDSHAKE_TIMEOUT_MS,
            associations: BTreeMap::new(),
            retired_hellos: VecDeque::new(),
        }
    }

    /// Set the fixed lifetime in milliseconds for future inbound negotiations.
    /// Existing deadlines and WirePeer retry timers keep their original timing.
    pub fn with_pending_handshake_timeout_ms(mut self, timeout_ms: NonZeroU64) -> Self {
        self.pending_handshake_timeout_ms = timeout_ms;
        self
    }

    pub fn status(&self, remote: SocketAddr) -> Option<Status> {
        self.associations
            .get(&remote)
            .map(|entry| entry.peer.status())
    }

    /// Earliest WirePeer retry or inbound handshake expiry, in monotonic milliseconds.
    pub fn deadline(&self) -> Option<u64> {
        self.associations
            .values()
            .flat_map(|entry| {
                [
                    entry.peer.deadline(),
                    entry.pending_until_ms,
                    entry.candidate.as_ref().map(|candidate| candidate.deadline),
                ]
            })
            .flatten()
            .min()
    }

    /// Expire due inbound handshakes and advance all due WirePeer timers.
    pub fn tick(&mut self, monotonic_ms: u64) -> Vec<Event> {
        let mut events = self.expire_inbound(monotonic_ms);
        let due: Vec<_> = self
            .associations
            .iter()
            .filter_map(|(&remote, entry)| {
                (entry
                    .peer
                    .deadline()
                    .is_some_and(|deadline| deadline <= monotonic_ms))
                .then_some(remote)
            })
            .collect();
        for remote in due {
            events.extend(self.drive(remote, |peer| peer.tick(monotonic_ms).map_err(Into::into)));
        }
        events
    }

    /// Start a client association at an unused remote address.
    pub fn connect(
        &mut self,
        remote: SocketAddr,
        client: &ResumableClient,
        unix_seconds: u32,
        monotonic_ms: u64,
    ) -> Vec<Event> {
        if self.associations.contains_key(&remote) {
            return diagnostic(remote, Diagnostic::AddressInUse);
        }
        if self.associations.len() == self.capacity {
            return diagnostic(remote, Diagnostic::AtCapacity);
        }
        let mut peer = match client.peer(unix_seconds) {
            Ok(peer) => peer,
            Err(error) => return diagnostic(remote, Diagnostic::Protocol(error)),
        };
        let events = self.events(remote, peer.start(monotonic_ms).map_err(Into::into));
        if has_send(&events) && peer.status() == Status::Negotiating {
            self.associations.insert(
                remote,
                Association {
                    peer,
                    client_random: None,
                    pending_until_ms: None,
                    candidate: None,
                },
            );
        }
        events
    }

    /// Expire due inbound handshakes before routing a complete datagram from
    /// the source address observed by the transport.
    pub fn receive(
        &mut self,
        remote: SocketAddr,
        bytes: &[u8],
        unix_seconds: u32,
        monotonic_ms: u64,
    ) -> Vec<Event> {
        let mut events = self.expire_inbound(monotonic_ms);
        events.extend(self.receive_datagram(remote, bytes, unix_seconds, monotonic_ms));
        events
    }

    fn receive_datagram(
        &mut self,
        remote: SocketAddr,
        bytes: &[u8],
        unix_seconds: u32,
        monotonic_ms: u64,
    ) -> Vec<Event> {
        if let Err(error) = self.budget.check(bytes) {
            return diagnostic(remote, Diagnostic::InboundTooLarge(error));
        }
        let (client_random, replacement_deadline) = match self.associations.get(&remote) {
            Some(entry) if entry.client_random.is_some() && entry.peer.status() == Status::Open => {
                return self.receive_established(remote, bytes, unix_seconds, monotonic_ms);
            }
            Some(entry) => {
                if let (Some(current_random), Some(deadline)) =
                    (entry.client_random, entry.pending_until_ms)
                    && entry.peer.status() == Status::Negotiating
                    && let Ok(hello) = opening_hello(bytes)
                    && hello.random != current_random
                {
                    (hello.random, Some(deadline))
                } else {
                    // WirePeer distinguishes an exact replay from a conflicting
                    // same-random hello and handles ordinary negotiation traffic.
                    return self.drive(remote, |peer| peer.receive_with_reply(bytes, monotonic_ms));
                }
            }
            None => {
                if self.server.is_none() {
                    return diagnostic(remote, Diagnostic::NoAssociation);
                }
                match opening_hello(bytes) {
                    Ok(hello) => (hello.random, None),
                    Err(error) => return diagnostic(remote, Diagnostic::Protocol(error)),
                }
            }
        };
        if self.retired_hellos.contains(&(remote, client_random)) {
            return diagnostic(remote, Diagnostic::PreviousClientHello);
        }
        if replacement_deadline.is_none() && self.associations.len() == self.capacity {
            return diagnostic(remote, Diagnostic::AtCapacity);
        }

        let (events, peer) = self.begin_inbound(remote, bytes, unix_seconds, monotonic_ms);
        if let Some(peer) = peer {
            let displaced = self.associations.insert(
                remote,
                Association {
                    peer,
                    client_random: Some(client_random),
                    pending_until_ms: Some(
                        replacement_deadline.unwrap_or_else(|| self.pending_deadline(monotonic_ms)),
                    ),
                    candidate: None,
                },
            );
            if let Some(random) = displaced.and_then(|entry| entry.client_random) {
                self.remember_retired_hello(remote, random);
            }
        }
        events
    }

    fn receive_established(
        &mut self,
        remote: SocketAddr,
        bytes: &[u8],
        unix_seconds: u32,
        monotonic_ms: u64,
    ) -> Vec<Event> {
        let entry = &self.associations[&remote];
        let receive = |peer: &mut WirePeer| peer.receive_with_reply(bytes, monotonic_ms);
        if entry.peer.recognizes_handshake_retry(bytes) {
            return self.drive(remote, receive);
        }
        let candidate = entry.candidate.as_ref();
        if candidate.is_some_and(|staged| staged.peer.recognizes_handshake_retry(bytes)) {
            return self.receive_candidate(remote, bytes, monotonic_ms);
        }

        if let Ok(hello) = opening_hello(bytes) {
            let random = hello.random;
            if entry.client_random == Some(random)
                || candidate.is_some_and(|staged| staged.client_random == random)
            {
                return diagnostic(remote, Diagnostic::Protocol(WireError::InvalidRecord));
            }
            if self.retired_hellos.contains(&(remote, random)) {
                return diagnostic(remote, Diagnostic::PreviousClientHello);
            }
            if candidate.is_some() {
                return diagnostic(remote, Diagnostic::AddressInUse);
            }
            let (events, peer) = self.begin_inbound(remote, bytes, unix_seconds, monotonic_ms);
            if let Some(peer) = peer {
                let deadline = self.pending_deadline(monotonic_ms);
                self.associations.get_mut(&remote).unwrap().candidate = Some(RecoveryCandidate {
                    peer,
                    client_random: random,
                    deadline,
                });
            }
            return events;
        }

        if candidate.is_some_and(|staged| staged.peer.recognizes_candidate_input(bytes)) {
            return self.receive_candidate(remote, bytes, monotonic_ms);
        }
        self.drive(remote, receive)
    }

    fn receive_candidate(
        &mut self,
        remote: SocketAddr,
        bytes: &[u8],
        monotonic_ms: u64,
    ) -> Vec<Event> {
        let entry = self.associations.get_mut(&remote).unwrap();
        let candidate = entry.candidate.as_mut().unwrap();
        let outcome = candidate
            .peer
            .receive_recovery(bytes, monotonic_ms, self.budget);
        let (actions, promote) = match outcome {
            Ok(RecoveryOutcome::VerifiedOpen(actions)) => (Ok(actions), true),
            Ok(RecoveryOutcome::VerifiedClose { scope, actions }) => {
                let candidate = entry.candidate.take().unwrap();
                self.remember_retired_hello(remote, candidate.client_random);
                let mut events: Vec<_> = actions
                    .into_iter()
                    .filter_map(|action| match action {
                        WireAction::Send(bytes) => Some(self.send_event(remote, bytes)),
                        _ => None,
                    })
                    .collect();
                events.push(Event::Diagnostic {
                    remote,
                    reason: Diagnostic::CandidateClosed(scope),
                });
                return events;
            }
            Ok(RecoveryOutcome::Incomplete(actions)) => (Ok(actions), false),
            Err(error) => (Err(error), false),
        };
        if candidate.peer.status() != Status::Negotiating {
            let candidate = entry.candidate.take().unwrap();
            if promote {
                entry.peer = candidate.peer;
                if let Some(random) = entry.client_random.replace(candidate.client_random) {
                    self.remember_retired_hello(remote, random);
                }
            } else {
                self.remember_retired_hello(remote, candidate.client_random);
            }
        }
        self.events(remote, actions)
    }

    fn begin_inbound(
        &self,
        remote: SocketAddr,
        bytes: &[u8],
        unix_seconds: u32,
        monotonic_ms: u64,
    ) -> (Vec<Event>, Option<WirePeer>) {
        let Some(server) = &self.server else {
            return (diagnostic(remote, Diagnostic::NoAssociation), None);
        };
        let mut peer = match server.peer(unix_seconds) {
            Ok(peer) => peer,
            Err(error) => return (diagnostic(remote, Diagnostic::Protocol(error)), None),
        };
        let events = self.events(remote, peer.receive_with_reply(bytes, monotonic_ms));
        // An initial alert leaves the peer idle. Admission requires a
        // negotiating peer whose first flight passed the datagram budget.
        let admitted = has_send(&events) && peer.status() == Status::Negotiating;
        (events, admitted.then_some(peer))
    }

    fn pending_deadline(&self, monotonic_ms: u64) -> u64 {
        monotonic_ms.saturating_add(self.pending_handshake_timeout_ms.get())
    }

    fn expire_inbound(&mut self, monotonic_ms: u64) -> Vec<Event> {
        let mut retired_candidates = Vec::new();
        let expired: Vec<_> = self
            .associations
            .iter_mut()
            .filter_map(|(&remote, entry)| {
                if entry
                    .candidate
                    .as_ref()
                    .is_some_and(|candidate| candidate.deadline <= monotonic_ms)
                {
                    let candidate = entry.candidate.take().unwrap();
                    retired_candidates.push((remote, candidate.client_random));
                }
                entry
                    .pending_until_ms
                    .filter(|&deadline| deadline <= monotonic_ms)
                    .map(|_| remote)
            })
            .collect();
        for (remote, random) in retired_candidates {
            self.remember_retired_hello(remote, random);
        }
        expired
            .into_iter()
            .map(|remote| {
                self.retire(remote);
                Event::TimedOut { remote }
            })
            .collect()
    }

    /// Protect an application payload and check the resulting encoded datagram
    /// against the budget. WirePeer may advance even when output exceeds it.
    pub fn send_application(&mut self, remote: SocketAddr, payload: Vec<u8>) -> Vec<Event> {
        self.drive(remote, |peer| {
            peer.send_application(payload).map_err(Into::into)
        })
    }

    pub fn close(&mut self, remote: SocketAddr, scope: CloseScope) -> Vec<Event> {
        self.drive(remote, |peer| peer.close(scope).map_err(Into::into))
    }

    fn drive(
        &mut self,
        remote: SocketAddr,
        operation: impl FnOnce(&mut WirePeer) -> Result<Vec<WireAction>, ReceiveError>,
    ) -> Vec<Event> {
        let Some(entry) = self.associations.get_mut(&remote) else {
            return diagnostic(remote, Diagnostic::NoAssociation);
        };
        let actions = operation(&mut entry.peer);
        match entry.peer.status() {
            Status::Closed => self.retire(remote),
            Status::Open | Status::AwaitingConfirmation => {
                entry.pending_until_ms = None;
            }
            _ => {}
        }
        self.events(remote, actions)
    }

    fn retire(&mut self, remote: SocketAddr) {
        if let Some(entry) = self.associations.remove(&remote) {
            for random in entry
                .client_random
                .into_iter()
                .chain(entry.candidate.map(|candidate| candidate.client_random))
            {
                self.remember_retired_hello(remote, random);
            }
        }
    }

    fn remember_retired_hello(&mut self, remote: SocketAddr, random: [u8; 16]) {
        if self.retired_hellos.len() == self.capacity {
            self.retired_hellos.pop_front();
        }
        self.retired_hellos.push_back((remote, random));
    }

    fn events(
        &self,
        remote: SocketAddr,
        actions: Result<Vec<WireAction>, ReceiveError>,
    ) -> Vec<Event> {
        let actions = match actions {
            Ok(actions) => actions,
            Err(error) => {
                let mut events = diagnostic(remote, Diagnostic::Protocol(error.diagnostic));
                if let Some(reply) = error.reply {
                    events.push(self.send_event(remote, reply));
                }
                return events;
            }
        };
        actions
            .into_iter()
            .map(|action| match action {
                WireAction::Send(bytes) => self.send_event(remote, bytes),
                WireAction::Established(kind) => Event::Established { remote, kind },
                WireAction::Deliver(payload) => Event::Deliver { remote, payload },
                WireAction::Closed(scope) => Event::Closed { remote, scope },
                WireAction::TimedOut => Event::TimedOut { remote },
            })
            .collect()
    }

    fn send_event(&self, remote: SocketAddr, bytes: Vec<u8>) -> Event {
        match self.budget.check(&bytes) {
            Ok(()) => Event::Send { remote, bytes },
            Err(error) => Event::Diagnostic {
                remote,
                reason: Diagnostic::OutboundTooLarge(error),
            },
        }
    }
}

fn opening_hello(bytes: &[u8]) -> Result<ClientHello<'_>, WireError> {
    let record = decode_record_envelope(bytes)
        .map_err(|kind| WireError::Decode(crate::DecodeError { offset: 0, kind }))?;
    record
        .check_datagram_header()
        .map_err(|kind| WireError::Decode(crate::DecodeError { offset: 0, kind }))?;
    if record.wire_len() != bytes.len()
        || record.cipher_spec() != CipherSpec::Null
        || record.content_type() != Ok(RecordType::Handshake)
        || record.sequence != Some(0)
    {
        return Err(WireError::InvalidRecord);
    }
    decode_client_hello(record.fragment)
}

fn diagnostic(remote: SocketAddr, reason: Diagnostic) -> Vec<Event> {
    vec![Event::Diagnostic { remote, reason }]
}

fn has_send(events: &[Event]) -> bool {
    events
        .iter()
        .any(|event| matches!(event, Event::Send { .. }))
}
