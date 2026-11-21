//! Address routing for whole WTLS UDP datagrams. Feed one datagram and its
//! source at a time, send each [Event::Send] as a single datagram to its
//! indicated destination, and call [Adapter::tick] when its deadline is due.

mod socket;

#[cfg(test)]
mod sequence_tests;

pub use socket::SocketTransport;

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::num::{NonZeroU64, NonZeroUsize};

use crate::handshake::{CloseScope, HandshakeKind, Status};
use crate::wire::{
    DatagramBudget, DatagramTooLarge, ResumableClient, ResumableServer, WireAction, WireError,
    WirePeer, decode_client_hello,
};
use crate::{CipherSpec, RecordType, decode_record_envelope};

const DEFAULT_PENDING_HANDSHAKE_TIMEOUT_MS: NonZeroU64 = NonZeroU64::new(30_000).unwrap();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Diagnostic {
    NoAssociation,
    AddressInUse,
    AtCapacity,
    PreviousClientHello,
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
                f.write_str("ClientHello from a recently closed association")
            }
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
}

/// A table of peers keyed by the full remote address (IP and port).
///
/// One capacity covers all live associations, including negotiations. A full
/// table refuses new associations. An inbound handshake gets a fixed deadline
/// from its first accepted ClientHello, even if its flight is repeated. Established
/// and outbound peers follow WirePeer's lifecycle. The most recent `capacity`
/// server-side (address, ClientHello random) pairs from closed or expired
/// associations are kept in FIFO order to reject stale hellos. The shared
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
            .flat_map(|entry| [entry.peer.deadline(), entry.pending_until_ms])
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
            events.extend(self.drive(remote, |peer| peer.tick(monotonic_ms)));
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
        let events = self.events(remote, peer.start(monotonic_ms));
        if has_send(&events) && peer.status() == Status::Negotiating {
            self.associations.insert(
                remote,
                Association {
                    peer,
                    client_random: None,
                    pending_until_ms: None,
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
        if self.associations.contains_key(&remote) {
            return self.drive(remote, |peer| peer.receive(bytes, monotonic_ms));
        }

        let Some(server) = &self.server else {
            return diagnostic(remote, Diagnostic::NoAssociation);
        };
        let client_random = match opening_random(bytes) {
            Ok(random) => random,
            Err(error) => return diagnostic(remote, Diagnostic::Protocol(error)),
        };
        if self.retired_hellos.contains(&(remote, client_random)) {
            return diagnostic(remote, Diagnostic::PreviousClientHello);
        }
        if self.associations.len() == self.capacity {
            return diagnostic(remote, Diagnostic::AtCapacity);
        }

        let mut peer = match server.peer(unix_seconds) {
            Ok(peer) => peer,
            Err(error) => return diagnostic(remote, Diagnostic::Protocol(error)),
        };
        let events = self.events(remote, peer.receive(bytes, monotonic_ms));
        // A resumption-only miss may emit an alert while the peer stays Idle.
        if has_send(&events) && peer.status() == Status::Negotiating {
            self.associations.insert(
                remote,
                Association {
                    peer,
                    client_random: Some(client_random),
                    pending_until_ms: Some(
                        monotonic_ms.saturating_add(self.pending_handshake_timeout_ms.get()),
                    ),
                },
            );
        }
        events
    }

    fn expire_inbound(&mut self, monotonic_ms: u64) -> Vec<Event> {
        let expired: Vec<_> = self
            .associations
            .iter()
            .filter_map(|(&remote, entry)| {
                entry
                    .pending_until_ms
                    .filter(|&deadline| deadline <= monotonic_ms)
                    .map(|_| remote)
            })
            .collect();
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
        self.drive(remote, |peer| peer.send_application(payload))
    }

    pub fn close(&mut self, remote: SocketAddr, scope: CloseScope) -> Vec<Event> {
        self.drive(remote, |peer| peer.close(scope))
    }

    fn drive(
        &mut self,
        remote: SocketAddr,
        operation: impl FnOnce(&mut WirePeer) -> Result<Vec<WireAction>, WireError>,
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
        if let Some(random) = self
            .associations
            .remove(&remote)
            .and_then(|entry| entry.client_random)
        {
            if self.retired_hellos.len() == self.capacity {
                self.retired_hellos.pop_front();
            }
            self.retired_hellos.push_back((remote, random));
        }
    }

    fn events(
        &self,
        remote: SocketAddr,
        actions: Result<Vec<WireAction>, WireError>,
    ) -> Vec<Event> {
        let actions = match actions {
            Ok(actions) => actions,
            Err(error) => return diagnostic(remote, Diagnostic::Protocol(error)),
        };
        actions
            .into_iter()
            .map(|action| match action {
                WireAction::Send(bytes) => match self.budget.check(&bytes) {
                    Ok(()) => Event::Send { remote, bytes },
                    Err(error) => Event::Diagnostic {
                        remote,
                        reason: Diagnostic::OutboundTooLarge(error),
                    },
                },
                WireAction::Established(kind) => Event::Established { remote, kind },
                WireAction::Deliver(payload) => Event::Deliver { remote, payload },
                WireAction::Closed(scope) => Event::Closed { remote, scope },
                WireAction::TimedOut => Event::TimedOut { remote },
            })
            .collect()
    }
}

fn opening_random(bytes: &[u8]) -> Result<[u8; 16], WireError> {
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
    Ok(decode_client_hello(record.fragment)?.random)
}

fn diagnostic(remote: SocketAddr, reason: Diagnostic) -> Vec<Event> {
    vec![Event::Diagnostic { remote, reason }]
}

fn has_send(events: &[Event]) -> bool {
    events
        .iter()
        .any(|event| matches!(event, Event::Send { .. }))
}
