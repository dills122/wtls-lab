use std::collections::VecDeque;
use std::num::{NonZeroU64, NonZeroUsize};
use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex, Weak};

use openssl::rand::rand_bytes;

use super::protection::MasterSecret;
use super::{NegotiatedParameters, ServerIdentity, TrustAnchor, WireError, WirePeer};
use crate::handshake::{HandshakeError, RetryPolicy, SessionId};

/// Owns one gateway identity and its bounded, in-memory session cache.
pub struct ResumableServer {
    identity: ServerIdentity,
    cache: SharedCache,
}

impl ResumableServer {
    pub fn new(identity: ServerIdentity, capacity: NonZeroUsize, lifetime_ms: NonZeroU64) -> Self {
        Self {
            identity,
            cache: SessionCache::shared(capacity, lifetime_ms),
        }
    }

    /// Create a peer with the given certificate wall clock. All peers created
    /// by this context must use the same monotonic millisecond time base.
    pub fn peer(&self, now: u32) -> Result<WirePeer, WireError> {
        let mut peer = WirePeer::server(self.identity.clone(), now)?;
        peer.cache = Some(self.cache.clone());
        Ok(peer)
    }
}

/// Owns one gateway's trust configuration and latest verified session.
pub struct ResumableClient {
    retry: RetryPolicy,
    trust: TrustAnchor,
    cache: SharedCache,
}

impl ResumableClient {
    pub fn new(retry: RetryPolicy, trust: TrustAnchor, lifetime_ms: NonZeroU64) -> Self {
        Self {
            retry,
            trust,
            cache: SessionCache::shared(NonZeroUsize::MIN, lifetime_ms),
        }
    }

    /// Create a peer with the given certificate wall clock. All peers created
    /// by this context must use the same monotonic millisecond time base.
    pub fn peer(&self, now: u32) -> Result<WirePeer, WireError> {
        let mut peer = WirePeer::client(self.retry, self.trust.clone(), now);
        peer.cache = Some(self.cache.clone());
        Ok(peer)
    }
}

pub(super) struct Session {
    pub(super) id: SessionId,
    pub(super) master: MasterSecret,
    pub(super) parameters: NegotiatedParameters,
    pub(super) validity: RangeInclusive<u32>,
    pub(super) established_ms: u64,
}

pub(super) type SharedCache = Arc<Mutex<SessionCache>>;

pub(super) struct SessionCache {
    entries: VecDeque<Arc<Session>>,
    capacity: NonZeroUsize,
    lifetime_ms: NonZeroU64,
}

impl SessionCache {
    fn shared(capacity: NonZeroUsize, lifetime_ms: NonZeroU64) -> SharedCache {
        Arc::new(Mutex::new(Self {
            entries: VecDeque::new(),
            capacity,
            lifetime_ms,
        }))
    }

    fn expire(&mut self, monotonic_ms: u64) {
        self.entries.retain(|entry| {
            monotonic_ms.saturating_sub(entry.established_ms) < self.lifetime_ms.get()
        });
    }

    pub(super) fn find(
        &mut self,
        id: Option<SessionId>,
        now: u32,
        monotonic_ms: u64,
    ) -> Option<Arc<Session>> {
        self.expire(monotonic_ms);
        self.entries
            .iter()
            .rev()
            .find(|entry| {
                monotonic_ms >= entry.established_ms
                    && id.is_none_or(|id| entry.id == id)
                    && entry.validity.contains(&now)
            })
            .cloned()
    }

    pub(super) fn fresh_id(
        &mut self,
        mut candidate: SessionId,
        offered: Option<SessionId>,
        monotonic_ms: u64,
    ) -> Result<SessionId, WireError> {
        self.expire(monotonic_ms);
        while Some(candidate) == offered || self.entries.iter().any(|entry| entry.id == candidate) {
            rand_bytes(&mut candidate.0)?;
        }
        Ok(candidate)
    }

    pub(super) fn insert(&mut self, entry: Arc<Session>) -> Result<(), WireError> {
        self.expire(entry.established_ms);
        if self.entries.iter().any(|existing| existing.id == entry.id) {
            return Err(HandshakeError::SessionIdCollision.into());
        }
        let index = self
            .entries
            .partition_point(|existing| existing.established_ms <= entry.established_ms);
        self.entries.insert(index, entry);
        if self.entries.len() > self.capacity.get() {
            self.entries.pop_front();
        }
        Ok(())
    }

    pub(super) fn invalidate(&mut self, session: &Weak<Session>) {
        // An old connection can only remove the particular entry it established or resumed.
        self.entries
            .retain(|entry| !session.ptr_eq(&Arc::downgrade(entry)));
    }
}
