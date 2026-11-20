//! WAP-199 handshake flight state over an in-memory datagram boundary.
//!
//! Each input contains the semantic messages of one transport SDU. A future
//! record adapter owns wire decoding, sequence checks for handshake records,
//! cipher activation and record authentication before delivering these inputs.

use std::error::Error;
use std::fmt;
use std::num::NonZeroU64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeKind {
    Full,
    Resumed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Idle,
    Negotiating,
    AwaitingConfirmation,
    Open,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionId(pub [u8; 8]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub timeout_ms: NonZeroU64,
    /// Maximum retransmissions after the initial send, separately per flight.
    pub max_retries: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseScope {
    Connection,
    Session,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alert {
    CloseNotify(CloseScope),
    DuplicateFinishedReceived,
}

pub type FinishedData = [u8; 12];
pub type Datagram = Vec<Message>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    ClientHello {
        random: [u8; 16],
        resume: Option<SessionId>,
    },
    ServerHello {
        random: [u8; 16],
        session: SessionId,
    },
    Certificate(Vec<u8>),
    ServerKeyExchange(Vec<u8>),
    ServerHelloDone,
    ClientKeyExchange(Vec<u8>),
    ChangeCipherSpec,
    Finished(FinishedData),
    Alert(Alert),
    ApplicationData {
        sequence: u16,
        payload: Vec<u8>,
    },
}

/// Supplies Finished generation and verification for the ordered handshake
/// messages. The transcript omits CCS, alerts, application data, and retries.
/// Implementations used by real peers must supply actual WTLS verification.
pub trait FinishedProvider {
    fn create(&self, sender: Role, transcript: &[Message]) -> Option<FinishedData>;
    fn verify(&self, sender: Role, transcript: &[Message], value: &FinishedData) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Send(Datagram),
    Established {
        kind: HandshakeKind,
        session: SessionId,
    },
    Deliver(Vec<u8>),
    Closed(CloseScope),
    TimedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    InvalidState,
    UnexpectedDatagram,
    SessionIdCollision,
    FinishedVerificationFailed,
    FinishedUnavailable,
    SequenceExhausted,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidState => "operation unavailable in the current handshake state",
            Self::UnexpectedDatagram => "unexpected datagram for the current handshake state",
            Self::SessionIdCollision => {
                "a new session ID would collide with an offered or cached ID"
            }
            Self::FinishedVerificationFailed => "peer Finished verification failed",
            Self::FinishedUnavailable => "could not generate Finished data",
            Self::SequenceExhausted => "application sequence space is exhausted",
        })
    }
}

impl Error for HandshakeError {}

enum Config {
    Client {
        retry: RetryPolicy,
        key_exchange: Vec<u8>,
    },
    Server {
        fresh_session: SessionId,
        random: [u8; 16],
        credential: Message,
    },
}

struct RetryFlight {
    datagram: Datagram,
    deadline: u64,
    remaining: u32,
}

impl RetryFlight {
    fn new(datagram: Datagram, now_ms: u64, policy: RetryPolicy) -> Self {
        Self {
            datagram,
            deadline: now_ms.saturating_add(policy.timeout_ms.get()),
            remaining: policy.max_retries,
        }
    }
}

#[derive(Clone)]
struct Exchange {
    incoming: Datagram,
    outgoing: Datagram,
}

struct ClientCommit {
    server_hello: Datagram,
    sent: RetryFlight,
    session: SessionId,
    transcript: Vec<Message>,
}

struct ServerCommit {
    hello: Exchange,
    kind: HandshakeKind,
    session: SessionId,
    transcript: Vec<Message>,
}

enum State {
    Idle,
    ClientHello(RetryFlight),
    ClientCommit(ClientCommit),
    ServerCommit(ServerCommit),
    Open(Open),
    Closed,
}

/// One association for either role. Carry the accepted session ID into a new
/// association to model resumption. The lab supplies the peer and its material.
pub struct Handshake {
    config: Config,
    state: State,
    cached_session: Option<SessionId>,
}

impl Handshake {
    pub fn client(retry: RetryPolicy, key_exchange: Vec<u8>, cached: Option<SessionId>) -> Self {
        Self::new(
            Config::Client {
                retry,
                key_exchange,
            },
            cached,
        )
    }

    pub fn server(
        fresh_session: SessionId,
        random: [u8; 16],
        certificate: Vec<u8>,
        cached: Option<SessionId>,
    ) -> Self {
        Self::new(
            Config::Server {
                fresh_session,
                random,
                credential: Message::Certificate(certificate),
            },
            cached,
        )
    }

    pub(crate) fn anonymous_server(
        fresh_session: SessionId,
        random: [u8; 16],
        public_key: Vec<u8>,
    ) -> Self {
        Self::new(
            Config::Server {
                fresh_session,
                random,
                credential: Message::ServerKeyExchange(public_key),
            },
            None,
        )
    }

    /// Let the wire server replace its pending session ID if an offer collides.
    pub(crate) fn idle_server_session(&mut self) -> Option<&mut SessionId> {
        match (&self.state, &mut self.config) {
            (State::Idle, Config::Server { fresh_session, .. }) => Some(fresh_session),
            _ => None,
        }
    }

    /// Supply a cache lookup made on the transport's clock before the first flight.
    pub(crate) fn set_idle_cached_session(
        &mut self,
        cached: Option<SessionId>,
    ) -> Result<(), HandshakeError> {
        if !matches!(self.state, State::Idle) {
            return Err(HandshakeError::InvalidState);
        }
        self.cached_session = cached;
        Ok(())
    }

    fn new(config: Config, cached_session: Option<SessionId>) -> Self {
        Self {
            config,
            state: State::Idle,
            cached_session,
        }
    }

    pub fn status(&self) -> Status {
        match &self.state {
            State::Idle => Status::Idle,
            State::ClientHello(_) | State::ClientCommit(_) | State::ServerCommit(_) => {
                Status::Negotiating
            }
            State::Open(open) if open.awaiting_confirmation() => Status::AwaitingConfirmation,
            State::Open(_) => Status::Open,
            State::Closed => Status::Closed,
        }
    }

    pub(crate) fn abort(&mut self) {
        self.cached_session = None;
        self.state = State::Closed;
    }

    pub fn cached_session(&self) -> Option<SessionId> {
        self.cached_session
    }

    pub fn start(&mut self, random: [u8; 16], now_ms: u64) -> Result<Vec<Action>, HandshakeError> {
        let (Config::Client { retry, .. }, State::Idle) = (&self.config, &self.state) else {
            return Err(HandshakeError::InvalidState);
        };
        let hello = vec![Message::ClientHello {
            random,
            resume: self.cached_session,
        }];
        self.state = State::ClientHello(RetryFlight::new(hello.clone(), now_ms, *retry));
        Ok(vec![Action::Send(hello)])
    }

    // The wire adapter validates the server certificate before installing a
    // key exchange to use in the client flight.
    pub(crate) fn install_client_key_exchange(
        &mut self,
        exchange: Vec<u8>,
    ) -> Result<(), HandshakeError> {
        let (Config::Client { key_exchange, .. }, State::ClientHello(_)) =
            (&mut self.config, &self.state)
        else {
            return Err(HandshakeError::InvalidState);
        };
        *key_exchange = exchange;
        Ok(())
    }

    pub fn deadline(&self) -> Option<u64> {
        match &self.state {
            State::ClientHello(flight) => Some(flight.deadline),
            State::ClientCommit(commit) => Some(commit.sent.deadline),
            _ => None,
        }
    }

    /// Advance client retransmission timers using caller-supplied monotonic time.
    pub fn tick(&mut self, now_ms: u64) -> Vec<Action> {
        let Config::Client { retry, .. } = &self.config else {
            return Vec::new();
        };
        let flight = match &mut self.state {
            State::ClientHello(flight) => flight,
            State::ClientCommit(commit) => &mut commit.sent,
            _ => return Vec::new(),
        };
        if now_ms < flight.deadline {
            return Vec::new();
        }
        if flight.remaining == 0 {
            self.state = State::Closed;
            return vec![Action::TimedOut];
        }
        flight.remaining -= 1;
        flight.deadline = now_ms.saturating_add(retry.timeout_ms.get());
        vec![Action::Send(flight.datagram.clone())]
    }

    pub fn receive(
        &mut self,
        datagram: &[Message],
        now_ms: u64,
        finished: &impl FinishedProvider,
    ) -> Result<Vec<Action>, HandshakeError> {
        let result = match (&self.config, &mut self.state) {
            (
                Config::Server {
                    fresh_session,
                    random,
                    credential,
                },
                State::Idle,
            ) => server_hello(
                datagram,
                *fresh_session,
                *random,
                credential,
                self.cached_session,
                finished,
            ),
            (
                Config::Client {
                    retry,
                    key_exchange,
                },
                State::ClientHello(hello),
            ) => client_hello_response(hello, datagram, now_ms, *retry, key_exchange, finished),
            (_, State::ClientCommit(commit)) => client_commit(commit, datagram, finished),
            (_, State::ServerCommit(commit)) => server_commit(commit, datagram, finished),
            (_, State::Open(open)) => {
                if let Some(scope) = open.received_close(datagram) {
                    return self.close(scope);
                }
                return open.receive(datagram);
            }
            (_, State::Closed) => return Ok(Vec::new()),
            _ => return Err(HandshakeError::UnexpectedDatagram),
        };

        match result {
            Ok((state, mut actions)) => {
                let close = match &state {
                    Some(State::Open(open)) => open.received_close(datagram),
                    _ => None,
                };
                if let Some(state) = state {
                    self.state = state;
                }
                for action in &actions {
                    if let Action::Established { session, .. } = action {
                        self.cached_session = Some(*session);
                    }
                }
                if let Some(scope) = close {
                    actions.extend(self.close(scope)?);
                }
                Ok(actions)
            }
            Err(HandshakeError::FinishedVerificationFailed) => {
                self.cached_session = None;
                self.state = State::Closed;
                Err(HandshakeError::FinishedVerificationFailed)
            }
            Err(error) => Err(error),
        }
    }

    pub fn send_application(&mut self, payload: Vec<u8>) -> Result<Vec<Action>, HandshakeError> {
        let State::Open(open) = &mut self.state else {
            return Err(HandshakeError::InvalidState);
        };
        open.send_application(payload)
    }

    /// Both locally initiated and peer-initiated closure send one notification.
    /// The closed association ignores replies and any late application data.
    pub fn close(&mut self, scope: CloseScope) -> Result<Vec<Action>, HandshakeError> {
        let State::Open(open) = &self.state else {
            return Err(HandshakeError::InvalidState);
        };
        let mut datagram = open.unconfirmed_commit();
        datagram.push(Message::Alert(Alert::CloseNotify(scope)));
        self.state = State::Closed;
        if scope == CloseScope::Session {
            self.cached_session = None;
        }
        Ok(vec![Action::Send(datagram), Action::Closed(scope)])
    }
}

type Transition = Result<(Option<State>, Vec<Action>), HandshakeError>;

fn server_hello(
    incoming: &[Message],
    fresh_session: SessionId,
    random: [u8; 16],
    credential: &Message,
    cached: Option<SessionId>,
    finished: &impl FinishedProvider,
) -> Transition {
    let [Message::ClientHello { resume, .. }] = incoming else {
        return Err(HandshakeError::UnexpectedDatagram);
    };

    let (kind, session) = match resume {
        Some(id) if Some(*id) == cached => (HandshakeKind::Resumed, *id),
        _ => {
            if Some(fresh_session) == *resume || Some(fresh_session) == cached {
                return Err(HandshakeError::SessionIdCollision);
            }
            (HandshakeKind::Full, fresh_session)
        }
    };
    let mut outgoing = vec![Message::ServerHello { random, session }];
    let mut transcript = incoming.to_vec();
    match kind {
        HandshakeKind::Full => {
            outgoing.push(credential.clone());
            outgoing.push(Message::ServerHelloDone);
            transcript.extend_from_slice(&outgoing);
        }
        HandshakeKind::Resumed => {
            transcript.extend_from_slice(&outgoing);
            outgoing.extend(commit_messages(Role::Server, &transcript, finished)?);
            transcript.push(outgoing[2].clone());
        }
    };
    Ok((
        Some(State::ServerCommit(ServerCommit {
            hello: Exchange {
                incoming: incoming.to_vec(),
                outgoing: outgoing.clone(),
            },
            kind,
            session,
            transcript,
        })),
        vec![Action::Send(outgoing)],
    ))
}

fn client_hello_response(
    hello: &RetryFlight,
    incoming: &[Message],
    now_ms: u64,
    retry: RetryPolicy,
    key_exchange: &[u8],
    finished: &impl FinishedProvider,
) -> Transition {
    let [Message::ClientHello { resume, .. }] = &hello.datagram[..] else {
        unreachable!("client sent one ClientHello");
    };
    let mut transcript = hello.datagram.clone();

    match incoming {
        [
            Message::ServerHello { session, .. },
            Message::Certificate(_),
            Message::ServerHelloDone,
        ] if Some(*session) != *resume => {
            transcript.extend_from_slice(incoming);
            let exchange = Message::ClientKeyExchange(key_exchange.to_vec());
            transcript.push(exchange.clone());
            let commit = commit_messages(Role::Client, &transcript, finished)?;
            transcript.push(commit[1].clone());
            let mut datagram = vec![exchange];
            datagram.extend(commit);
            Ok((
                Some(State::ClientCommit(ClientCommit {
                    server_hello: incoming.to_vec(),
                    sent: RetryFlight::new(datagram.clone(), now_ms, retry),
                    session: *session,
                    transcript,
                })),
                vec![Action::Send(datagram)],
            ))
        }
        [
            server_hello @ Message::ServerHello { session, .. },
            Message::ChangeCipherSpec,
            peer_finished @ Message::Finished(proof),
        ] if Some(*session) == *resume => {
            transcript.push(server_hello.clone());
            verify_finished(finished, Role::Server, &transcript, proof)?;
            transcript.push(peer_finished.clone());
            let datagram = Vec::from(commit_messages(Role::Client, &transcript, finished)?);
            Ok((
                Some(State::Open(Open::new(OpenSide::ResumedClient {
                    commit: Exchange {
                        incoming: incoming.to_vec(),
                        outgoing: datagram.clone(),
                    },
                    confirmed: false,
                }))),
                vec![
                    Action::Send(datagram),
                    established(HandshakeKind::Resumed, *session),
                ],
            ))
        }
        _ => Err(HandshakeError::UnexpectedDatagram),
    }
}

fn client_commit(
    commit: &ClientCommit,
    incoming: &[Message],
    finished: &impl FinishedProvider,
) -> Transition {
    if incoming == commit.server_hello {
        // The outstanding client flight owns retransmission timing.
        return Ok((None, Vec::new()));
    }
    let [Message::ChangeCipherSpec, Message::Finished(proof)] = incoming else {
        return Err(HandshakeError::UnexpectedDatagram);
    };
    verify_finished(finished, Role::Server, &commit.transcript, proof)?;
    Ok((
        Some(State::Open(Open::new(OpenSide::FullClient {
            server_hello: commit.server_hello.clone(),
            peer_commit: incoming.to_vec(),
        }))),
        vec![established(HandshakeKind::Full, commit.session)],
    ))
}

fn server_commit(
    commit: &ServerCommit,
    incoming: &[Message],
    finished: &impl FinishedProvider,
) -> Transition {
    if incoming == commit.hello.incoming {
        return Ok((None, vec![Action::Send(commit.hello.outgoing.clone())]));
    }
    match (commit.kind, incoming) {
        (
            HandshakeKind::Full,
            [
                key @ Message::ClientKeyExchange(_),
                Message::ChangeCipherSpec,
                peer_finished @ Message::Finished(proof),
            ],
        ) => {
            let mut transcript = commit.transcript.clone();
            transcript.push(key.clone());
            verify_finished(finished, Role::Client, &transcript, proof)?;
            transcript.push(peer_finished.clone());
            let response = Vec::from(commit_messages(Role::Server, &transcript, finished)?);
            Ok((
                Some(State::Open(Open::new(OpenSide::FullServer {
                    hello: commit.hello.clone(),
                    commit: Exchange {
                        incoming: incoming.to_vec(),
                        outgoing: response.clone(),
                    },
                }))),
                vec![
                    Action::Send(response),
                    established(HandshakeKind::Full, commit.session),
                ],
            ))
        }
        (
            HandshakeKind::Resumed,
            [
                ccs @ Message::ChangeCipherSpec,
                peer_finished @ Message::Finished(proof),
                rest @ ..,
            ],
        ) => {
            let mut open = Open::new(OpenSide::ResumedServer {
                hello: commit.hello.clone(),
                peer_commit: vec![ccs.clone(), peer_finished.clone()],
            });
            let data = if open.received_close(incoming).is_some() {
                None
            } else {
                application_tail(rest)?
            };
            verify_finished(finished, Role::Client, &commit.transcript, proof)?;
            let mut actions = vec![established(HandshakeKind::Resumed, commit.session)];
            open.deliver(data, &mut actions);
            Ok((Some(State::Open(open)), actions))
        }
        _ => Err(HandshakeError::UnexpectedDatagram),
    }
}

fn commit_messages(
    sender: Role,
    transcript: &[Message],
    finished: &impl FinishedProvider,
) -> Result<[Message; 2], HandshakeError> {
    let proof = finished
        .create(sender, transcript)
        .ok_or(HandshakeError::FinishedUnavailable)?;
    Ok([Message::ChangeCipherSpec, Message::Finished(proof)])
}

fn verify_finished(
    finished: &impl FinishedProvider,
    sender: Role,
    transcript: &[Message],
    proof: &FinishedData,
) -> Result<(), HandshakeError> {
    if finished.verify(sender, transcript, proof) {
        Ok(())
    } else {
        Err(HandshakeError::FinishedVerificationFailed)
    }
}

fn alert(alert: Alert) -> Action {
    Action::Send(vec![Message::Alert(alert)])
}

fn established(kind: HandshakeKind, session: SessionId) -> Action {
    Action::Established { kind, session }
}

enum OpenSide {
    FullClient {
        server_hello: Datagram,
        peer_commit: Datagram,
    },
    FullServer {
        hello: Exchange,
        commit: Exchange,
    },
    ResumedClient {
        commit: Exchange,
        confirmed: bool,
    },
    ResumedServer {
        hello: Exchange,
        peer_commit: Datagram,
    },
}

struct Open {
    side: OpenSide,
    next_sequence: u32,
    replay: ReplayWindow,
}

impl Open {
    fn new(side: OpenSide) -> Self {
        Self {
            side,
            // Finished is the first record after CCS and occupies sequence zero.
            next_sequence: 1,
            replay: ReplayWindow::default(),
        }
    }

    fn awaiting_confirmation(&self) -> bool {
        matches!(
            &self.side,
            OpenSide::ResumedClient {
                confirmed: false,
                ..
            }
        )
    }

    fn send_application(&mut self, payload: Vec<u8>) -> Result<Vec<Action>, HandshakeError> {
        let sequence =
            u16::try_from(self.next_sequence).map_err(|_| HandshakeError::SequenceExhausted)?;
        self.next_sequence += 1;

        let mut datagram = self.unconfirmed_commit();
        datagram.push(Message::ApplicationData { sequence, payload });
        Ok(vec![Action::Send(datagram)])
    }

    fn unconfirmed_commit(&self) -> Datagram {
        match &self.side {
            OpenSide::ResumedClient {
                commit,
                confirmed: false,
            } => commit.outgoing.clone(),
            _ => Vec::new(),
        }
    }

    fn received_close(&self, incoming: &[Message]) -> Option<CloseScope> {
        let tail = match &self.side {
            OpenSide::ResumedServer { peer_commit, .. } => incoming
                .strip_prefix(peer_commit.as_slice())
                .unwrap_or(incoming),
            _ => incoming,
        };
        match tail {
            [Message::Alert(Alert::CloseNotify(scope))] => Some(*scope),
            _ => None,
        }
    }

    fn receive(&mut self, incoming: &[Message]) -> Result<Vec<Action>, HandshakeError> {
        let mut actions = Vec::new();

        match &mut self.side {
            OpenSide::FullClient {
                server_hello,
                peer_commit,
            } if incoming == server_hello || incoming == peer_commit => return Ok(actions),
            OpenSide::FullServer { hello, .. } | OpenSide::ResumedServer { hello, .. }
                if incoming == hello.incoming =>
            {
                return Ok(vec![Action::Send(hello.outgoing.clone())]);
            }
            OpenSide::FullServer { commit, .. } if incoming == commit.incoming => {
                return Ok(vec![Action::Send(commit.outgoing.clone())]);
            }
            OpenSide::ResumedClient { commit, confirmed } => {
                if incoming == commit.incoming {
                    if !*confirmed {
                        actions.push(Action::Send(commit.outgoing.clone()));
                    }
                    return Ok(actions);
                }
                if incoming == [Message::Alert(Alert::DuplicateFinishedReceived)] {
                    *confirmed = true;
                    return Ok(actions);
                }
            }
            OpenSide::ResumedServer { peer_commit, .. } if incoming.starts_with(peer_commit) => {
                let data = application_tail(&incoming[peer_commit.len()..])?;
                actions.push(alert(Alert::DuplicateFinishedReceived));
                self.deliver(data, &mut actions);
                return Ok(actions);
            }
            _ => {}
        }

        let [Message::ApplicationData { sequence, payload }] = incoming else {
            return Err(HandshakeError::UnexpectedDatagram);
        };
        self.deliver(Some((*sequence, payload)), &mut actions);
        Ok(actions)
    }

    fn deliver(&mut self, data: Option<(u16, &[u8])>, actions: &mut Vec<Action>) {
        if let Some((sequence, payload)) = data
            && sequence != 0
            && self.replay.accept(sequence)
        {
            if let OpenSide::ResumedClient { confirmed, .. } = &mut self.side {
                *confirmed = true;
            }
            actions.push(Action::Deliver(payload.to_vec()));
        }
    }
}

fn application_tail(messages: &[Message]) -> Result<Option<(u16, &[u8])>, HandshakeError> {
    match messages {
        [] => Ok(None),
        [Message::ApplicationData { sequence, payload }] => Ok(Some((*sequence, payload))),
        _ => Err(HandshakeError::UnexpectedDatagram),
    }
}

/// Datagram replay window for application records already authenticated by the
/// caller. This slice starts each association at sequence zero and never wraps.
#[derive(Default)]
struct ReplayWindow {
    highest: u16,
    received: u32,
}

impl ReplayWindow {
    fn accept(&mut self, sequence: u16) -> bool {
        if sequence > self.highest {
            let shift = u32::from(sequence - self.highest);
            self.received = self.received.checked_shl(shift).unwrap_or_default() | 1;
            self.highest = sequence;
            return true;
        }

        let distance = u32::from(self.highest - sequence);
        let Some(mask) = 1u32.checked_shl(distance) else {
            return false;
        };
        if self.received & mask != 0 {
            return false;
        }
        self.received |= mask;
        true
    }
}
