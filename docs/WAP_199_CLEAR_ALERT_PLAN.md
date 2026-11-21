# WAP-199 clear alert handling

**WTLS-219 · Verified at `0d49c5a`.** G3 covers receiving clear alerts
in the scoped server-authenticated UDP profile. [WAP-199 evidence matrix](WAP_199_EVIDENCE_MATRIX.md#g3-alert-scope)

## What the specification requires

Section 10.2 defines a four-byte XOR checksum over the complete last
WTLSCiphertext record received, with zero padding for a partial final
block. The receiving endpoint checks the alert against a record it sent.
An earlier sent record can match when a later record was lost. The
all-zero exception is permissive when the receiver can determine that
the sender received no record to checksum. A normal computed checksum
can also be zero. This checksum correlates the alert to traffic. It
provides no cryptographic authentication.

Sections 10.2 and 10.2.2 call for terminating a connection on a fatal
or critical error and distinguish termination from the fate of a stored
session. Section 10.2.2 recommends preserving an existing valid session
on a clear fatal alert. Appendix B.4 advises protecting existing secure
state from a single clear message and checking a clear alert's checksum
before accepting its sequence number. Section 10.2.1 defines the separate
closure-notification exchange and session invalidation. [WAP-199 §§10.2–10.2.2 and Appendix B.4](https://www.openmobilealliance.org/tech/affiliates/wap/Technical_June2000-20021106%5B1%5D.zip)

Before WTLS-219, the clear receive branch reported a decoded alert
without checksum validation and left a pending peer open on a matching fatal. A protected
alert already checks the checksum against sent records and follows the
authenticated receive-epoch rules. [Clear receive branch](../src/wire.rs#L767) ·
[Protected alert receive path](../src/wire.rs#L972)

## Profile behavior

Process a well-framed, standalone clear alert while a pending negotiation
is still receiving clear records. Require a checksum matching a complete
record emitted by that peer in the current attempt. Use its actual record
framing and existing sent-record checksum history. Treat zero as an
ordinary checksum that must match here. These paths have no evidence for
the special no-record exception.

Apply the expected clear sequence to ordinary alerts. WAP-199 §10.2.2
recommends accepting a fatal or critical `no_connection` regardless of
its record sequence. Honor that exception during a pending negotiation
after checksum validation. The sender's recommended value is 65,535.
The exception grants no authority over committed state and advances no
receive sequence. Leave sequence and retry state untouched when reporting
a nonterminal alert. [WAP-199 §10.2.2](https://www.openmobilealliance.org/tech/affiliates/wap/Technical_June2000-20021106%5B1%5D.zip)

| Input | Connection result | Cached session |
| --- | --- | --- |
| Framing or checksum fails, or epoch is ineligible | Reject with a receive diagnostic. The current connection or attempt keeps its state. | Preserve. |
| Matching clear fatal or critical error while pending | End only this negotiation and report `PeerAlert(Clear)`. Cancel retries and release pending state, so the adapter frees the slot. | Preserve verified entries at their original expiry and trust context. |
| Matching clear warning while pending | Report it as a clear observation. Keep the existing retry deadline and sequence state. | Preserve. |
| Correctly leveled and checksum-matched clear closure notification or duplicate-Finished warning while pending | Report it as a clear observation. Keep pending, with no closure acknowledgment or confirmation. | Preserve. |
| Clear alert after authenticated receive commit | Reject as an unexpected clear record. Continue the authenticated connection, including a client awaiting abbreviated confirmation. | Preserve. |
| Checksum-matched authenticated critical or fatal in a committed receive epoch | Keep the existing terminal-error handling. Keep the protected closure-notification path. | Critical preserves the session. Fatal or authenticated Session close invalidates the exact entry. |

An eligible clear termination should reuse the existing peer alert and
adapter diagnostic path. Closure is visible through the peer's closed
state and adapter slot retirement. The receiver sends no close
acknowledgment for a clear error. A caller can start another handshake
through the existing connection API. Cache eligibility and timers apply as
usual. [Adapter retirement](../src/udp.rs#L316) · [Existing cache policy](WIRE_SESSION_RESUMPTION.md#cache-policy)

The existing protected-epoch rules also cover provisional authentication
and remain the authority for protected alerts. Specialized `time_required`
timer behavior and new outbound certificate or error alerts are separate
work. [Protected epoch check](../src/wire.rs#L670) ·
[Local certificate rejection](../src/wire.rs#L416)

## Deterministic tests

Use only local in-memory peers and fixtures with fixed clocks.

| Case | Acceptance |
| --- | --- |
| Checksum reference and validation | Match an independent expected checksum for an earlier emitted record in a multi-record server flight. Reject malformed framing, a mismatched checksum, an unrelated previous-attempt checksum, and unmatched zero. Confirm the expected normal flight still works after rejection. |
| Pending full or abbreviated termination | Exercise matched clear fatal and critical errors across client and server roles before receive commit. Confirm immediate terminal state and no retry or close acknowledgment. An adapter test observes its slot free on the same receive call. |
| `no_connection` sequence exception | Cover checksum-matched fatal or critical `no_connection` at 65,535 and another off-sequence value during pending negotiation. A wrong checksum still rejects and preserves the attempt. |
| Cache preservation | Seed an eligible verified session, start an abbreviated attempt, and end that attempt with a matched clear terminal error before receive commit. Reconnect with the same session ID, verify abbreviated establishment and protected traffic, and confirm that expiry still comes from the original verified full handshake. |
| Advisory and protected-only meanings | A matching clear warning preserves the pending deadline. Clear close notifications and a clear duplicate-Finished warning leave cache and confirmation state intact. |
| Committed receive state and protected regression | A committed full connection and an abbreviated client awaiting confirmation retain their state on clear observations. Protected traffic still flows. Keep the existing protected fatal, critical and Session close tests and add a server-side generic critical case to verify closure with cache retention. |

The first regression reproduced a matched clear fatal leaving the peer
negotiating. The verified suite covers the checked receive behavior and
retains outbound checksum and protected lifecycle controls. [TRUST-03 outbound checksum test](../tests/provisioned_trust.rs#L400) ·
[Current alert lifecycle tests](../src/wire/alert_tests.rs#L565)
