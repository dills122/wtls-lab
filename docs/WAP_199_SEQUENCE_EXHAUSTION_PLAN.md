# WAP-199 sequence exhaustion plan

**WTLS-215 · Verified at `b7d5baf`.** Both provisioned UDP
roles passed the deterministic boundary suite and exact Ruflo review.
[WAP-199 evidence matrix](WAP_199_EVIDENCE_MATRIX.md#g1-sequence-exhaustion) · [Evidence ledger](WTLS_EVIDENCE.json)

## Decision

Retire the exhausted connection locally and preserve its existing,
otherwise eligible cached session. Keep the cache entry's original
expiry, credential validity constraints, and trust and identity context.
A resumed connection can reuse that session ID and master secret. Its
fresh hello randoms produce new traffic keys, and its new protected
sequence starts at zero at ChangeCipherSpec. Ordinary key refresh within
a connection keeps the current sequence space.

§9.2.3.1 requires closure when a sequence would exceed 65,535. §10.2
and §10.2.1 distinguish connection closure from session invalidation.
§11.1.4 explains why a resumed connection gets new traffic key material.
Appendix B.3 describes ordinary key refresh within an existing connection.
Preserving the cache on local exhaustion is a profile decision based on
those rules. [WAP-199 in the official release](https://www.openmobilealliance.org/tech/affiliates/wap/Technical_June2000-20021106%5B1%5D.zip) · [Existing cache policy](WIRE_SESSION_RESUMPTION.md#cache-policy)

| Situation | Connection and wire result | Local cached session |
| --- | --- | --- |
| A new record uses the last available number | Allow sequence 65,535 for a legal record. A protected close can use that number if requested in time. | Normal rules for the record apply. |
| A send needs a new record after the last number | Return a typed sequence-exhaustion diagnostic. Close locally, release the association's traffic state, and retire its UDP slot. Emit no datagram for this failed send. | Preserve the eligible entry at the original expiry. |
| Explicit local Session close while the association still exists | Close locally in either case. Send the protected alert if a record number remains. Report exhaustion if the alert cannot be sent. | Invalidate the exact entry locally even if the alert cannot be sent. |
| An authenticated peer Session close or a validated fatal alert requires invalidation | Honor the event for the committed receive epoch. Perform required local closure even if a close acknowledgment cannot be encoded. | Apply the existing invalidation rule to the exact entry. |

A Session close that could not be sent only invalidates the local entry.
An ordinary Connection close or a validated critical alert preserves
eligibility. Clear or provisional alerts have no cache revocation authority
under the existing authenticated profile.

The wire record counter governs fresh output across application records
and alerts. Both the application guard and wire encoder report
`WireError::Handshake(HandshakeError::SequenceExhausted)` at the limit.
The wire peer closes and releases connection-local state. The UDP adapter
reports its existing protocol diagnostic and removes the peer when it
reports `Closed`. [Wire implementation](../src/wire.rs) ·
[Adapter retirement](../src/udp.rs)

A byte-identical cached retransmission uses its original sequences and
requires no new number while the association is open. A cached resumed
commit prefix also reuses its bytes. A fresh tail or a new duplicate-Finished
acknowledgment still needs a number. If encoding exhausts the sequence space,
emit no partial datagram.
After retirement the peer ends all sends.
[Cached flight encoding](../src/wire.rs#L981)

## UDP reconnect boundary

Local retirement frees the local slot. When there is no number left for
a protected alert, the peer can still retain its association for the
old UDP tuple. An active server routes a new ClientHello on that tuple to
the old association. Verify resumption with eligible caches on a fresh UDP
tuple or after both endpoints retire the old association. Server admission
uses a new ClientHello random and the existing capacity and retired-hello
checks. Active-tuple takeover and proactive rotation before the limit are
separate design decisions. [UDP routing](../src/udp.rs#L223)

## Deterministic acceptance

| Case | Observable success |
| --- | --- |
| Client and server send to the boundary | The peer accepts the last protected record at 65,535. The next send requiring a new number reports exhaustion, emits no record, and leaves the peer closed. Cover application and alert output so a counter advanced by an alert does not change the result. |
| Cached retransmission and resumed prefix | A pure retransmission while still open is byte-identical at the limit. A retransmitted commit plus a fresh record still requires capacity for the fresh record. The exhausted send produces no partial output. |
| Cache preservation and reuse | A new association with the same live trust and identity context can resume the exact ID and exchange protected data using fresh keys. Original expiry still governs eligibility. |
| Session close and fatal alert | An explicit local Session close and an authenticated peer Session close invalidate the applicable entry even if their own send or reply cannot be encoded. A validated fatal alert continues to invalidate it. Check that exhaustion alone does not invalidate it. |
| UDP adapter | The attempt returns a protocol diagnostic and removes the local association. Its slot is usable by a fresh association. |

Parameterize the boundary cases by sender role. Use private test state to
seed the post-CCS counters if needed. Exercise both wire roles and the
UDP adapter, then rerun the
existing alert, resumption, protected echo, and WinWAP regression suites.
