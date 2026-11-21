# WAP-199 pending server ClientHello replacement

**WTLS-218 · Verified at `d12211e`.** This slice covers G6 for an inbound
server handshake that has started and has yet to authenticate Finished.
[WAP-199 evidence matrix](WAP_199_EVIDENCE_MATRIX.md#g6-fresh-clienthello-during-a-pending-handshake)

## Wire rule and current behavior

WAP-199 §10.4 requires the server to repeat its ServerHello SDU for a
duplicate ClientHello and start a handshake for a new ClientHello. The
same distinction applies to abbreviated handshakes. The specification also
calls for a `SEC-Create.ind` service primitive. The standalone adapter
exposes a new initial flight and negotiating state through its existing
interface. The deterministic tests verify the fresh handshake transition at that
boundary. `Established` reports the later commit. WAP service-level
conformance would also require a creation indication with the §6.3.2.1
parameters before the initial flight.
[WAP-199 in the official release](https://www.openmobilealliance.org/tech/affiliates/wap/Technical_June2000-20021106%5B1%5D.zip)

After the adapter admits a first hello, it routes later datagrams from the
same source to that peer. Exact retransmissions work because the wire peer
matches a previously accepted datagram and returns its stored response. A
different opening hello cannot start on the existing peer, since normal
ClientHello admission expects an idle server. The UDP adapter can make the
replacement decision while the wire peer continues to own negotiation.
[UDP routing](../src/udp.rs#L216) · [Opening validation](../src/udp.rs#L380) · [Wire retry path](../src/wire.rs#L326)

## Adapter behavior

Apply replacement only while the tuple holds an inbound server peer with
a pending deadline and negotiating status. Use the parsed random for
candidate classification and the wire peer's existing exact-byte matching
for replay. Established connections and outbound clients use their normal
routing paths.

| Received on the pending tuple | Result |
| --- | --- |
| Exact copy of the current ClientHello SDU | Use the wire peer's existing cached-flight path. Emit the same bytes and keep the deadline. |
| Same ClientHello random with different bytes | Diagnose the conflicting offer. Preserve the pending peer and emit no handshake flight. An exact retry can still recover its flight. |
| Hello for a recently retired random | Apply the existing retired-hello rejection while the random remains in the bounded history. Keep the current peer and its deadline. |
| Different random and an admissible opening hello | Evaluate the entire SDU using a new server peer from the same context. Replace the existing pending peer only after a successful initial handshake flight fits the datagram budget. Keep one slot. Record the displaced random in the existing bounded history. |
| Candidate fails framing, negotiation, or the outbound budget | Preserve the current negotiation. Use the applicable normal idle-path diagnostic or initial alert when one exists. An alert-only response does not count as admission. |

Retain the first admission's deadline across replacement within the same
occupied slot. Duplicates, rejected candidates, and accepted replacements
share the remaining time in that slot. A replacement late in the window
gets only the remaining time. A new admission after expiry gets its own
lifetime through the existing path. This is local admission
policy. It avoids extending a slot's lifetime through successive hellos.
Appendix B.4 informs the separate treatment of established connections.
Established connection replacement belongs to a separate negotiation design. [Expiry and retirement](../src/udp.rs#L286) · [WAP-199 Appendix B.4](https://www.openmobilealliance.org/tech/affiliates/wap/Technical_June2000-20021106%5B1%5D.zip)

A replacement starts a new transcript from its own ClientHello. Its first
flight and Finished belong to that attempt. An older in-flight commit must
fail to establish the replacement, and a normal retry of the replacement
must remain usable. Discard the old provisional state without a Session
close. Use the ordinary full or abbreviated cache lookup and expiry on the
candidate, and require its own verified Finished before full-session
insertion. Existing verified session entries remain eligible on their
original terms, including the abbreviated commit-time recheck.
[Selection and cache insertion](../src/wire.rs#L558) · [Cache policy](WIRE_SESSION_RESUMPTION.md#cache-policy)

## Deterministic tests

Use the existing in-memory UDP adapter link, fixed clocks, and ordinary
locally generated client flights. Use distinct supplied wall-clock values
for A and B so that different hello randoms can be asserted independently of
random key material. The first test reproduced the missing fresh B admission before the fix.

| Case | What to prove |
| --- | --- |
| A, duplicate A, B, duplicate B at capacity one | Compare both duplicate replies byte for byte with their respective original flights. B starts on the same tuple while capacity is full. The peer stays pending until B's Finished. A later third tuple still sees the capacity limit. |
| Delayed A after replacement | A's original hello is recognized as retired while retained. Deliver A's genuine delayed commit. Observe no establishment or application delivery. B retains its cached flight, finishes once, and carries a protected request and echo. |
| Rejected candidate | A malformed datagram, a same-random conflict, or a fresh candidate that cannot produce a usable first flight leaves A and its deadline intact. Replay A to verify the exact original bytes, then deliver its legitimate commit and establish. Include an alert-only or outbound-budget rejection to exercise the commit point. |
| Pending deadline | Accept B just before A's deadline. Check that it still expires at that original deadline, releasing the slot. Duplicates also leave the deadline fixed. |
| Abbreviated replacement | Seed a verified session and close its connection. Replace one pending abbreviated offer with another fresh offer for that session. Verify the cached ID, the server-first Finished flight and its exact repeat, then B's Finished and protected delivery. |
| Established tuple guard | Send an ordinary fresh hello on the completed tuple. Verify the established peer can still exchange protected data. |

Keep existing retry, timeout, cache, and WinWAP checks in the regression gate.
[Existing initial-flight loss test](../tests/udp_adapter.rs#L634) · [Existing timeout test](../tests/udp_adapter.rs#L941)
