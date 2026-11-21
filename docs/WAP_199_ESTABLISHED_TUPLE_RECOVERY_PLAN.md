# WAP-199 recovery on an established UDP tuple

**WTLS-223 · Verified at `4796ed6`.** The gateway stages a fresh full
handshake on an occupied inbound tuple while the incumbent carries
protected traffic. Promotion requires verified client Finished and a
final server flight within budget. A UDP tuple here is the remote
address and port as seen by one adapter.
[Support promise review](WAP_199_SUPPORT_PROMISE_REVIEW.md) ·
[Current UDP routing](../src/udp.rs#L234)

## Protocol and verified scope

WAP-199 §10.4 specifies byte-identical flight retransmission for
duplicates and starting a handshake for a fresh ClientHello. Appendix
B.4 discusses retaining the active state until the new handshake
succeeds. Apply that guidance by holding an independent wire peer for
the pending attempt. The adapter still exposes its existing datagram
and establishment events. The WAP `SEC-Create.ind` service primitive
and its parameters remain a separate interface decision.
[WAP-199 §10.4](https://ptacts.uspto.gov/ptacts/public-informations/petitions/1549804/download-documents?artifactId=q91LjyqB9tLZ-LVakpTsgAE_GyThWnjP3JSk0xnVhQkx_FB33j7C-1I#page=51) ·
[WAP-199 Appendix B.4](https://ptacts.uspto.gov/ptacts/public-informations/petitions/1549804/download-documents?artifactId=q91LjyqB9tLZ-LVakpTsgAE_GyThWnjP3JSk0xnVhQkx_FB33j7C-1I#page=91)

Start with a fresh full ClientHello that carries an empty session ID.
That covers a client that lost its session state on restart. The
established peer may have opened through either a full or an abbreviated
handshake. A staged abbreviated replacement requires its own design
for two potentially matching commit prefixes and shared-session cache
lifecycle, including the existing locked cache-entry recheck at Finished.
Keep the current occupied-tuple behavior for fresh hellos that carry
a session ID. Ordinary fresh-tuple full and abbreviated handshakes use
the existing paths. This is a profile rollout decision.
[Pending ClientHello design](WAP_199_PENDING_CLIENT_HELLO_PLAN.md#adapter-behavior) ·
[Abbreviated prefix behavior](WIRE_SESSION_RESUMPTION.md#wire-contract)

## Ownership and routing while a replacement is pending

Keep one active inbound peer A and at most one staged peer B in the
same capacity slot. Only established inbound peers may stage a
replacement. Independently configured client peers use their existing
routing. Validate B through the ordinary opening, authority,
algorithm, and outbound-budget gates. A rejected offer can produce
the applicable initial alert. A staged peer exists only after an
admissible first flight can be sent. Start a fixed monotonic deadline
using the existing pending lifetime. Keep that first candidate until
it commits, is retired, or expires. Report the existing address-in-use
diagnostic for another fresh full offer while the candidate is present.
Retries leave the deadline unchanged. Retain the existing G6 rule for
tuples that have a pending handshake and no incumbent connection.

| Incoming on A's tuple | Proposed handling |
| --- | --- |
| Exact retry for a previously accepted flight | Resolve A's exact cached SDUs and verified abbreviated prefix before matching B's exact cached SDUs. Give the whole datagram to its owner, which retains its existing replay and reply rules. |
| Another hello reuses an active or pending random with different bytes, or uses a retained retired random | Use the existing conflict or retired-hello outcome. Keep both peers and their deadlines. |
| A fresh eligible full ClientHello | Stage an independent negotiation when the candidate position is free. A continues to own protected traffic and application sends. |
| Protected traffic belonging to A, including an old abbreviated retry prefix | Use A's normal receive path and replay state. It must remain usable even with B pending. |
| A full client commit for B | Select B only for the supported complete full-commit flight. Run normal framing, key exchange, and Finished checks inside B. Process the complete datagram once. |
| A standalone clear alert for B | Use B's G3 checksum and receive-state checks. A clear alert can end B alone. |
| Invalid or ambiguous input | Keep each peer's normal failure semantics in its selected lane. Never retry the same input against the other peer after a failure. A rejected B attempt cannot alter A's state or verified cache entry. |

Routing uses existing framing and byte-exact replay recognition. The
datagram has no independent connection ID. The Session ID identifies a
resumable session and can be shared by several connections. Use the
existing verified-prefix boundary check for A, and leave its complete
suffix on A's authentication and replay path. A pending candidate must
pass its own commit checks before it can publish any establishment or
delivery.
[Wire flight matching](../src/wire.rs#L519) ·
[Server commit handling](../src/handshake.rs#L621) ·
[G3 alert policy](WAP_199_CLEAR_ALERT_PLAN.md#profile-behavior)

## Handover, timeout, and close behavior

Promote that same B peer when the server's receive path succeeds, B is
open, and the final server flight fits the budget. At that point retire A
locally and publish the new `Established` event once. The application
uses this event to start state for the new connection. The selected
profile authenticates the gateway to the client. A proved client
Finished establishes key and transcript agreement for B. Application
identity and state carry-forward require their own policy.
[Server final flight and establishment](../src/handshake.rs#L642) ·
[Application event handling](../src/bin/wtls-udp-lab.rs#L168)

Promotion sends no Session close and preserves existing cache policy.
The fully verified B session uses the usual insertion, expiry and
eviction rules. A's delayed records after promotion go through B's
normal receive checks and produce no A application delivery. B owns
its accepted flight history immediately, so a retransmitted B commit
recovers a lost final server flight byte for byte without a second
`Established` event.

While B is staged, adapter `status`, connection metadata, application
sends and explicit closes still refer to A. Include B's deadline in
adapter scheduling and expire it before routing when the clock reaches
that deadline. A candidate-only terminal rejection or expiry removes only
B. Use existing diagnostics where relevant. Do not emit the tuple-wide
`TimedOut` or `Closed` event for B while A is still serving traffic,
since callers use those events to tear down application state. If A
ends independently, preserve its normal close, timeout and cache
effects. Cancel the staged attempt and allow a later fresh hello
through ordinary admission. Record retired hello randoms under the
existing bounded policy. These are local ownership rules.
[Adapter scheduling](../src/udp.rs#L153) ·
[Existing association retirement](../src/udp.rs#L466) ·
[Cache policy](WIRE_SESSION_RESUMPTION.md#cache-policy)

At the public API, writes address the current association by tuple.
Once B is established, delayed application work submitted for that
tuple uses B. Consumers reset tuple-bound state on `Established`. The
lab responder already resets its application session there. Carrying
application work across a handover needs an association-aware API.
[Tuple-based send](../src/udp.rs#L454) ·
[Application reset](../src/bin/wtls-udp-lab.rs#L172)

## Deterministic tests

Use two local client state machines, a fixed UDP tuple and explicit
wall and monotonic clocks. Keep A's state in the harness to check
continuity while B simulates a restart. Use ordinary, locally generated
handshake and application datagrams. To exercise a budget refusal, use
preseeded caches and an adapter budget that admits A's resumed flight
while rejecting B's larger full certificate flight.

| Test | Acceptance evidence |
| --- | --- |
| Stage B at capacity one | A remains open and exchanges protected data after B's first flight. Exact A and B hello retries receive their own cached replies. B's deadline is fixed, and a separate tuple sees the existing capacity guard. |
| Authenticate and promote B | Verify that B's Finished is the transition point. Check one new establishment and protected traffic under B. Deliver genuine delayed A data after promotion and observe no old application delivery. |
| Lose B's final server flight | Drop the normal final reply after the server has promoted B. Let B retry the identical client commit, compare the repeated server flight byte for byte, and complete a protected exchange. |
| Failed or expired B | Use an initial refusal, first-flight budget rejection, a failed candidate verification and an ordinary WTLS-221 certificate rejection. Verify continued A traffic and cache eligibility. Check expiry through both `tick` and inbound routing at the exact deadline, including a B commit at that deadline. Observe no tuple-wide close or timeout. |
| Incomplete input during staging | Verify A remains usable and B retains its deadline and cached flight. |
| Candidate capacity and replay | Exercise B retry, same-random conflict and a fresh eligible C while B is staged. Verify B keeps its flight and deadline. Once B retires, stage a fresh offer and check that delayed traffic from B cannot complete it. |
| Existing abbreviated A | Stage a full B while A is open on the server and its client still uses the G4 abbreviated commit prefix. Verify that A's valid prefixed application data reaches A's path and B stays pending. |
| Independent close of A | Process an authenticated A close before B's commit and verify ordinary Connection or Session close and cache effects, B cancellation, and admission of a later fresh client. In a separate order, promote B first and verify delayed A closure leaves B open. |

All 154 Rust tests, Clippy, formatting, and the exact-commit
Ruflo review passed. The regression gate retains G3, G4, G6, terminal
retirement, sequence exhaustion, and final-flight retry controls.
[Established recovery tests](../tests/udp_adapter.rs#L1458) ·
[Supervised verification](SUPERVISED_WORKFLOW.md#run-the-wtls-loop)
