# WTLS product boundaries

**DQ-10 · Proposed for review.** The standalone Rust library implements one
server-authenticated WAP-199 UDP profile. The BlackBerry lifecycle and live
packet-loss cases give us two callers to design around. These proposals keep
the existing profile and public API in place while we review what each caller
needs. [Support boundary](WAP_199_PROVISIONED_TRUST_PLAN.md#support-boundary)

| Scenario | What the caller needs to supply or observe |
| --- | --- |
| Provisioned BlackBerry full, resumed, and full after close | Supply the expected server identity and provisioned trust, keep the cached session and current connection distinct, and show one establishment outcome and protected page acknowledgment per request. Session-close eviction determines the gateway's next handshake even when the BlackBerry reoffers the same ID. [Rust lifecycle](../fixtures/HISTORICAL_PEERS.md#blackberry-provisioned-trust-reconnect-lifecycle) · [KWTLS cache control](KWTLS_LAB_BASELINE.md#session-cache-invalidation-control) |
| Handshake with one missing server datagram | Correlate the drop or delivery observed by the relay, next client retry, server behavior, endpoint establishment, and page acknowledgment or timeout. A server may report successful client Finished while the browser still waits for the last flight. [Live loss comparison](KWTLS_LAB_BASELINE.md#live-handshake-datagram-loss) · [Rust retry test](WAP_199_EVIDENCE_MATRIX.md#g2-full-handshake-final-flight-retry) |

## Proposed ownership

| Layer | Responsibility |
| --- | --- |
| Standalone protocol library | Own record framing and protection, the handshake and its deadlines, peer verification, and session and close policy. Keep the existing testable actions and diagnostics as the starting surface. |
| UDP adapter | Route whole datagrams, supply monotonic and Unix clocks, schedule the library's deadlines, enforce the datagram budget, and report observable transport failures. A successful local UDP send records an attempt. A relay can supply independent drop or delivery evidence. |
| Inspector | Explain the captured sequence, direction, record boundaries, and observed retry relationships. Accept drop markers from the capture and correlate them by time. Keep ciphertext opaque and rely on endpoint events for Finished verification, cache decisions, and application outcomes. |
| Ready-to-run peers and lab tooling | Own endpoint and trust configuration, reading provisioned identities, starting the association, and reporting the page or echo. Keep WTP/WSP handling and deliberate frame loss in the tools that exercise them. |

## Example diagnostic transcripts

These are example summaries assembled from existing observations. Each
sentence identifies its source so a caller can tell which conclusions
require an endpoint or application log.

**Provisioned reconnect.** The capture shows a full handshake with fresh
ID `0x31`. The endpoint reports that Connection close kept the cache
entry. The capture then shows the BlackBerry reoffer `0x31` and the
gateway resume. The endpoint reports that Session close removed the
entry. The capture shows the BlackBerry reoffer `0x31` again and the
gateway perform a full handshake with `0x32`. The backend recorded
protected page acknowledgments `0019`, `22d4`, and `3353` in order.
The cache decisions come from the KWTLS lab control.
[Close and reconnect evidence](KWTLS_LAB_BASELINE.md#session-cache-invalidation-control)

**Lost final server flight.** KWTLS reports that it accepted the client
Finished. The relay withheld the 51-byte server final flight and then
observed five byte-identical client commits. The first retry came 6.376 s
after the original client commit. The relay saw no response to any retry.
The client sent `handshake_failure` 37.580 s after the original commit.
The browser reported a negotiation failure, and the backend recorded no
protected page acknowledgment.
[Final-flight evidence](KWTLS_LAB_BASELINE.md#final-server-flight)

## Decision to review

Keep handshake retry and final-flight retention in the protocol library.
The adapter supplies clocks and transports datagrams. The inspector shows
drop markers and annotates byte-identical ClientHello and full client
commit datagrams. The annotations identify repeats within a capture.
A drop marker that carries only a length cannot establish whether a subsequent
server send repeats the withheld bytes. The lab tooling can provide that
comparison when its relay retains the original bytes. The tools can also
assemble endpoint and application outcomes alongside the capture.

Review the transcripts and ownership before changing the public API.
A concrete missing observation from a caller should drive the next
diagnostic change. Consider WAP service primitives separately when
there is a caller for them.
[Current adapter and lab app](../README.md#reusable-udp-adapter-and-blackberry-lab) ·
[Inspector format](../README.md#handshake-timeline)
