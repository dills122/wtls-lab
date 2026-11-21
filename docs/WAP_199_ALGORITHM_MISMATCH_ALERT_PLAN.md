# WAP-199 server alert for unmatched algorithms

**WTLS-222 · Verified at `036ce51`.**
This slice covers the authenticated UDP server's response to an otherwise
admissible opening ClientHello when it cannot choose the fixed RSA
profile and cannot use a compatible verified session.
[Support promise review](WAP_199_SUPPORT_PROMISE_REVIEW.md) ·
[Current selection](../src/wire.rs#L686)

## WAP-199 rule

WAP-199 §§10.5.1.2 and 10.5.1.3 call for `handshake_failure` if the
server cannot choose acceptable algorithms. SIN _104 §3.3 also requires
this outcome when no key-exchange option is acceptable and keeps the
advertised trusted-authority rule. Section 10.2.2 defines
`handshake_failure` as fatal. A cipher suite pairs one bulk cipher with
one MAC. An offer has to contain the supported pair together.
[WAP-199 §§10.5.1.2–10.5.1.3](https://ptacts.uspto.gov/ptacts/public-informations/petitions/1549804/download-documents?artifactId=q91LjyqB9tLZ-LVakpTsgAE_GyThWnjP3JSk0xnVhQkx_FB33j7C-1I#page=59) ·
[WAP-199 baseline and SIN _104](https://www.openmobilealliance.org/tech/affiliates/wap/Technical_June2000-20021106%5B1%5D.zip)

The selected full profile uses unrestricted RSA (8) with default
parameters and the exact 3DES-CBC-EDE (6) and full SHA MAC (3) pair.
Opening profile failures return `UnsupportedProfile`. A full algorithm
selection failure produces the alert after the admission, cache and
authority decisions.
[Current profile and selector](../src/wire/codec.rs#L24) ·
[Key-exchange and record choice checks](../src/wire/codec.rs#L80)

## Decision order

1. Require one complete clear ClientHello with an explicit record
   sequence field of 0. Accept an explicit length or an omitted length
   on the sole record. Malformed framing or vectors, invalid opening
   state and inbound budget failures stay on their local paths.
   On the authenticated server, check version 1, the explicit
   sequence-mode proposal and the presence of null compression before
   any initial alert selection. These checks win when an offer also
   fails the cache or authority checks. NULL is mandatory in the offer.
   Requiring an explicit proposal when the client proposes off is the
   existing lab profile choice. It stays in place even though §10.5.1.3
   permits the server to enable sequencing. Keep the current key-refresh
   cap, including zero and proposals above the cap. Operational provider
   and encoder failures stay local.
2. Check for a usable verified session using the existing ID, context,
   expiry and offered record choices. The cache uses eight-byte IDs
   and shorter nonempty IDs miss it. A session can resume with the
   existing cipher/MAC without a matching RSA offer. The ServerHello
   uses the existing one-based index when a compatible key is listed
   and uses zero for an omitted or incompatible key-exchange list.
3. Keep `unknown_key_id` (critical level 2, description 52) for a resume-only ClientHello
   with a nonempty session ID, an empty key-exchange list, and no
   usable cached session. Section 10.5.1.2 specifies this case.
   Preserve the existing precedence over the advertised-authority
   check for the same resume-only miss. Critical severity is the
   existing lab choice.
4. Preserve fatal `handshake_failure` (40) for a provisioned authority
   mismatch when the current policy declines the offer. This includes
   a conflicting nonempty authority list on an otherwise compatible
   cache hit. Checking an advertised authority on resumption is local
   policy. The _104 certificate rule applies to a full certificate
   flight. An empty authority list remains eligible.
5. If an eligible session remains usable, take the abbreviated path.
   Otherwise evaluate the full profile. If the otherwise admissible
   hello has no selectable RSA entry or lacks the supported cipher/MAC
   pair, return fatal `handshake_failure`. This includes an empty
   full key list without a session ID and a matching RSA entry whose
   one-based index exceeds 255. Use the first selectable entry and keep
   existing identifier syntax checks. Explicit parameter bodies are
   opaque to this parser. This slice requires default RSA parameters
   and leaves specialized parameter-index negotiation separate.
   Successful full fallback selects a fresh ID as usual.

The current fixed authenticated profile uses the same cipher/MAC pair for
full and cached connections. An offer that excludes that pair also cannot
use the full fallback. The positive fallback control can use an empty or
expired cache with a full-capable offer.
[Cache and fallback policy](WIRE_SESSION_RESUMPTION.md#wire-contract) ·
[Authority selection and rejection](WAP_199_PROVISIONED_TRUST_PLAN.md#profile-behavior)

## Reply and association state

Use the existing initial alert path, which returns one send action through
both receive APIs and the UDP adapter. The response is one explicit-length
clear alert record with server sequence 0. Its fragment contains fatal
level 3, description 40, and the §10.2 checksum computed from the complete
received ClientHello record, including its actual header and length form.
The initial server reply path already supplies the checksum for other
negotiation refusals.
[Initial server reply](../src/wire.rs#L451) ·
[Initial alert values](../src/wire/codec.rs#L533) ·
[WAP-199 §§10.2–10.2.2](https://ptacts.uspto.gov/ptacts/public-informations/petitions/1549804/download-documents?artifactId=q91LjyqB9tLZ-LVakpTsgAE_GyThWnjP3JSk0xnVhQkx_FB33j7C-1I#page=44)

The rejected offer produces no ServerHello, certificate, traffic keys,
establishment event, cache insertion or admitted UDP slot. The candidate
remains idle and reusable. Cache lookup may prune expired entries. An
eligible entry keeps its original validity and expiry. A fresh
candidate can receive an alert while the tuple has a pending handshake.
Keep the old pending peer, its deadline and its cached reply. Process
an eligible repeated rejected hello as another initial refusal, giving
the same bytes while the conditions are the same. The server sends
nothing on a timer for a rejected hello. An exact duplicate of an
accepted hello retains the existing byte-identical flight retry.
Preserve the same-random conflict and established-tuple guards, retired
hello handling, and the separate explicit WinWAP profile. The legacy
runner claims a remote after a successful receive. Keep its existing
negative-offer result. Apply UDP capacity and budget checks through
the existing dispatch.
[UDP admission and replacement](../src/udp.rs#L218) ·
[Pending rejection control](../tests/udp_adapter.rs#L594) ·
[WinWAP fixture tests](../tests/legacy_winwap.rs#L87) ·
[WinWAP runner](../src/bin/wtls-winwap-lab.rs#L70)

## Deterministic tests

Use in-memory wire peers or the UDP adapter with fixed clocks and
locally encoded, ordinary offers. Verify the record bytes and observable
events. The first regression reproduced the prior local error
for a valid offer that lacked the supported pair.
[Existing negative-offer test](../tests/protected_echo.rs#L699)

| Case | Acceptance evidence |
| --- | --- |
| Valid offer without a selectable algorithm | Table-drive missing usable RSA, missing cipher/MAC pair, both missing, the desired cipher and MAC split across different pairs, empty full key list and a matching key after index 255. Each yields one clear fatal `handshake_failure`. Include a usable RSA entry and pair after other options as a positive control. |
| Alert envelope and repeat | Check the send-only result through both receive APIs. Independently compute the checksum over the original record in both length forms. Verify one clear alert with explicit length, sequence 0 and fatal description 40. Repeat an eligible rejected hello byte for byte. A fresh corrected hello can start and complete a protected connection on the same idle peer. |
| Invalid opening or out-of-scope selection | Use malformed vectors, invalid record sequencing, a truncated record or trailing record, and well-framed offers outside the version, sequence or null-compression profile. Include an invalid admission choice combined with a resume-only miss to pin precedence. Verify no alert and retain the UDP budget diagnostic. Verify that refresh 0 and a value above the cap still negotiate normally. Keep WinWAP controls. |
| Cache and authority precedence | A compatible hit resumes with index 0 when the RSA list is absent or lacks a usable entry. A cipher-incompatible hit cannot resume. A resume-only miss with a conflicting authority still receives critical 52. A compatible hit with a conflicting authority and an inadmissible full algorithm offer each receive fatal 40. Verify that an eligible cached ID still resumes under its original expiry. A cold or expired cache with a usable full offer establishes with a different ID. |
| Pending tuple and capacity | With capacity one, keep A pending, send an otherwise valid fresh B with mismatched algorithms from the same tuple, and observe B's alert and A's unchanged deadline. Retry A byte for byte, complete its handshake, and pass protected data. Keep the capacity, same-random conflict, and established-tuple controls. |

Ruflo reviewed the exact implementation commit after all 145 Rust tests,
Clippy, and formatting passed.
[Admission and idle-state tests](../src/wire/algorithm_alert_tests.rs#L16) ·
[Wire framing and selection tests](../tests/protected_echo.rs#L542) ·
[Cache and authority tests](../tests/provisioned_trust.rs#L639) ·
[Pending UDP association test](../tests/udp_adapter.rs#L659) ·
[Supervised verification](SUPERVISED_WORKFLOW.md#run-the-wtls-loop)
