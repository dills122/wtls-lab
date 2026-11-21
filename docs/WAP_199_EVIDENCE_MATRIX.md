# WAP-199 client and server evidence matrix

**WTLS-214 · Review draft.** Evidence baseline `ba13f6e` (through WTLS-213).
The [support promise](WAP_199_PROVISIONED_TRUST_PLAN.md#support-boundary) covers
one server-authenticated UDP profile. It uses unrestricted RSA, a native
WTLS leaf and one provisioned RSA authority, 3DES-CBC-EDE, full HMAC-SHA-1,
null compression, and explicit sequence numbers.

The row IDs and **M** (mandatory), **O** (optional), and **N/A** labels come
from WAP-199_103 §3.3, A.1 (server, pp. 5–8) and A.2 (client, pp. 9–12).
Restore the `WTLS-` prefix to read the printed ID. A range includes every
number in that range. Status is the publisher's label. A selected optional
row can be a dependency of a mandatory parent. The disposition describes
this project's evidence for the scoped profile. [WAP Forum release index](https://www.wapforum.org/what/technical_1_2_1.htm) · [Official release archive](https://www.openmobilealliance.org/tech/affiliates/wap/Technical_June2000-20021106%5B1%5D.zip)

**Verified** means an executed test or capture demonstrates the stated
behavior. **Partial** means the evidence covers the stated subset and the
linked gap is open. **Deferred** means outside the first profile. The
[existing support plan](WAP_199_PROVISIONED_TRUST_PLAN.md) governs the
profile. Implementation decisions and further tests in the gap list are
proposals for review.

## Protocol and selected options

The Rust client and server have deterministic wire evidence. WTLS-211–213
add live evidence for the Rust server with the stock BlackBerry 7290 as its
client. BlackBerry's CA enrollment, prompt setting, and persistence are
observations about that simulator. The [WTLS-213 capture](../fixtures/HISTORICAL_PEERS.md#blackberry-provisioned-trust-reconnect-lifecycle)
and [work item ledger](WTLS_EVIDENCE.json) retain the peer and run provenance.
The baseline passed all 99 tests in `cargo test --locked --offline`.

| Server row | Client row | Requirement | Disposition and evidence |
| --- | --- | --- | --- |
| S-001 M | C-001 M | Full handshake (§10.3) | **Verified, both.** Matching provisioned authority, certificate flight, client key exchange, both Finished exchanges, and protected echo. WTLS-213 verifies the server twice with an independent peer. [TRUST-02](../tests/provisioned_trust.rs#L284) |
| S-002 M | C-002 M | Abbreviated handshake (§10.3) | **Verified, both.** Same-ID abbreviated flight and fresh hello randoms and traffic keys. Cache miss falls back with a usable full offer. WTLS-213 shows the server resumes after Connection close and takes the full path after Session close when the peer reoffers the same ID. [Client random and fresh keys](../tests/wire_resumption.rs#L228) · [Server random](../tests/protected_echo.rs#L444) · [TRUST-06](../tests/provisioned_trust.rs#L535) |
| S-005 M | C-005 M | Concatenated handshake records in one SDU (§10.4) | **Verified, both.** Distinct records carry each handshake message. Both full commit directions and the server-first abbreviated flight are exercised. The codec checks explicit and final omitted lengths. [Full wire exchange](../tests/protected_echo.rs#L259) · [Abbreviated wire exchange](../tests/protected_echo.rs#L389) · [Record codec](../tests/record_codec.rs#L36) |
| S-006 M | C-006 M | Handshake reliability over datagrams (§10.4) | **Partial, both.** Lost ServerHello flight recovers over the UDP adapter through byte-identical ClientHello and server retries. Wire evidence also covers resumed commit recovery and the server's byte-identical reply to a repeat full client Finished. The full retry timer path has typed coverage. See [G2](#g2-full-handshake-final-flight-retry) and [G6](#g6-fresh-clienthello-during-a-pending-handshake). [UDP loss test](../tests/udp_adapter.rs#L231) · [Resumed commit test](../tests/wire_resumption.rs#L306) · [Full typed retry](../tests/handshake.rs#L172) · [Full server wire retry](../tests/protected_echo.rs#L344) |
| S-010 M | C-010 M | Explicit sequence numbers (§9.2.3.1) | **Partial, both.** Explicit fields and CCS reset are exercised. The codec rejects a missing UDP sequence field. See [G1](#g1-sequence-exhaustion) for connection retirement at the limit. [Codec rejection](../tests/record_codec.rs#L99) · [Wire echo](../tests/protected_echo.rs#L580) · [UDP sequence assertions](../tests/udp_adapter.rs#L112) |
| S-012 M | C-012 M | Duplicate removal (§9.2.3.1) | **Verified for protected application records, both.** UDP tests accept in-window reordered records across refresh and suppress repeated delivery in each direction. The typed server test also drops an older record outside the window. [UDP replay test](../tests/udp_adapter.rs#L142) · [Typed window test](../tests/handshake.rs#L371) |
| S-013 M | C-013 M | Key refresh (Appendix B.3) | **Verified, both.** Independent ciphertext expectations cover the refresh boundary. UDP tests cross it in both directions with loss or reordering. [Wire vectors](../tests/protected_echo.rs#L259) · [UDP refresh tests](../tests/udp_adapter.rs#L142) |
| S-020 M | C-020 M | Critical alerts (§10.2) | **Partial, both.** Protected Connection close preserves the cache. The authenticated generic critical receive case is exercised with the Rust client as receiver. See [G3](#g3-alert-scope). [Client-initiated close](../tests/wire_resumption.rs#L705) · [Server-initiated close](../tests/wire_resumption.rs#L786) · [Generic critical test](../src/wire/alert_tests.rs#L254) |
| S-021 M | C-021 M | Fatal alerts (§10.2) | **Partial, both.** Protected Session close invalidates the session. Generic fatal receive behavior is covered on committed epochs, including a resumed client awaiting confirmation. The server emits a clear fatal alert for an unmatched authority. Clear receive behavior and provisional epochs follow the lab alert policy. See [G3](#g3-alert-scope). [TRUST-03](../tests/provisioned_trust.rs#L400) · [Fatal receive tests](../src/wire/alert_tests.rs#L138) · [Provisional epoch test](../src/wire/alert_tests.rs#L471) |
| S-022 M | C-022 M | Alert checksums (§10.2) | **Partial, both.** Protected checksum matching, corrupted checksums, and close checksums referencing earlier sent records are exercised. TRUST-03 checks the checksum on an outbound clear fatal alert. Clear inbound reports lack this check. See [G3](#g3-alert-scope). [Outbound checksum assertion](../tests/provisioned_trust.rs#L149) · [Protected checksum tests](../src/wire/alert_tests.rs#L254) · [Earlier-record close](../tests/wire_resumption.rs#L782) |
| S-025 M | C-025 M | ChangeCipherSpec (§10.1) | **Verified, both.** Client-first full and server-first abbreviated transition, then protected Finished at sequence zero; the typed test requires CCS and valid Finished before opening. [Full wire exchange](../tests/protected_echo.rs#L259) · [Abbreviated wire exchange](../tests/protected_echo.rs#L389) · [Typed rejection](../tests/handshake.rs#L326) |
| S-026 M | C-026 M | Application data (§§9.2–9.2.1) | **Partial, both.** Protected echo and rejection of clear or integrity-failing data are covered. A protected page is acknowledged in each WTLS-213 leg. See [G4](#g4-multiple-application-records-per-sdu). [Wire echo and negatives](../tests/protected_echo.rs#L580) |
| S-030 M | C-030 M | At least one anonymous handshake (Appendix A) | **Deferred for the scoped profile.** The corrected dependency is any same-role option 031–038 or 049. The separately selected WinWAP server supports the single 034 option below. The Rust client has no corresponding anonymous profile. |
| S-060 M | C-060 M | Server-authenticated handshake (Appendix A) | **Verified for the selected branch.** Each role requires (061 or 064) and 191. The project selects 061 and 191. Supporting 062 or 063 would also require 061 with a minimum supported modulus of 1024 bits. [TRUST-02](../tests/provisioned_trust.rs#L284) · [TRUST-05](../tests/provisioned_trust.rs#L454) |
| S-061 O | C-061 O | Unrestricted RSA (Appendix A) | **Verified, both.** Offers and selection use suite 8, and full wire tests complete the native RSA certificate and key transport. [Captured offer test](../tests/protected_echo.rs#L129) · [TRUST-02](../tests/provisioned_trust.rs#L284) |
| S-100 M | C-100 O | At least one data cipher (Appendix A) | **Verified for 104, both.** Each role lists alternatives 101–108. The RC5 and cipher-strength recommendations remain outside the chosen suite. |
| S-104 O | C-104 O | 3DES-CBC-EDE (Appendix A) | **Verified, both.** Negotiated as cipher 6. The independent expected ciphertext and echo cover the selected suite. [Wire vectors](../tests/protected_echo.rs#L259) |
| S-130 M | C-130 M | MAC support (Appendix A) | **Verified for the selected MAC, both.** SHA_80 is a recommendation and is deferred. See 131. |
| S-131 M | C-131 M | Full SHA MAC (Appendix A) | **Verified, both.** Selected as MAC 3. The test independently computes HMAC-SHA-1 for the protected record vector. [Independent expectations](../tests/protected_echo.rs#L201) · [Wire vectors](../tests/protected_echo.rs#L259) |
| S-141 M | C-141 M | Null compression (Appendix A) | **Verified, both.** Compression 0 negotiated and used for the protected echo. [Client offer](../tests/protected_echo.rs#L109) · [Server selection](../tests/protected_echo.rs#L129) · [Wire echo](../tests/protected_echo.rs#L580) |
| S-191 O | C-191 O | Native WTLS certificate verification (§10.5.2) | **Verified within the profile, both.** Conditional requirement via 060. Rust server validates its configured signed leaf and key before use. Rust client independently checks the issuer, signature, expected subject, and validity of the received leaf. Client-certificate verification is a separate feature. [TRUST-02](../tests/provisioned_trust.rs#L284) · [TRUST-05](../tests/provisioned_trust.rs#L454) |
| S-200 M | C-200 O | GMT Unix time support (§10.5.1) | **Partial, both.** The shared hello generator writes caller-supplied Unix seconds as four big-endian bytes, followed by 12 random bytes. The client codec vector prescribes bytes rather than exercising the clock-to-wire path. See [G5](#g5-gmt-time-on-the-wire). [Hello generator](../src/wire.rs#L1100) · [Client codec vector](../tests/protected_echo.rs#L109) |

## Other corrected rows

These grouped rows account for the remaining IDs in A.1 and A.2.

| Server row | Client row | Requirement | Disposition |
| --- | --- | --- | --- |
| S-003 O | C-003 O | Optimized public-key handshake (§10.3) | **Deferred.** |
| S-004 O | C-004 O | Session sharing across multiple connections (§11.1.4) | **Deferred as a support claim.** The scoped evidence covers reconnect and cache reuse. The matrix makes no claim about concurrent same-session lifecycle. |
| S-007 O | C-007 O | HelloRequest (§10.5.1 / §10.5.1.1) | **Deferred.** Server sending and client startup after a clear HelloRequest are distinct roles. Inspector decoding alone does not exercise either endpoint behavior. |
| S-011 O | C-011 O | Implicit sequence numbering (§9.2.3.1) | **Deferred.** The UDP profile uses explicit numbers. |
| S-031–033, S-035–038, S-049 O | C-031–033, C-035–038, C-049 O | Other anonymous exchanges (Appendix A) | **Deferred.** DH, limited-size RSA and ECDH variants. |
| S-034 O | C-034 O | Anonymous RSA (Appendix A) | **Server compatibility only.** WinWAP exercised the explicitly selected RSA_ANON/DES-CBC path and protected WSP. **Client deferred.** [WinWAP mode and evidence](../README.md#direct-winwap-compatibility-test) |
| S-062–064 O | C-062–064 O | Other authenticated exchanges (Appendix A) | **Deferred.** 062 and 063 depend on same-role 061. 064 depends on 165 or 167. |
| S-070–072 O | C-070–072 O | Client authentication (Appendix A) | **Deferred.** Parent 070 depends on 071 or 072. See the _106 overlay below. |
| S-080, S-090 O | C-080, C-090 O | Shared-secret and null key exchange (Appendix A) | **Deferred.** |
| S-103 O | C-103 O | DES-CBC (Appendix A) | **Server compatibility only.** Explicitly selected with RSA_ANON for WinWAP. **Client deferred.** [WinWAP mode](../README.md#direct-winwap-compatibility-test) |
| S-101–102, S-105–108, S-120 O | C-101–102, C-105–108, C-120 O | Other data ciphers and null encryption (Appendix A) | **Deferred.** |
| S-132, S-133, S-135–137, S-140 O | C-132, C-133, C-135–137, C-140 O | Truncated SHA, MD5, and null MAC options (Appendix A) | **Deferred.** |
| S-134 N/A | C-134 N/A | Removed MAC option | **N/A.** |
| S-151–152 O | C-151–152 O | Predefined DH parameters (Appendix A) | **Deferred.** |
| S-161, S-163–172, S-180 O | C-161, C-163–172, C-180 O | ECC curves and point compression (Appendix A / §11.1.3) | **Deferred.** 165 and 167 are the basic curves. When ECC is selected, 165 requires at least one basic curve. The server SHOULD support all basic curves. The client SHOULD verify with all basic curves of at least 160 bits. |
| S-192, S-193 O | C-192, C-193 O | X.509 and X9.68 certificate verification (§10.5.2) | **Deferred.** |
| — | C-220 O | WIM support | **Deferred.** The corrected client row depends on C-070, WIM:MCF, and WIM-C-001. |

## Specification Information Notes

| Correction | Profile mapping |
| --- | --- |
| _102 §§3–6 | Clear HelloRequest and WIM appear as deferred entries in the corrected table. The ECC OIDs, 40-bit-cipher advisory, and WAPCREQ reference apply to the broader spec. The selected suite avoids 40-bit ciphers. |
| _103 §3.3 | The two tables above use its role-specific IDs, statuses, and relevant dependencies. The project support boundary covers the chosen profile. Full Appendix E conformance would also need a qualifying anonymous option for each role and any still-open mandatory behaviors. |
| _104 §3.3, §§10.5.1.2, 10.5.2 | **Verified for the provisioned RSA profile.** The server picks the configured leaf only if a nonempty authority list matches the signer. An empty authority list permits certificate selection with an acceptable authenticated offer. Rejection and both permitted cases have wire tests. [TRUST-02–04](WAP_199_PROVISIONED_TRUST_PLAN.md#deterministic-release-gate) |
| _105 §3.3, §10.5.1.2 | **Verified for the RSA authority identifier.** Hash the raw unsigned modulus, excluding the DER sign octet and ASN.1 structure. The known-answer check and the ClientHello vector exercise type 254 in the authority list. ECC identifiers are deferred. [TRUST-01](../tests/provisioned_trust.rs#L239) |
| _106 §3.3, §10.5.4 | **Deferred with client certificate authentication.** CertificateRequest limits trusted authority identifiers to types 0 and 254. ClientHello authority selection follows _104/_105. |

WAP-261 and its corrections remain outside this WAP-199 matrix.

## Gaps for review

### G1. Sequence exhaustion

§9.2.3.1 requires connection closure after the 16-bit range is exhausted.
The current application send guard returns `SequenceExhausted` while the
association stays open. Alerts advance the wire counter and can reach a
separate exhaustion check during encoding. An encoding error there aborts
the association. The adapter retires peers that report `Closed`. Test both
send paths and both roles at the last usable number. Check that numbers
never wrap and that endpoints and adapters reach a terminal state. The
[WTLS-215 design](WAP_199_SEQUENCE_EXHAUSTION_PLAN.md) preserves an eligible
cached session on local exhaustion. [Application guard](../src/handshake.rs#L707) · [Wire send](../src/wire.rs#L306) · [Wire counter](../src/wire.rs#L139) · [Encoding failure](../src/wire.rs#L945) · [Adapter retirement](../src/udp.rs#L292)

### G2. Full handshake final flight retry

Take the typed loss case through the wire/UDP boundary. Drop the final
server CCS/Finished SDU in a full handshake, assert client timer expiry and
byte-identical retries of both commits, then check a protected echo. The
server's byte-identical response to a repeat client Finished already has
a wire assertion. [Typed loss case](../tests/handshake.rs#L172) · [Wire retry assertion](../tests/protected_echo.rs#L344) · [Existing UDP loss test](../tests/udp_adapter.rs#L231)

### G3. Alert scope

§10.2 requires verification of an alert's checksum. During initial
negotiation, the clear receive path reports the parsed alert without
checking that checksum. Even a matching clear fatal alert currently leaves
the Rust client negotiating. §10.2.2 separates ending the failed negotiation
from preserving an existing valid session on a clear fatal alert. A bad
native leaf also closes the local client with `CertificateRejected` while
the gateway remains negotiating. Review checksum and closure handling
together with the scope of peer-visible error alerts. Add a direct generic
critical receive check on the server if that behavior stays in the promise.
[Clear receive path](../src/wire.rs#L717) · [Clear fatal test](../src/wire/alert_tests.rs#L263) · [Trust rejection](../tests/provisioned_trust.rs#L486) · [Generic critical receive](../src/wire/alert_tests.rs#L344)

### G4. Multiple application records per SDU

§9 describes concatenation into one SDU. §9.2.1 defines length framing
and permits content-type interleaving. The established peer currently
expects one application record, including after an abbreviated commit
prefix. Decide whether the first profile will accept multiple protected
application records per SDU or document the current limit as a profile
restriction. The observed BlackBerry exchanges use the supported path. [Open receive path](../src/handshake.rs#L740) · [Abbreviated application tail](../src/handshake.rs#L797)

### G5. GMT time on the wire

Assert the exact supplied wall-clock value in emitted client and server
hellos. Exercise full and resumed negotiation, with a distinct monotonic
time to rule out mixing the two clocks. This is an evidence gap for an
existing implementation, with mandatory status on the server and optional
status on the client. [Wire hello generator](../src/wire.rs#L1100)

### G6. Fresh ClientHello during a pending handshake

§10.4 distinguishes a duplicate ClientHello, which gets the cached
flight, from a new ClientHello, which starts a handshake and signals its
creation. On the same remote tuple, the UDP adapter forwards a fresh
ClientHello to the pending peer. That wire peer accepts a new ClientHello
only in `Idle`. Review replacement of a pending association and verify
that the duplicate path still returns the original flight. Handling
handshakes initiated on an established connection is a separate question.
[UDP routing](../src/udp.rs#L223) · [Wire receive state](../src/wire.rs#L733)

Review G1 first. G2 and G5 can start with tests of the current
implementation. G3 and G4 need an explicit scope decision. G6 is a
separate server-side lifecycle gap.
