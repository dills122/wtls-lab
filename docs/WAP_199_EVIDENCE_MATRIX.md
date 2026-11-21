# WAP-199 client and server evidence matrix

**Evidence baseline.** Live evidence through WTLS-213. Deterministic updates
for WTLS-215 at `b7d5baf`, WTLS-216 at `e166de4`, WTLS-217 at `85c601b`, WTLS-218 at `d12211e`, WTLS-219 at `0d49c5a`, WTLS-220 at `ff294cb`, and WTLS-221 at `32f112a`.
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
WTLS-221 passed all 137 tests in `cargo test --locked --offline`.

| Server row | Client row | Requirement | Disposition and evidence |
| --- | --- | --- | --- |
| S-001 M | C-001 M | Full handshake (§10.3) | **Verified, both.** Matching provisioned authority, certificate flight, client key exchange, both Finished exchanges, and protected echo. WTLS-213 verifies the server twice with an independent peer. [TRUST-02](../tests/provisioned_trust.rs#L284) |
| S-002 M | C-002 M | Abbreviated handshake (§10.3) | **Verified, both.** Same-ID abbreviated flight and fresh hello randoms and traffic keys. Cache miss falls back with a usable full offer. WTLS-213 shows the server resumes after Connection close and takes the full path after Session close when the peer reoffers the same ID. [Client random and fresh keys](../tests/wire_resumption.rs#L228) · [Server random](../tests/protected_echo.rs#L444) · [TRUST-06](../tests/provisioned_trust.rs#L535) |
| S-005 M | C-005 M | Concatenated handshake records in one SDU (§10.4) | **Verified, both.** Distinct records carry each handshake message. Both full commit directions and the server-first abbreviated flight are exercised. The codec checks explicit and final omitted lengths. [Full wire exchange](../tests/protected_echo.rs#L259) · [Abbreviated wire exchange](../tests/protected_echo.rs#L389) · [Record codec](../tests/record_codec.rs#L36) |
| S-006 M | C-006 M | Handshake reliability over datagrams (§10.4) | **Verified for the scoped client and server UDP paths.** The deterministic UDP tests cover a lost ServerHello flight and a lost final full-handshake CCS/Finished flight. Wire tests cover abbreviated commit recovery. The server replaces a pending handshake for a fresh admissible hello and repeats cached flights for exact duplicates. [G6](#g6-fresh-clienthello-during-a-pending-handshake) [ServerHello loss](../tests/udp_adapter.rs#L788) · [Final flight loss](../tests/udp_adapter.rs#L838) · [Abbreviated commit recovery](../tests/wire_resumption.rs#L306) |
| S-010 M | C-010 M | Explicit sequence numbers (§9.2.3.1) | **Verified, both.** Explicit fields and CCS reset are exercised. The codec rejects a missing UDP sequence field. WTLS-215 verifies the last valid number, retirement before wrap, and reuse of the eligible cached session. [G1](#g1-sequence-exhaustion) [Codec rejection](../tests/record_codec.rs#L99) · [Wire echo](../tests/protected_echo.rs#L580) · [UDP sequence assertions](../tests/udp_adapter.rs#L230) |
| S-012 M | C-012 M | Duplicate removal (§9.2.3.1) | **Verified for protected application records, both.** UDP tests accept in-window reordered records across refresh and suppress repeated delivery in each direction. The typed server test also drops an older record outside the window. [UDP replay test](../tests/udp_adapter.rs#L352) · [Typed window test](../tests/handshake.rs#L371) |
| S-013 M | C-013 M | Key refresh (Appendix B.3) | **Verified, both.** Independent ciphertext expectations cover the refresh boundary. UDP tests cross it in both directions with loss or reordering. [Wire vectors](../tests/protected_echo.rs#L259) · [UDP refresh tests](../tests/udp_adapter.rs#L352) |
| S-020 M | C-020 M | Critical alerts (§10.2) | **Verified for the scoped receive behavior, both roles.** Matched clear critical errors end pending negotiations with cache retention. Generic protected critical receive is covered for both roles. [G3](#g3-alert-scope) |
| S-021 M | C-021 M | Fatal alerts (§10.2) | **Verified for the scoped receive behavior, both roles.** Matched clear fatal errors end pending negotiations with cache retention. Protected fatal and Session close still invalidate the applicable entry. [G3](#g3-alert-scope) |
| S-022 M | C-022 M | Alert checksums (§10.2) | **Verified for the scoped receive behavior, both roles.** Clear and protected alerts correlate against complete emitted records. The zero exception is unused. The pending no_connection sequence exception still requires checksum validation. [G3](#g3-alert-scope) |
| S-025 M | C-025 M | ChangeCipherSpec (§10.1) | **Verified, both.** Client-first full and server-first abbreviated transition, then protected Finished at sequence zero; the typed test requires CCS and valid Finished before opening. [Full wire exchange](../tests/protected_echo.rs#L259) · [Abbreviated wire exchange](../tests/protected_echo.rs#L389) · [Typed rejection](../tests/handshake.rs#L326) |
| S-026 M | C-026 M | Application data (§§9.2–9.2.1) | **Verified for the scoped UDP application path, both roles.** Protected echo, receive-side batches, and framing, integrity, and replay checks are covered. WTLS-213 verifies single-record protected pages on the BlackBerry. [G4](#g4-multiple-application-records-per-sdu) |
| S-030 M | C-030 M | At least one anonymous handshake (Appendix A) | **Deferred for the scoped profile.** The corrected dependency is any same-role option 031–038 or 049. The separately selected WinWAP server supports the single 034 option below. The Rust client has no corresponding anonymous profile. |
| S-060 M | C-060 M | Server-authenticated handshake (Appendix A) | **Verified for the selected branch.** Each role requires (061 or 064) and 191. The project selects 061 and 191. Supporting 062 or 063 would also require 061 with a minimum supported modulus of 1024 bits. [TRUST-02](../tests/provisioned_trust.rs#L284) · [TRUST-05](../tests/provisioned_trust.rs#L454) |
| S-061 O | C-061 O | Unrestricted RSA (Appendix A) | **Verified, both.** Offers and selection use suite 8, and full wire tests complete the native RSA certificate and key transport. [Captured offer test](../tests/protected_echo.rs#L129) · [TRUST-02](../tests/provisioned_trust.rs#L284) |
| S-100 M | C-100 O | At least one data cipher (Appendix A) | **Verified for 104, both.** Each role lists alternatives 101–108. The RC5 and cipher-strength recommendations remain outside the chosen suite. |
| S-104 O | C-104 O | 3DES-CBC-EDE (Appendix A) | **Verified, both.** Negotiated as cipher 6. The independent expected ciphertext and echo cover the selected suite. [Wire vectors](../tests/protected_echo.rs#L259) |
| S-130 M | C-130 M | MAC support (Appendix A) | **Verified for the selected MAC, both.** SHA_80 is a recommendation and is deferred. See 131. |
| S-131 M | C-131 M | Full SHA MAC (Appendix A) | **Verified, both.** Selected as MAC 3. The test independently computes HMAC-SHA-1 for the protected record vector. [Independent expectations](../tests/protected_echo.rs#L201) · [Wire vectors](../tests/protected_echo.rs#L259) |
| S-141 M | C-141 M | Null compression (Appendix A) | **Verified, both.** Compression 0 negotiated and used for the protected echo. [Client offer](../tests/protected_echo.rs#L109) · [Server selection](../tests/protected_echo.rs#L129) · [Wire echo](../tests/protected_echo.rs#L580) |
| S-191 O | C-191 O | Native WTLS certificate verification (§10.5.2) | **Verified within the profile, both.** Conditional requirement via 060. Rust server validates its configured signed leaf and key before use. Rust client independently checks the issuer, signature, expected subject, and validity of the received leaf. Client-certificate verification is a separate feature. [TRUST-02](../tests/provisioned_trust.rs#L284) · [TRUST-05](../tests/provisioned_trust.rs#L454) |
| S-200 M | C-200 O | GMT Unix time support (§10.5.1) | **Verified, both.** Full and abbreviated ClientHello and ServerHello carry the supplied Unix seconds in the first four Random bytes. The UDP tests use a separate monotonic clock and exercise fresh wall times on resumption. [G5](#g5-gmt-time-on-the-wire) |

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

## Verified gap work

G1–G6 are verified within the selected profile. The
[support promise review](WAP_199_SUPPORT_PROMISE_REVIEW.md) records
remaining protocol and evidence gaps and proposes the next slice.

### G1. Sequence exhaustion

**Verified in WTLS-215.** Either provisioned role can use sequence 65,535.
The next fresh record attempt closes the connection with a typed
diagnostic and no output. The adapter retires the association. The
eligible session retains its original expiry and can resume on a fresh
association. The tests also cover close and alert behavior at the limit.
[Reviewed design and boundary tests](WAP_199_SEQUENCE_EXHAUSTION_PLAN.md) · [Evidence ledger](WTLS_EVIDENCE.json)

### G2. Full handshake final flight retry

**Verified in WTLS-216.** The adapter test drops the final server CCS and
protected Finished datagram in a full handshake. At the retry deadline
the client resends its entire commit byte for byte. The open server repeats
its original final flight and emits no second establishment event. The
client opens and exchanges a protected echo on the recovered connection.
[Deterministic UDP test](../tests/udp_adapter.rs#L838) · [Evidence ledger](WTLS_EVIDENCE.json)

### G3. Alert scope

**Verified in WTLS-219 for clear alert receive.** An eligible clear alert
must match a complete emitted record from the pending attempt. A matched
fatal or critical error retires that attempt, and a verified cached
session keeps its original expiry. Clear advisories do not alter
sequence or retry state. Committed peers reject clear alerts and retain
protected traffic. The protected alert and close regressions still pass.
WTLS-221 verifies classified native certificate failures on the
provisioned client, including a clear fatal reply and the gateway's
pending retirement. [Certificate alert design and tests](WAP_199_CERTIFICATE_ALERT_PLAN.md)
[Reviewed policy](WAP_199_CLEAR_ALERT_PLAN.md) · [Alert tests](../src/wire/alert_tests.rs#L172) · [Evidence ledger](WTLS_EVIDENCE.json)

### G4. Multiple application records per SDU

**Verified in WTLS-220.** Both roles accept multiple protected application
records in one UDP datagram and deliver each accepted payload separately.
The receive path covers explicit lengths and a final omitted length,
per-record replay filtering across key refresh, invalid-tail rejection,
and abbreviated commit and retry. The close checksum follows the highest
accepted sequence. Authenticated terminal alerts retain precedence and
their existing close and cache effects. Existing BlackBerry exchanges
exercise single-record traffic. Outbound batching and general
content-type interleaving remain outside this profile.
[Receive design and tests](WAP_199_APPLICATION_RECORD_BATCH_PLAN.md) ·
[Wire batch tests](../src/wire/application_batch_tests.rs#L51) ·
[UDP replay and budget](../tests/udp_adapter.rs#L268) ·
[Alert lifecycle](../src/wire/alert_tests.rs#L459) ·
[Evidence ledger](WTLS_EVIDENCE.json)

### G5. GMT time on the wire

**Verified in WTLS-217.** Deterministic adapter tests compare the exact
four big-endian wire bytes of each hello's Unix timestamp to that sender's
supplied wall clock. Both peers establish the full and abbreviated
handshakes. The abbreviated handshake echoes the cached session ID and
uses a new wall-clock value for each role. The monotonic millisecond values
are independent of the wall-clock inputs. The corrected status is mandatory
for the server and optional for the client.
[Full hello timestamp test](../tests/udp_adapter.rs#L153) · [Resumed hello timestamp test](../tests/udp_adapter.rs#L163) · [Evidence ledger](WTLS_EVIDENCE.json)

### G6. Fresh ClientHello during a pending handshake

**Verified in WTLS-218.** An admissible fresh ClientHello starts a new
pending handshake in the same UDP slot with its original deadline. An exact
retry of the current hello returns its cached flight byte for byte. The
deterministic tests cover replacement, rejection, delayed previous
traffic, abbreviated resumption, expiry, and established-connection
routing. [Reviewed design](WAP_199_PENDING_CLIENT_HELLO_PLAN.md) ·
[Adapter tests](../tests/udp_adapter.rs#L511) · [Evidence ledger](WTLS_EVIDENCE.json)
