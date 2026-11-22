# KWTLS 1.0.3 source reference

**Status** — Historical source study with live BlackBerry full and abbreviated exchanges. Use this page to orient future discovery rounds. The corrected WAP-199 documents govern protocol requirements, and the [support boundary](WAP_199_PROVISIONED_TRUST_PLAN.md#support-boundary) governs the Rust profile.

KWTLS gives us a period gateway that completed a server-authenticated handshake and served protected WAP traffic to the BlackBerry 7290. The test covered RSA, DES-CBC, and full SHA. The next design review should ask how to test issuer-aware certificate selection independently while retaining the Rust profile's 3DES-CBC-EDE suite.

## Evidence and reproducibility

| Evidence | Identity and use |
| --- | --- |
| Upstream source | Kannel's `kwtls-1.0.3.tar.gz`, SHA-256 `7c727beabc0ea55518790a995a83ad411843097db0c90ebc9eaf797a3afedd65`. The executable's banner says `0.1.3`. All source locations below refer to the pristine archive. Review `COPYING` and `ACRYPTO` if considering upstream code reuse. |
| Protocol requirements | WAP-199 of 18 February 2000 and the five published correction notes. The relevant corrections here are WAP-199_104 on certificate selection and WAP-199_105 on the RSA authority identifier. |
| Live run | BlackBerry 7290 from RIM JDE 4.0 in a host-only XP clone. The gateway was the archived KWTLS code built with OpenSSL 1.0.2u under Rosetta, with compiler portability, byte-order, loopback, and logging adaptations. A small WTP/WSP backend served the lab CA and the protected page. The trace `blackberry-retry.trace` has SHA-256 `207aa4ab03ce514d5cbc0215157b60607465e37cebc9988a474fe8b58f4e01ac`. |
| Rust comparison | `wtls-lab` baseline `cbdbad4`. Its BlackBerry lifecycle traces exercise the gateway on RSA, 3DES-CBC-EDE, and full SHA. The existing inspector also decoded the KWTLS capture and left encrypted record bodies opaque. |

[KWTLS source archive](https://www.kannel.org/download/wtls/kwtls-1.0.3.tar.gz) · [WAP Forum 1.2.1 publisher index](https://www.wapforum.org/what/technical_1_2_1.htm) · [WAP-199 corrections and support plan](WAP_199_PROVISIONED_TRUST_PLAN.md#correction-crosswalk) · [Rust peer evidence](../fixtures/HISTORICAL_PEERS.md#blackberry-provisioned-trust-reconnect-lifecycle)

The [baseline recipe](KWTLS_LAB_BASELINE.md) preserves the build and launch steps, the original full exchange, the two failed fresh-process attempts, and the successful rerun with a different returned session ID. The [first discovery review](WTLS_DISCOVERY_FIRST_REVIEW.md) records the certificate-selection comparison and the remaining independent gateway gap.

## Round 1 — Gateway responsibilities

```text
BlackBerry WAP Browser
    ⇅ protected UDP datagrams on port 9203
kwtls executable → libwtls.a → per-peer WTLS state and record protection
    ⇅ plaintext WAP datagrams to the configured backend on UDP 9201
WTP/WSP backend → page or other WAP response
```

**Source.** The Makefile builds `libwtls.a` from transport, machine, record, handshake, certificate, and crypto files. The distribution also has `kwtls`, a separate `fake_wtls` peer tool, and a separate `mk_cert` utility. The library boundary is a static build boundary, with UDP glue and the server engine in the same archive. The standalone `kwtls` program owns a `select()` loop that reads the WTLS listener and each machine's connected backend socket. `wdp.c` uses a numeric IPv4 backend address and UDP 9201. See `Makefile` lines 112–159, `kwtls.c` lines 92–187, and `wdp.c` lines 163–242.

**Source.** The loop delivers an incoming datagram as a transport event. The machine dispatcher drains its event queue and invokes the handler for its current server state. Machine lookup checks source and destination endpoints, while the executable's WDP receive path supplies zero destination fields. In that deployment, the incoming source address and port distinguish peers on the shared listener. In the open state, the server decrypts application data and forwards the resulting WAP datagram to the backend. A backend reply becomes an application-data event and is protected for the original peer. See `wtls_machine.c` lines 203–326, `wdp.c` lines 216–242, and `wtls_server.c` lines 555–640 and 1873–1888.

**Design inference.** Keep the independently useful boundary between wire state, datagram I/O, and the application that consumes decrypted bytes. The Rust core can continue to own handshake, records, and trust. The UDP adapter can own transport scheduling and peer routing. A WAP backend and the inspector can remain separate callers.

## Round 2 — The authenticated full exchange

| Stage | Upstream source | Live BlackBerry observation |
| --- | --- | --- |
| Receive and choose | The hello parser reads the key exchange offers and the trusted-authority vector separately. The full-handshake selector scans the key offers and uses the selected offer's one-based index. The cipher loop accepts DES-CBC or RC5 variants with full SHA in offer order. It requires null compression and explicit sequences and echoes the offered key-refresh field. `client_hello.c` lines 133–183, `wtls_server.c` lines 667–862, `algorithm.h` lines 59–64. | A 948-byte ClientHello offered an empty session ID, explicit sequences, refresh value 5, and 29 trusted entries. Entry 29 was the enrolled lab CA. ServerHello sent offer index 1, which refers to ClientHello's RSA type 8, and cipher/MAC values 5/3 for DES-CBC and full SHA. |
| Select a certificate | The exercised unrestricted-RSA path loads a stored certificate body based on the selected RSA key type and the corresponding configured key. This selection path uses the RSA choice and the stored file. It has no issuer match against the parsed authority vector. `wtls_server.c` lines 1001–1088. | The configured leaf's issuer matched the CA already enrolled in the BlackBerry. The same setup therefore checked the client's trust path. Gateway behavior with a different advertised CA remains untested in this run. |
| Send the first flight | The unrestricted-RSA branch encodes ServerHello, Certificate, and ServerHelloDone as individually framed clear records and concatenates them into one datagram. The authenticated RSA exchange uses the certificate key. `wtls_server.c` lines 1037–1047 and 1168–1208. | The 427-byte datagram carried the exact configured leaf. Clear record sequences were 0, 1, and 2, with fragment sizes 28, 381, and 3 bytes. |
| Complete the handshake | The server processes RSA key exchange, checks the protected client Finished over the handshake transcript, and emits a clear ChangeCipherSpec followed by its protected Finished. The positive comparison logs `Session is successfully established`. `wtls_server.c` lines 1398–1451 and 1453–1575, `wtls_encrypt.c` lines 445–469 and 499–515. | The client sent a 189-byte combined flight about 412 ms after ClientHello. KWTLS logged a matching client Finished and sent a 51-byte final flight. Both protected Finished records used sequence 0 in their new cipher state. |
| Hand off protected data | Open-state events bridge application records and plaintext WAP datagrams. `wtls_server.c` lines 555–640. | The Browser rendered **KWTLS protected reply** without a gateway certificate prompt. The backend matched the BlackBerry's protected page acknowledgment to WTP transaction `1b7c`, about 793 ms after ClientHello. |

**Specification.** WAP-199 §10.3 describes the full flight and the directional cipher change. Correction _104 §3.3 requires a sent certificate to be issued by a listed authority when the client supplies a nonempty list. The empty-list case permits a certificate when an authenticated handshake was offered. Correction _105 §3.3 specifies that an RSA type-254 authority ID hashes the raw unsigned modulus. The identifier guides server selection. The client still independently verifies the leaf and the Finished exchange. [WAP Forum release index](https://www.wapforum.org/what/technical_1_2_1.htm) · [Rust provisioned-trust behavior](WAP_199_PROVISIONED_TRUST_PLAN.md#profile-behavior)

## Round 3 — Lifecycle and limits of the evidence

| Area | What the source shows | What the live run establishes |
| --- | --- | --- |
| Session resumption | The server looks up an offered Session ID in a process-level cache and has an abbreviated branch with key index zero and reused master-secret material. Newly assigned IDs are formatted from a process counter. Cipher activation adds session parameters to the linked cache. `wtls_server.c` lines 700–750 and 808–857, `wtls_machine.c` lines 48–49 and 328–391, `conn_state.c` lines 104–176. | The BlackBerry completed a full handshake, restarted, and resumed with the issued ID and server key index zero while the gateway kept running. Both protected pages were acknowledged. Cache lifetime remains open. [Live resumption](KWTLS_LAB_BASELINE.md#live-blackberry-resumption) |
| Connection and session close | The standalone loop only queues backend data events. OPEN handles an explicit termination request by sending an alert and returning to NULL. The alert sender serializes a clear record, and the termination branch does not distinguish the two closure descriptions for cache invalidation. `kwtls.c` lines 149–184, `wtls_server.c` lines 576–580 and 1945–1966, and `wtls_record.c` lines 150–184. | The lab-only trigger emitted two protected close alerts and used the existing termination event. The gateway reused the session after both alerts and delivered a protected page each time. [Live close scopes](KWTLS_LAB_BASELINE.md#live-blackberry-close-scopes) |
| UDP flight retry | The exchange handler has a branch that references a previous send buffer on a byte-identical ClientHello and a separate branch for a fresh hello. The reviewed first-flight path builds and sends the flight. The executable's `select()` call has no timer argument. `wtls_server.c` lines 1168–1208 and 1583–1607, `kwtls.c` lines 149–184. | One successful delivery sequence. Flight retention and retransmission, loss, and same-tuple recovery still need live evidence. |
| Protected records | The send path schedules key calculation from the negotiated refresh value. The receive path invokes key calculation on a fixed eight-record cadence, and the calculation itself uses the negotiated value. `wtls_record.c` lines 264–273 and 1027–1029, `wtls_encrypt.c` lines 232–277. | The last visible protected sequence was 5. The run stayed below both the receive calculation at sequence 8 and the negotiated 32-record refresh boundary. |
| Algorithm scope | The normal server selector in this release covers DES-CBC and RC5 choices with full SHA. Its selection branches omit 3DES-CBC-EDE. `wtls_server.c` lines 752–793. | This is independent authenticated gateway evidence for DES-CBC. The Rust client still needs an independent gateway run on its existing 3DES-CBC-EDE profile. |

**Interpretation.** The server log records a matching client Finished. The following protected request and page acknowledgment show that the Browser proceeded after the server Finished. Treat refusal behavior, clean closure, loss handling, and session replacement as separate questions. The original capture includes one trailing protected client record after the page acknowledgment. The minimal backend logged that record as unhandled and the original run ended there.

## Carrying discoveries into the design loop

1. Keep source locations and implementation details on this discovery page. For future entries, record the upstream code anchor, the spec section, the observed peer input and output, and the remaining question.
2. For the design round, write a short handoff from the corrected spec and independently observed wire behavior. Decide which behavior is required in the default Rust profile and which compatibility behavior has a demonstrated peer need. Review the behavior and acceptance tests with the maintainer.
3. Give the implementer a fresh context with the reviewed behavior brief, corrected spec, wire evidence, and the Rust baseline needed for the change. For a clean-room round, stage those inputs in a workspace with access limited to that set. The KWTLS archive, this source reference, the source-review transcript, and the KWTLS build adjustments stay with discovery. Use the [supervised workflow](SUPERVISED_WORKFLOW.md#run-the-wtls-loop) to verify the exact implementation candidate later.

The [WTLS discovery queue](WTLS_DISCOVERY_QUEUE.md) carries these findings into the next rounds, starting with a repeatable baseline and the certificate-selection review.
