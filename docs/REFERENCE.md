# Protocol and tooling reference

[Project handbook](README.md) · [Testing guide](lab/TESTING.md)

## Record fixtures

Each fixture file is one transport service data unit (SDU). Write each octet as two hex digits, separated by whitespace. A `#` starts a comment. The inspector prints each record's offset, content type, header octet, sequence number, fragment length, length form, and cipher-spec bit. The cipher-spec bit reports the wire field alone.

The inspector can read the diagnostic record envelope before applying the datagram profile. For clear alerts it shows the level and description. For clear ClientHello messages it lists key exchanges, cipher and MAC pairs, compression and sequence settings in wire order. It keeps omitted sequences absent and reports the first profile mismatch. For a truncated record it prints the records already framed, then reports the stopping offset and remaining bytes with a failure exit status. The inspector leaves protected record bodies opaque.

```sh
cargo run --locked --bin wtls-inspect -- fixtures/kannel-handshake-failure.hex
cargo run --locked --bin wtls-inspect -- fixtures/winwap-client-hello.hex
```

The library exposes `decode_record_envelope`, `wire::decode_client_hello` and `wire::decode_server_hello`. The wire peer enforces explicit sequencing through `decode_datagram`. The server uses `wire::decode_client_hello` for offer selection. `wire::decode_handshake` reads messages encoded for the fixed lab profile.

## Handshake timeline

```sh
cargo run --locked --bin wtls-inspect -- --timeline fixtures/winwap-kannel-9203.trace
cargo run --locked --bin wtls-inspect -- --timeline fixtures/winwap-kannel-9202-retry.trace
cargo run --locked --bin wtls-inspect -- --timeline fixtures/winwap-kannel-9203-retry.trace
```

Each trace follows an endpoint pair in chronological order and can include a reconnect. The input contains UDP payloads and optional relay observations as text. Time is in microseconds from the start of the trace. Sizes count UDP payload bytes.

```text
<elapsed-us> <client|server> datagram <space-separated hex bytes>
<elapsed-us> <client|server> dropped <payload-bytes>
<elapsed-us> <client|server> over-limit <payload-bytes> <limit>
```

The inspector resolves the ServerHello key exchange index against the observed ClientHello offers. It shows the cipher, MAC, compression, sequence mode and key refresh selected by the server. It marks byte-identical ClientHello and full client commit datagrams with `repeat-of` and `elapsed-since-original-us` relative to the first observed copy. A full client commit contains clear ClientKeyExchange, clear ChangeCipherSpec, and a protected handshake record in one datagram. A distinct observed ClientHello starts a new commit comparison. A capture records what was seen at its tap. Explicit relay rows supply drop or size-limit evidence. Negotiation is shown as observed and protected records remain opaque.

The normal UDP 9203 trace comes from the first four packets of the isolated WinWAP 4.2.0.290 to Kannel 1.4.5 capture. The two retry traces combine UDP payloads from the delivery capture with the dropped-reply and over-limit rows from the relay log. Packet times use the capture clock. The relay rows retain millisecond precision. The 300-byte limit is the test relay's UDP payload budget.

## Source and fixture notes

- WAP-199 (18 February 2000), §§8.1, 9.2.1 and 9.2.3.1 govern the header and datagram sequencing. The HelloRequest fragment comes from §§10.5 and 10.5.1.1. The two single-record fixtures use independently derived bytes. The concatenated fixture adds a synthetic opaque fragment to demonstrate the record boundary. [WAP 1.2.1 publisher release](https://www.wapforum.org/what/technical_1_2_1.htm) · [Official release archive](https://www.openmobilealliance.org/tech/affiliates/wap/Technical_June2000-20021106%5B1%5D.zip)
- §9.2.1's field summary calls for explicit lengths when concatenating records. Its more specific flag description permits omitting the final record's length when the receiver knows the SDU boundary. This codec follows the flag description. An omitted length consumes the rest of the SDU, and the encoder requires lengths on all earlier records. Use explicit lengths on every record for the more conservative reading.
- The framing API reports unassigned content types and a set reserved bit as errors for this edition. It preserves the current-cipher bit without authenticating the fragment.

The Kannel alert comes from the WTLS-enabled 1.4.5 build's loopback reply to a 3DES offer. The WinWAP fixture is the first ClientHello from WinWAP for Windows 4.2.0.290 in secure connectionless mode on UDP 9202. Both were captured in an isolated test environment. The truncation fixture is synthetic.

The [KWTLS source reference](KWTLS_SOURCE_REFERENCE.md) maps the historical gateway's architecture and authenticated handshake to the live BlackBerry 7290 evidence and the corrected WAP-199 requirements.

## Handshake state machines

The `handshake` module runs a client or server association with a caller-supplied clock. Each `Datagram` groups the semantic messages of one SDU. The machine consumes those messages and emits actions for the driver, including sends, establishment, application delivery and closure. The full path models a server certificate with a client key exchange. A matching saved session selects the abbreviated path and reverses the order of the Finished flights.

`deadline` and `tick` let a driver schedule bounded client retries. A full handshake reuses the original flight on retransmission. An abbreviated client keeps prepending its CCS and Finished until it accepts server data or the duplicate-Finished notification. A server recognizes the duplicate Finished, keeps its open state and discards duplicate application records. Both peers support connection and session closure. Connection closure preserves the cached session. Session closure invalidates it.

The state-machine tests exchange typed datagrams in memory and use a fixture-only Finished provider. The wire peer connects the same state machines to record framing, protected records, and certificate verification. The full handshake in the standalone authenticated profile uses a server certificate.

```sh
cargo test --offline --test handshake
```

The flight and closure rules come from WAP-199 §§7, 9.2.3.1 and 10.1–10.5.9. [Official WAP 1.2.1 archive](https://www.openmobilealliance.org/tech/affiliates/wap/Technical_June2000-20021106%5B1%5D.zip)

## Protected in-memory echo

The wire peer accepts multiple protected application records in a UDP
datagram, including after the verified abbreviated client commit. It
delivers each replay-admitted record separately and in datagram order.
The full client handshake can also deliver one application record that
follows the verified server Finished in the same datagram.
The send API emits one application record per call, with the existing
abbreviated commit prefix when required.
[Receive behavior and tests](WAP_199_APPLICATION_RECORD_BATCH_PLAN.md)

The `wire::WirePeer` adapter drives the handshake state machines with actual WAP-199 record bytes. It selects **RSA / 3DES-CBC-EDE / SHA** (Appendix A values 8, 6, and 3), null compression, explicit sequencing, and a key refresh interval of at most eight records. The server selects the implemented algorithms from the client's lists and uses the smaller refresh value. The Finished calculation uses the original ClientHello bytes and the actual ServerHello selection. The client verifies a native WTLS RSA leaf against one provisioned RSA authority, the configured exact WTLS subject identity, and the supplied certificate-validation time. The full handshake transports a random RSA secret, derives both directional keys, and authenticates the encoded handshake transcript. Each ChangeCipherSpec switches its direction and resets the record sequence so the protected Finished starts at zero. Retries reuse the recorded wire bytes.

Build with the OpenSSL development libraries and pkg-config. The lab server uses OpenSSL 3.2 or later with the default provider for RSA decryption. The `cargo test --offline` examples assume the locked dependencies are already in Cargo's cache. Run `cargo test --locked` to resolve the workspace on a fresh machine. [OpenSSL EVP decryption](https://docs.openssl.org/3.6/man3/EVP_PKEY_decrypt/)

```sh
cargo test --locked --test protected_echo
```

The echo tests exchange only in-memory datagrams and generate their own lab RSA keys. They check certificate identity, Finished flight framing, loss recovery, authenticated data in both directions, refresh, and authenticated closure. A separate fixed vector checks the RSA premaster composition and bytes on each side of the refresh boundary. The RSA premaster appends the WAP-199 `RSAPublicKey` encoding (the length-prefixed exponent and modulus), also seen in the Kannel 1.4.5 anonymous-RSA implementation. That source is a cross-check of the byte order. The echo itself uses server authentication.

The opt-in `ResumableServer` and `ResumableClient` contexts support abbreviated wire handshakes for this authenticated profile. Each new connection derives keys from fresh hello randoms and the cached master secret. The [cache design](WIRE_SESSION_RESUMPTION.md) describes configuration and lifetime. The [BlackBerry 7290 run](../fixtures/HISTORICAL_PEERS.md#blackberry-abbreviated-handshake) verified an actual abbreviated exchange and protected WSP traffic after reconnect. The legacy record protection is intended for isolated lab use. [WAP-199 §§8.7, 9.2.3, 10–11, and Appendix A](https://www.openmobilealliance.org/tech/affiliates/wap/Technical_June2000-20021106%5B1%5D.zip) · [Kannel 1.4.5 source release](https://www.kannel.org/download/1.4.5/)

## Provisioned authority selection

Use `WirePeer::provisioned_client` or `ResumableClient::provisioned` with the
client's `TrustAnchor` to advertise the authority that verifies the expected
gateway leaf. `ServerIdentity::provisioned` accepts the gateway certificate,
its private key, the expected issuer name, and the issuer's RSA public key.
Its validated identity works with `WirePeer::server` and `ResumableServer::new`.
The resumable contexts work with the existing UDP adapter.

The gateway accepts a matching RSA authority in a nonempty list and permits
an empty list with an authenticated full offer. The client independently
verifies the leaf signature, issuer, expected subject, and validity before key
transport. A conflicting nonempty list declines resumption while preserving
the cached session for an eligible reconnect. Create fresh contexts when
changing credentials, trust, or certificate-selection policy.

```sh
cargo test --locked --offline --test provisioned_trust
```

[WAP-199 corrections and deterministic gate](WAP_199_PROVISIONED_TRUST_PLAN.md)

A classified native leaf failure in a provisioned full handshake produces
a typed local rejection and one clear fatal certificate alert. Use
`WirePeer::receive_with_reply` when a direct wire caller can forward the
optional reply returned with an error. The UDP adapter reports the
diagnostic and applies its datagram budget to the reply. The existing
`receive` method exposes the diagnostic-only result.
[Certificate alert behavior and tests](WAP_199_CERTIFICATE_ALERT_PLAN.md)

The authenticated gateway sends a clear fatal `handshake_failure` when
an admissible opening offer needs a full handshake and has no usable
RSA choice or matching cipher/MAC pair. The alert covers the exact
ClientHello record and leaves any incumbent pending association intact.
[Algorithm mismatch behavior and tests](WAP_199_ALGORITHM_MISMATCH_ALERT_PLAN.md)

## Connection reporting for adapters

Use `WirePeer::status()` while driving the handshake and `WirePeer::connection_info()` after establishment. It reports the WAP-199 negotiated identifiers and the verification performed on the remote identity from that endpoint. In this profile the client verifies the server certificate and the server has no authenticated client identity.

On the authenticated profile, the wire peer checks a clear alert against a
complete record sent during the pending negotiation. A matched fatal or
critical error can close that attempt while preserving a verified cached
session. Matched clear warnings and well-leveled clear closure notifications
remain diagnostic observations. Once the receive epoch is committed, clear
alerts are rejected. A checksum-matched authenticated critical or fatal
alert in the committed receive epoch closes the association. Critical
preserves the cached session and fatal invalidates its exact cache entry.
Callers can inspect `status()` after `WireError::PeerAlert`. Protected
closure notifications continue to produce `WireAction::Closed` and their
normal acknowledgements. [Clear alert policy and evidence](WAP_199_CLEAR_ALERT_PLAN.md)

Use `DatagramBudget::check` on a complete encoded `WireAction::Send` payload before sending it. The size error includes the encoded byte count and the transport's configured limit. Drivers own delivery observations and must supply them when available. WSP session establishment and origin retrieval are reported by their respective layers.

## Reusable UDP adapter and BlackBerry lab

`wtls_lab::udp::Adapter` routes complete datagrams by remote IP and port. Feed
it each datagram with the observed source address, Unix certificate time, and a
shared monotonic millisecond clock. Send each `Event::Send` as one datagram to
the given destination. Call `tick` by the reported `deadline`, and handle
delivery, close, timeout, and diagnostic events separately. `SocketTransport`
provides the equivalent whole-datagram I/O for a standard UDP socket.

The adapter enforces a datagram budget and an association capacity. A pending
inbound slot has a configurable fixed deadline. An admissible fresh
ClientHello can start a new handshake in that slot while it is pending.
Exact duplicates receive the cached flight. Both paths keep the slot's
original deadline. On an open inbound tuple, a fresh ClientHello can stage
one full or abbreviated replacement in the same slot. Protected traffic
stays on the incumbent until the replacement verifies Finished and opens.
A full replacement also needs a final server flight within the datagram
budget. An `Established` event marks the switch for tuple-addressed work.

A verified resumed replacement that sends a protected close with Finished
leaves the incumbent active and emits `Diagnostic::CandidateClosed(scope)`.
Connection close preserves the resumed cache entry. Session close removes
that entry from eligibility for future handshakes. The adapter keeps a
bounded history of retired ClientHello randoms keyed by remote address.
[Full recovery](WAP_199_ESTABLISHED_TUPLE_RECOVERY_PLAN.md) ·
[Abbreviated recovery](WAP_199_ABBREVIATED_TUPLE_RECOVERY_PLAN.md)

```sh
cargo run --locked --offline --bin wtls-udp-lab
```

The sample binds `127.0.0.1:9203` and serves one static WML page through its
minimal WTP/WSP responder. Run it on the same isolated network as the
historical client. The sample allows 300 seconds for certificate inspection.
In the BlackBerry WTLS options, enable **Prompt For Server Trust**. Open
`http://lab.invalid/resume;WAPGatewayIP=10.0.2.2;WAPGatewayAPN=rim.net.gprs;WAPGatewayPort=9203`
when using the XP guest's QEMU loopback gateway. Compare the displayed leaf
thumbprint with the printed fingerprint before accepting it.

After `wsp=page-ack`, enter `connection-close` on stdin and refresh the
Browser. Verify `handshake=Resumed` and another page acknowledgment. Enter
`session-close` and refresh again. Verify `handshake=Full` and a page
acknowledgment. The stdin commands target the most recently established
association. [BlackBerry run and wire trace](../fixtures/HISTORICAL_PEERS.md#blackberry-reconnect-through-the-udp-adapter)

## Direct WinWAP compatibility test

`wire::WirePeer::legacy_winwap_server` explicitly selects the anonymous RSA,
DES-CBC and full HMAC-SHA-1 profile observed in WinWAP. It uses a fresh RSA
key, advertises only the selected legacy tuple, and chooses explicit sequences
with a key refresh value of at most 2. The compatibility codec preserves the
original ClientHello in the transcript and reads WinWAP's modulus-sized RSA
ciphertext directly from the ClientKeyExchange body. The existing authenticated
constructor continues to require the authenticated profile.

The one-request lab server binds loopback UDP 9202 and returns a static WBXML
deck for an authenticated WTLS application record carrying a WSP GET. WTLS
authenticates the protected record with the connection keys. The anonymous
profile does not authenticate peer identities. Run in an isolated network with
the client and test gateway.

```sh
cargo run --locked --bin wtls-winwap-lab -- --legacy-winwap
```

Select **Secure Connection less** in WinWAP and target the lab gateway on UDP
9202. Look for separate `wtls=established`, `wsp=get-received`, and
`wsp=reply-sent` lines. The reply comes from the lab adapter's static deck.
[Supervised workflow and slice packet](SUPERVISED_WORKFLOW.md)

### Observe WinWAP reconnect after a protected close

```sh
cargo run --locked --bin wtls-winwap-lab -- --legacy-winwap --probe-session-cache
```

After the first protected deck renders, reload from the same WinWAP process.
The probe serves one reply, sends a protected connection-close alert, and
accepts one more handshake on a fresh peer. The logs show the raw ClientHello
and ServerHello session IDs separately from WTLS establishment and the WSP
reply. In the buffered XP trial both requests completed and WinWAP sent an
empty session ID on each ClientHello. [WTLS evidence](WTLS_EVIDENCE.json)
