# WTLS lab

A standalone Rust workspace for WAP-199 record framing, handshake inspection, and a protected wire peer. Run the inspector from the workspace root.

```sh
cargo run --offline --bin wtls-inspect -- fixtures/hello-request-implicit.hex
cargo run --offline --bin wtls-inspect -- fixtures/hello-request-explicit.hex
cargo run --offline --bin wtls-inspect -- fixtures/concatenated.hex
cargo test --offline
```

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

The inspector resolves the ServerHello key exchange index against the observed ClientHello offers. It shows the cipher, MAC, compression, sequence mode and key refresh selected by the server. It marks byte-identical ClientHello datagrams and prints their time since the original. A capture records what was seen at its tap. Explicit relay rows supply drop or size-limit evidence. Negotiation is shown as observed and protected records remain opaque.

The normal UDP 9203 trace comes from the first four packets of the isolated WinWAP 4.2.0.290 to Kannel 1.4.5 capture. The two retry traces combine UDP payloads from the delivery capture with the dropped-reply and over-limit rows from the relay log. Packet times use the capture clock. The relay rows retain millisecond precision. The 300-byte limit is the test relay's UDP payload budget.

## Source and fixture notes

- WAP-199 (18 February 2000), §§8.1, 9.2.1 and 9.2.3.1 govern the header and datagram sequencing. The HelloRequest fragment comes from §§10.5 and 10.5.1.1. The two single-record fixtures use independently derived bytes. The concatenated fixture adds a synthetic opaque fragment to demonstrate the record boundary. [WAP 1.2.1 publisher release](https://www.wapforum.org/what/technical_1_2_1.htm) · [Official release archive](https://www.openmobilealliance.org/tech/affiliates/wap/Technical_June2000-20021106%5B1%5D.zip)
- §9.2.1's field summary calls for explicit lengths when concatenating records. Its more specific flag description permits omitting the final record's length when the receiver knows the SDU boundary. This codec follows the flag description. An omitted length consumes the rest of the SDU, and the encoder requires lengths on all earlier records. Use explicit lengths on every record for the more conservative reading.
- The framing API reports unassigned content types and a set reserved bit as errors for this edition. It preserves the current-cipher bit without authenticating the fragment.

The Kannel alert comes from the WTLS-enabled 1.4.5 build's loopback reply to a 3DES offer. The WinWAP fixture is the first ClientHello from WinWAP for Windows 4.2.0.290 in secure connectionless mode on UDP 9202. Both were captured in an isolated test environment. The truncation fixture is synthetic.

## Handshake state machines

The `handshake` module runs a client or server association with a caller-supplied clock. Each `Datagram` groups the semantic messages of one SDU. The machine consumes those messages and emits actions for the driver, including sends, establishment, application delivery and closure. The full path models a server certificate with a client key exchange. A matching saved session selects the abbreviated path and reverses the order of the Finished flights.

`deadline` and `tick` let a driver schedule bounded client retries. A full handshake reuses the original flight on retransmission. An abbreviated client keeps prepending its CCS and Finished until it accepts server data or the duplicate-Finished notification. A server recognizes the duplicate Finished, keeps its open state and discards duplicate application records. Both peers support connection and session closure. Connection closure preserves the cached session. Session closure invalidates it.

The test driver exchanges typed datagrams in memory and uses a fixture-only Finished provider. Its application sequence window is a model of authenticated record acceptance. Establishment indicates the modeled association state. To connect it to the record codec, a later adapter must supply real handshake and alert serialization, key exchange and trust, directional cipher changes, authenticated record sequences, and a real Finished provider. The current one-association model uses one externally supplied cached session ID and fixes the full handshake to the server-certificate path. Additional negotiation variants and renegotiation are separate work.

```sh
cargo test --offline --test handshake
```

The flight and closure rules come from WAP-199 §§7, 9.2.3.1 and 10.1–10.5.9. [Official WAP 1.2.1 archive](https://www.openmobilealliance.org/tech/affiliates/wap/Technical_June2000-20021106%5B1%5D.zip)

## Protected in-memory echo

The `wire::WirePeer` adapter drives the handshake state machines with actual WAP-199 record bytes. It selects **RSA / 3DES-CBC-EDE / SHA** (Appendix A values 8, 6, and 3), null compression, explicit sequencing, and a key refresh interval of at most eight records. The server selects the implemented algorithms from the client's lists and uses the smaller refresh value. The Finished calculation uses the original ClientHello bytes and the actual ServerHello selection. The client verifies a native WTLS RSA leaf against one provisioned RSA authority, the configured exact WTLS subject identity, and the supplied certificate-validation time. The full handshake transports a random RSA secret, derives both directional keys, and authenticates the encoded handshake transcript. Each ChangeCipherSpec switches its direction and resets the record sequence so the protected Finished starts at zero. Retries reuse the recorded wire bytes.

Build with the OpenSSL development libraries and pkg-config. The lab server uses OpenSSL 3.2 or later with the default provider for RSA decryption. The `cargo test --offline` examples assume the locked dependencies are already in Cargo's cache. Run `cargo test --locked` to resolve the workspace on a fresh machine. [OpenSSL EVP decryption](https://docs.openssl.org/3.6/man3/EVP_PKEY_decrypt/)

```sh
cargo test --locked --test protected_echo
```

The echo tests exchange only in-memory datagrams and generate their own lab RSA keys. They check certificate identity, Finished flight framing, loss recovery, authenticated data in both directions, refresh, and authenticated closure. A separate fixed vector checks the RSA premaster composition and bytes on each side of the refresh boundary. The RSA premaster appends the WAP-199 `RSAPublicKey` encoding (the length-prefixed exponent and modulus), also seen in the Kannel 1.4.5 anonymous-RSA implementation. That source is a cross-check of the byte order. The echo itself uses server authentication.

This wire adapter covers the selected full-handshake profile. Abbreviated handshakes remain exercised by the typed state-machine tests. The [BlackBerry 7290 run](fixtures/HISTORICAL_PEERS.md#blackberry-authenticated-exchange-and-cached-id) completed two full handshakes with explicit acceptance of the lab certificate, exchanged protected WSP traffic, and reoffered a cached session ID after a protected connection close. The legacy record protection is intended for isolated lab use. [WAP-199 §§8.7, 9.2.3, 10–11, and Appendix A](https://www.openmobilealliance.org/tech/affiliates/wap/Technical_June2000-20021106%5B1%5D.zip) · [Kannel 1.4.5 source release](https://www.kannel.org/download/1.4.5/)

## Connection reporting for adapters

Use `WirePeer::status()` while driving the handshake and `WirePeer::connection_info()` after establishment. It reports the WAP-199 negotiated identifiers and the verification performed on the remote identity from that endpoint. In this profile the client verifies the server certificate and the server has no authenticated client identity.

The wire peer returns `WireError::PeerAlert` for a parsed clear alert during negotiation or an authenticated alert outside the supported control messages. Clear observations are unverified and leave the association state unchanged. Protected close notifications continue to produce `WireAction::Closed`.

Use `DatagramBudget::check` on a complete encoded `WireAction::Send` payload before sending it. The size error includes the encoded byte count and the transport's configured limit. Drivers own delivery observations and must supply them when available. WSP session establishment and origin retrieval are reported by their respective layers.

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
[Supervised workflow and slice packet](docs/SUPERVISED_WORKFLOW.md)

### Observe WinWAP reconnect after a protected close

```sh
cargo run --locked --bin wtls-winwap-lab -- --legacy-winwap --probe-session-cache
```

After the first protected deck renders, reload from the same WinWAP process.
The probe serves one reply, sends a protected connection-close alert, and
accepts one more handshake on a fresh peer. The logs show the raw ClientHello
and ServerHello session IDs separately from WTLS establishment and the WSP
reply. In the buffered XP trial both requests completed and WinWAP sent an
empty session ID on each ClientHello. [WTLS evidence](docs/WTLS_EVIDENCE.json)
