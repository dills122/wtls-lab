# Authenticated WTLS session resumption

WTLS-205 adds abbreviated handshake support to the existing authenticated RSA
profile. An opt-in, long-lived server context owns a particular gateway
identity and its cache. An opt-in client context is used for one gateway and
owns that gateway's trust configuration and latest verified session. `ResumableServer` and `ResumableClient` create a `WirePeer` through `peer(now)`, where `now` is the certificate wall clock in Unix seconds. Datagram
adapters create a new wire peer for each connection and supply a shared
monotonic millisecond clock for peers using the same context. Certificate
validation continues to use the caller-supplied wall clock.

## Cache policy

- Store an eight-byte ID, the zeroizing master secret, negotiated profile and
  the authenticated credential's validity. Keep session material private and
  in memory. Connections retain their own sequence and retry state.
- Use caller-configured, nonzero capacity and lifetime per server context.
  Keep one latest entry per client context. Expire from the original verified
  full establishment. Resume does not extend the lifetime. Evict the oldest
  entry on capacity pressure. A new identity or trust configuration gets a
  new context. Newly issued IDs must differ from the offered ID and any live
  cached ID. Treat insertion collisions as errors or preserve the incumbent.
- Install a fresh session only after the authenticated full Finished check.
  A Connection close leaves it available. Sending or accepting an
  authenticated Session close invalidates it. A malformed or unverified
  packet cannot evict an existing session. Use the cached credential only
  during its validity interval. The legacy anonymous server stays full-only.

## Wire contract

On a usable cache match, echo the exact ID, keep the cached cipher/MAC and
compression, and select a compatible sequence mode and key refresh. Follow
the ServerHello immediately with ChangeCipherSpec and protected Finished.
The client sends its own ChangeCipherSpec and protected Finished. Hash the
actual handshake bytes in their original order. Derive fresh traffic keys
with both new hello randoms and reset each protected sequence at CCS.

A miss with a usable full offer returns a distinct ID and a full certificate
flight. A resumption-only offer without a usable cache entry receives a clear
unknown_key_id alert. Until confirmed by authenticated server data or the
duplicate-Finished alert, the resumed client prepends its original commit to
application traffic. The server recognizes the validated exact commit prefix
and processes trailing data under its existing replay window. Either close
scope carries the original commit while confirmation is pending so the
server can validate it even if the standalone flight was lost. The server
checks that the selected cache entry is still valid when accepting the commit.

A protected close can reference a record that reached the peer before a
long run of losses. Each connection retains checksums for its sent records,
bounded by the non-wrapping sequence space. A retry reuses the existing
record bytes and checksum.

Use the one-based index of the selected RSA offer when present. An offer
without a matching key entry uses the optional zero index on resumption.

## Verification

Run `cargo test --locked --offline`,
`cargo clippy --locked --offline --all-targets -- -D warnings`, and
`cargo fmt --all --check`. The live BlackBerry test starts from a verified
full handshake and a protected Connection close. The capture must show
the original ID on both reconnect hellos, the server committing first, and
the absence of a certificate/key-exchange flight on the reconnect. The
endpoint must verify the client Finished and carry protected WSP traffic.
[WAP-199 §§9.1, 10.2–10.5 and 11.1.4–11.2](https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf)
