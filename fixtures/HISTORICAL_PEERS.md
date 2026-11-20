# Historical WTLS peer candidates

WTLS-203 screens a second historical client alongside the existing WinWAP
fixtures. The BlackBerry 7290 simulator reached the authenticated lab endpoint
in disposable XP. The screening below records the original candidate ranking.

## Candidate ranking

1. **Openwave Simulator 7.0.** First choice. Openwave's 2003 Mobile Browser 7.0
   datasheet explicitly lists WTLS Class II for its WAP 1.x stack. The simulator
   installer is staged on the read-only XP CD. The Windows build and its
   selected connection mode still need wire confirmation.
   [Openwave Mobile Browser 7.0 datasheet](https://www1.lasalle.edu/~beatty/430/wireless/toolkit/client_tech_and_sdk/pdf/DS_MobileBrowser7.0_0103.pdf)
2. **Openwave SDK 6.2.2.** The installer is also staged on the read-only XP
   CD. Its browser build and secure gateway behavior need confirmation.
   The Class II documentation above names 7.0. Openwave 4.1.1 stopped at a
   separate export attestation. Record any installer gate against the specific
   build and leave agreements to the maintainer.
3. **BlackBerry OS 4 simulators.** RIM's 2004 enterprise guide documents
   `WapEnableWTLS`, a Class II handheld stack, and a simulator WAP source-port
   option. The developer brochure documents JDE and device simulator
   distribution. An archive lists generic OS 4 and model-specific simulators.
   The exact build, installer contents and availability, browser provisioning,
   and simulator WTLS traffic remain unverified.
   [RIM enterprise programming guide](https://media.journoportfolio.com/users/51888/uploads/84f291ae-c7fa-4cc3-b63b-491729e2fb2b.pdf) ·
   [BlackBerry developer tools brochure](https://www.blackberry.com/emailers/developers/javaone/DevZoneWelcomePDF_Final.pdf) ·
   [Simulator archive listing](https://archive.lunar-project.org/BlackBerry%20OS/Simulators/)

Kannel records connectionless networking for Ericsson R380s Emulator 3.0 and
external gateway configuration on unsecured UDP 9201 for Motorola ADK 1.1.
Both still need evidence of a secure offer. The Nokia 7110 simulator guide
excludes WTLS, and the 7210 SDK has an installer/serial gate. Handset support
alone leaves simulator capability open.
[Kannel compatibility notes](https://www.kannel.org/compatibility.shtml)

## Maintainer XP gate

For each attempt, record the installer source and build, any installer or
provisioning blocker, the selected browser mode and gateway, and the capture
and endpoint log references. Preserve the original UDP payloads, direction,
and timestamps.

| Observation | Evidence to record |
| --- | --- |
| WAP gateway traffic | Identify unsecured WSP on UDP 9201 or WAP 2 HTTPS by the decoded traffic. For a WTLS candidate, capture a clear WTLS ClientHello sent to the lab gateway over UDP 9202 or 9203. Record the endpoints and decode the record and handshake. The port alone leaves the protocol unconfirmed. |
| Authenticated offer | Preserve the ordered ClientHello key exchange entries and cipher/MAC pairs with their raw identifiers, plus compression, sequence mode, key refresh, and raw session ID bytes (including an empty ID). Decode against WAP-199 Appendix A and record any mismatch with the lab profile. RSA (8) is the authenticated key exchange in the lab profile, which uses 3DES-CBC-EDE (6) and SHA (3). Resolve any ServerHello selection against the actual offer list. |
| Authentication completed | If the offer agrees with the profile, correlate the negotiated tuple and server certificate with evidence that the client verified the certificate against its configured trust and server identity. Record successful protected Finished verification in both directions and a protected WSP request and reply. A capture can show the flight order, while peer or endpoint evidence establishes verification of protected records. |
| Cached offer or stale-ID fallback | Compare the reconnect ClientHello's raw ID to the ServerHello ID issued in an earlier completed exchange. An initial nonempty ID with no recorded issuance is an uncorrelated offer. If the server declines the offered ID and sends a different ID with a full handshake, record full-handshake fallback. Call the offer stale when cache expiry, invalidation, or absence is evidenced. |
| Abbreviated resumption | Correlate the reconnect offer with the earlier issued ID and verify that the new ServerHello echoes the same bytes. Observe the server ChangeCipherSpec and protected Finished before the client's ChangeCipherSpec and protected Finished, with the full certificate and key-exchange flight absent. Correlate both verified Finished messages and subsequent protected traffic. |

## BlackBerry 7290 simulator result

The RIM BlackBerry JDE 4.0 installer (`JDE_4.0.exe`, SHA-256
`10f73ec16376e617cdf74bbe79c6332e38c64e8338751acf704412a96e19afb0`)
installed in a disposable Windows XP disk overlay. Its stock `7290.bat`
launched a simulated 7290. This `fledge` binary rejected the developer guide's
`/rport=8205` option. The stock launch sent traffic from UDP 8205.
[RIM JDE archive](https://archive.org/details/blackberry-jde) ·
[RIM 4.0 developer guide](https://media.journoportfolio.com/users/51888/uploads/84f291ae-c7fa-4cc3-b63b-491729e2fb2b.pdf)

In the built-in Browser, use **Go To** with
`http://lab.invalid/probe;WAPGatewayIP=10.0.2.2;WAPGatewayAPN=rim.net.gprs;WAPGatewayPort=9203`.
The guide documents WTLS enabled by default on port 9203 for the explicit
gateway path. The tests used another request path on each attempt. The
isolated QEMU guest sent from `10.0.2.15:8205` to `10.0.2.2:9203`. A UDP
observer passed each received datagram directly to the unchanged authenticated
`WirePeer::server` using a generated lab certificate. The peer recorded the
profile error and stayed idle.

- All three requests started with fresh randoms and empty IDs. Each sent
  one 925-byte ClientHello and five byte-identical retries, then a clear fatal
  `handshake_failure` alert. The endpoint logged the profile rejection on both
  live runs. The listener had timed out before the middle request, whose
  observations came from the guest capture.
- The client preferred unrestricted authenticated RSA (8). It also offered
  RSA_768 (10) and RSA_512 (9), followed by anonymous options. The first of
  48 cipher/MAC pairs was the lab's 3DES-CBC-EDE (6) and full SHA (3). The hello
  contained 10 key exchange offers, 28 trusted-key hashes, null compression,
  explicit sequence mode (2), and offered key refresh 5.
- The current fixed profile rejects the shape of the offer at its singleton
  RSA and empty trusted-key check. The preferred RSA entry also carries a
  binary identifier, and the client offered multiple cipher/MAC pairs. The
  server produced no ServerHello and issued no session ID. Certificate
  acceptance, protected traffic, and a cached-ID offer were tested in WTLS-204 below.

WAP-199 §10.5.1.3 allows the server to select the offered RSA entry by its
one-based index, select the offered cipher/MAC pair, and choose a key refresh
value at or below the client's value. The captured hello supports testing
selection of the existing authenticated suite. The certificate acceptance
policy needs its own live check against the advertised trust identifiers.
[WAP-199 §§10.5.1.2–10.5.2 and Appendix A](https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf)

The first datagram is in [blackberry-7290-client-hello.hex](blackberry-7290-client-hello.hex).
The filtered capture `blackberry-7290-9203.pcap` started at
2026-11-20 17:11:47 UTC and has SHA-256 `a9f3fc7d3e2d187b22470862aae34941c3b9be8d198aecb831768034e34b8a84`. The derived timeline
`blackberry-7290-9203.trace` has SHA-256 `213f02c0dce19b1ad95667606d0ae327de13ccea7dc3836d80f549a4e314abbf`.

The staged Openwave 7.0.107 installer reached a separate export-eligibility
screen in XP. That run ended before acceptance. The Openwave 6.2.2 installer
remains staged for a later test.


## BlackBerry authenticated exchange and cached ID

WTLS-204 used the same stock JDE 4.0 BlackBerry 7290 Browser in isolated XP
and sent the same local probe to UDP 9203. The Rust endpoint selected the
first offered key exchange, unrestricted RSA (8), and 3DES-CBC-EDE (6) with
full HMAC-SHA-1 (3), null compression, explicit sequencing, and key refresh
3 from the client's offer of 5. The server included the generated native WTLS
leaf for `10.0.2.2` in both full handshakes.

The simulator's **Prompt For Server Trust** setting was set to **Yes**. Its
certificate viewer reported an untrusted chain. The displayed SHA-1
thumbprint `1ca5c481213a543b633bdc295f9cdb2cef0d667f` matched the temporary
lab leaf and the certificate bytes sent in both server flights. The operator
chose to continue each time after that comparison. This test used explicit
leaf acceptance. Automatic CA-chain validation remains untested.
[RIM 7290 user guide, WAP Browser security options](https://www.att.com/support_static_files/manuals/BlackBerry_7290.pdf)

| Event | Observed ID or result |
| --- | --- |
| First ClientHello | Empty session ID |
| First ServerHello | `ac51a992d73be1a9` |
| First established connection | The server verified the protected client Finished. The BlackBerry acknowledged the protected WSP reply and rendered the local WML page. |
| Connection close | The lab sent a protected `connection_close_notify` and the Browser was refreshed. |
| Reconnect ClientHello | `ac51a992d73be1a9`, exactly the first ServerHello's ID |
| Reconnect ServerHello | Fresh ID `7877de87c4ade752` and a full certificate flight |
| Reconnect result | The server verified the protected client Finished again. The BlackBerry acknowledged the protected WSP reply. |

WTLS-204 treated the cached offer as a cache miss. The handset reoffered
the ID and fell back to another full handshake. WTLS-205 and WTLS-206
below verify the abbreviated exchange. The test harness used a local, minimal
WTP/WSP responder for the synthetic Connect and GET requests.
[WAP-199 §§10.2.1, 10.5.1.2–10.5.1.3 and 10.5.9](https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf)

The [trace](blackberry-7290-authenticated.trace) contains 22 UDP payloads
from the same address pair across the two connections. Event 12 carries the
protected close and event 13 the cached-ID offer. Capture began at
2026-11-20 17:32:35 UTC. The UDP-filtered PCAP SHA-256 is
`a51a62bfd4142de9605750a6c6adc020d194d65dfa482986ca25aee0249ceefa` and the timeline SHA-256 is
`8bd740dcc1ddfb4864388a9db12d50139effce659bdc6fb590d2eeed782260ed`. The inspector displays the clear negotiation and protected
record envelopes. The endpoint log records Finished verification and the
WSP transactions.

```sh
cargo run --locked --bin wtls-inspect -- --timeline fixtures/blackberry-7290-authenticated.trace
```


## BlackBerry abbreviated handshake

WTLS-205 added the authenticated wire cache. WTLS-206 retained the one-based
RSA index on a resumed ServerHello when the client supplied that option.
The BlackBerry 7290 initially stopped before sending Finished on a test that
used the optional zero index. It completed an abbreviated exchange with its
offered index (1). An offer with an empty key list still uses the allowed
zero index. [WAP-199 §§10.3 and 10.5.1.3](https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf)

The isolated XP guest used the stock RIM JDE 4.0 browser and the UDP 9203
probe from WTLS-204. The gateway cache was set to 32 entries with a 15-minute
lifetime. The handset first offered the previous listener's ID `90e1041ad9894d49`.
The listener took the full-handshake path. The displayed
thumbprint matched the newly generated lab WTLS leaf
(`638d001c11a91e6243d49b812401ebe674519ba3`), which the operator explicitly accepted.

| Trace event | Observation |
| --- | --- |
| 1–2 | The initial full server flight issued `a3ae109830b84aa6`. The server then verified the client Finished and exchanged protected WSP traffic. |
| 12 | The lab sent a protected connection close, leaving the session eligible for reuse. |
| 13–14 | On Browser refresh, both hellos carried `a3ae109830b84aa6` with fresh randoms. The server's datagram contained ServerHello, ChangeCipherSpec, and protected Finished. |
| 15 | The client sent ChangeCipherSpec, protected Finished, and a protected WSP Connect. The server reported `Established(Resumed)` after verification. |
| After event 15 | The server returned the local WML page in a protected WSP reply. The handset acknowledged the reply, and the page rendered without a second certificate prompt. |

The resumed flight contained no certificate, ServerHelloDone, or RSA key
exchange. The [trace](blackberry-7290-resumed.trace) contains all 20 UDP payloads from
the two connections. The filtered PCAP SHA-256 is `6f8a16723e0fafbbc70953a797fbe8053714c6b401cfecdf93fa761cecd0031c`.
The trace SHA-256 is `3b09d237e1158fd490d9427868fb564bc2b38dad2ac11e883d43b8f5b4818e19`. The endpoint log confirms the
encrypted Finished verification and the WSP acknowledgement that are opaque
in the capture.

```sh
cargo run --locked --bin wtls-inspect -- --timeline fixtures/blackberry-7290-resumed.trace
```


## BlackBerry connection and session close

The WTLS-207 run used the stock JDE 4.0 BlackBerry 7290 Browser in isolated
XP against the authenticated Rust endpoint on UDP 9203. The operator matched
the lab leaf's displayed SHA-1 thumbprint (`37dc033cc40977d03b8abd1b31cf665c23e09810`) before accepting
it on each full handshake.

1. The full handshake issued `7ae7417145b8ac4b` and completed a protected WSP
   request and reply.
2. The lab sent a protected Connection close. On refresh the client offered
   `7ae7417145b8ac4b`, the server echoed the ID and committed first, and the protected
   WSP exchange completed again.
3. The lab sent a protected Session close on that resumed connection. The client reoffered `7ae7417145b8ac4b`. The gateway selected a new ID, `beba37cb32ed50c1`.
   The certificate flight, both Finished messages, and the WSP reply followed
   the full-handshake path.

The [trace](blackberry-7290-close-reconnect.trace) contains 37 UDP payloads. Its SHA-256 is
`35ddadd70deb89422ffc445416c6b71a605b85c2ef1e38f52165c74c728ac5e0`. The filtered PCAP SHA-256 is
`4b1a4b97f6848f009632889890ee763b73f58c84cfc09756085ff8496d3734e7`. The endpoint log verifies the full, resumed, and full
transitions and the protected WSP acknowledgements. Native wire tests
exercise generic critical, fatal, warning, and unauthenticated alert
handling. [WAP-199 §§10.2–10.2.2](https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf)
