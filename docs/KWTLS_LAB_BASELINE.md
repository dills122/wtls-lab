# KWTLS BlackBerry baseline

The BlackBerry 7290 completed a full authenticated WTLS handshake against KWTLS
1.0.3 on November 21, 2026, first with an empty session ID and again when KWTLS
returned a different ID from the one the Browser offered. Two fresh-process
attempts that reused the offered ID stopped before Finished.
[Original wire capture](../fixtures/blackberry-7290-kwtls-full.trace) ·
[Different-ID comparison](#different-id-comparison) ·
[Live resumption](#live-blackberry-resumption) ·
[Live close scopes](#live-blackberry-close-scopes)

## Build and launch

| Input | SHA-256 |
| --- | --- |
| [KWTLS 1.0.3 source](https://www.kannel.org/download/wtls/kwtls-1.0.3.tar.gz) | `7c727beabc0ea55518790a995a83ad411843097db0c90ebc9eaf797a3afedd65` |
| [OpenSSL 1.0.2u source](https://www.openssl.org/source/old/1.0.2/openssl-1.0.2u.tar.gz) | `ecd0c6ffb493dd06707d38b14bb4d8c2288bb7033735606569d8f90f89669d16` |
| [RIM JDE 4.0 installer](https://archive.org/details/blackberry-jde) | `10f73ec16376e617cdf74bbe79c6332e38c64e8338751acf704412a96e19afb0` |

The local reproduction attachment, `kwtls-blackberry/kwtls-reproduction.zip`,
holds `reproduction/kwtls-1.0.3-macos.patch`, `live_lab.py`, and the separate
certificate generator. The ZIP SHA-256 is
`3f0f1db84d61fc66d78c1078b80f8accceba92095d908ca65c6ffacd2b508fa5`.
Keep these with the discovery workspace. The gateway source, installer, private
identity, and raw KWTLS logs stay local. Git retains the WTLS datagrams
from the successful lab exchanges.

Extract the two source archives into sibling directories and use an x86-64
shell under Rosetta on Apple Silicon. The patch replaces obsolete pointer
casts, preserves network byte order in the record MAC header, binds the gateway
to loopback, and flushes log lines promptly.

```sh
cd openssl-1.0.2u
perl Configure darwin64-x86_64-cc no-asm no-shared no-dso enable-rc5
make -j8 build_crypto
cd ../kwtls-1.0.3
patch -p1 < ../kwtls-1.0.3-macos.patch
make -j2 libwtls.a kwtls.o CC='clang -arch x86_64' \
  CFLAGS='-std=gnu89 -fcommon -g -O0 -Wall -I../openssl-1.0.2u/include -Wno-int-conversion -Wno-implicit-function-declaration'
clang -arch x86_64 -o kwtls kwtls.o libwtls.a ../openssl-1.0.2u/libcrypto.a
cd ..
```

Use the existing matching identity for an already-enrolled simulator. To set
up a fresh lab, point the bundle's `provision/Cargo.toml` at your local
`wtls-lab` checkout, set `umask 077`, and run
`cargo run --locked --offline --manifest-path provision/Cargo.toml -- identity`
with a new output directory. It generates the native root and gateway leaf,
the fixed-width raw RSA files KWTLS reads, and the length-prefixed native
certificate body. The new root needs its own enrollment. Compare validity
with the simulator's clock before running the test.

Use an isolated XP clone with a host-only NIC, guest address
`192.168.128.2/24`, and no default route. The host bridge address in this
recipe is `192.168.128.1`. Put `live_lab.py` beside the extracted directories
and `identity/`. The host-only relay accepts datagrams from the guest address
on UDP 9203, relays them to KWTLS on loopback UDP 9203, and serves the test
page from the loopback WTP/WSP backend on UDP 9201. For enrollment only,
host-only UDP 9201 serves the native CA at `/kwtls-root.wtlscacert`.
Start `python3 live_lab.py blackberry-check --seconds 600` after checking
that the capture filenames are unused. Ctrl+C stops the relay and its KWTLS
child.

In the XP clone, launch `7290.bat` from the installed JDE simulator
directory. The stock Browser's **Go To** accepts the following URL. Paste via
the simulator's **Edit → Paste** from XP Notepad to preserve the gateway
parameters.

```text
http://kwtls.lab.invalid/baseline;WAPGatewayIP=192.168.128.1;WAPGatewayAPN=rim.net.gprs;WAPGatewayPort=9203
```

## Evidence and rerun status

The original capture has SHA-256
`207aa4ab03ce514d5cbc0215157b60607465e37cebc9988a474fe8b58f4e01ac`.
Run `cargo run --locked --offline --bin wtls-inspect -- --timeline <trace>`
with the fixture path to inspect the clear handshake and protected record
boundaries. The 948-byte ClientHello offered an empty session ID and advertised
CA identifier `ef1e63077f314b8f400c5a129f287be44b44c082`. The 427-byte server
flight sent ServerHello, Certificate, and ServerHelloDone in that order.
Offer index 1 selected authenticated RSA (8), DES-CBC (5), and full SHA (3),
with null compression, explicit sequences, and key-refresh value 5.
The received native leaf matched the configured leaf byte for byte, with SHA-256
`4c7e0c68cb14be933c7735eecab02873249c3d69ab0944c50f8d6b7d9d9be9b7`.

KWTLS logged a verified client Finished and sent its protected Finished.
The Browser rendered **KWTLS protected reply** without a certificate prompt,
and the backend matched the protected page acknowledgment to WTP transaction
`1b7c`. The acknowledgment and the page are the client-side evidence of the
completed exchange.

The local `kwtls-blackberry/reruns/` attachment holds
`blackberry-warm-restart.trace` for the already-running simulator and
`blackberry-check.trace` for the relaunched simulator. In each capture the
BlackBerry offered the one-byte cached ID `0x31` (ASCII `1`), and KWTLS sent
that ID in a full certificate flight. KWTLS's log identifies it as a new
assignment. The client returned fatal `handshake_failure`. The live simulator
display showed JVM Error 104 on each attempt. Both runs stopped
before Finished and the protected page. WAP-199 §10.3 uses a matching ID
to signal resumption and calls for a new ID on a cache miss. KWTLS's counter
restarts with each gateway process. The observations are consistent with
the BlackBerry interpreting the ID as a resumption signal. The simulator's
internal cause remains unconfirmed.
[WAP-199 §10.3](https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf#page=49) ·
[KWTLS session source](KWTLS_SOURCE_REFERENCE.md#round-3--lifecycle-and-limits-of-the-evidence)

### Different-ID comparison

Start the same KWTLS binary with the same enrolled CA and leaf. Before the
Browser request, send the original capture's empty-ID ClientHello to KWTLS
on loopback UDP 9203 from a separate socket. The preparation ends when
KWTLS allocates `0x31` and sends the certificate flight. This advances
the process counter before the live request. The probe ends before
ClientKeyExchange and creates no completed session. It stays outside the
BlackBerry capture taken at the host-only relay.

The rerun used the existing lab executable, with SHA-256
`92b4cd9aa37f972a44be20d06293385f9546ee38076519e60cc5a8319fc71e8a`.
The failed-run notes identify the executable by its lab path.

On the November 21 comparison, the relaunched BlackBerry offered cached ID
`0x31` (ASCII `1`). KWTLS selected fresh ID `0x32` (ASCII `2`) and sent
the same native leaf on RSA (8), DES-CBC (5), and full SHA (3). The capture
contains ClientKeyExchange, both ChangeCipherSpec messages, and the protected
Finished record in each direction. KWTLS logged successful verification
of the client Finished. The BlackBerry rendered **KWTLS protected reply**
without a certificate prompt and acknowledged WTP transaction `250b`.
The page and acknowledgment show the client proceeded after the server Finished.

The fixture preserves the ten datagrams through that acknowledgment.
Its SHA-256 is `34b3ad2cbb43b41d78422455c111a9a1a7be76750819267cb632552741d50318`.
This reproduces the full authenticated exchange with a cached ID present
and supports the session-ID collision explanation for the two earlier failures.
[Different-ID wire capture](../fixtures/blackberry-7290-kwtls-distinct-id.trace)

## Live BlackBerry resumption

On November 21, 2026, a fresh KWTLS 1.0.3 lab process served two requests
with the existing enrolled CA. The first request used a full authenticated
handshake. Between requests, the operator closed and relaunched only the
BlackBerry simulator and then requested the same lab URL. The KWTLS
process and the relay's gateway-facing UDP socket stayed up for both
requests. The gateway process was stopped after the second page.

| Trace event | Observation |
| --- | --- |
| 1–4 | The BlackBerry offered a previously cached ID of `0x32`. KWTLS returned `0x31`, sent the configured native leaf, and completed the full RSA / DES-CBC / full SHA exchange. |
| 8–10 | The browser rendered **KWTLS protected reply** and the backend matched protected WTP page acknowledgment `2e87`. |
| 11–12 | The restarted client reoffered `0x31`. KWTLS logged a cache hit and echoed `0x31` in ServerHello with key-exchange index `0` and the same cipher and MAC. The 84-byte flight contains ServerHello, ChangeCipherSpec, and protected Finished. Both hellos used fresh randoms. |
| 13 | The BlackBerry coalesced ChangeCipherSpec, protected Finished, and a protected application record in one 1,056-byte datagram. KWTLS logged successful session establishment. The relay's backend logged WSP Connect transaction `13ac` immediately after receiving the datagram. |
| 16–18 | The browser rendered the page again. The backend matched a second protected page acknowledgment, WTP transaction `13ad`. |

Neither exchange prompted for certificate approval. The abbreviated
exchange omitted Certificate, ServerHelloDone, and ClientKeyExchange.
The encrypted Finished bodies are opaque in the fixture. Gateway
verification of the client Finished and the browser's subsequent protected
traffic and page rendering supply endpoint evidence.

The fixture contains 18 datagrams through the second page acknowledgment.
Its SHA-256 is `e7f574b2eb5557c0d98903b48db27fc3a09415b4117b7f850d624d92a6cc83fc`.
This run establishes that the BlackBerry accepts index `0` with KWTLS on
this DES-CBC exchange. The earlier BlackBerry/Rust run used 3DES-CBC-EDE
and succeeded after retaining the offered index `1`. The difference remains
specific to the observed runs. The ordering of traffic during same-tuple
recovery remains open for KWTLS.
[Full-to-resumed trace](../fixtures/blackberry-7290-kwtls-resumption.trace) ·
[Rust peer evidence](../fixtures/HISTORICAL_PEERS.md#blackberry-abbreviated-handshake)

## Live BlackBerry close scopes

On November 21, 2026, the same instrumented KWTLS 1.0.3 process and
BlackBerry 7290 Browser stayed running for a full handshake and both
refreshes. The close trigger was added to the lab executable because
the standalone program has no close command and its existing alert
sender serializes cleartext. The trigger creates each protected alert
with the existing KWTLS record machinery and dispatches the existing
server termination event. The lab's `libwtls.a`, session lookup, and
cache behavior were unchanged.

| Trace events | Alert and next handshake | Protected page |
| --- | --- | --- |
| 1–10 | The full RSA / DES-CBC / full SHA exchange issued `0x32` and sent the configured native leaf. | Browser rendered the page and the backend matched WTP acknowledgment `2b98`. |
| 11–20 | The gateway sent protected critical `connection_close_notify` (level 2, description 0). On refresh, the BlackBerry offered `0x32`. KWTLS echoed it with key-exchange index `0` and completed the abbreviated handshake. | Page rendered and acknowledgment `1d55` arrived. |
| 22–30 | The gateway sent protected fatal `session_close_notify` (level 3, description 1). On refresh, the BlackBerry again offered `0x32`. KWTLS echoed it with index `0` and completed another abbreviated handshake. | Page rendered and acknowledgment `382f` arrived. |

KWTLS logged successful establishment after both reconnects. Each
abbreviated server flight carried ChangeCipherSpec and protected Finished
after ServerHello. Each client returned its ChangeCipherSpec and protected
Finished. No certificate prompt appeared during the three page requests.
The endpoint log identifies the two encrypted alert descriptions. The
capture shows no client close alert before either reconnect.

WAP-199 §10.2.1 requires session invalidation on Session close. The observed
KWTLS path kept the session eligible and reused it, so this comparison did
not reach a full handshake after Session close. The earlier BlackBerry run
against the Rust gateway also saw a reoffered ID after Session close. That
gateway invalidated it and completed a full handshake.
[WAP-199 §10.2.1](https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf#page=45) ·
[Rust close comparison](../fixtures/HISTORICAL_PEERS.md#blackberry-connection-and-session-close)

The 30-datagram fixture ends at the third page acknowledgment. SHA-256
`8bc5ea1398f54e64748c503634ba7e156d3ff8dfac4e0e9805e388c133eae7f3`.
The local `kwtls-blackberry/close-scopes/` attachment holds the two
lab patches and a sanitized endpoint receipt. The executable SHA-256
is `549367aed579455bbab3076bc8de5a8b5a71de0e4fbfe2fef6781c4d901325b8`.
[Close-scope wire capture](../fixtures/blackberry-7290-kwtls-close-scopes.trace)

### Session cache invalidation control

A follow-up run reused the lab close sender, library, and enrolled CA.
The private Session-close control added one operation after the existing
termination event. It unlinked the current session's matching cache entry.
The Connection-close control checked that its entry remained eligible.
The relay, gateway process, and Browser stayed running for both refreshes.

| Trace events | What the BlackBerry and gateway did | Protected page acknowledgment |
| --- | --- | --- |
| 1–10 | The initial full RSA / DES-CBC / full SHA handshake replaced the old offered ID `0x32` with `0x31`. | WTP `0019` |
| 11–20 | The critical Connection-close alert left `0x31` cached. On refresh, the Browser reoffered `0x31`, the gateway echoed it, and both peers completed an abbreviated handshake. | WTP `22d4` |
| 21–32 | The fatal Session-close alert was followed by removal of `0x31`. The Browser reoffered `0x31`, so the cache miss led to a new `0x32`, the same native certificate, RSA key exchange, and both full-handshake Finished messages. | WTP `3353` |

The Browser rendered the protected page after all three requests without
prompting for the certificate. The gateway verified the client Finished
each time. The close descriptions and the cache outcomes come from the
gateway log. The capture shows the next handshake branches and protected
record boundaries.

The baseline run and the control observed the same client decision after
Session close. The BlackBerry offered the prior ID. The gateway's cache
policy determined whether the two peers resumed or completed a full
handshake. Cache invalidation in this run came from the lab-only control.

The fixture contains 32 datagrams through the final page acknowledgment.
SHA-256 `2a1291268a61526b2f512cf535bf5475e358f8f2992d6cb8a87903051e5ff265`.
The local `kwtls-blackberry/close-cache-control/` attachment holds the
incremental lab patch and sanitized endpoint receipt. The patch applies
after the earlier close-scope patch. Its SHA-256 is
`19f263621c99d5b2ab807e0c17e06bf2d18cb76a167ce3b62195ccc3eb016cf6`.
[Cache-control wire capture](../fixtures/blackberry-7290-kwtls-cache-control.trace)

## Live handshake datagram loss

DQ-04 used two separate KWTLS 1.0.3 processes with the same enrolled CA and
native leaf as the authenticated baseline. This was the baseline executable
(SHA-256 `92b4cd9aa37f972a44be20d06293385f9546ee38076519e60cc5a8319fc71e8a`)
on RSA (8), DES-CBC (5), and full SHA (3). The host-only relay withheld
one server UDP datagram per run, identified by its explicit record headers.
It logged the drop and preserved its bytes separately. All other datagrams
were forwarded as received. Retries below are timed from the original
client datagram using the relay's monotonic clock.

### First server flight

The relay dropped the 427-byte ServerHello, Certificate, and ServerHelloDone
datagram at event 2. The BlackBerry retransmitted all 949 bytes of its
ClientHello unchanged after 5.618 seconds. KWTLS generated a new 427-byte
certificate flight with the same leaf and a new session ID. The client
offered `0x32` both times, and the gateway issued `0x33` in the withheld
flight and `0x34` on retry. Both full-handshake Finished records followed.
KWTLS logged establishment, the browser rendered **KWTLS protected reply**
without a certificate prompt, and the backend matched protected WTP page
acknowledgment `0680`.

An initial attempt was inconclusive because the retry response used the same
ID the BlackBerry had offered. The recorded run advanced the fresh gateway's
ID counter through two unfinished loopback handshakes before the browser
request. These preparations used separate sockets, ended at the certificate
flight, and stayed outside the live trace. See the
[different-ID comparison](#different-id-comparison).

The trace ends at the 12th event, including the single drop marker and the
protected page acknowledgment. SHA-256
`5c1dd7b17d75eb3d424ea87a83a3e270b3416d239ede59fb49f8460d7ec51f42`.
[First-flight loss capture](../fixtures/blackberry-7290-kwtls-drop-first.trace)

### Final server flight

In a fresh process, the BlackBerry offered `0x34` and KWTLS issued
`0x31` with the same native leaf. KWTLS accepted the client Finished and
logged establishment. The relay withheld the 51-byte server
ChangeCipherSpec and protected Finished at event 4. The BlackBerry repeated
all 189 bytes of its ClientKeyExchange, ChangeCipherSpec, and protected
Finished datagram five times. The retries came 6.376, 12.551, 18.804,
25.061, and 31.312 seconds after the original.

The relay observed no server reply to any of those retries. At 37.580 seconds
the client sent a fatal `handshake_failure`. The browser reported a secure
negotiation failure and the backend received no protected page request or
acknowledgment. An earlier setup attempt ended before the test handshake
began. For the recorded run, the simulator was already back at its home
screen when the fresh gateway started.

The trace ends at the 10th event, including the single drop marker and the
client alert. SHA-256
`ed2770ef02c8d8aa95102368a2921a9fbf117e0f4c4c57c7280c0366ff48e358`.
[Final-flight loss capture](../fixtures/blackberry-7290-kwtls-drop-final.trace)

These are peer observations for this KWTLS build and DES-CBC suite. The
Rust deterministic final-flight test uses the supported 3DES-CBC-EDE
suite and verifies a byte-identical server replay and a protected echo.
The Rust and historical results give us separate evidence for what the
browser attempts, what the gateway does with the retry, and whether the
application exchange completes.
[Rust retry evidence](WAP_199_EVIDENCE_MATRIX.md#g2-full-handshake-final-flight-retry)

The local `kwtls-blackberry/handshake-loss/` attachment contains the
relay patch, the two withheld payloads, and the endpoint receipt.

## Live key refresh on one connection

DQ-05 used the November 22, 2026 authenticated BlackBerry 7290 simulator
and KWTLS 1.0.3 baseline build. The Browser used its enrolled lab CA
without a certificate prompt. The full handshake replaced offered ID
`0x34` with `0x33` and selected RSA (8), DES-CBC (5), full SHA (3),
null compression, explicit sequences, and refresh value 5. KWTLS
verified the client Finished. Two unfinished loopback hellos advanced
the fresh gateway counter before the measured run, as in the
[different-ID comparison](#different-id-comparison).

The Browser loaded the lab page and refreshed it on that connection.
The relay recorded one guest UDP source and one gateway-facing socket,
with one ClientHello, one ServerHello, and one pair of cipher changes
through the last acknowledgment. KWTLS and the relay stayed running.
The relay forwarded the datagrams and timestamped the backend events on
the same monotonic clock. For each page, the client request, server
response, and client acknowledgment appeared in that order. The backend
matched the WTP acknowledgment against the outstanding response.

| Protected sequence | Client → KWTLS | KWTLS → client |
| --- | --- | --- |
| 7 | GET `388b` (event 14), acknowledgment at event 16 | Page `388d` (event 24), acknowledgment at event 25 |
| 8 | Acknowledgment `388b` (event 16) | Page `388d` (event 27), acknowledgment at event 28 |
| 9 | GET `388c` (event 17), acknowledgment at event 19 | Page `388d` (event 30), acknowledgment at event 31 |
| 31 | Acknowledgment `3892` (event 50) | Page `38a2` (event 97), acknowledgment at event 98 |
| 32 | GET `3893` (event 51), acknowledgment at event 53 | Page `38a3` (event 100), acknowledgment at event 101 |
| 33 | Acknowledgment `3893` (event 53) | Page `38a4` (event 103), acknowledgment at event 104 |

Server sequences 7–9 carried separate responses to repeated requests
with TID `388d`. Each request, response, and matched acknowledgment
completed before the next request. These are three acknowledged
responses for one TID. The final fixture contains 33 acknowledged page
exchanges across 29 distinct TIDs. The Browser displayed **KWTLS protected
reply** during the run. For the reply at server sequence 34, the backend
matched the last acknowledgment, TID `38a5`, on client sequence 69
(event 107).

The fixture ends at that acknowledgment, before a later unrelated WTP
datagram. SHA-256
`a59eeabe1bcb2bb2fa1421e51a4f33c74015b12463842dca971c69eb27aa695d`.
The local `kwtls-blackberry/key-refresh/` attachment contains the relay
logging patch, sanitized backend receipt, and event-to-transaction map.
[Wire capture](../fixtures/blackberry-7290-kwtls-key-refresh.trace)

Protected application traffic succeeded through sequence 8 and through
the negotiated refresh boundary at sequence 32 in each direction.
The acknowledgments establish application delivery for this peer pair.
The capture exposes record sequence numbers and keeps the protected
payloads opaque. The observed behavior supports retaining the existing refresh policy.
The Rust 3DES-CBC-EDE tests remain separate evidence for ciphertext
expectations, loss, and reordering across refresh.
[WAP-199 §9.1](https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf#page=36) ·
[Rust key-refresh evidence](WAP_199_EVIDENCE_MATRIX.md#protocol-and-selected-options)
