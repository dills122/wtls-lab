# KWTLS BlackBerry baseline

The BlackBerry 7290 completed a full authenticated WTLS handshake against KWTLS
1.0.3 on November 21, 2026, first with an empty session ID and again when KWTLS
returned a different ID from the one the Browser offered. Two fresh-process
attempts that reused the offered ID stopped before Finished.
[Original wire capture](../fixtures/blackberry-7290-kwtls-full.trace) ·
[Different-ID comparison](#different-id-comparison) ·
[Live resumption](#live-blackberry-resumption)

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
specific to the observed runs. The two close scopes and the ordering of
traffic during same-tuple recovery remain open for KWTLS.
[Full-to-resumed trace](../fixtures/blackberry-7290-kwtls-resumption.trace) ·
[Rust peer evidence](../fixtures/HISTORICAL_PEERS.md#blackberry-abbreviated-handshake)
