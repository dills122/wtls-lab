# KWTLS BlackBerry baseline

The BlackBerry 7290 completed a full authenticated WTLS handshake against KWTLS
1.0.3 on November 21, 2026. Two later attempts against newly started gateways
ended before Finished. Both returned the same session ID the client had offered
from its cache. Reproducing the protected exchange from the existing simulator
state remains open. [Successful wire capture](../fixtures/blackberry-7290-kwtls-full.trace)

## Build and launch

| Input | SHA-256 |
| --- | --- |
| [KWTLS 1.0.3 source](https://www.kannel.org/download/wtls/kwtls-1.0.3.tar.gz) | `7c727beabc0ea55518790a995a83ad411843097db0c90ebc9eaf797a3afedd65` |
| [OpenSSL 1.0.2u source](https://www.openssl.org/source/old/1.0.2/openssl-1.0.2u.tar.gz) | `ecd0c6ffb493dd06707d38b14bb4d8c2288bb7033735606569d8f90f89669d16` |
| [RIM JDE 4.0 installer](https://archive.org/details/blackberry-jde) | `10f73ec16376e617cdf74bbe79c6332e38c64e8338751acf704412a96e19afb0` |

The local reproduction bundle accompanying this run holds the portability patch,
`live_lab.py`, and the separate certificate generator. Keep these with the
discovery workspace. The gateway source, installer, private identity, and raw
KWTLS logs stay local. The capture in Git contains only WTLS datagrams from the
earlier successful run.

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

On each rerun the BlackBerry offered the one-byte cached ID `0x31` (ASCII
`1`), including after a simulator process restart. KWTLS logged a new session
assignment of `1` and sent a full certificate flight. The client returned
fatal `handshake_failure` and displayed JVM Error 104. Both runs stopped
before Finished and the protected page. WAP-199 §10.3 uses a matching ID
to signal resumption and calls for a new ID on a cache miss. KWTLS's counter
restarts with each gateway process. The observations are consistent with
the BlackBerry interpreting the ID as a resumption signal. The simulator's
internal cause remains unconfirmed. A successful comparison with a different
returned ID or an empty client ID is still needed. Preserve the enrolled CA
for that comparison.
[WAP-199 §10.3](https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf#page=49) ·
[KWTLS session source](KWTLS_SOURCE_REFERENCE.md#round-3--lifecycle-and-limits-of-the-evidence)
