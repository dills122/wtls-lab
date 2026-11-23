# Tooling and historical peers

[Handbook](../README.md) · [XP setup](XP_SETUP.md) · [Testing](TESTING.md)

## Modern tools

| Tool | Use it for |
| --- | --- |
| Stable Rust, Cargo, OpenSSL 3.2+ | Build the native library and binaries. Run deterministic tests and the protected echo on the host. |
| `wtls-inspect` | Read one datagram or a timestamped timeline. Inspect framing, negotiation, direction, sequence numbers, and byte-identical retries. Protected record bodies remain opaque. |
| `wtls-udp-lab`, `wtls-winwap-lab` | Run the Rust reference gateways for the BlackBerry and WinWAP lanes. Keep the selected profiles explicit. |
| UTM and QEMU | Run the isolated XP guest. The simulator's GUI is available for operating the period Browser and confirming page rendering. |
| Host relay and WTP/WSP backend | Forward whole datagrams, record direction and time, and match the test page's transaction acknowledgment. Use the relay only while a live run is in progress. |
| Ruflo and the local Codex CLI | Run a scoped implementation or research slice with an independent review. The repository pins the Ruflo workflow and records reviewed evidence. |

[Inspector and lab binary reference](../REFERENCE.md) · [Pinned Ruflo workflow](../SUPERVISED_WORKFLOW.md#run-the-wtls-loop)

## Period tools and what they proved

| Tool and version | Role | Verified use |
| --- | --- | --- |
| BlackBerry 7290 from RIM JDE 4.0 | Historical WTLS client in Windows XP | Authenticated full and abbreviated exchanges against the Rust gateway, provisioned CA trust, and protected WAP pages. [Peer evidence](../../fixtures/HISTORICAL_PEERS.md#blackberry-provisioned-trust-reconnect-lifecycle) |
| KWTLS 1.0.3 with OpenSSL 1.0.2u | Historical gateway built on the host | RSA / DES-CBC / full SHA against the BlackBerry. Full exchange, resumption, close scopes, handshake-loss comparison, and protected pages across a key refresh. Read the notes on the lab-only close and cache controls before comparing outcomes. [KWTLS baseline](../KWTLS_LAB_BASELINE.md) |
| WinWAP 4.2.0.290 | Historical WTLS client in Windows XP | Secure connectionless WSP in the explicit anonymous RSA / DES-CBC server mode. The close probe observed an empty client session ID on both requests. [WinWAP reference](../REFERENCE.md#direct-winwap-compatibility-test) |
| WTLS-enabled Kannel 1.4.5 | Historical gateway comparison | Saved WinWAP negotiation, alert, and retry traces. [Trace reference](../REFERENCE.md#handshake-timeline) |
| NowWAP trial and Openwave candidates | Candidates for additional coverage | The NowWAP trial run lacked a working secure listener. Openwave setup stopped before wire verification. [Discovery notes](../WTLS_DISCOVERY_QUEUE.md#start-here) · [Candidate screening](../../fixtures/HISTORICAL_PEERS.md#candidate-ranking) |

The supported Rust authenticated suite uses **3DES-CBC-EDE**. The authenticated KWTLS comparison uses **DES-CBC**. Track peer roles and negotiated suites on every result. Independent gateway verification for the Rust client on the exact supported suite remains open. [Support boundary](../WAP_199_PROVISIONED_TRUST_PLAN.md#support-boundary)

## Where the inputs live

- **In the repository** · Rust code, inspector, demo gateways, test code, captured hex and timelines, protocol notes, and Ruflo runner.
- **Supplied separately** · Windows installation media and vendor installers. The [KWTLS recipe](../KWTLS_LAB_BASELINE.md#build-and-launch) lists archived sources and checksums. Its local reproduction bundle contains the portability patch, relay/backend, and identity generator. A fresh clone needs that bundle for an exact KWTLS rerun.
- **Keep local** · Generated private identities, raw endpoint logs, guest disk images, and VM state. Share the reviewed protocol trace and sanitized receipt for a reproducible result.
