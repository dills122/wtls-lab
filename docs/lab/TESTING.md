# Run and verify WTLS tests

[Handbook](../README.md) · [XP setup](XP_SETUP.md) · [Tooling](TOOLS.md)

## Run the host checks

These are the normal starting gates for a fresh clone. Use a recent stable Rust toolchain, OpenSSL 3.2+ development libraries, and pkg-config.

```sh
cargo test --locked --workspace
cargo clippy --locked --offline --all-targets -- -D warnings
cargo fmt --all --check
python3 -B -m unittest discover -s scripts/ruflo -p '*_test.py'
```

The first Cargo command fills the dependency cache. Add `--offline` to the test command once the cache is populated. The Python command checks the Ruflo runner locally without launching a reviewer.

| What you changed | Start with |
| --- | --- |
| Record framing | `cargo test --locked --test record_codec` |
| Trace output | `cargo test --locked --test inspector` |
| Live UDP abstraction | `cargo test --locked --test udp_adapter` |
| Final flight with application data | `cargo test --locked dq08_` |

## Inspect an existing exchange

```sh
cargo run --locked --bin wtls-inspect -- --timeline fixtures/blackberry-7290-kwtls-drop-final.trace
```

Read the event direction and record boundaries first. In this capture, the length-only relay drop is event 4, and the five client commit repeats point to event 3. The endpoint and relay observations establish where the handshake stopped. [Timeline format](../REFERENCE.md#handshake-timeline) · [Final-flight loss evidence](../KWTLS_LAB_BASELINE.md#final-server-flight)

## Live BlackBerry and KWTLS

1. Prepare the [isolated XP guest](XP_SETUP.md), enrolled lab CA, and the pinned [KWTLS build and relay](../KWTLS_LAB_BASELINE.md#build-and-launch). Choose a new capture name before starting the run. Run one gateway on the lab address and port for the selected test.
2. Open the lab URL in the stock 7290 Browser. Confirm an authenticated full handshake, the protected page, and a matched WTP acknowledgment. Record the exact negotiated suite and any prompt.
3. Change one condition per run. The [loss runs](../KWTLS_LAB_BASELINE.md#live-handshake-datagram-loss) withheld one server datagram in each case. The [refresh run](../KWTLS_LAB_BASELINE.md#live-key-refresh-on-one-connection) kept one connection and matched page transactions around record sequences 8 and 32 in both directions.
4. Stop the host processes and shut down the XP guest after preserving the evidence.

For the Rust gateway full → resumed → full check, follow the [close commands and expected outcomes](../REFERENCE.md#reusable-udp-adapter-and-blackberry-lab). Use the [provisioned BlackBerry receipt](../../fixtures/HISTORICAL_PEERS.md#blackberry-provisioned-trust-reconnect-lifecycle) as the strict-trust comparison. The standalone [WinWAP lane](../REFERENCE.md#direct-winwap-compatibility-test) uses its own server profile and port.

## What counts as evidence

| Claim | Keep with the result |
| --- | --- |
| A datagram arrived or was withheld | Capture point, direction, timestamp, disposition, and bytes or a documented length-only marker |
| A retry was byte-identical | Original event, retry event, direction, and elapsed time from the capture |
| A handshake was full or resumed | Negotiated suite, when the session ID was issued or reoffered, flight shape, and endpoint verification of protected Finished |
| Protected application data worked | Browser page or echo and the matching endpoint delivery or WTP acknowledgment |
| A result is reproducible | Code or build revision, peer and tool versions, lab topology, test inputs, and a capture path or digest |

Use the [peer notes](../../fixtures/HISTORICAL_PEERS.md), [evidence matrix](../WAP_199_EVIDENCE_MATRIX.md), and [machine-readable ledger](../WTLS_EVIDENCE.json) to check which evidence already exists. A deterministic result and a live historical-peer observation support different claims.

## For agents and resumed sessions

- Start with the current [discovery queue](../WTLS_DISCOVERY_QUEUE.md) and verify the current branch and checkpoint. The [November 22 handoff](../work/handoffs/2026-11-22-wtls.md) records the DQ-08 restart point.
- Pin the WAP edition and corrected clauses, commit baseline, allowed files, focused commands, and live acceptance criteria before changing behavior.
- Use the [supervised workflow](../SUPERVISED_WORKFLOW.md#run-the-wtls-loop) for the Ruflo work and read-only review. Keep the operator-run XP check distinct from Cargo gates.
- Record the tested commit, observed outcome, and remaining gap with the capture or test reference.
