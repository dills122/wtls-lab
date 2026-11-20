# Supervised WTLS workflow

The Codex chat **Set up Ruflo workflows** proved a supervised claim, work, verify, and release cycle in wap-labs. Its runner and setup are documented in [wap-labs PR #671](https://github.com/dills122/wap-labs/pull/671). The [first live clause slice](https://github.com/dills122/wap-labs/pull/672) shows what implementation, independent review, and closing evidence look like.

For each WTLS slice, prepare a packet with the objective, WAP edition and specific clauses, allowed paths, exact Cargo checks, a deadline, and any required peer evidence. Keep one active writer and pin the baseline. Record any spec interpretation separately from observed client behavior. A reviewer checks the exact candidate against the packet and reruns the gates. Record the test counts and results, reviewer outcome, and links to applicable captures or logs. Release the claim after review and any required maintainer run. A stopped or failed run keeps its checkpoint and evidence together.

## WinWAP UDP 9202 packet

- **Objective** — Complete a direct full handshake and protected connectionless WSP request/reply with WinWAP 4.2.0.290. Use an explicit server-only compatibility profile and an isolated XP guest.
- **Sources** — WAP-199 (18 February 2000) §§9.2.3, 10.4, 10.5.1, 10.5.3, 10.5.7, 10.5.9, 11 and Appendix A. Use the existing WinWAP offers and Kannel traces as independent compatibility evidence. WAP-203 governs connectionless WSP.
- **Ownership** — WTLS handshake, wire adapter and codec, the loopback WSP test binary, their tests and documentation.
- **Checks** — `cargo test --locked --offline`, `cargo clippy --locked --offline --all-targets -- -D warnings`, and `cargo fmt --all --check`. Verify suite selection, exact duplicate-flight handling, and the existing authenticated profile.
- **Peer evidence** — Capture UDP 9202 between the guest and the Rust endpoint. Correlate the protected WSP request and reply with the endpoint log and a WinWAP screen when available. Keep this maintainer-run gate distinct from deterministic Cargo results.

## Run the WTLS loop

The local runner ports the supervisor from wap-labs commit
`0b42eaac49dc473e2f58a4d3c0c1bdbc6146baba`. It uses the WTLS evidence manifest
and the focused packet checks, followed by locked offline Cargo tests, Clippy,
and formatting. The supervisor requires one clean feature worktree and holds
a repository-wide claim until verification and release.

Use Python 3.11+, Node 26, an authenticated local Codex CLI, and the pinned Ruflo
3.77.1 release. An existing installation from the wap-labs pilot can be reused
read-only by setting `WTLS_RUFLO_RELEASE` to its release directory. Alternatively,
use the wap-labs bootstrap and package lock from the pinned revision and set
`WTLS_RUFLO_RELEASE` to that installation. The runner verifies the release's
lockfile and installation marker. It invokes Ruflo through the pinned shim.
Keep packets local and trusted. Their checks are executable argument arrays.

```sh
git worktree add -b codex/wtls-next /path/to/wtls-next
python3 -B scripts/ruflo/compliance_loop.py claim /path/to/open-wtls-packet.json --worktree /path/to/wtls-next
python3 -B scripts/ruflo/compliance_loop.py work
python3 -B scripts/ruflo/compliance_loop.py status
# Inspect and commit the scoped candidate in its linked worktree.
python3 -B scripts/ruflo/compliance_loop.py verify
python3 -B scripts/ruflo/compliance_loop.py release
```

Verification reruns the packet checks and all Cargo gates, then launches a fresh
read-only Ruflo reviewer against the exact candidate commit. The claim, context,
checkpoint, logs and receipt live under the repository's Git common directory at
`ruflo-wtls-loop/`. Use `resume` for a scoped interrupted checkpoint or a
reviewed candidate requiring changes. The supervisor checks the branch and file
digests before resuming. Release the verified claim after gathering any required
independent peer evidence, then reconcile the evidence manifest as the maintainer.

Use `python3 -B -m unittest discover -s scripts/ruflo -p '*_test.py'` to test
the supervisor without starting Ruflo or contacting Codex.

## Execution index

| Work item | Scope | Verification |
| --- | --- | --- |
| WTLS-201 (verified) | Fall back to a new full legacy handshake when an offered session cannot be resumed | Scoped legacy tests, all Cargo gates, exact-commit review. See [the evidence manifest](WTLS_EVIDENCE.json) and [the completed packet](../scripts/ruflo/packets/WTLS-201.json). |
| WTLS-202 (verified) | Observe WinWAP after a protected connection close | Live XP capture with two successful buffered exchanges and empty ClientHello IDs. The [evidence manifest](WTLS_EVIDENCE.json) records the scoped result. |
| WTLS-203 (verified at ClientHello) | Screen and run an independent historical peer | The BlackBerry 7290 simulator offered authenticated RSA and the lab's cipher/MAC pair on UDP 9203. The fixed profile rejected the hello before key selection. See [the capture provenance](../fixtures/HISTORICAL_PEERS.md). |
| WTLS-204 (verified) | Negotiate an authenticated offer and observe a real cached session ID | Independent exact-commit review, 57 Cargo tests, two live BlackBerry full handshakes with explicit leaf acceptance, protected WSP replies, and a matching cached offer followed by full-handshake fallback. See [the live evidence](../fixtures/HISTORICAL_PEERS.md#blackberry-authenticated-exchange-and-cached-id). |
| WTLS-205 (verified) | Authenticated wire resumption and bounded cache | Deterministic wire and cache tests. Fresh Ruflo review verified the duplicate-Finished retry correction. See [the design](WIRE_SESSION_RESUMPTION.md). |
| WTLS-206 (verified) | Resumption with the BlackBerry 7290 | The live peer echoed the cached session ID, verified the abbreviated handshake, and acknowledged protected WSP after reconnect. See [the capture notes](../fixtures/HISTORICAL_PEERS.md#blackberry-abbreviated-handshake). |
