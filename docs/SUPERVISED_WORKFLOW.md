# Supervised WTLS workflow

The Codex chat **Set up Ruflo workflows** proved a supervised claim, work, verify, and release cycle in wap-labs. Its runner and setup are documented in [wap-labs PR #671](https://github.com/dills122/wap-labs/pull/671). The [first live clause slice](https://github.com/dills122/wap-labs/pull/672) shows what implementation, independent review, and closing evidence look like.

For each WTLS slice, prepare a packet with the objective, WAP edition and specific clauses, allowed paths, exact Cargo checks, a deadline, and any required peer evidence. Keep one active writer and pin the baseline. Record any spec interpretation separately from observed client behavior. A reviewer checks the exact candidate against the packet and reruns the gates. Record the test counts and results, reviewer outcome, and links to applicable captures or logs. Release the claim after review and any required maintainer run. A stopped or failed run keeps its checkpoint and evidence together.

## WinWAP UDP 9202 packet

- **Objective** — Complete a direct full handshake and protected connectionless WSP request/reply with WinWAP 4.2.0.290. Use an explicit server-only compatibility profile and an isolated XP guest.
- **Sources** — WAP-199 (18 February 2000) §§9.2.3, 10.4, 10.5.1, 10.5.3, 10.5.7, 10.5.9, 11 and Appendix A. Use the existing WinWAP offers and Kannel traces as independent compatibility evidence. WAP-203 governs connectionless WSP.
- **Ownership** — WTLS handshake, wire adapter and codec, the loopback WSP test binary, their tests and documentation.
- **Checks** — `cargo test --locked --offline`, `cargo clippy --locked --offline --all-targets -- -D warnings`, and `cargo fmt --all --check`. Verify suite selection, exact duplicate-flight handling, and the existing authenticated profile.
- **Peer evidence** — Capture UDP 9202 between the guest and the Rust endpoint. Correlate the protected WSP request and reply with the endpoint log and a WinWAP screen when available. Keep this maintainer-run gate distinct from deterministic Cargo results.

## Porting the runner

The current workspace is a standalone directory. This slice uses a scoped scratch copy, Cargo gates, and a separate maintainer VM run. To run the same automation, use a clean Git baseline and a linked worktree in the WTLS repository. Preserve the pilot's pinned bootstrap, narrow tool surface, bounded writer, checkpoint guard, and independent read-only review. Replace the WML-specific clause-pack lookup and full WAP gate with a WTLS evidence manifest and the packet's locked Cargo checks. Keep the XP run a separate gate with recorded artifacts. The resulting WTLS runner should operate from its own working directory.

Follow the runner guide's `claim <packet> --worktree <path>`, `work`, `verify`, and `release` sequence once those WTLS hooks are in place. The upstream runner is tied to wap-labs and expects its WML ledger and graph.
