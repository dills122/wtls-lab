# WTLS project handbook

wtls-lab implements WAP-199 and checks its behavior against real software from the era. The project has a reusable Rust library, a UDP adapter, a capture inspector, and small test gateways. The host tests give us repeatable protocol checks. The XP lab tells us what historical peers actually do.

## Start with a task

| I want to… | Guide | What it gives you |
| --- | --- | --- |
| Inspect a saved exchange | [Protocol and tooling reference](REFERENCE.md#handshake-timeline) | Trace commands, record boundaries, and retry annotations |
| Build or reuse a Windows XP test guest | [XP lab setup](lab/XP_SETUP.md) | Host-only networking, the 7290 Browser, and shutdown |
| Pick a client, gateway, or test tool | [Tooling and peer matrix](lab/TOOLS.md) | Versions, roles, suites, and observed results |
| Run the tests or verify a live peer | [Testing and evidence](lab/TESTING.md) | Commands, acceptance criteria, and the Ruflo workflow |
| Find a gap or propose a slice | [Discovery queue](WTLS_DISCOVERY_QUEUE.md) | Open questions and evidence required to close them |

## How it fits together

| Surface | Responsibility |
| --- | --- |
| Protocol library | Record framing, handshake state, traffic protection, trust, and session policy |
| UDP adapter | Whole datagrams, peer address and port, deadlines, and transport events |
| Inspector | Clear negotiation, protected record boundaries, timing, and byte-identical repeats |
| Lab tools | Endpoint setup, test pages, WAP application responses, and test evidence |

The [product boundaries](WTLS_PRODUCT_BOUNDARIES.md) show why a wire capture, an endpoint log, and a protected page acknowledgment answer different questions.

## Project status

The initial support promise is one server-authenticated WAP-199 UDP profile using RSA, a native WTLS certificate, 3DES-CBC-EDE, full SHA, explicit sequence numbers, and null compression. WinWAP has a separately selected server compatibility profile. The authenticated KWTLS lab uses DES-CBC and is a separate historical comparison.

Use the [support plan](WAP_199_PROVISIONED_TRUST_PLAN.md#support-boundary) for scope, the [evidence matrix](WAP_199_EVIDENCE_MATRIX.md) for verified requirements, and the [peer notes](../fixtures/HISTORICAL_PEERS.md) for provenance. The [WAP 1.2.1 release index](https://www.wapforum.org/what/technical_1_2_1.htm) lists WAP-199 and its correction notes.

## Project site

The GitHub Pages overview is sourced from [the static site directory](../site/). Keep detailed recipes in the handbook. Preview the page from the repository root with:

```sh
python3 -m http.server --bind 127.0.0.1 --directory site 8765
```

After a site update reaches `main`, publish just that directory to the configured Pages branch:

```sh
pages_commit=$(git subtree split --prefix=site main)
git push origin "$pages_commit:refs/heads/gh-pages"
```
