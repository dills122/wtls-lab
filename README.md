# wtls-lab

A standalone Rust implementation of **WAP-199 Wireless Transport Layer Security**. Build and inspect WTLS exchanges, then compare them with period WAP clients and gateways in an isolated lab.

[Project site](https://dills122.github.io/wtls-lab/) · [Handbook](docs/README.md) · [Support and evidence](docs/WAP_199_EVIDENCE_MATRIX.md)

## Try it locally

Use a recent stable Rust toolchain, OpenSSL 3.2+ development libraries, and pkg-config.

```sh
cargo test --locked --workspace
cargo run --locked --bin wtls-inspect -- --timeline fixtures/blackberry-7290-kwtls-key-refresh.trace
```

The tests and capture inspector run on the host. A Windows XP guest is needed for live historical-client testing.

## Find what you need

| Task | Start here |
| --- | --- |
| Set up the isolated Windows XP guest | [XP lab setup](docs/lab/XP_SETUP.md) |
| Choose a modern tool or a period peer | [Tooling and peer matrix](docs/lab/TOOLS.md) |
| Run a test, capture traffic, or continue a slice | [Testing and evidence](docs/lab/TESTING.md) |
| Integrate the Rust library or inspect a trace | [Protocol and tooling reference](docs/REFERENCE.md) |
| See the support promise and open work | [Discovery queue](docs/WTLS_DISCOVERY_QUEUE.md) |

**Pre-alpha.** The authenticated RSA / 3DES-CBC-EDE / full SHA UDP profile covers full and resumed handshakes, protected records, key refresh, and close handling. The BlackBerry 7290 has verified the Rust gateway live. Independent gateway evidence for the Rust client on that exact suite remains open.

Part of [WAP Labs](https://github.com/dills122/wap-labs). The library and lab tools build independently of Waves.
