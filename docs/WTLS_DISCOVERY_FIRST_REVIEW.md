# WTLS certificate selection and gateway review

## DQ-02 · Certificate selection

The CA list in ClientHello tells a gateway which issuers it may use for its
certificate. It is distinct from the key-exchange offer list. Under WAP-199
correction _104, a certificate sent after a nonempty CA list must come from a
listed issuer. If the client offers authentication and leaves the list empty,
the gateway may send its configured certificate. Client verification of that
leaf still applies. Correction _105 defines the RSA authority ID from the
raw unsigned modulus. [WAP Forum WAP 1.2.1 index](https://www.wapforum.org/what/technical_1_2_1.htm)

| Offer | Verified on the Rust profile | Independent observation |
| --- | --- | --- |
| Matching CA | TRUST-02 accepted the matching issuer even after an unrelated entry, checked both Finished messages, and delivered a protected echo. | BlackBerry → KWTLS selected the first RSA key-exchange offer and sent the exact configured native leaf between ServerHello and ServerHelloDone. The enrolled CA appeared as entry 29. The upstream source selects the stored leaf by RSA choice, so successful client trust does not establish issuer-aware selection by KWTLS. |
| Nonempty list with no match | TRUST-03 returned only fatal `handshake_failure` for an unrelated CA, a leaf ID, or the right ID only in the key-exchange vector. No attempt became resumable. | Live WTLS-211 observed the BlackBerry's unmatched offer rejected by the **Rust gateway**. KWTLS comparison remains open. |
| Empty list with authenticated offer | TRUST-04 allowed the leaf to be sent and verified it against independently provisioned trust before the full exchange completed. | Historical peer comparison remains open. |

All 13 tests in `cargo test --locked --offline --test provisioned_trust` passed
at `7c3514f`. The matching capture adds an external first-flight example.
Keep issuer-aware selection and independent leaf verification in the Rust
profile. A separate KWTLS comparison for empty and unmatched lists needs a
client that controls those offers while exercising the historical suite.
[Rust trust plan](WAP_199_PROVISIONED_TRUST_PLAN.md#deterministic-release-gate) ·
[WTLS-211 live control](../fixtures/HISTORICAL_PEERS.md#blackberry-native-ca-enrollment) ·
[KWTLS source comparison](KWTLS_SOURCE_REFERENCE.md#round-2--the-authenticated-full-exchange)

## DQ-03 · Independent gateway

The search did not find a self-serve gateway verified to select authenticated
RSA (8), 3DES-CBC-EDE (6), and full SHA (3) with a native RSA leaf, null
compression, and explicit UDP sequence numbers. The independent client-side
interop gate stays open.

| Candidate | Result |
| --- | --- |
| KWTLS 1.0.3 | Runnable historical control for authenticated DES-CBC. Its normal selector covers DES-CBC and RC5 variants. [Source comparison](KWTLS_SOURCE_REFERENCE.md#round-3--lifecycle-and-limits-of-the-evidence) |
| Kannel / Alligata | Kannel documents an RSA-anonymous setup. Its Alligata manual describes Class 2 generally, and the bounded search found no runnable Class 2 build with the required suite. [Kannel user guide](https://kannel.org/download/kannel-userguide-snapshot/userguide.pdf) · [Alligata guide](https://www.kannel.org/download/kannel-wtls-snapshot/wtls.html) |
| NowWAP Secure | The previously tested official free trial started only the standard listeners. Separate vendor licensing documentation explains the WTLS entitlement. Exact suite negotiation remains unverified. [Vendor licensing thread](https://support.nowsms.com/discus/messages/131/16207.html) |
| VOCAL WTLS | The vendor's library page includes a 3DES-CBC-EDE algorithm table and a contact option. It gives no self-serve WTLS build or observed negotiation evidence. [Vendor WTLS page](https://vocal.com/networking/wireless-transport-layer-security-wtls/) |
| Openwave / Nokia | Sun's integration guide names Openwave WAP Gateway, Nokia Activ Server, and Nokia Artus as external gateways. It supplies no gateway installer or exact suite evidence. [Sun integration guide](https://docs.oracle.com/cd/E19097-01/sjs.cds5.05q4/819-3216-10/wap_gateway.html) |

Accept independent full-handshake evidence when a local gateway build selects
the exact suite, the Rust client verifies the leaf, both Finished exchanges
are supported by endpoint evidence, and protected data passes. Track resumption
separately.
