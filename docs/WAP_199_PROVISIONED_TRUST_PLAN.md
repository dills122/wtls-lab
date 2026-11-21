# WAP-199 provisioned trust plan

**Status.** WTLS-210 passed deterministic verification at `6926c74`. The live BlackBerry trust-provisioning check remains separate. See the [WTLS-210 packet](../scripts/ruflo/packets/WTLS-210.json) and [evidence ledger](WTLS_EVIDENCE.json).

## Support boundary

The first support promise covers server-authenticated WTLS over UDP with
unrestricted RSA, native WTLS leaf certificates, 3DES-CBC-EDE, full HMAC-SHA-1,
null compression, and explicit record sequences. The reference Rust client
uses one explicitly provisioned RSA authority and an expected WTLS subject.
The gateway uses one certificate and its corresponding private key. The
supported traffic includes full handshakes, session resumption, and protected
application records. The reference for existing behavior is the
[WTLS evidence ledger](WTLS_EVIDENCE.json).

The scoped promise is a WAP-199 profile. Full Appendix E conformance has its own
client and server requirements, including an anonymous option for each role.
The WinWAP server profile is separately selected. WAP-261 coverage, additional
suites, X.509, client certificates, and WIM integration are deferred.
[WAP-199 §§10.5.1–10.5.2 and Appendix E](https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf) ·
[WinWAP profile](../README.md#direct-winwap-compatibility-test)

## Correction crosswalk

The baseline is `WAP-199-WTLS-20000218-a`. Review all five specification
information notes (SINs) listed for it in the June 2000 release. The document
IDs below identify the corresponding PDFs in the release archive.
[Publisher index](https://www.wapforum.org/what/technical_1_2_1.htm) ·
[Official release archive](https://www.openmobilealliance.org/tech/affiliates/wap/Technical_June2000-20021106%5B1%5D.zip)

| Correction | Effect | First-profile disposition |
| --- | --- | --- |
| `WAP-199_102-WTLS-20010214-a`, §§3–6 | Adds conformance dependencies and references, an optional clear HelloRequest row, an Appendix A advisory on 40-bit ciphers, and ECC object identifiers. | Retain the single unrestricted RSA profile and record the exclusions. WIM, clear HelloRequest, ECC, and 40-bit suites are deferred. |
| `WAP-199_103-WTLS-20010730-a`, §3 and A.1–A.2 | Restates the client/server static conformance tables with dependency columns and revised item IDs. | Use those role-specific rows to record implemented, planned, and deferred requirements. See the [WTLS-214 review matrix](WAP_199_EVIDENCE_MATRIX.md) for the role-specific mapping. |
| `WAP-199_104-WTLS-20010926-a`, §3.3 | Updates baseline §§10.5.1.2 and 10.5.2. A certificate sent by the gateway must come from an advertised trusted authority when the list is nonempty. An empty list with a non-anonymous offer permits a certificate. | Gate the full certificate flight on the configured signer's authority ID. Exercise matching, nonmatching, and empty lists. The authenticated profile requires an acceptable authenticated choice. |
| `WAP-199_105-WTLS-20011027-a`, §3.3 | Clarifies identifier type 254 in §10.5.1.2. RSA hashes the unsigned modulus bytes with SHA-1, without an ASN.1 encoding or sign octet. | Compute and verify RSA authority identifiers with an independent known-answer fixture. ECC identifiers are deferred. |
| `WAP-199_106-WTLS-20011027-a`, §3.3 | Narrows the acceptable identifier types in the optional client CertificateRequest path in §10.5.4 to 0 and 254. | Defer with client-certificate authentication. The trusted-authority vector in ClientHello continues to follow §§10.5.1.2 and 10.5.2. |

## Profile behavior

**Reference client.** In the provisioned path, use its configured CA public key
to place one type-254 RSA entry in the ClientHello trusted-authority vector.
Keep that entry separate from the RSA offer in the key-exchange vector. Verify
the received leaf using the provisioned key, exact WTLS identity and validity
interval, then complete the Finished exchange over the original wire transcript.
A matching advertised identifier is a certificate-selection hint. The client
verifies the leaf signature independently.
[ClientHello codec](../src/wire/codec.rs#L35) ·
[Existing trust verifier](../src/wire/certificate.rs#L16)

**Gateway.** Provision a CA public key alongside the gateway's existing leaf
and key. Establish that this CA actually signed the configured leaf and matches
the issuer identity before serving it. Match supported RSA hash entries against
that authority's ID. A nonempty list without a compatible match receives an
initial clear fatal `handshake_failure` alert with the ClientHello checksum,
before any ServerHello, certificate flight, or new session allocation.
Anonymous negotiation uses a separately selected compatibility profile. An
empty list with a usable authenticated offer permits the configured
certificate under _104.
The Rust client still verifies it through its independently provisioned anchor.
Select provisioned behavior explicitly while the existing baseline and
manual-trust harnesses retain documented entry points.
[Existing server identity](../src/wire/certificate.rs#L57) ·
[Server hello decision](../src/wire.rs#L551)

**Resumption.** A session can resume in the gateway identity, trust and policy
context in which it was established. A change to those inputs starts a fresh
context. A valid abbreviated exchange can omit the authority vector and has
no certificate flight. The profile declines resumption when
a supplied nonempty list excludes the cached authority. Preserve the existing
cache entry for eligible peers. A cache miss with a usable full offer goes
through the full certificate-selection rules. A resume-only miss keeps the existing
`unknown_key_id` behavior.
[Existing cache policy](WIRE_SESSION_RESUMPTION.md)

## Deterministic release gate

Use in-memory wire peers, fixed timestamps, and separately provisioned RSA
test authorities and leaves. Assert public wire output and endpoint outcomes.

| ID | Scenario | Acceptance evidence |
| --- | --- | --- |
| TRUST-01 | RSA authority hash and ClientHello encoding | Use a fixed RSA authority modulus whose DER integer has a leading sign octet and an expected digest computed outside the production helper. Decode a provisioned ClientHello and assert an RSA default-parameter type-254 entry with the expected CA digest. The existing RSA offer remains in its own vector. |
| TRUST-02 | Matching authority and valid gateway leaf | With distinct issuer and leaf keys, observe ServerHello selecting the RSA offer index and sending the native leaf, both sides verifying Finished over the emitted ClientHello, then a protected echo. A mixed list with the supported matching entry after an unrelated listed authority also selects the configured certificate. |
| TRUST-03 | Nonmatching authority list | An unrelated CA hash, a leaf hash, or a correct CA hash appearing only in the key-exchange vector each cause `handshake_failure` for a nonempty unmatched authority list. The wire response contains no certificate or anonymous flight, the peer stays unestablished, and the attempt creates no resumable session. |
| TRUST-04 | Empty authority list and authenticated offer | The gateway can send its configured native leaf. Use the existing empty-list client path with the correct provisioned authority. Verify the native leaf before the handshake completes. |
| TRUST-05 | Provisioning and certificate rejection | Pair a gateway leaf with the wrong same-name authority key and reject the configuration. Exercise the client against validly encoded leaves signed by the wrong authority, bearing the wrong subject, or expired under the fixed clock. Assert that rejection occurs before key transport, protected delivery, or cache installation. |
| TRUST-06 | Resumption and fallback | Resume a verified session in the same trust and identity context. A valid resume-only offer with an omitted vector still gets the abbreviated flight. An explicit nonmatching list declines a cache hit and preserves the valid entry. Changing trust or identity starts a fresh context. Apply the same full-offer rules on fallback, including the empty-list exception, and preserve the resume-only miss result. |

For the hash unit fixture, raw bytes `80ff0123` give SHA-1
`341a8adb7aba93ad750cb51a81a97854ebb6ad10` using Python `hashlib`. The padded
variant `0080ff0123` gives `3f4b00d00928a45d56cb8c7609b143810494f9bf`. Use
a valid fixed RSA CA key for the handshake and its own independently computed
expected hash. For the wire fixture, the single authority vector is
`00 17 08 00 fe` followed by the 20 digest bytes.

Tests should pin the decision and outcome at the wire boundary before the
implementation changes. Preserve the existing WinWAP fixture behavior, the
resumed ServerHello key-exchange index, and the protected UDP tests. Proposed
checks are the focused protected-echo and wire-resumption suites followed by
the existing locked offline Cargo test, Clippy, and formatting gates.
[Supervised verification workflow](SUPERVISED_WORKFLOW.md)

## Separate BlackBerry interop check

WTLS-211 verified live native CA enrollment in the stock BlackBerry 7290
simulator. After a separate CA trust action through the Browser's key store,
the next ClientHello advertised the lab authority hash and the strict gateway
completed a full handshake and protected WSP exchange. The Browser required
no gateway leaf prompt. The deterministic WTLS-210 gate and the historical
manual-trust run retain their own evidence.
[Live enrollment capture](../fixtures/HISTORICAL_PEERS.md#blackberry-native-ca-enrollment)

WTLS-212 confirmed that the simulator still advertised the enrolled authority
after a graceful restart on the same XP overlay. The gateway used a fresh
session cache and a new leaf signed by that authority. The handset completed
a full handshake and protected WSP exchange without a certificate prompt.
[Live restart capture](../fixtures/HISTORICAL_PEERS.md#blackberry-ca-persistence-across-restart)

WTLS-213 verified the full, resumed, full sequence through one strict
gateway using the enrolled lab CA. The BlackBerry reoffered its cached ID
after both close scopes. The gateway resumed after Connection close and
issued a new ID after Session close. All three protected page acknowledgments
were verified, with certificate prompts enabled throughout.
[Live lifecycle capture](../fixtures/HISTORICAL_PEERS.md#blackberry-provisioned-trust-reconnect-lifecycle)

## Approved decisions

- A full authenticated offer may omit the authority list. A nonempty list requires a compatible match.
- A nonmatching nonempty list declines resumption while keeping the valid cache entry.
- The profile covers one gateway leaf and one provisioned authority.
- TRUST-01 through TRUST-06 are the deterministic gate. Live BlackBerry provisioning has its own verification milestone.
