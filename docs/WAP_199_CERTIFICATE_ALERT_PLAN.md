# WAP-199 outbound certificate rejection alert design

**WTLS-221 · Verified at `32f112a`.** Use the provisioned
RSA trust decision to end a pending full handshake at both endpoints.
This plan covers the opt-in provisioned client processing a complete,
well-framed, ordered server flight for a fresh session in the clear
epoch. The native certificate is evaluated after `ServerHelloDone`
and before key transport. The gateway uses the validated alert to
retire its pending attempt through the G3 path.
[Support promise review](WAP_199_SUPPORT_PROMISE_REVIEW.md) ·
[Certificate rejection path](../src/wire.rs#L478) ·
[G3 receive policy](WAP_199_CLEAR_ALERT_PLAN.md#profile-behavior)

## Rejection mapping

Section 10.2.2 defines the alert descriptions and requires fatal
severity for `unknown_ca`. Use fatal severity for every listed
certificate rejection in this profile because the client cannot proceed
without the expected authenticated gateway. This severity choice for
the other descriptions is profile policy. Keep the existing broad
typed local certificate rejection and classify the reason internally
before selecting the on-wire description.
[WAP-199 §§10.2–10.2.2](https://ptacts.uspto.gov/ptacts/public-informations/petitions/1549804/download-documents?artifactId=q91LjyqB9tLZ-LVakpTsgAE_GyThWnjP3JSk0xnVhQkx_FB33j7C-1I#page=44) ·
[WAP-199 §§10.5.2, 10.5.5](https://www.openmobilealliance.org/tech/affiliates/wap/Technical_June2000-20021106%5B1%5D.zip) ·
[Provisioned verifier](../src/wire/certificate.rs#L51)

| Rejection | WTLS alert and treatment |
| --- | --- |
| Corrupt supported native RSA certificate body, including invalid certificate fields | `bad_certificate` (42), if the containing Certificate record and server flight are well framed. |
| Fully framed native RSA leaf with a modulus outside 1,024–4,096 bits or an exponent wider than 32 bits | `unsupported_certificate` (43) when the key fields are structurally valid. |
| Parsed native leaf has an issuer absent from the configured trust context | `unknown_ca` (48). The single provisioned issuer is the only match in the selected profile. |
| Leaf claims the configured issuer and its signature fails validation | `bad_certificate` (42). This includes the same issuer name with a different signing key and a peer-supplied invalid signature encoding. |
| A trusted, correctly signed leaf has the wrong expected WTLS subject | `certificate_unknown` (46). Treat the identity mismatch as another certificate processing rejection. |
| A trusted, correctly signed leaf with the expected subject is expired or its validity has yet to start | `certificate_expired` (45). Preserve the current inclusive validity endpoints. |
| Non-native format tag, unclassified native variant, malformed record or handshake envelope, bad flight order, or unsupported negotiated parameters | Use the existing local failure path. The certificate envelope decoder rejects non-native formats before trust verification. |
| Local provider or encoding failure, ambiguous verification result, or bad server provisioning | Keep the failure local. An operational failure to perform verification is distinct from a proven signature mismatch. |

Evaluate structure and supported leaf profile first, then issuer,
signature, expected subject, and validity. Subject wins over time if both
fail. Check an overlapping failure to pin the priority.
An invalid date interval is a corrupt body. A valid date interval that
excludes the supplied wall clock is a time rejection. Keep operational
provider errors separate even when the current verifier collapses them
into `CertificateRejected`. Require a verification boundary that can
distinguish a peer signature mismatch from a local provider error and
preserve WTLS `rsa_sha` over the raw SHA-1 digest. Unclassifiable failures
retain a local diagnostic with no reply. The provisioned opt-in selects
the new outbound behavior. The existing manual client and local server
configuration paths keep their current rejection behavior.
[Certificate body parser](../src/wire/certificate.rs#L277) ·
[Issuer and signature checks](../src/wire/certificate.rs#L230) ·
[Certificate envelope decoder](../src/wire/codec.rs#L463)

## Receive contract

`WirePeer::receive_with_reply` returns
`Result<Vec<WireAction>, ReceiveError>`. `ReceiveError` carries a typed
`WireError` and an optional owned reply datagram. A classified trust
rejection returns `CertificateRejected` and one alert on the error side.
Other failures carry their local diagnostic and no reply. Successful
receives keep returning the usual action list. Both entry points share
the same receive and state processing. The existing `receive` method
continues to return its diagnostic-only result. Document
`receive_with_reply` as the entry point for direct consumers that can
forward an alert from a failed receive.

The UDP adapter uses the detailed result and emits the existing
`Event::Diagnostic(Diagnostic::Protocol(...))`, followed by the
budget-checked send event when a reply exists. An outbound budget
failure adds the existing `OutboundTooLarge` diagnostic. It preserves
the original trust diagnostic. Association retirement remains driven
by the peer's closed state.
[Receive API](../src/wire.rs#L367) ·
[UDP dispatch](../src/udp.rs#L356) ·
[Direct WinWAP consumer](../src/bin/wtls-winwap-lab.rs#L87)

The additive method keeps `WireError` copyable and leaves existing
`WireAction` matches, negative tests, and callers' error handling valid.
A diagnostic wire action would put terminal rejection on the successful
result side. Changing the existing receive result would require a wider
caller migration.

The outbound datagram contains exactly one explicit-length null-cipher
alert record. Use the next clear write sequence, ordinarily 1 after
ClientHello. Compute the §10.2 checksum over the exact received
`ServerHelloDone` record including its header and actual length form.
The canonical explicit-length record `c3 00 02 00 03 0e 00 00` yields
checksum `c0 0e 02 00`.
Obtain it from the accepted server flight before installing any traffic
keys. The rejecting client ends the attempt, cancels retries and
releases provisional session state. A prior verified cache entry keeps
its original expiry. The emitted alert is a one-shot response. The
gateway checks the record sequence and sent-record checksum and retires
its pending slot without a close-notify acknowledgment. A dropped alert
leaves the gateway's existing pending deadline in force.
[Clear alert admission](../src/wire.rs#L847) ·
[Session release](../src/wire.rs#L1162) ·
[UDP slot retirement](../src/udp.rs#L320)

## Deterministic tests

The tests use in-memory wire peers, the UDP link, and fixed certificate
and retry clocks. The first regression reproduced the missing alert
after a properly framed server flight containing a rejected leaf.
[TRUST-05 fixture](../tests/provisioned_trust.rs#L454) ·
[Existing alert tests](../src/wire/alert_tests.rs) ·
[UDP tests](../tests/udp_adapter.rs)

| Test | Acceptance evidence |
| --- | --- |
| Rejection reasons and precedence | Table-drive corrupt native body, a recognizable native key-profile mismatch, absent issuer, claimed issuer with invalid signature, wrong subject, expired and not-yet-valid dates. Check the alert code and fatal level plus the same typed local diagnostic. Use wrong subject plus expired to verify precedence and valid certificates at both time boundaries as controls. |
| Exact wire reply and one-shot closure | Check the whole canonical reply and compute the checksum independently over the last received record. Repeat after a byte-identical ClientHello retry to verify the alert still uses sequence 1. Include a final omitted-length `ServerHelloDone` fixture at the wire boundary. Check closed client status and absence of key exchange, CCS, Finished, establishment and application delivery. A repeated server flight or later tick yields no second alert. |
| Scoped rejection and API compatibility | An incomplete or malformed handshake flight and a non-native format rejected by the envelope decoder return the existing local diagnostics without a reply. A later valid flight still works. Exercise an operational provider failure at the verifier boundary and assert no reply. Verify the manual client and the existing diagnostic-only `receive` contract. |
| UDP outcomes and retirement | The client emits a certificate diagnostic and a send, then its slot is free. Deliver the alert to the pending gateway, which reports a clear peer alert and retires without acknowledgment. Use capacity one to verify fresh admission. Drop the alert in a separate case and observe the existing server pending timeout. |
| Budget | A valid server flight fits the adapter budget and the smaller alert can go out. Use the adapter event mapping boundary or existing budget coverage to check diagnostics independently of send rejection. A budget too small for the alert cannot admit the larger server flight at the normal UDP entry point. |
| Prior session and positive controls | Seed a verified session, use a cache-empty gateway context to force a full fallback, and reject its leaf. Resume the original ID with the original gateway before the original expiry and decline it at expiry. Hold certificate wall time eligible while advancing the monotonic cache clock. Keep the valid full handshake and protected echo, G3 clear alert receive and existing resumption cases in the gate. |

Broad server negotiation alerts, protection errors after cipher
activation, alternate certificate support, and live historical-peer
verification belong to separate work. Ruflo reviewed the exact
implementation commit after all 137 Rust tests, Clippy, and formatting
passed.
[UDP budget regression](../src/udp/certificate_alert_tests.rs#L4) ·
[Provider failure regression](../src/wire/certificate_alert_tests.rs#L7) ·
[Wire and UDP integration tests](../tests/provisioned_trust.rs#L642) ·
[Supervised verification](SUPERVISED_WORKFLOW.md#run-the-wtls-loop)
