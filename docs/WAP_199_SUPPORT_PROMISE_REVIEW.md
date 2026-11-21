# WAP-199 support promise review after G1–G6

**Audit baseline.** Baseline `519b0fa` in `wtls-lab`. The WAP-199
profile covers server-authenticated UDP with unrestricted RSA, one
provisioned native WTLS authority and leaf, 3DES-CBC-EDE, full HMAC-SHA-1,
null compression, and explicit record sequence numbers.
[Support boundary](WAP_199_PROVISIONED_TRUST_PLAN.md#support-boundary) ·
[Evidence matrix](WAP_199_EVIDENCE_MATRIX.md)

## Evidence and remaining scope

The audit matched all 149 role-specific IDs and publisher statuses in
the matrix against the corrected WAP-199_103 tables and confirmed the
six verified gap entries in the evidence ledger. A read-only Ruflo
review checked the baseline and five specification notes against the
implementation and recorded evidence. The most recent execution gate
was the 129-test WTLS-220 Cargo run.
[WAP Forum release index](https://www.wapforum.org/what/technical_1_2_1.htm) ·
[Evidence ledger](WTLS_EVIDENCE.json)

| Area | Evidence and disposition |
| --- | --- |
| Selected success path | Deterministic client and server evidence covers full and abbreviated handshakes, provisioned trust, protected data, retries, and closure. G1–G6 add sequence retirement, final-flight loss recovery, clear alert receive, batched application receive, hello wall clocks, and fresh hellos on pending tuples. |
| Historical interoperability | The provisioned BlackBerry 7290 verifies the Rust gateway's full → resumed → full lifecycle with protected page acknowledgments. The separately selected WinWAP server path uses anonymous RSA/DES-CBC. The strict Rust client currently has deterministic lab evidence for the selected suite. Independent authenticated gateway evidence for this client remains open. |
| Outbound handshake errors | Existing wire output covers protected close, duplicate-Finished warnings, and initial server alerts for unmatched advertised authority and a resume-only cache miss. The provisioned client closes locally on certificate rejection and returns `CertificateRejected`. Its peer stays negotiating. Alert rows 020–022 cover the scoped behavior recorded in the matrix. A well-formed ClientHello with no acceptable algorithms can produce a local `UnsupportedProfile` error. Section 10.5.1.3 calls for a `handshake_failure` response in that case. |
| Reconnect on an occupied tuple | G6 proves fresh ClientHello replacement while a server handshake is pending. An established server association retains its slot and protected traffic. Section 10.4 addresses fresh ClientHello recovery. Appendix B.4 calls for preserving the active connection until the new handshake succeeds. Treat this as its own lifecycle decision and keep the currently verified reliability claim scoped. |
| Service and record surface | The current API exposes datagram, delivery, establishment, close, timeout, and diagnostic events. The WAP service primitive contract, including the §10.4 `SEC-Create.ind` behavior, needs separate design if claimed. G4 covers receive-side application batches and the verified abbreviated prefix. General mixed records, application records on full final flights, and outbound coalescing remain outside its evidence. |
| Broader conformance and peer options | Full Appendix E conformance would require a qualifying anonymous option per role and verification beyond the selected profile. Concurrent same-session connections are optional under row 004. WAP-261, more suites, additional certificate formats, client authentication, and WIM remain deferred. |

[Certificate rejection path](../src/wire.rs#L595) ·
[TRUST-05](../tests/provisioned_trust.rs#L451) ·
[Server selection](../src/wire/codec.rs#L151) ·
[Established tuple policy](WAP_199_PENDING_CLIENT_HELLO_PLAN.md#adapter-behavior) ·
[BlackBerry lifecycle](../fixtures/HISTORICAL_PEERS.md#blackberry-provisioned-trust-reconnect-lifecycle) ·
[WAP-199 baseline and corrections](https://www.openmobilealliance.org/tech/affiliates/wap/Technical_June2000-20021106%5B1%5D.zip)

## Recommended next slice at the audit baseline

**Send a WTLS alert when the provisioned client rejects a gateway
certificate during a full handshake.** TRUST-05 already reproduces a
closed client and a gateway left waiting for key exchange. A checksum-
correlated alert lets a matching gateway retire that pending slot when
the alert arrives. This is a bounded improvement in a mandatory protocol
area using the trust validation and clear alert receive behavior already
exercised by the selected profile. The server's no-common-algorithm
response is the next closely related alert slice. Other error handling
remains open, including `time_required` retry semantics, sending
`no_connection`, and protected terminal errors before Finished
commits the receive epoch. Independent gateway research remains
valuable for the client interoperability claim. Recovery on an occupied
tuple needs a larger design for retaining active and provisional state.
[G3 receive boundary](WAP_199_CLEAR_ALERT_PLAN.md#profile-behavior) ·
[WAP-199 §§10.2.2, 10.5.1.3](https://www.openmobilealliance.org/tech/affiliates/wap/Technical_June2000-20021106%5B1%5D.zip)

Use a well-framed, ordered full server flight that reaches trust
validation before either side changes cipher state. Sections 10.5.2 and
10.5.5 cover the certificate and its verification. Review the mapping
from validation results to alert descriptions with a deliberate fatal
policy for trust failures. Section 10.2.2 defines certificate-related
descriptions and specifically marks `unknown_ca` fatal. The exact
mapping and public result shape are implementation design decisions.
Preserve a typed local trust failure and make the outbound datagram
available in the same receive outcome. The UDP adapter currently turns
an error into a diagnostic and emits datagrams from successful wire actions.
[WAP-199 §§10.2–10.2.2](https://ptacts.uspto.gov/ptacts/public-informations/petitions/1549804/download-documents?artifactId=q91LjyqB9tLZ-LVakpTsgAE_GyThWnjP3JSk0xnVhQkx_FB33j7C-1I#page=44) ·
[Wire action surface](../src/wire.rs#L163) ·
[UDP event dispatch](../src/udp.rs#L504)

### Acceptance for a proposed implementation

1. A deliberately rejected native leaf yields one clear fatal alert and
   the typed local trust diagnostic. Verify the next clear sequence and
   compute the checksum independently from the exact last received record
   in the complete server flight, the ServerHelloDone record.
2. The alert reaches the already implemented pending-server receive
   path. Check that both attempts are closed, their retry state and UDP
   slots are retired, and the outcome emits no client key transport,
   established event, or application delivery.
3. A previously verified eligible cache entry keeps its original
   lifetime. Exercise a failed full fallback with cached state and a
   later valid handshake. Retain the valid full and same-ID abbreviated
   paths as controls.
4. Exercise certificate rejection reasons from TRUST-05 using fixed
   clocks and local peers. Preserve the existing datagram budget and
   receive policy for malformed traffic. Keep broad protocol error
   generation, live historical runs, and same-tuple open recovery out of
   this slice.

WTLS-221 implemented and verified this slice. The scoped wire and UDP
evidence is recorded at `32f112a`.
[Certificate alert design](WAP_199_CERTIFICATE_ALERT_PLAN.md) ·
[Supervised verification](SUPERVISED_WORKFLOW.md#run-the-wtls-loop)

WTLS-222 verified the server alert for well-formed offers with no
selectable full-handshake algorithms at `036ce51`.
[Algorithm mismatch alert design](WAP_199_ALGORITHM_MISMATCH_ALERT_PLAN.md)

WTLS-223 verified full-handshake recovery on the same address and port
at `4796ed6`. The incumbent stays active until the new peer verifies
Finished. Staged abbreviated recovery remains separate.
[Established tuple recovery design](WAP_199_ESTABLISHED_TUPLE_RECOVERY_PLAN.md)
