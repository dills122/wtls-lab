# WAP-199 full final-flight application data review

**DQ-08 · Proposed test plan.** The question is whether to check receive
behavior for one initial, server-authenticated full handshake whose final
UDP datagram carries clear ChangeCipherSpec (CCS), protected Finished,
and one protected application record. The corrected text supports this
grouping as a receive case. The saved captures leave historical use of
the exact server grouping open. Review the tests before approving a
runtime change.

## Corrected specification

The source set is the 18 February 2000 WAP-199 base specification and
WAP-199_102 through _106 from the WAP 1.2.1 release archive. The five notes
were checked against their copies in that archive. _103 §3.3 replaces the
Appendix E conformance tables. Both roles list 005 (concatenated handshake
records), 006 (datagram handshake reliability), 025 (CCS), and 026
(application data) as mandatory. _102 covers dependencies and related
corrections. _104–_106 cover certificate and key-identifier behavior.
The notes leave the record ordering, length, and Finished rules below
as written in the base specification. The conformance rows apply to
their named behaviors. The exact mixed server datagram is a receive
design inferred from the combined base rules.
[WAP Forum release index](https://www.wapforum.org/what/technical_1_2_1.htm) ·
[Official release archive](https://www.openmobilealliance.org/tech/affiliates/wap/Technical_June2000-20021106%5B1%5D.zip) ·
[Corrected evidence matrix](WAP_199_EVIDENCE_MATRIX.md#protocol-and-selected-options)

| Question | Reading |
| --- | --- |
| Can the records share one datagram? | §§9 and 9.2.1 permit record concatenation and interleaving of content types. §10.4 requires grouped handshake messages to remain separate records in the same datagram and expressly describes the client-side application prefix for abbreviated and optimized handshakes. The §7 client COMMIT2 table shows CCS and Finished opening the connection. Treat the mixed server grouping as an inference from general framing, the full-handshake order in §10.3, and the application-data gate in §10.5.9. |
| When can the application data be used? | In this initial full handshake, the server has validated the client's Finished before sending its own CCS and Finished. CCS uses the prior null cipher state. The server's Finished is the first protected record under the new state at sequence zero. The first application record uses the new state and the next sequence. The client must validate Finished before application delivery. Use establishment before delivery as the observable event order. |
| Where are the record boundaries? | Use explicit lengths on all records for the baseline test. The two prefix records need explicit lengths. An omitted length consumes the datagram remainder. A separate receive variant can omit only the final application record's length under §9.2.1's header-bit rule and the existing G4 interpretation. The general length-field summary in that section calls for explicit lengths in concatenated records. Set length flags when encoding because the protected record authenticates the record-type byte. |
| What must a repeat preserve? | §10.4 requires the full-handshake server to retransmit the transport SDU containing CCS and Finished when the client's Finished repeats. §9.2.3.1 calls for duplicate detection with explicit datagram sequences. If the server originally sent a combined datagram, the receiver's observable result should be a single establishment and a single delivery. The existing two-record retransmission test remains the control. |

[WAP-199 §§9–9.2.1](https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf#page=38) ·
[Client COMMIT2 state table](https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf#page=24) ·
[Record protection and duplicate handling](https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf#page=41) ·
[CCS](https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf#page=43) ·
[Full handshake and datagram retry](https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf#page=49) ·
[Finished](https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf#page=69)

## Capture check

At `6cf5e43`, `wtls-inspect --timeline` parsed all 18 committed
`fixtures/*.trace` files. This covered 429 events, including 154
captured server datagrams, 271 captured client datagrams, and four
relay events with metadata only. The scan compared direction and
the ordered record type and cipher state within each captured UDP
payload.

- Zero server datagrams carried all three target record types and cipher
  states together in any order. Twenty-one server datagrams matched the
  two-record CCS and protected Handshake shape. For example, the full
  KWTLS key-refresh run has two records at event 4 and the first protected
  server application record at event 6.
- Eight client datagrams carried the target record shape. The adjoining
  handshake evidence identifies them as abbreviated client commits.
  The KWTLS resumption fixture has one at event 13.
- The inspector identifies a protected record's type and sequence from
  the envelope. The handshake context identifies the expected Finished.
  A metadata-only drop has no payload to inspect, and the capture scan
  verifies framing and direction.

[Full KWTLS control](../fixtures/blackberry-7290-kwtls-key-refresh.trace) ·
[Abbreviated KWTLS comparison](../fixtures/blackberry-7290-kwtls-resumption.trace) ·
[Capture provenance](KWTLS_LAB_BASELINE.md#live-key-refresh-on-one-connection)

## Proposed verification

If approved, use one deterministic, provisioned in-memory exchange on
the existing RSA / 3DES-CBC-EDE / full SHA profile. Generate normal
protected records in a test sender and group them at the test boundary.
Use distinct records, one application payload, and the existing datagram
budget. Historical ciphertext belongs to its original session. The
captured DES-CBC datagrams remain framing evidence.

| Case | Expected result |
| --- | --- |
| All-explicit valid flight | Check explicit sequence and length fields on all three records. CCS carries byte `0x01` in the prior null state and switches the read state. The client has already sent its own Finished. It verifies the server Finished at sequence 0 against the transcript that includes the client Finished. Then establish once and deliver the sequence 1 payload once, in that order. |
| Finished rejected | Use a test-controlled failure of Finished verification with record authentication intact and a valid application suffix. Terminate the pending attempt through the existing Finished failure path. Expect zero establishment, zero application delivery, and no new cached session. §10.2.2 recommends fatal `decrypt_error` for this failure. Alert output is a separate policy decision. |
| Exact combined flight repeated | Repeat the same datagram on the established association. Observe zero additional establishment and zero application delivery. A standalone repeat of the sequence 1 application record is also suppressed. A fresh sequence 2 record delivers normally, confirming the read state survived the repeat. |
| Final application length omitted | Encode the final record with that length form from the start. Repeat the success check with the same sequence and event ordering under the existing G4 receive interpretation. |
| Missing or misplaced CCS | Reject the grouping before establishment or delivery and keep the full handshake's normal response to an invalid flight. The existing typed test provides a server-side order check. |
| Valid Finished with rejected application suffix | Proposed local policy follows G4. Stage the receive until the whole datagram passes validation. A suffix rejection leaves the handshake pending and retryable without installing a session or advancing replay state. Verify that the subsequent valid flight opens and delivers once. Review this policy explicitly before implementation. |
| Standalone final flight control | The existing G2 case still verifies byte-identical two-record final-flight retransmission followed by a protected echo. |

The first three rows are the core checks. The length variant, CCS order,
and invalid suffix cover the adjacent receive boundaries. G2 and G4
provide regression controls. Agree on these outcomes before a wire-test
or implementation slice. Revisit outbound coalescing when a concrete
peer or transport measurement calls for it.

[Finished failure alert](https://www.wapforum.org/tech/documents/WAP-199-WTLS-20000218-a.pdf#page=47) ·
[Existing typed order and Finished check](../tests/handshake.rs#L326) ·
[Existing full final-flight retry](WAP_199_EVIDENCE_MATRIX.md#g2-full-handshake-final-flight-retry) ·
[Existing batched receive policy](WAP_199_APPLICATION_RECORD_BATCH_PLAN.md)
