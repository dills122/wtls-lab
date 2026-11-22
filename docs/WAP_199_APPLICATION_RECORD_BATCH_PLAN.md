# WAP-199 receive of batched application records

**WTLS-220 · Verified at `ff294cb`.** The standalone UDP profile
receives batches of protected application records in both roles,
including after the abbreviated client commit.
[WAP-199 evidence matrix](WAP_199_EVIDENCE_MATRIX.md#g4-multiple-application-records-per-sdu)

## WAP-199 requirements

Sections 9 and 9.2.1 permit several records in one transport service data
unit (one UDP datagram here). Each application record carries an
independent block for the next layer. Section 9.2.1's length field
description requires lengths for concatenated records. Its header-bit
description allows the final or sole record to omit the length when the
transport supplies the total size. Keep explicit lengths as the default
and retain the codec's existing interpretation on receive. Every record
before the final one needs a length. A record with an omitted length
consumes the datagram's remainder.
[WAP-199 §§9–9.2.1](https://ptacts.uspto.gov/ptacts/public-informations/petitions/1549804/download-documents?artifactId=q91LjyqB9tLZ-LVakpTsgAE_GyThWnjP3JSk0xnVhQkx_FB33j7C-1I#page=34) ·
[Record framing](../src/lib.rs#L305)

Section 9.2.3.1 requires explicit datagram sequences and duplicate
suppression. The existing 32-record window follows the example in the
specification. Each record's sequence selects its receive keys across
key refreshes. Sections 10.3 and 10.4 govern abbreviated Finished
verification and retries.
[WAP-199 §§9.2.3.1, 10.3–10.4](https://www.openmobilealliance.org/tech/affiliates/wap/Technical_June2000-20021106%5B1%5D.zip) ·
[Replay window](../src/handshake.rs#L877)

## Receive behavior

The wire layer frames and authenticates each protected record. The
handshake layer admits a batch in established traffic and after an
abbreviated client commit. DQ-08 applies the same staging policy to one
application record on the full server final flight. The send API,
record size limit, and UDP datagram budget are unchanged. Outbound
batching and general content-type interleaving remain separate scope.
[Open receive path](../src/handshake.rs#L794) ·
[Full server final-flight receive](WAP_199_FULL_FINAL_FLIGHT_REVIEW.md) ·
[Abbreviated commit](../src/handshake.rs#L658) ·
[Datagram budget](../src/udp.rs#L216)

| Received | Result |
| --- | --- |
| Established application batch | Frame and authenticate every record before committing application state. In datagram order, run each record through the existing replay window and deliver one block per accepted record. Skip duplicates and records outside the window individually. |
| Malformed or unauthenticated record in an application batch | Reject the batch before any delivery, replay-window update, or close reference update. A valid retry remains deliverable. This all-or-nothing behavior is local receive policy. |
| First abbreviated client ChangeCipherSpec and Finished followed by a batch | Validate the batch, verify the resumed Finished, and retain the existing cache eligibility check. Commit once and establish before delivering the suffix. An invalid application suffix leaves the pending commit retryable. A Finished verification failure still closes the pending connection. |
| Exact repeat of a verified abbreviated prefix with a batch | Preserve the committed keys and duplicate-Finished warning. Admit each application record through the same replay window. The prefix must end at the same record boundary when framed in the new datagram. A cached Finished with omitted length can end its original datagram and cannot prefix a suffix. |
| Verified terminal alert in a committed epoch | Preserve existing precedence. Discard staged application deliveries, stop consuming the datagram, and retain the existing acknowledgment and connection-versus-session cache effects. |

Associate every accepted protected application record with a checksum of
its own framed bytes. Section 10.2 describes referencing the last received
record. Keep the existing local choice of the highest accepted protected
sequence under reordering. An older or duplicate tail cannot displace
that reference. Rejected and all-duplicate batches leave it intact. The
duplicate-Finished warning still references the verified Finished.
[Close reference](../src/wire.rs#L511) ·
[Prefix framing](../src/wire.rs#L727) ·
[Terminal handling](../src/wire.rs#L882)

## Deterministic tests

Use normally encoded protected records from the in-memory peers and
exercise the normal receive entry points. Generate the omitted-length
fixture with its length flag set appropriately during protection, since
record authentication covers the flag.
[Record protection](../src/wire/protection.rs#L237) ·
[Codec tests](../tests/record_codec.rs#L36)

| Case | Observable result |
| --- | --- |
| Established framing and delivery | In both directions, deliver distinct payloads separately and in datagram order. Cover all-explicit lengths and an omitted length on the final record. |
| Replay and key refresh | Reverse records across a refresh boundary and verify delivery in their received order. Replay the whole batch. Mix fresh and duplicate records within and across datagrams. Include a record at the window cutoff with a valid new record. Deliver each accepted payload once. |
| Close checksum | Put the highest accepted sequence before an older or duplicate tail. Verify that the checksum in a later close references the exact framed bytes of the highest accepted record, including after an all-duplicate batch. |
| Rejected tail and budget | Cover a late framing error and a late integrity failure. Retry the valid batch and deliver every record once. Test a valid batch at the UDP budget and one byte over it by varying the budget. An over-budget receive leaves peer state intact. |
| Abbreviated commit and retry | Withhold the standalone commit and establish using a valid prefixed batch. Reject an invalid suffix before commit or delivery, then retry with the valid batch. Separately verify that a failing Finished closes the pending connection without establishment or delivery. Repeat the exact accepted prefix with old and fresh application records. Check one establishment overall, the warning's Finished checksum, and delivery of only fresh records. Retain the cached omitted-length Finished boundary regression. |
| Terminal alerts | Extend committed-epoch close, critical, and fatal tests with application records before the alert. Verify zero application delivery, the existing close acknowledgment, and cache preservation or invalidation according to the alert. Retain the G3 clear-alert regressions. |

[Refresh harness](../tests/udp_adapter.rs#L352) ·
[Close checksum regression](../tests/wire_resumption.rs#L633) ·
[Abbreviated receive harness](../tests/wire_resumption.rs#L306) ·
[Alert regressions](../src/wire/alert_tests.rs#L669) ·
[Budget regression](../tests/udp_adapter.rs#L1178)

Observed BlackBerry exchanges carry one application record per datagram.
The deterministic tests verify batched receive for S-026 and C-026 in
the scoped UDP profile.
[Explicit lengths](../tests/protected_echo.rs#L752) ·
[Framing and resumed commits](../src/wire/application_batch_tests.rs#L51) ·
[UDP replay and budget](../tests/udp_adapter.rs#L268) ·
[Alert lifecycle](../src/wire/alert_tests.rs#L454)
