# WAP-199 same-tuple recovery with a cached session

**WTLS-224 · Proposed after a read-only Ruflo review of `143ad2f`.**
Extend WTLS-223 to cover a client that restarts with its resumable
session and reuses its UDP address and port. The old connection stays
available until the new one proves Finished and remains open. A session
ID identifies cached negotiation state. Both connections can share that
state while using fresh hello randoms, separate traffic keys and separate
replay windows.
[Verified full recovery](WAP_199_ESTABLISHED_TUPLE_RECOVERY_PLAN.md) ·
[Wire resumption contract](WIRE_SESSION_RESUMPTION.md)

WAP-199 §10.3 specifies the abbreviated flight order. The server sends
its Finished before the client sends its own. Section 10.4 covers
retries and appending application data to a handshake flight. Appendix
B.4 describes retaining the old connection until the new handshake
succeeds. The routing and application event rules below are choices for
the UDP adapter.
[WAP-199 §10.4](https://ptacts.uspto.gov/ptacts/public-informations/petitions/1549804/download-documents?artifactId=q91LjyqB9tLZ-LVakpTsgAE_GyThWnjP3JSk0xnVhQkx_FB33j7C-1I#page=51) ·
[WAP-199 Appendix B.4](https://ptacts.uspto.gov/ptacts/public-informations/petitions/1549804/download-documents?artifactId=q91LjyqB9tLZ-LVakpTsgAE_GyThWnjP3JSk0xnVhQkx_FB33j7C-1I#page=91)

## Admission and datagram ownership

Allow a fresh session-bearing ClientHello to take the existing single
candidate slot on an established inbound tuple. Apply the usual authority,
credential, offer and outbound budget checks. Stage only after the
initial flight fits the budget. Preserve WTLS-223's hello-random conflict
checks, retired-hello tracking, address-in-use diagnostic and fixed
monotonic deadline. An exact retry retains that deadline. Expire the
candidate at the deadline before either receive or tick routing.

| Ordinary negotiation result | Occupied-tuple behavior |
| --- | --- |
| Eligible cache hit | Stage an abbreviated candidate. The first flight echoes the cached ID and carries ServerHello, CCS and Finished. |
| Cache miss with a usable full offer | Stage the existing full recovery path. ServerHello assigns a fresh ID. The final server flight must fit its budget before promotion or cache insertion. |
| Resume-only miss or other rejected offer | Return the existing initial alert or diagnostic where applicable. Leave the candidate slot free and preserve the incumbent. |

Route the whole datagram once. Give the incumbent first claim on
its exact accepted flights and verified resumed prefix. Reframe that
prefix against the whole datagram to verify the Finished boundary,
including when a lengthless record ends the datagram. Then check the
candidate's exact retries. The candidate's negotiated handshake kind
selects its new commit shapes. For an abbreviated candidate, accept
the existing wire form of clear CCS and protected Finished alone or
with a protected application batch or a single protected close. Keep
the existing standalone clear-alert path. Ordinary incumbent traffic
uses the incumbent's receive path. A selected peer authenticates the
datagram under its own keys and a failed check ends processing for that
datagram.
[Current adapter routing](../src/udp.rs#L299) ·
[Verified prefix matching](../src/wire.rs#L424) ·
[Full and abbreviated Finished handling](../src/handshake.rs#L621)

## Promotion and closure

Use a typed outcome from the complete candidate receive to distinguish
verified open, verified commit with immediate close, and unsuccessful
or incomplete negotiation. At resumed commit, keep the existing locked
recheck of the exact selected cache entry and its expiry through Finished
verification. Resumption preserves the original expiry. Candidate
rejection or timeout leaves incumbent traffic and eligible cache state
intact.
[Exact cache recheck](../src/wire.rs#L630) ·
[Cache policy](WIRE_SESSION_RESUMPTION.md#cache-policy)

- **Candidate opens.** Install that peer before publishing one
  `Established(Resumed)` followed by any verified application deliveries.
  An abbreviated commit can succeed silently on the wire because the
  server sent its Finished in the first flight. Preserve the existing
  send gate for full fallback. Retire the incumbent locally. The new
  peer owns its replay state and commit prefix, and duplicate commits
  follow ordinary replay and warning rules.
- **Candidate verifies Finished and closes in the same datagram.**
  Send its protected close reply subject to the reply budget, retire
  that candidate and keep serving the incumbent. Surface the candidate
  close scope as a diagnostic. Publish no tuple-wide establishment,
  delivery, closure or timeout for this attempt. Connection close
  preserves the cache entry. Session close invalidates the exact entry
  used by this candidate, even when the incumbent shares it. Only future
  attempts to resume that entry lose eligibility. The incumbent keeps
  its committed keys and application state. Model the cache effect in
  the wire outcome since filtering adapter events happens after the
  current wire code applies closure.
- **Incumbent closes first.** Apply the incumbent's ordinary close and
  cache rules, cancel the staged candidate and let the next fresh hello
  use ordinary admission. After promotion, delayed incumbent data
  and close can no longer deliver, close the new peer or invalidate its
  cache entry.

Leave mixed application-and-close suffixes and the association-aware
application API outside this slice. Published application writes
continue to address the currently installed peer by tuple.
[WAP-199 §10.2.1](https://ptacts.uspto.gov/ptacts/public-informations/petitions/1549804/download-documents?artifactId=q91LjyqB9tLZ-LVakpTsgAE_GyThWnjP3JSk0xnVhQkx_FB33j7C-1I#page=44) ·
[Existing wire close effects](../src/wire.rs#L1237)

## Deterministic acceptance tests

1. Stage a second connection with the same ID and fresh randoms. Interleave
   byte-identical hello retries and protected incumbent traffic, including
   the incumbent's own resumed prefix. Verify a competing hello cannot
   replace the single candidate and retries do not extend its deadline.
2. Drop the new client's standalone commit and deliver its later
   application datagram carrying the commit prefix. Verify promotion
   precedes the first delivery, protected replies reach the new client,
   and repeating the commit and application records yields no second
   establishment or delivery. Delayed incumbent traffic and close have
   no effect after promotion. Cover the standalone successful commit too.
3. Expire a staged candidate at the exact deadline via receive and tick.
   In separate cases expire or invalidate its cache entry before a valid
   Finished. Keep the incumbent usable throughout. Include a first-flight
   budget rejection and check that it leaves the slot free.
4. Exercise full fallback on a stale ID and confirm the
   resume-only `unknown_key_id` outcome using the existing wire fixture.
   Preserve the existing authority and algorithm rejection precedence.
5. Send each protected close scope as the candidate's first prefixed
   send. Check the protected reply, continued incumbent delivery and
   resulting eligibility of a third peer's resume. Exercise a shared
   entry and a distinct entry to verify exact invalidation. Cover an
   incumbent close that arrives before the candidate's commit.
