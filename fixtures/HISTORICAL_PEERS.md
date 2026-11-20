# Historical WTLS peer candidates

WTLS-203 screens a second historical client alongside the existing WinWAP
fixtures. The maintainer's disposable XP gate is pending for all candidates.
The ranking uses the lead's installer inventory and published documentation.

## Candidate ranking

1. **Openwave Simulator 7.0.** First choice. Openwave's 2003 Mobile Browser 7.0
   datasheet explicitly lists WTLS Class II for its WAP 1.x stack. The simulator
   installer is staged on the read-only XP CD. The Windows build and its
   selected connection mode still need wire confirmation.
   [Openwave Mobile Browser 7.0 datasheet](https://www1.lasalle.edu/~beatty/430/wireless/toolkit/client_tech_and_sdk/pdf/DS_MobileBrowser7.0_0103.pdf)
2. **Openwave SDK 6.2.2.** The installer is also staged on the read-only XP
   CD. Its browser build and secure gateway behavior need confirmation.
   The Class II documentation above names 7.0. Openwave 4.1.1 stopped at a
   separate export attestation. Record any installer gate against the specific
   build and leave agreements to the maintainer.
3. **BlackBerry OS 4 simulators.** RIM's 2004 enterprise guide documents
   `WapEnableWTLS`, a Class II handheld stack, and a simulator WAP source-port
   option. The developer brochure documents JDE and device simulator
   distribution. An archive lists generic OS 4 and model-specific simulators.
   The exact build, installer contents and availability, browser provisioning,
   and simulator WTLS traffic remain unverified.
   [RIM enterprise programming guide](https://media.journoportfolio.com/users/51888/uploads/84f291ae-c7fa-4cc3-b63b-491729e2fb2b.pdf) ·
   [BlackBerry developer tools brochure](https://www.blackberry.com/emailers/developers/javaone/DevZoneWelcomePDF_Final.pdf) ·
   [Simulator archive listing](https://archive.lunar-project.org/BlackBerry%20OS/Simulators/)

Kannel records connectionless networking for Ericsson R380s Emulator 3.0 and
external gateway configuration on unsecured UDP 9201 for Motorola ADK 1.1.
Both still need evidence of a secure offer. The Nokia 7110 simulator guide
excludes WTLS, and the 7210 SDK has an installer/serial gate. Handset support
alone leaves simulator capability open.
[Kannel compatibility notes](https://www.kannel.org/compatibility.shtml)

## Maintainer XP gate

For each attempt, record the installer source and build, any installer or
provisioning blocker, the selected browser mode and gateway, and the capture
and endpoint log references. Preserve the original UDP payloads, direction,
and timestamps.

| Observation | Evidence to record |
| --- | --- |
| WAP gateway traffic | Identify unsecured WSP on UDP 9201 or WAP 2 HTTPS by the decoded traffic. For a WTLS candidate, capture a clear WTLS ClientHello sent to the lab gateway over UDP 9202 or 9203. Record the endpoints and decode the record and handshake. The port alone leaves the protocol unconfirmed. |
| Authenticated offer | Preserve the ordered ClientHello key exchange entries and cipher/MAC pairs with their raw identifiers, plus compression, sequence mode, key refresh, and raw session ID bytes (including an empty ID). Decode against WAP-199 Appendix A and record any mismatch with the lab profile. RSA (8) is the authenticated key exchange in the lab profile, which uses 3DES-CBC-EDE (6) and SHA (3). Resolve any ServerHello selection against the actual offer list. |
| Authentication completed | If the offer agrees with the profile, correlate the negotiated tuple and server certificate with evidence that the client verified the certificate against its configured trust and server identity. Record successful protected Finished verification in both directions and a protected WSP request and reply. A capture can show the flight order, while peer or endpoint evidence establishes verification of protected records. |
| Cached offer or stale-ID fallback | Compare the reconnect ClientHello's raw ID to the ServerHello ID issued in an earlier completed exchange. An initial nonempty ID with no recorded issuance is an uncorrelated offer. If the server declines the offered ID and sends a different ID with a full handshake, record full-handshake fallback. Call the offer stale when cache expiry, invalidation, or absence is evidenced. |
| Abbreviated resumption | Correlate the reconnect offer with the earlier issued ID and verify that the new ServerHello echoes the same bytes. Observe the server ChangeCipherSpec and protected Finished before the client's ChangeCipherSpec and protected Finished, with the full certificate and key-exchange flight absent. Correlate both verified Finished messages and subsequent protected traffic. |

The current wire adapter covers the full handshake. The typed state-machine
tests cover abbreviated handshakes. Live screening, authentication, and
resumption results remain pending for the maintainer to record.
[Lab profiles and fixtures](../README.md) ·
[WAP-199-WTLS-20000218-a, §§10.3, 10.5.1.2–10.5.1.3 and Appendix A](https://www.openmobilealliance.org/tech/affiliates/wap/Technical_June2000-20021106%5B1%5D.zip)
