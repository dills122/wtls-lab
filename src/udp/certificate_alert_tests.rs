use super::*;

#[test]
fn certificate_alert_outbound_budget_preserves_the_original_diagnostic() {
    let remote = "127.0.0.1:9203".parse().unwrap();
    let reply = vec![0xc2, 0, 1, 0, 6, 3, 42, 0xc0, 0x0e, 2, 0];
    let size = reply.len();
    let limit = size - 1;
    let adapter = Adapter::new(None, DatagramBudget::new(limit), NonZeroUsize::MIN);

    // The full server flight cannot fit this budget at the UDP entry point.
    // Exercise the outbound event mapping independently of inbound admission.
    let events = adapter.events(
        remote,
        Err(ReceiveError {
            diagnostic: WireError::CertificateRejected,
            reply: Some(reply),
        }),
    );
    assert!(matches!(
        events.as_slice(),
        [
            Event::Diagnostic {
                remote: diagnostic_remote,
                reason: Diagnostic::Protocol(WireError::CertificateRejected),
            },
            Event::Diagnostic {
                remote: outbound_remote,
                reason: Diagnostic::OutboundTooLarge(DatagramTooLarge {
                    size: observed_size,
                    limit: observed_limit,
                }),
            },
        ] if (*diagnostic_remote, *outbound_remote, *observed_size, *observed_limit)
            == (remote, remote, size, limit)
    ));
}
