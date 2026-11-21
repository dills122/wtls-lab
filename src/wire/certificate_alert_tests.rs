use std::num::NonZeroU64;

use super::alert_tests::{NOW, credentials, send};
use super::*;

#[test]
fn certificate_alert_provider_failure_returns_diagnostic_only() {
    let (trust, identity) = credentials();
    let retry = RetryPolicy {
        timeout_ms: NonZeroU64::new(10).unwrap(),
        max_retries: 2,
    };
    let mut client = WirePeer::provisioned_client(retry, trust, NOW);
    let mut server = WirePeer::server(identity, NOW).unwrap();
    let hello = send(&client.start(0).unwrap());
    let flight = send(&server.receive(&hello, 1).unwrap());

    let mut attempted = false;
    let rejected = client.receive_with_certificate_check(&flight, 2, |trust, certificate, now| {
        trust.verify_provisioned(certificate, now, |_, _, _| {
            attempted = true;
            Err(WireError::Provider)
        })
    });
    assert!(attempted);
    assert_eq!(
        rejected,
        Err(ReceiveError {
            diagnostic: WireError::CertificateRejected,
            reply: None,
        })
    );
    assert_eq!(client.status(), Status::Closed);
    assert_eq!(client.deadline(), None);
    assert!(client.traffic.is_none());
    assert!(client.session.is_none());
    assert_eq!(client.receive_with_reply(&flight, 3), Ok(vec![]));
    assert_eq!(client.tick(30), Ok(vec![]));
}
