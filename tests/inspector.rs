use std::path::Path;
use std::process::Command;

fn inspect(fixture: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(fixture);
    let output = Command::new(env!("CARGO_BIN_EXE_wtls-inspect"))
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn inspector_distinguishes_the_two_length_forms() {
    let implicit = inspect("hello-request-implicit.hex");
    let explicit = inspect("hello-request-explicit.hex");

    assert_eq!(
        implicit,
        "offset=0 type=handshake flags=0x43 seq=0 length=3 length-form=datagram-remainder cipher=null\n"
    );
    assert_eq!(
        explicit,
        "offset=0 type=handshake flags=0xc3 seq=0 length=3 length-form=explicit cipher=null\n"
    );
}

#[test]
fn inspector_prints_each_record_with_its_own_offset() {
    assert_eq!(
        inspect("concatenated.hex"),
        concat!(
            "offset=0 type=handshake flags=0xc3 seq=0 length=3 length-form=explicit cipher=null\n",
            "offset=8 type=application-data flags=0xe4 seq=1 length=3 length-form=explicit cipher=current\n",
        )
    );
}

#[test]
fn inspector_reports_the_actual_kannel_alert_and_profile_problem() {
    let output = inspect("kannel-handshake-failure.hex");
    assert!(output.contains("type=alert flags=0x82 seq=absent length=6"));
    assert!(output.contains("level=fatal(3) description=handshake-failure(40) checksum=30303030"));
    assert!(
        output.contains(
            "profile=reject reason=datagram record is missing its explicit sequence field"
        )
    );
}

#[test]
fn inspector_reports_winwap_offers_in_order_even_when_the_profile_rejects_them() {
    let output = inspect("winwap-client-hello.hex");
    assert!(output.contains("offset=0 type=handshake flags=0xc3 seq=0 length=119"));
    assert!(
        output
            .contains("client-hello version=1 session-id-length=0 sequence-mode=2 key-refresh=16")
    );
    assert!(output.contains(
        "key-exchanges=rsa-anon(5),rsa-anon-768(7),rsa-anon-512(6),dh-anon-768(4),dh-anon-512(3)"
    ));
    assert!(output.contains("cipher-suites=3des-cbc-ede(6)/sha-160(3),3des-cbc-ede(6)/sha-80(2),3des-cbc-ede(6)/sha-40(1),des-cbc(5)/sha-160(3),des-cbc(5)/sha-80(2),des-cbc(5)/sha-40(1),null(0)/sha-160(3)"));
    assert!(
        output
            .contains("profile=reject reason=no compatible default-parameter key exchange offered")
    );
}

#[test]
fn inspector_reports_the_blackberry_offer_without_rejecting_the_authenticated_profile() {
    let output = inspect("blackberry-7290-client-hello.hex");
    assert!(
        output.contains("client-hello version=1 session-id-length=0 sequence-mode=2 key-refresh=5")
    );
    assert!(output.contains("key-exchanges=rsa(8),"));
    assert!(output.contains("  key[1] parameter-index=0 identifier=binary:"));
    assert!(output.contains("  trusted-key[1] parameter-index=0 identifier=sha1:"));
    assert!(!output.contains("profile=reject"));
}

#[test]
fn inspector_keeps_the_valid_prefix_and_reports_unparsed_bytes() {
    let output = Command::new(env!("CARGO_BIN_EXE_wtls-inspect"))
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/truncated-following-record.hex"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("offset=0 type=handshake")
    );
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("byte 8: truncated record fragment (declares 4 bytes, has 2)"));
    assert!(error.contains("remaining=c3000100041400"));
}

#[test]
fn both_capture_fixtures_remain_outside_the_engine_profile() {
    use wtls_lab::wire::{WireError, decode_handshake};
    use wtls_lab::{DecodeErrorKind, decode_datagram};

    let load = |fixture: &str| {
        fixture
            .lines()
            .flat_map(|line| line.split('#').next().unwrap().split_whitespace())
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect::<Vec<_>>()
    };
    let alert = load(include_str!("../fixtures/kannel-handshake-failure.hex"));
    assert_eq!(
        decode_datagram(&alert).unwrap_err().kind,
        DecodeErrorKind::MissingSequence,
    );
    let hello = load(include_str!("../fixtures/winwap-client-hello.hex"));
    let records = decode_datagram(&hello).unwrap();
    assert_eq!(
        decode_handshake(records[0].fragment),
        Err(WireError::UnsupportedProfile),
    );
}

fn timeline(fixture: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_wtls-inspect"))
        .arg("--timeline")
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures")
                .join(fixture),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn timeline_shows_winwap_kannel_negotiation_and_datagram_sizes() {
    let output = timeline("winwap-kannel-9203.trace");
    assert!(output.contains("direction=client payload-bytes=124"));
    assert!(output.contains("direction=server payload-bytes=313"));
    assert!(output.contains("direction=client payload-bytes=315"));
    assert!(output.contains("client-key-id=1 key-exchange=rsa-anon(5)"));
    assert!(output.contains("cipher-suite=des-cbc(5)/sha-160(3)"));
    assert!(output.contains("sequence-mode=2 key-refresh=2"));
    assert!(output.contains("type=change-cipher-spec"));
    assert!(output.contains("type=handshake flags=0xe3"));
}

#[test]
fn timeline_distinguishes_observed_retries_alerts_and_relay_dispositions() {
    let lost = timeline("winwap-kannel-9202-retry.trace");
    assert!(lost.contains("direction=server payload-bytes=313 delivery=relay-dropped"));
    assert!(lost.contains("repeat-of=1 elapsed-since-original-us=5001253"));
    assert!(lost.contains("description=unexpected-message(10)"));

    let limited = timeline("winwap-kannel-9203-retry.trace");
    assert!(
        limited.contains("direction=server payload-bytes=313 delivery=relay-over-limit limit=300")
    );
    assert!(limited.contains("repeat-of=1 elapsed-since-original-us=4991702"));
    assert!(limited.contains("description=unexpected-message(10)"));
}
