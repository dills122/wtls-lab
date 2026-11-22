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

fn timeline_at(path: &Path) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_wtls-inspect"))
        .arg("--timeline")
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

fn timeline(fixture: &str) -> String {
    timeline_at(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join(fixture),
    )
}

fn repeat_events(output: &str) -> Vec<&str> {
    output
        .lines()
        .filter(|line| line.starts_with("event=") && line.contains(" repeat-of="))
        .collect()
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

#[test]
fn timeline_matches_blackberry_commit_repeats() {
    let final_drop = timeline("blackberry-7290-kwtls-drop-final.trace");
    assert!(final_drop.lines().any(|line| line
        == "event=4 elapsed-us=16131271 direction=server payload-bytes=51 delivery=relay-dropped"));
    assert_eq!(
        repeat_events(&final_drop),
        [
            "event=5 elapsed-us=22504230 direction=client payload-bytes=189 delivery=captured repeat-of=3 elapsed-since-original-us=6375935",
            "event=6 elapsed-us=28678999 direction=client payload-bytes=189 delivery=captured repeat-of=3 elapsed-since-original-us=12550704",
            "event=7 elapsed-us=34932264 direction=client payload-bytes=189 delivery=captured repeat-of=3 elapsed-since-original-us=18803969",
            "event=8 elapsed-us=41189327 direction=client payload-bytes=189 delivery=captured repeat-of=3 elapsed-since-original-us=25061032",
            "event=9 elapsed-us=47440662 direction=client payload-bytes=189 delivery=captured repeat-of=3 elapsed-since-original-us=31312367",
        ],
    );
}

#[test]
fn timeline_preserves_blackberry_hello_repeats_and_cache_control() {
    let first_drop = timeline("blackberry-7290-kwtls-drop-first.trace");
    assert_eq!(
        repeat_events(&first_drop),
        [
            "event=3 elapsed-us=233133015 direction=client payload-bytes=949 delivery=captured repeat-of=1 elapsed-since-original-us=5617711"
        ],
    );
    assert!(repeat_events(&timeline("blackberry-7290-kwtls-cache-control.trace")).is_empty());
}

#[test]
fn timeline_compares_opaque_commit_bytes_and_resets_on_a_fresh_hello() {
    let capture = include_str!("../fixtures/blackberry-7290-kwtls-drop-final.trace");
    let client_datagram = |line: &'static str| line.split_once(" client datagram ").unwrap().1;
    let hello = client_datagram(capture.lines().next().unwrap());
    let other_capture = include_str!("../fixtures/blackberry-7290-kwtls-drop-first.trace");
    let fresh_hello = client_datagram(other_capture.lines().next().unwrap());
    assert_ne!(fresh_hello, hello);
    let commit = client_datagram(capture.lines().nth(2).unwrap());
    let (prefix, last_byte) = commit.rsplit_once(' ').unwrap();
    let changed_byte = u8::from_str_radix(last_byte, 16).unwrap() ^ 1;
    let trace = format!(
        "10 client datagram {commit}\n\
         20 client datagram {prefix} {changed_byte:02x}\n\
         30 client datagram {commit}\n\
         40 client datagram {hello}\n\
         50 client datagram {commit}\n\
         60 client datagram {hello}\n\
         70 client datagram {commit}\n\
         80 client datagram {fresh_hello}\n\
         90 client datagram {commit}\n\
         100 client datagram {commit}\n"
    );
    let path = Path::new(env!("CARGO_BIN_EXE_wtls-inspect")).with_file_name(format!(
        "inspector-commit-repeat-{}.trace",
        std::process::id(),
    ));
    std::fs::write(&path, trace).unwrap();
    let output = timeline_at(&path);
    std::fs::remove_file(path).unwrap();

    assert_eq!(
        repeat_events(&output),
        [
            "event=3 elapsed-us=30 direction=client payload-bytes=189 delivery=captured repeat-of=1 elapsed-since-original-us=20",
            "event=6 elapsed-us=60 direction=client payload-bytes=949 delivery=captured repeat-of=4 elapsed-since-original-us=20",
            "event=7 elapsed-us=70 direction=client payload-bytes=189 delivery=captured repeat-of=5 elapsed-since-original-us=20",
            "event=10 elapsed-us=100 direction=client payload-bytes=189 delivery=captured repeat-of=9 elapsed-since-original-us=10",
        ],
    );
}
