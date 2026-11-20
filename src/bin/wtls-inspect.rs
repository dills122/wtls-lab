use std::error::Error;
use std::io::{self, Write};
use std::process::ExitCode;
use std::{env, fs};
use wtls_lab::wire::{
    KeyExchangeOffer, KeyIdentifier, decode_alert_fields, decode_client_hello, decode_server_hello,
};
use wtls_lab::{CipherSpec, DecodeError, RecordEnvelope, RecordType, decode_record_envelope};

#[path = "wtls-inspect/timeline.rs"]
mod timeline;

const USAGE: &str = "usage: wtls-inspect <datagram.hex> | wtls-inspect --timeline <capture.trace>";

fn main() -> ExitCode {
    match inspect_fixture() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("wtls-inspect: {error}");
            ExitCode::FAILURE
        }
    }
}

fn inspect_fixture() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let first = args.next().ok_or(USAGE)?;
    let timeline = first == "--timeline";
    let path = if timeline {
        args.next().ok_or(USAGE)?
    } else {
        first
    };
    if args.next().is_some() {
        return Err(USAGE.into());
    }

    let fixture = fs::read_to_string(path)?;
    let mut output = io::stdout().lock();
    if timeline {
        timeline::print_timeline(&mut output, &fixture)
    } else {
        inspect_datagram(&mut output, &parse_hex_fixture(&fixture)?, None)
    }
}

fn inspect_datagram(
    output: &mut impl Write,
    datagram: &[u8],
    client_offers: Option<&[u8]>,
) -> Result<(), Box<dyn Error>> {
    let mut offset = 0;
    loop {
        let remaining = &datagram[offset..];
        let record = match decode_record_envelope(remaining) {
            Ok(record) => record,
            Err(kind) => {
                output.flush()?;
                return Err(format!(
                    "{}; remaining={}",
                    DecodeError { offset, kind },
                    hex(remaining)
                )
                .into());
            }
        };
        print_record(output, offset, record, client_offers)?;
        offset += record.wire_len();
        if offset == datagram.len() {
            break;
        }
    }
    Ok(())
}

fn print_record(
    output: &mut impl Write,
    offset: usize,
    record: RecordEnvelope<'_>,
    client_offers: Option<&[u8]>,
) -> io::Result<()> {
    let content_type = record.content_type();
    let type_name = content_type.map_or_else(
        |_| format!("unknown({})", record.header_byte() & 0x0f),
        |kind| kind.to_string(),
    );
    let sequence = record
        .sequence
        .map_or_else(|| "absent".into(), |seq| seq.to_string());
    writeln!(
        output,
        "offset={offset} type={type_name} flags=0x{:02x} seq={sequence} length={} length-form={} cipher={}",
        record.header_byte(),
        record.fragment.len(),
        record.length_form,
        record.cipher_spec(),
    )?;

    if record.cipher_spec() == CipherSpec::Null {
        match content_type {
            Ok(RecordType::Alert) => print_alert(output, record.fragment)?,
            Ok(RecordType::Handshake) if record.fragment.first() == Some(&1) => {
                print_client_hello(output, record.fragment)?;
            }
            Ok(RecordType::Handshake) if record.fragment.first() == Some(&2) => {
                print_server_hello(output, record.fragment, client_offers)?;
            }
            _ => {}
        }
    }
    if let Err(kind) = record.check_datagram_header() {
        writeln!(output, "  profile=reject reason={kind}")?;
    }
    Ok(())
}

fn print_alert(output: &mut impl Write, fragment: &[u8]) -> io::Result<()> {
    match decode_alert_fields(fragment) {
        Ok(alert) => writeln!(
            output,
            "  alert level={} description={} checksum={}",
            label(alert.level, &["unknown", "warning", "critical", "fatal"]),
            format_args!(
                "{}({})",
                alert.description_name().unwrap_or("code"),
                alert.description
            ),
            hex(&alert.checksum)
        ),
        Err(error) => writeln!(output, "  alert error={error} fragment={}", hex(fragment)),
    }
}

fn print_client_hello(output: &mut impl Write, fragment: &[u8]) -> io::Result<()> {
    let hello = match decode_client_hello(fragment) {
        Ok(hello) => hello,
        Err(error) => {
            return writeln!(
                output,
                "  client-hello error={error} fragment={}",
                hex(fragment)
            );
        }
    };
    writeln!(
        output,
        "  client-hello version={} session-id-length={} sequence-mode={} key-refresh={}",
        hello.version,
        hello.session_id.len(),
        hello.sequence_mode,
        hello.key_refresh,
    )?;
    let exchanges = labels(
        hello
            .key_exchanges
            .iter()
            .map(|offer| label(offer.suite, KEY_EXCHANGES)),
    );
    let trusted = labels(
        hello
            .trusted_keys
            .iter()
            .map(|offer| label(offer.suite, KEY_EXCHANGES)),
    );
    let ciphers = labels(
        hello
            .cipher_suites
            .iter()
            .map(|&[cipher, mac]| format!("{}/{}", label(cipher, CIPHERS), label(mac, MACS))),
    );
    let compression = labels(hello.compression.iter().map(|&code| label(code, &["null"])));
    writeln!(
        output,
        "  key-exchanges={exchanges} trusted-keys={trusted} cipher-suites={ciphers} compression={compression}",
    )?;
    for (list, offers) in [
        ("key", &hello.key_exchanges),
        ("trusted-key", &hello.trusted_keys),
    ] {
        for (index, offer) in offers.iter().enumerate() {
            print_key_offer(output, list, index + 1, offer)?;
        }
    }
    if let Some(reason) = hello.profile_mismatch() {
        writeln!(output, "  profile=reject reason={reason}")?;
    }
    Ok(())
}

fn print_server_hello(
    output: &mut impl Write,
    fragment: &[u8],
    client_offers: Option<&[u8]>,
) -> io::Result<()> {
    let hello = match decode_server_hello(fragment) {
        Ok(hello) => hello,
        Err(error) => {
            return writeln!(
                output,
                "  server-hello error={error} fragment={}",
                hex(fragment)
            );
        }
    };
    let key = hello
        .key_exchange_index
        .checked_sub(1)
        .and_then(|index| client_offers?.get(usize::from(index)))
        .map_or_else(
            || "unresolved".to_owned(),
            |&suite| label(suite, KEY_EXCHANGES),
        );
    let [cipher, mac] = hello.cipher_suite;
    writeln!(
        output,
        "  server-hello version={} session-id-length={} client-key-id={} key-exchange={key} cipher-suite={}/{} compression={} sequence-mode={} key-refresh={}",
        hello.version,
        hello.session_id.len(),
        hello.key_exchange_index,
        label(cipher, CIPHERS),
        label(mac, MACS),
        label(hello.compression, &["null"]),
        hello.sequence_mode,
        hello.key_refresh,
    )
}

fn print_key_offer(
    output: &mut impl Write,
    list: &str,
    index: usize,
    offer: &KeyExchangeOffer<'_>,
) -> io::Result<()> {
    let identifier = match offer.identifier {
        KeyIdentifier::Null => "null".into(),
        KeyIdentifier::Text {
            character_set,
            name,
        } => format!("text({character_set}):{}", hex(name)),
        KeyIdentifier::Binary(bytes) => format!("binary:{}", hex(bytes)),
        KeyIdentifier::KeyHash(hash) => format!("sha1:{}", hex(&hash)),
        KeyIdentifier::X509Name(name) => format!("x509:{}", hex(name)),
    };
    write!(
        output,
        "  {list}[{index}] parameter-index={} identifier={identifier}",
        offer.parameter_index
    )?;
    if let Some(parameters) = offer.explicit_parameters {
        write!(output, " parameter-bytes={}", hex(parameters))?;
    }
    writeln!(output)
}

const KEY_EXCHANGES: &[&str] = &[
    "null",
    "shared-secret",
    "dh-anon",
    "dh-anon-512",
    "dh-anon-768",
    "rsa-anon",
    "rsa-anon-512",
    "rsa-anon-768",
    "rsa",
    "rsa-512",
    "rsa-768",
    "ecdh-anon",
    "ecdh-anon-113",
    "ecdh-anon-131",
    "ecdh-ecdsa",
    "ecdh-anon-uncomp",
    "ecdh-anon-uncomp-113",
    "ecdh-anon-uncomp-131",
    "ecdh-ecdsa-uncomp",
];
const CIPHERS: &[&str] = &[
    "null",
    "rc5-cbc-40",
    "rc5-cbc-56",
    "rc5-cbc",
    "des-cbc-40",
    "des-cbc",
    "3des-cbc-ede",
    "idea-cbc-40",
    "idea-cbc-56",
    "idea-cbc",
];
const MACS: &[&str] = &[
    "sha-0",
    "sha-40",
    "sha-80",
    "sha-160",
    "sha-xor-40",
    "md5-40",
    "md5-80",
    "md5-128",
];

fn label(code: u8, names: &[&str]) -> String {
    let name = names.get(usize::from(code)).unwrap_or(&"unknown");
    format!("{name}({code})")
}

fn labels(values: impl Iterator<Item = String>) -> String {
    values.collect::<Vec<_>>().join(",")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut formatted = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(formatted, "{byte:02x}").expect("writing to a string cannot fail");
    }
    formatted
}

fn parse_hex_fixture(fixture: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    for (line_index, line) in fixture.lines().enumerate() {
        let data = line.split_once('#').map_or(line, |(data, _)| data);
        for token in data.split_ascii_whitespace() {
            bytes.push(
                parse_hex_byte(token)
                    .map_err(|error| format!("line {} {error}", line_index + 1))?,
            );
        }
    }
    Ok(bytes)
}

fn parse_hex_byte(token: &str) -> Result<u8, String> {
    u8::from_str_radix(token, 16)
        .ok()
        .filter(|_| token.len() == 2 && !token.starts_with('+'))
        .ok_or_else(|| format!("expected a two-digit hex byte, got {token:?}"))
}
