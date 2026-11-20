use std::error::Error;
use std::io::Write;

use wtls_lab::wire::{ClientHello, DatagramBudget, decode_client_hello};
use wtls_lab::{CipherSpec, RecordType, decode_record_envelope};

use super::{inspect_datagram, parse_hex_byte};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Client,
    Server,
}

enum Observation {
    Datagram(Vec<u8>),
    Dropped(usize),
    OverLimit { size: usize, limit: usize },
}

struct Entry {
    elapsed_us: u64,
    direction: Direction,
    observation: Observation,
}

impl Entry {
    fn parse(line: &str) -> Result<Self, Box<dyn Error>> {
        let mut fields = line.split_ascii_whitespace();
        let elapsed_us = fields.next().ok_or("missing elapsed time")?.parse()?;
        let direction = match fields.next() {
            Some("client") => Direction::Client,
            Some("server") => Direction::Server,
            _ => return Err("expected client or server direction".into()),
        };
        let observation = match fields.next() {
            Some("datagram") => {
                let bytes = fields
                    .by_ref()
                    .map(parse_hex_byte)
                    .collect::<Result<Vec<_>, _>>()?;
                if bytes.is_empty() {
                    return Err("missing datagram bytes".into());
                }
                Observation::Datagram(bytes)
            }
            Some("dropped") => {
                Observation::Dropped(fields.next().ok_or("missing payload size")?.parse()?)
            }
            Some("over-limit") => {
                let size = fields.next().ok_or("missing payload size")?.parse()?;
                let limit = fields.next().ok_or("missing datagram limit")?.parse()?;
                if DatagramBudget::new(limit).check_size(size).is_ok() {
                    return Err("the payload size must exceed the reported limit".into());
                }
                Observation::OverLimit { size, limit }
            }
            _ => return Err("expected datagram, dropped, or over-limit observation".into()),
        };
        if fields.next().is_some() {
            return Err("unexpected extra fields".into());
        }
        Ok(Self {
            elapsed_us,
            direction,
            observation,
        })
    }
}

struct ClientFlight {
    event: usize,
    elapsed_us: u64,
    bytes: Vec<u8>,
    key_exchanges: Vec<u8>,
}

fn clear_client_hello(bytes: &[u8]) -> Option<ClientHello<'_>> {
    let record = decode_record_envelope(bytes).ok()?;
    if record.cipher_spec() != CipherSpec::Null
        || record.content_type().ok()? != RecordType::Handshake
    {
        return None;
    }
    decode_client_hello(record.fragment).ok()
}

pub(super) fn print_timeline(output: &mut impl Write, trace: &str) -> Result<(), Box<dyn Error>> {
    let mut last_elapsed_us = 0;
    let mut client_flight: Option<ClientFlight> = None;
    let mut event = 0;
    for (index, line) in trace.lines().enumerate() {
        let line = line.split_once('#').map_or(line, |(data, _)| data).trim();
        if line.is_empty() {
            continue;
        }
        let entry = Entry::parse(line).map_err(|err| format!("trace line {}: {err}", index + 1))?;
        let Entry {
            elapsed_us,
            direction,
            observation,
        } = entry;
        if elapsed_us < last_elapsed_us {
            return Err(format!("trace line {}: elapsed time decreased", index + 1).into());
        }
        last_elapsed_us = elapsed_us;
        event += 1;
        let direction_label = match direction {
            Direction::Client => "client",
            Direction::Server => "server",
        };
        write!(
            output,
            "event={event} elapsed-us={elapsed_us} direction={direction_label}"
        )?;
        match observation {
            Observation::Datagram(bytes) => {
                write!(output, " payload-bytes={} delivery=captured", bytes.len())?;
                let result = match direction {
                    Direction::Client => {
                        let hello = clear_client_hello(&bytes);
                        let duplicate = client_flight
                            .as_ref()
                            .filter(|flight| flight.bytes == bytes);
                        if let Some(previous) = duplicate {
                            writeln!(
                                output,
                                " repeat-of={} elapsed-since-original-us={}",
                                previous.event,
                                elapsed_us - previous.elapsed_us
                            )?;
                        } else {
                            writeln!(output)?;
                        }
                        let result = inspect_datagram(output, &bytes, None);
                        if result.is_ok()
                            && duplicate.is_none()
                            && let Some(hello) = hello
                        {
                            client_flight = Some(ClientFlight {
                                event,
                                elapsed_us,
                                key_exchanges: hello
                                    .key_exchanges
                                    .into_iter()
                                    .map(|offer| offer.suite)
                                    .collect(),
                                bytes,
                            });
                        }
                        result
                    }
                    Direction::Server => {
                        writeln!(output)?;
                        let offers = client_flight
                            .as_ref()
                            .map(|flight| flight.key_exchanges.as_slice());
                        inspect_datagram(output, &bytes, offers)
                    }
                };
                result.map_err(|err| format!("trace line {}: {err}", index + 1))?;
            }
            Observation::Dropped(size) => {
                writeln!(output, " payload-bytes={size} delivery=relay-dropped")?;
            }
            Observation::OverLimit { size, limit } => {
                writeln!(
                    output,
                    " payload-bytes={size} delivery=relay-over-limit limit={limit}"
                )?;
            }
        }
    }
    if event == 0 {
        return Err("trace has no observations".into());
    }
    Ok(())
}
