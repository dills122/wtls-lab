use super::NegotiatedParameters;
use super::codec::{EXPLICIT_SEQUENCE, VERSION};

pub(super) const RSA_ANON: u8 = 5;
pub(super) const DES_CBC: u8 = 5;
const SHA: u8 = 3;
pub(super) const WINWAP_PARAMETERS: NegotiatedParameters = NegotiatedParameters {
    version: VERSION,
    key_exchange: RSA_ANON,
    bulk_cipher: DES_CBC,
    mac: SHA,
    compression: 0,
    sequence_mode: EXPLICIT_SEQUENCE,
    key_refresh: 2,
};
