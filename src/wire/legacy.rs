use super::codec::{
    EXPLICIT_SEQUENCE, VERSION, decode_client_hello, encode_handshake_with_selection,
};
use super::{NegotiatedParameters, WireError};
use crate::handshake::Message;

pub(super) const RSA_ANON: u8 = 5;
pub(super) const DES_CBC: u8 = 5;
const SHA: u8 = 3;
const MAX_REFRESH: u8 = 2;

pub(super) struct LegacySelection {
    pub(super) parameters: NegotiatedParameters,
    pub(super) client_random: [u8; 16],
    key_exchange_index: u8,
    client_hello: Vec<u8>,
}

impl LegacySelection {
    pub(super) fn select(bytes: &[u8]) -> Result<Self, WireError> {
        let offer = decode_client_hello(bytes)?;
        let key_exchange_index = offer
            .key_exchanges
            .iter()
            .position(|key| key.suite == RSA_ANON && key.parameter_index == 0)
            .and_then(|index| u8::try_from(index + 1).ok())
            .ok_or(WireError::UnsupportedProfile)?;
        if offer.version != VERSION
            || !offer.session_id.is_empty()
            || offer.sequence_mode != EXPLICIT_SEQUENCE
            || !offer.cipher_suites.contains(&[DES_CBC, SHA])
            || !offer.compression.contains(&0)
        {
            return Err(WireError::UnsupportedProfile);
        }
        Ok(Self {
            parameters: NegotiatedParameters {
                version: VERSION,
                key_exchange: RSA_ANON,
                bulk_cipher: DES_CBC,
                mac: SHA,
                compression: 0,
                sequence_mode: EXPLICIT_SEQUENCE,
                key_refresh: offer.key_refresh.min(MAX_REFRESH),
            },
            client_random: offer.random,
            key_exchange_index,
            client_hello: bytes.to_vec(),
        })
    }

    pub(super) fn encode(&self, message: &Message) -> Result<Vec<u8>, WireError> {
        if matches!(message, Message::ClientHello { .. }) {
            // The peer hashes its original offer, including order and unused choices.
            return Ok(self.client_hello.clone());
        }
        encode_handshake_with_selection(message, self.parameters, self.key_exchange_index)
    }
}
