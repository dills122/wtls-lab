use openssl::encrypt::{Decrypter, Encrypter};
use openssl::hash::{Hasher, MessageDigest};
use openssl::memcmp;
use openssl::pkey::{HasPublic, PKey, Private, Public};
use openssl::rand::rand_bytes;
use openssl::rsa::{Padding, Rsa, RsaRef};
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};
use zeroize::Zeroizing;

use super::certificate::write_rsa_key;
use super::codec::{FIXED_PARAMETERS, VERSION, encode_handshake};
use super::legacy::{DES_CBC, LegacySelection};
use super::{NegotiatedParameters, WireError};
use crate::Record;
use crate::handshake::{FinishedData, FinishedProvider, Message, Role};

const BLOCK_SIZE: usize = 8;
const MAC_SIZE: usize = 20;
const KEY_BLOCK_SIZE: usize = MAC_SIZE + 24 + BLOCK_SIZE;
pub(super) const MAX_PLAINTEXT: usize =
    (u16::MAX as usize / BLOCK_SIZE) * BLOCK_SIZE - MAC_SIZE - 1;

pub(super) struct Traffic {
    master: Zeroizing<[u8; 20]>,
    client_random: [u8; 16],
    server_random: [u8; 16],
    parameters: NegotiatedParameters,
}

impl Traffic {
    fn from_secret(
        secret: &[u8],
        key: &RsaRef<impl HasPublic>,
        client_random: [u8; 16],
        server_random: [u8; 16],
        parameters: NegotiatedParameters,
    ) -> Result<Self, WireError> {
        let mut premaster = Zeroizing::new(secret.to_vec());
        write_rsa_key(&mut premaster, key)?;
        let master = prf::<20>(
            &premaster,
            b"master secret",
            &[&client_random, &server_random],
        )?;
        Ok(Self {
            master,
            client_random,
            server_random,
            parameters,
        })
    }

    pub(super) fn begin_client(
        key: &Rsa<Public>,
        client_random: [u8; 16],
        server_random: [u8; 16],
    ) -> Result<(Vec<u8>, Self), WireError> {
        let mut secret = Zeroizing::new([0u8; 20]);
        secret[0] = VERSION;
        rand_bytes(&mut secret[1..])?;
        let pkey = PKey::from_rsa(key.clone())?;
        let mut encrypt = Encrypter::new(&pkey)?;
        encrypt.set_rsa_padding(Padding::PKCS1)?;
        let mut ciphertext = vec![0u8; key.size() as usize];
        let len = encrypt.encrypt(&secret[..], &mut ciphertext)?;
        ciphertext.truncate(len);

        Ok((
            ciphertext,
            Self::from_secret(
                &secret[..],
                key,
                client_random,
                server_random,
                FIXED_PARAMETERS,
            )?,
        ))
    }

    pub(super) fn begin_server(
        ciphertext: &[u8],
        key: &Rsa<Private>,
        client_random: [u8; 16],
        server_random: [u8; 16],
        parameters: Option<NegotiatedParameters>,
    ) -> Result<Self, WireError> {
        let pkey = PKey::from_rsa(key.clone())?;
        let mut decrypt = Decrypter::new(&pkey)?;
        decrypt.set_rsa_padding(Padding::PKCS1)?;
        let mut secret = Zeroizing::new([0u8; 20]);
        rand_bytes(&mut secret[..])?;
        let mut decrypted = Zeroizing::new(vec![0; key.size() as usize]);

        // Use EVP's default-provider implicit rejection and keep invalid
        // premaster values on the same handshake path.
        if let Ok(20) = decrypt.decrypt(ciphertext, &mut decrypted)
            && decrypted[0] == VERSION
        {
            secret.copy_from_slice(&decrypted[..20]);
        }
        Self::from_secret(
            &secret[..],
            key,
            client_random,
            server_random,
            parameters.unwrap_or(FIXED_PARAMETERS),
        )
    }

    fn finished(
        &self,
        sender: Role,
        transcript: &[Message],
        legacy: Option<&LegacySelection>,
    ) -> Result<FinishedData, WireError> {
        let mut hash = Hasher::new(MessageDigest::sha1())?;
        for message in transcript {
            let bytes = match legacy {
                Some(selection) => selection.encode(message)?,
                None => encode_handshake(message)?,
            };
            hash.update(&bytes)?;
        }
        let digest = hash.finish()?;
        let label: &[u8] = match sender {
            Role::Client => b"client finished",
            Role::Server => b"server finished",
        };
        Ok(*prf::<12>(&self.master[..], label, &[&digest])?)
    }

    fn keys(
        &self,
        sender: Role,
        sequence: u16,
    ) -> Result<Zeroizing<[u8; KEY_BLOCK_SIZE]>, WireError> {
        let label: &[u8] = match sender {
            Role::Client => b"client expansion",
            Role::Server => b"server expansion",
        };
        let refresh = self.parameters.key_refresh;
        let epoch = (sequence >> refresh) << refresh;
        prf(
            &self.master[..],
            label,
            &[
                &epoch.to_be_bytes(),
                &self.server_random,
                &self.client_random,
            ],
        )
    }

    pub(super) fn seal(&self, sender: Role, record: Record<'_>) -> Result<Vec<u8>, WireError> {
        if record.fragment.is_empty() || record.fragment.len() > MAX_PLAINTEXT {
            return Err(WireError::InvalidRecord);
        }
        let keys = self.keys(sender, record.sequence)?;
        let tag = record_mac(&keys[..MAC_SIZE], record, record.fragment)?;
        let mut padded = Zeroizing::new(record.fragment.to_vec());
        padded.extend_from_slice(&tag[..]);
        let padding = BLOCK_SIZE - (padded.len() % BLOCK_SIZE);
        let padded_len = padded.len() + padding;
        padded.resize(padded_len, (padding - 1) as u8);
        Ok(crypt(
            &keys,
            self.parameters.bulk_cipher == DES_CBC,
            record.sequence,
            Mode::Encrypt,
            &padded,
        )?
        .to_vec())
    }

    pub(super) fn open(
        &self,
        sender: Role,
        record: Record<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, WireError> {
        if record.fragment.len() < (MAC_SIZE + 2).next_multiple_of(BLOCK_SIZE)
            || !record.fragment.len().is_multiple_of(BLOCK_SIZE)
        {
            return Err(WireError::AuthenticationFailed);
        }
        let keys = self.keys(sender, record.sequence)?;
        let mut padded = crypt(
            &keys,
            self.parameters.bulk_cipher == DES_CBC,
            record.sequence,
            Mode::Decrypt,
            record.fragment,
        )
        .map_err(|_| WireError::AuthenticationFailed)?;
        let pad_len = usize::from(padded[padded.len() - 1]) + 1;
        let content_len = padded.len().saturating_sub(MAC_SIZE + pad_len);
        let (content, trailer) = padded.split_at(content_len);
        let (tag, padding) = trailer.split_at(MAC_SIZE);
        let expected = record_mac(&keys[..MAC_SIZE], record, content)?;
        if !memcmp::eq(tag, &expected[..])
            || content.is_empty()
            || padding.len() != pad_len
            || padding.iter().any(|&byte| usize::from(byte) != pad_len - 1)
        {
            return Err(WireError::AuthenticationFailed);
        }
        padded[content_len..].fill(0);
        padded.truncate(content_len);
        Ok(padded)
    }
}

pub(super) struct WireFinished<'a>(pub Option<&'a Traffic>, pub Option<&'a LegacySelection>);

impl FinishedProvider for WireFinished<'_> {
    fn create(&self, sender: Role, transcript: &[Message]) -> Option<FinishedData> {
        self.0?.finished(sender, transcript, self.1).ok()
    }

    fn verify(&self, sender: Role, transcript: &[Message], proof: &FinishedData) -> bool {
        self.create(sender, transcript)
            .is_some_and(|expected| memcmp::eq(&expected, proof))
    }
}

fn record_mac(
    key: &[u8],
    record: Record<'_>,
    content: &[u8],
) -> Result<Zeroizing<[u8; MAC_SIZE]>, WireError> {
    let len = u16::try_from(content.len()).map_err(|_| WireError::InvalidRecord)?;
    hmac(
        key,
        &[
            &record.sequence.to_be_bytes(),
            &[record.header_byte()],
            &len.to_be_bytes(),
            content,
        ],
    )
}

fn crypt(
    keys: &[u8; KEY_BLOCK_SIZE],
    single_des: bool,
    sequence: u16,
    mode: Mode,
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, WireError> {
    let key_len = if single_des { 8 } else { 24 };
    let [high, low] = sequence.to_be_bytes();
    let mut iv = Zeroizing::new([0; BLOCK_SIZE]);
    for (index, value) in iv.iter_mut().enumerate() {
        *value =
            keys[MAC_SIZE + key_len + index] ^ if index.is_multiple_of(2) { high } else { low };
    }
    // EDE with all three subkeys equal is single DES. Keep the OpenSSL default
    // provider for this isolated compatibility profile.
    let source = &keys[MAC_SIZE..MAC_SIZE + key_len];
    let mut key = Zeroizing::new([0; 24]);
    for chunk in key.chunks_exact_mut(key_len) {
        chunk.copy_from_slice(source);
    }
    let mut cipher = Crypter::new(Cipher::des_ede3_cbc(), mode, &key[..], Some(&iv[..]))?;
    cipher.pad(false);

    let mut out = Zeroizing::new(vec![0; bytes.len() + BLOCK_SIZE]);
    let len = cipher.update(bytes, &mut out)?;
    let len = len + cipher.finalize(&mut out[len..])?;
    out.truncate(len);
    Ok(out)
}

fn prf<const N: usize>(
    key: &[u8],
    label: &[u8],
    seed: &[&[u8]],
) -> Result<Zeroizing<[u8; N]>, WireError> {
    let mut labeled_seed = vec![label];
    labeled_seed.extend_from_slice(seed);
    let mut a = hmac(key, &labeled_seed)?;
    let mut out = Zeroizing::new([0; N]);
    for chunk in out.chunks_mut(MAC_SIZE) {
        let mut input = vec![&a[..]];
        input.extend_from_slice(&labeled_seed);
        chunk.copy_from_slice(&hmac(key, &input)?[..chunk.len()]);
        a = hmac(key, &[&a[..]])?;
    }
    Ok(out)
}

fn hmac(key: &[u8], data: &[&[u8]]) -> Result<Zeroizing<[u8; MAC_SIZE]>, WireError> {
    let key = PKey::hmac(key)?;
    let mut hmac = Signer::new(MessageDigest::sha1(), &key)?;
    for part in data {
        hmac.update(part)?;
    }
    let mut out = Zeroizing::new([0; MAC_SIZE]);
    if hmac.sign(&mut out[..])? != MAC_SIZE {
        return Err(WireError::Provider);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use openssl::bn::BigNum;

    use super::*;
    use crate::{CipherSpec, LengthForm, RecordType};

    #[test]
    fn single_des_matches_an_openssl_des_cbc_vector() {
        let mut keys = [0u8; KEY_BLOCK_SIZE];
        keys[MAC_SIZE..MAC_SIZE + 8].copy_from_slice(&0x0123_4567_89ab_cdefu64.to_be_bytes());
        keys[MAC_SIZE + 8..MAC_SIZE + 16].copy_from_slice(&0x1234_5678_90ab_cdefu64.to_be_bytes());
        let ciphertext = 0xe5c7_cdde_872b_f27cu64.to_be_bytes();
        assert_eq!(
            &*crypt(&keys, true, 0, Mode::Encrypt, b"Now is t").unwrap(),
            &ciphertext
        );
        assert_eq!(
            &*crypt(&keys, true, 0, Mode::Decrypt, &ciphertext).unwrap(),
            b"Now is t"
        );
    }

    #[test]
    fn rsa_schedule_and_protected_records_match_independent_vectors() {
        // WAP-199 §§9.2.3 and 11. The reference used Python hmac/sha1 for
        // composition and OpenSSL enc -des-ede3-cbc -nopad for the block mode.
        const MASTER: [u8; 20] = [
            0x95, 0xe0, 0x37, 0xbe, 0xf7, 0xbe, 0xf8, 0x5b, 0x57, 0x50, 0xd7, 0x4c, 0x4b, 0x6f,
            0x68, 0x37, 0xe5, 0x73, 0xaf, 0x65,
        ];
        const RECORD_7: [u8; 32] = [
            0xca, 0x5d, 0xba, 0x5b, 0x0a, 0x08, 0x4d, 0xcc, 0x1b, 0x05, 0x53, 0x9c, 0x8a, 0x83,
            0x71, 0x26, 0x18, 0x52, 0x7e, 0x57, 0x59, 0x99, 0xaf, 0x76, 0xe0, 0x5b, 0x21, 0xaa,
            0x0d, 0x36, 0x65, 0x70,
        ];
        const RECORD_8: [u8; 32] = [
            0x17, 0x08, 0x1d, 0xf9, 0x04, 0xbd, 0x1a, 0x5d, 0xf0, 0xb3, 0x15, 0x66, 0xad, 0xf9,
            0x11, 0x9b, 0xf5, 0x51, 0xb6, 0x11, 0x19, 0x9a, 0xf2, 0x79, 0x1d, 0x11, 0xfd, 0xda,
            0x6a, 0xaa, 0x84, 0xab,
        ];

        let client = std::array::from_fn(|index| index as u8);
        let server = std::array::from_fn(|index| index as u8 + 16);
        let mut secret = std::array::from_fn::<_, 20, _>(|index| index as u8);
        secret[0] = VERSION;
        let modulus = BigNum::from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]).unwrap();
        let exponent = BigNum::from_u32(65537).unwrap();
        let key = Rsa::from_public_components(modulus, exponent).unwrap();
        let traffic =
            Traffic::from_secret(&secret, &key, client, server, FIXED_PARAMETERS).unwrap();
        assert_eq!(*traffic.master, MASTER);

        for (sequence, expected) in [(7, &RECORD_7), (8, &RECORD_8)] {
            let record = Record {
                content_type: RecordType::ApplicationData,
                cipher_spec: CipherSpec::Current,
                length_form: LengthForm::Explicit,
                sequence,
                fragment: b"WTLS echo",
            };
            let ciphertext = traffic.seal(Role::Client, record).unwrap();
            assert_eq!(&ciphertext[..], expected);
            let encrypted = Record {
                fragment: expected,
                ..record
            };
            assert_eq!(
                &traffic.open(Role::Client, encrypted).unwrap()[..],
                record.fragment
            );
        }
    }
}
