use std::ops::RangeInclusive;

use openssl::bn::BigNum;
use openssl::memcmp;
use openssl::pkey::{HasPublic, Private, Public};
use openssl::rsa::{Padding, Rsa, RsaRef};
use openssl::sha::sha1;

use super::WireError;
use super::codec::{Reader, write_vector};

const RSA_CERTIFICATE_PREFIX: &[u8] = &[1, 2]; // certificate version and rsa_sha
const RSA_KEY_PREFIX: &[u8] = &[2, 0]; // RSA public key, no parameters
const UTF8_TEXT_IDENTIFIER: &[u8] = &[1, 0, 106];

/// One out-of-band RSA CA key and the exact expected WTLS subject identity.
#[derive(Clone)]
pub struct TrustAnchor {
    issuer: String,
    subject: String,
    key: Rsa<Public>,
}

impl TrustAnchor {
    pub fn new(issuer: &str, subject: &str, key: Rsa<Public>) -> Result<Self, WireError> {
        check_rsa_key(&key)?;
        Ok(Self {
            issuer: issuer.to_owned(),
            subject: subject.to_owned(),
            key,
        })
    }

    pub(super) fn authority_id(&self) -> [u8; 20] {
        authority_id(&self.key)
    }

    pub(super) fn verify(&self, certificate: &[u8], now: u32) -> Result<VerifiedLeaf, WireError> {
        let certificate = parse(certificate).map_err(|_| WireError::CertificateRejected)?;
        if certificate.subject != self.subject || !certificate.validity.contains(&now) {
            return Err(WireError::CertificateRejected);
        }
        certificate.verify_issuer(&self.issuer, &self.key)?;
        Ok(VerifiedLeaf {
            key: certificate.key,
            validity: certificate.validity,
        })
    }
}

pub(super) struct VerifiedLeaf {
    pub(super) key: Rsa<Public>,
    pub(super) validity: RangeInclusive<u32>,
}

#[derive(Clone)]
pub struct ServerIdentity {
    pub(super) certificate: Vec<u8>,
    pub(super) key: Rsa<Private>,
    pub(super) validity: RangeInclusive<u32>,
    pub(super) authority_id: Option<[u8; 20]>,
}

impl ServerIdentity {
    pub fn new(certificate: Vec<u8>, key: Rsa<Private>) -> Result<Self, WireError> {
        Self::bind(certificate, key, None)
    }

    /// Opt into authority-based selection using the issuing RSA public key.
    /// Checks the native leaf's issuer, signature and binding to the gateway key.
    pub fn provisioned(
        certificate: Vec<u8>,
        key: Rsa<Private>,
        issuer: &str,
        authority: Rsa<Public>,
    ) -> Result<Self, WireError> {
        check_rsa_key(&authority)?;
        Self::bind(certificate, key, Some((issuer, &authority)))
    }

    fn bind(
        certificate: Vec<u8>,
        key: Rsa<Private>,
        authority: Option<(&str, &RsaRef<Public>)>,
    ) -> Result<Self, WireError> {
        check_rsa_key(&key)?;
        let leaf = parse(&certificate).map_err(|_| WireError::CertificateRejected)?;
        if leaf.key.n() != key.n() || leaf.key.e() != key.e() {
            return Err(WireError::CertificateRejected);
        }
        let authority_id = if let Some((issuer, authority)) = authority {
            leaf.verify_issuer(issuer, authority)?;
            Some(authority_id(authority))
        } else {
            None
        };
        let validity = leaf.validity;
        Ok(Self {
            certificate,
            key,
            validity,
            authority_id,
        })
    }
}

/// Issue a compact WTLS RSA leaf for an isolated lab. The authority key is
/// provisioned on the client separately and stays outside the handshake.
pub fn issue_certificate(
    issuer: &str,
    subject: &str,
    validity: RangeInclusive<u32>,
    authority: &RsaRef<Private>,
    server: &RsaRef<Public>,
) -> Result<Vec<u8>, WireError> {
    check_rsa_key(authority)?;
    check_rsa_key(server)?;
    if validity.is_empty() {
        return Err(WireError::CertificateRejected);
    }
    let mut tbs = RSA_CERTIFICATE_PREFIX.to_vec();
    write_identifier(&mut tbs, issuer)?;
    tbs.extend_from_slice(&validity.start().to_be_bytes());
    tbs.extend_from_slice(&validity.end().to_be_bytes());
    write_identifier(&mut tbs, subject)?;
    tbs.extend_from_slice(RSA_KEY_PREFIX);
    write_rsa_key(&mut tbs, server)?;

    let mut signature = vec![0; authority.size() as usize];
    let len = authority.private_encrypt(&sha1(&tbs), &mut signature, Padding::PKCS1)?;
    write_vector(&mut tbs, &signature[..len])?;
    Ok(tbs)
}

struct Leaf<'a> {
    tbs: &'a [u8],
    issuer: &'a str,
    subject: &'a str,
    validity: RangeInclusive<u32>,
    key: Rsa<Public>,
    signature: &'a [u8],
}

impl Leaf<'_> {
    fn verify_issuer(&self, issuer: &str, key: &RsaRef<Public>) -> Result<(), WireError> {
        if self.issuer != issuer || self.signature.len() != key.size() as usize {
            return Err(WireError::CertificateRejected);
        }
        // WTLS rsa_sha signs the raw SHA-1 digest with PKCS #1 block type 1.
        let mut digest = vec![0; key.size() as usize];
        let len = key
            .public_decrypt(self.signature, &mut digest, Padding::PKCS1)
            .map_err(|_| WireError::CertificateRejected)?;
        if len != 20 || !memcmp::eq(&digest[..len], &sha1(self.tbs)) {
            return Err(WireError::CertificateRejected);
        }
        Ok(())
    }
}

fn authority_id(key: &RsaRef<Public>) -> [u8; 20] {
    // WAP-199_105 hashes the unsigned modulus, with no DER sign octet.
    sha1(&key.n().to_vec())
}

fn parse(data: &[u8]) -> Result<Leaf<'_>, WireError> {
    let mut input = Reader::new(data);
    input.profile(RSA_CERTIFICATE_PREFIX)?;
    let issuer = read_identifier(&mut input)?;
    let start = u32::from_be_bytes(input.array()?);
    let end = u32::from_be_bytes(input.array()?);
    let subject = read_identifier(&mut input)?;
    input.profile(RSA_KEY_PREFIX)?;

    let exponent = read_integer(&mut input)?;
    let modulus = read_integer(&mut input)?;
    let key = Rsa::from_public_components(modulus, exponent)?;
    check_rsa_key(&key)?;

    let tbs = &data[..data.len() - input.rest().len()];
    let signature = input.vector()?;
    input.end()?;
    if signature.is_empty() || start > end {
        return Err(WireError::CertificateRejected);
    }
    Ok(Leaf {
        tbs,
        issuer,
        subject,
        validity: start..=end,
        key,
        signature,
    })
}

fn read_integer(input: &mut Reader<'_>) -> Result<BigNum, WireError> {
    let value = input.vector()?;
    if value.is_empty() || value[0] == 0 || value.len() > 512 {
        return Err(WireError::CertificateRejected);
    }
    Ok(BigNum::from_slice(value)?)
}

fn write_identifier(out: &mut Vec<u8>, name: &str) -> Result<(), WireError> {
    let length = u8::try_from(name.len()).map_err(|_| WireError::CertificateRejected)?;
    if length == 0 {
        return Err(WireError::CertificateRejected);
    }
    out.extend_from_slice(UTF8_TEXT_IDENTIFIER);
    out.push(length);
    out.extend_from_slice(name.as_bytes());
    Ok(())
}

fn read_identifier<'a>(input: &mut Reader<'a>) -> Result<&'a str, WireError> {
    input.profile(UTF8_TEXT_IDENTIFIER)?;
    let length = usize::from(input.byte()?);
    if length == 0 {
        return Err(WireError::CertificateRejected);
    }
    std::str::from_utf8(input.take(length)?).map_err(|_| WireError::CertificateRejected)
}

fn check_rsa_key(key: &RsaRef<impl HasPublic>) -> Result<(), WireError> {
    if !(1024..=4096).contains(&key.n().num_bits()) || key.e().num_bits() > 32 {
        return Err(WireError::CertificateRejected);
    }
    Ok(())
}

/// WAP-199 RSAPublicKey octets also follow the secret in the RSA premaster.
pub(super) fn write_rsa_key(
    out: &mut Vec<u8>,
    key: &RsaRef<impl HasPublic>,
) -> Result<(), WireError> {
    write_vector(out, &key.e().to_vec())?;
    write_vector(out, &key.n().to_vec())
}
