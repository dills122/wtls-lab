use std::{error::Error, fmt};

/// The selected WAP-199 identifiers and record settings for an established connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiatedParameters {
    pub version: u8,
    pub key_exchange: u8,
    pub bulk_cipher: u8,
    pub mac: u8,
    pub compression: u8,
    pub sequence_mode: u8,
    pub key_refresh: u8,
}

/// The identity verification performed on the remote peer from this endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAuthentication {
    None,
    VerifiedServerCertificate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionInfo {
    pub parameters: NegotiatedParameters,
    pub peer_authentication: PeerAuthentication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertProtection {
    Clear,
    Authenticated,
}

impl fmt::Display for AlertProtection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Clear => "clear and unverified",
            Self::Authenticated => "authenticated",
        })
    }
}

/// Maximum WTLS payload per transport datagram, excluding transport headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramBudget {
    limit: usize,
}

impl DatagramBudget {
    pub fn new(limit: usize) -> Self {
        Self { limit }
    }

    /// Check one complete encoded datagram before an adapter sends it.
    pub fn check(self, datagram: &[u8]) -> Result<(), DatagramTooLarge> {
        self.check_size(datagram.len())
    }

    /// Compare an observed or encoded payload size with this transport budget.
    pub fn check_size(self, size: usize) -> Result<(), DatagramTooLarge> {
        if size > self.limit {
            return Err(DatagramTooLarge {
                size,
                limit: self.limit,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramTooLarge {
    pub size: usize,
    pub limit: usize,
}

impl fmt::Display for DatagramTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WTLS datagram has {} bytes, limit is {}",
            self.size, self.limit
        )
    }
}

impl Error for DatagramTooLarge {}
