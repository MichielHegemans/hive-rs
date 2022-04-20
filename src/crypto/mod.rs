pub mod public_key;
pub mod private_key;

use ripemd::{Digest, Ripemd160};
use sha2::Sha256;

/// Hashes the input using ripemd-160
///
/// # Arguments
/// * `input` - Data to hash
fn ripemd160(input: impl AsRef<[u8]>) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Hashes the input using SHA-256
///
/// # Arguments
/// * `input` - Data to hash
fn sha256(input: impl AsRef<[u8]>) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(input);
    hasher.finalize().into()
}

/// Hashes the input using SHA-256 twice
///
/// # Arguments
/// * `input` - Data to hash
fn double_sha256(input: impl AsRef<[u8]>) -> [u8; 32] {
    sha256(sha256(input))
}

pub trait IntoWif {
    fn to_wif(&self) -> String;
}

pub trait FromWif {
    type Err;

    fn from_wif(wif: impl AsRef<[u8]>) -> Result<Self, Self::Err> where Self: Sized;
}

pub enum KeyRole {
    Owner,
    Active,
    Posting,
    Memo,
}

pub(crate) const NETWORK_ID: u8 = 0x80;
pub(crate) const DEFAULT_ADDRESS_PREFIX: [u8; 3] = [b'S', b'T', b'M'];
