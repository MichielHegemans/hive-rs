use std::fmt::{Debug, Formatter};
use secp256k1::{
    ecdsa::Signature,
    Message,
};

use crate::crypto::{FromWif, IntoWif, ripemd160};

pub struct PublicKey {
    key: secp256k1::PublicKey,
    prefix: [u8; 3],
}

impl PublicKey {
    pub fn verify(&self, message: &Message, signature: &Signature) -> bool {
        let secp = secp256k1::Secp256k1::new();

        match secp.verify_ecdsa(&message, &signature, &self.key) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl FromWif for PublicKey {
    type Err = PublicKeyWifError;

    fn from_wif(wif: impl AsRef<[u8]>) -> Result<Self, Self::Err> {
        let wif = wif.as_ref();
        /*
        Public key WIF consists of a prefix of 3 bytes, then the base58 encoded public key +
        checksum.

        The size of the key is 33 bytes (compressed) or 65 bytes (uncompressed) and the size of the
        checksum is 4 bytes.

         */

        let mut prefix: [u8; 3] = [0u8; 3];
        let mut checksum: [u8; 4] = [0u8; 4];
        let mut checksum_verify: [u8; 4] = [0u8; 4];

        if wif.len() < 3 {
            return Err(PublicKeyWifError::Invalid);
        }

        prefix.copy_from_slice(&wif[0..3]);
        let decoded = bs58::decode(&wif[3..]).into_vec().map_err(|e| PublicKeyWifError::Decode(e))?;

        let key: &[u8] = match decoded.len() {
            37 => {
                // Compressed case
                checksum.copy_from_slice(&decoded[33..]);
                &decoded[0..33]
            }
            69 => {
                // Uncompressed case, 65 bytes  + 4 bytes checksum
                checksum.copy_from_slice(&decoded[65..]);
                &decoded[0..65]
            }
            _ => return Err(PublicKeyWifError::Invalid),
        };

        checksum_verify.copy_from_slice(&ripemd160(key)[0..4]);

        if checksum_verify != checksum {
            return Err(PublicKeyWifError::Checksum(checksum, checksum_verify));
        }

        Ok(Self {
            key: secp256k1::PublicKey::from_slice(key).map_err(|e| PublicKeyWifError::Secp256k1(e))?,
            prefix,
        })
    }
}

impl IntoWif for PublicKey {
    fn to_wif(&self) -> String {
        let mut v = vec![];
        let checksum = ripemd160(self.key.serialize());

        let prefix = String::from_utf8_lossy(&self.prefix);

        v.extend_from_slice(&self.key.serialize());
        v.extend_from_slice(&checksum[0..4]);

        format!("{}{}", prefix, bs58::encode(v).into_string())
    }
}

#[derive(Debug)]
pub enum PrivateKeyBuildError {
    Decode(bs58::decode::Error),
    Secp256k1(secp256k1::Error),
    InvalidLength(usize),
    InvalidNetworkId(u8),
    Checksum([u8; 4], [u8; 4]),
    InvalidCompressionByte(u8),
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::crypto::{FromWif, IntoWif};
    use crate::crypto::public_key::PublicKey;

    #[test]
    fn wif_to_compressed_public_key() {
        let wif = b"STM6rGZuZf3MBykvASN4xEgmJU5oNcwtZjyQc3x6ZL8Mts5UrpQfq";

        let key = PublicKey::from_wif(wif).unwrap();

        assert_eq!(key.key, secp256k1::PublicKey::from_str("030259b4961bed2db07dfa61983d538b9dd11e66777f2931558f3267c613485ec6").unwrap());
        assert_eq!(&key.prefix, b"STM");
    }

    #[test]
    fn public_key_full_cycle() {
        let wif = "STM6rGZuZf3MBykvASN4xEgmJU5oNcwtZjyQc3x6ZL8Mts5UrpQfq".to_owned();
        let key = PublicKey::from_wif(&wif).unwrap();
        let actual = key.to_wif();
        assert_eq!(wif, actual);
    }

    #[test]
    fn wif_to_uncompressed_public_key() {
        let wif = "ABC3nJ4XSefGZrjiWxsUSQmAJFYhuxJ8kSCvkCaKngUYBbiqpmWywaxmdgTcWbPio55q7CHDTNBK9mhuK9fbHg6nAKXpZCb43";

        let key = PublicKey::from_wif(wif).unwrap();

        assert_eq!(key.key, secp256k1::PublicKey::from_str("04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a").unwrap());
        assert_eq!(&key.prefix, b"ABC");
    }

    #[test]
    fn public_key_invalid_length() {
        let wif = "";

        let key = PublicKey::from_wif(wif);

        assert_eq!(key.is_err(), true);
    }
}

#[derive(Debug)]
pub enum PublicKeyWifError {
    Decode(bs58::decode::Error),
    Secp256k1(secp256k1::Error),
    Invalid,
    Checksum([u8; 4], [u8; 4]),
}
