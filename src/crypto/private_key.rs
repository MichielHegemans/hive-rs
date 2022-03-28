use secp256k1::ecdsa::Signature;
use secp256k1::Message;

use crate::crypto::{double_sha256, FromWif, IntoWif, KeyRole, NETWORK_ID, sha256};
use crate::crypto::public_key::PrivateKeyBuildError;

pub struct PrivateKey {
    key: secp256k1::SecretKey,
    network_id: u8,
    compressed: bool,
}

impl FromWif for PrivateKey {
    type Err = PrivateKeyBuildError;

    fn from_wif(wif: impl AsRef<[u8]>) -> Result<Self, Self::Err> where Self: Sized {
        let r = bs58::decode(wif).into_vec().map_err(|e| PrivateKeyBuildError::Decode(e))?;

        // https://en.bitcoin.it/wiki/Wallet_import_format
        /*
        The Base 58 decoded string should consist of the private key itself, together with 1 byte of
        network id and 4 bytes of checksum. The private key itself should be 32 bytes.
        It might also have an additional byte for "corresponding compressed public key"

        We are not sure if this compressed public key is then also attached to this byte array, but
        for the moment we assume it's not.

        So the key vector of bytes is either these 2 lengths:
        - 1 + 32 + 1 + 4 = 38
        - 1 + 32     + 4 = 37
         */

        let network_id: u8;
        let mut secret: [u8; 32] = Default::default();
        let mut compression: Option<u8> = None;
        let mut checksum: [u8; 4] = Default::default();
        let mut checksum_verify: [u8; 4] = Default::default();

        match r.len() {
            38 => {
                network_id = r[0];
                secret.copy_from_slice(&r[1..33]);
                compression = Some(r[33]);
                checksum.copy_from_slice(&r[34..38]);
                checksum_verify.copy_from_slice(&double_sha256(&r[0..34])[0..4]);
            }
            37 => {
                network_id = r[0];
                secret.copy_from_slice(&r[1..33]);
                checksum.copy_from_slice(&r[33..37]);
                checksum_verify.copy_from_slice(&double_sha256(&r[0..33])[0..4]);
            }
            x => return Err(PrivateKeyBuildError::InvalidLength(x)),
        }

        if network_id != NETWORK_ID {
            return Err(PrivateKeyBuildError::InvalidNetworkId(network_id));
        }

        if checksum_verify != checksum {
            return Err(PrivateKeyBuildError::Checksum(checksum, checksum_verify));
        }

        if let Some(x) = compression {
            if x != 0x01 {
                return Err(PrivateKeyBuildError::InvalidCompressionByte(x));
            }
        }

        Ok(PrivateKey {
            compressed: compression.is_some(),
            key: secp256k1::SecretKey::from_slice(&secret).map_err(|e| PrivateKeyBuildError::Secp256k1(e))?,
            network_id,
        })
    }
}

impl IntoWif for PrivateKey {
    fn to_wif(&self) -> String {
        let mut v = vec![];

        v.push(self.network_id);
        v.extend_from_slice(self.key.as_ref());

        if self.compressed {
            v.push(0x01);
        }

        let checksum = double_sha256(&v);

        v.extend_from_slice(&checksum[0..4]);

        bs58::encode(v).into_string()
    }
}

impl PrivateKey {
    pub fn from_key(key: secp256k1::SecretKey, network_id: u8) -> Self {
        Self { key, network_id, compressed: false }
    }

    #[allow(dead_code)]
    pub fn from_seed(seed: &str) -> Result<Self, secp256k1::Error> {
        let key = sha256(seed);

        Ok(Self {
            key: secp256k1::SecretKey::from_slice(&key)?,
            compressed: false,
            network_id: NETWORK_ID,
        })
    }

    #[allow(dead_code)]
    pub fn from_login(username: &str, password: &str, key_role: KeyRole) -> Result<Self, secp256k1::Error> {
        let role = match key_role {
            KeyRole::Owner => "owner",
            KeyRole::Active => "active",
            KeyRole::Posting => "posting",
            KeyRole::Memo => "memo",
        };

        let seed = format!("{}{}{}", username, role, password);
        Self::from_seed(&seed)
    }

    pub fn sign(&self, message: [u8; secp256k1::constants::MESSAGE_SIZE]) -> Signature {
        let secp = secp256k1::Secp256k1::new();
        let message = Message::from_slice(&message).unwrap();
        secp.sign_ecdsa(&message, &self.key)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use secp256k1::rand::rngs::OsRng;
    use secp256k1::Secp256k1;

    use crate::crypto::{FromWif, IntoWif, sha256};
    use crate::crypto::private_key::PrivateKey;

    #[test]
    fn wif_to_private_key() {
        // Test from http://gobittest.appspot.com/PrivateKey
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";

        let key = PrivateKey::from_wif(wif).unwrap();

        assert_eq!(key.key, secp256k1::SecretKey::from_str("0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D").unwrap());
        assert_eq!(key.compressed, false);
        assert_eq!(key.network_id, 0x80);
    }

    #[test]
    fn private_key_full_cycle() {
        let wif = "5JMmGLTnJnm4mDm2bEjQqU1hPqPqUh3MSTuMDkv5vAKDricTYcZ".to_owned();
        let key = PrivateKey::from_wif(&wif).unwrap();

        assert_eq!(wif, key.to_wif());
    }

    #[test]
    fn sign_ecdsa() {
        let secp = Secp256k1::new();
        let mut rng = OsRng::new().unwrap();
        let (key, _) = secp.generate_keypair(&mut rng);
        let key = PrivateKey::from_key(key, 0x80);

        let message = sha256("Hello dear world");

        let signature = key.sign(message);
        let sa = signature.serialize_compact();

        let is_canonical = !(sa[0] & 0x80 > 0) &&
            !(sa[0] == 0 && !(sa[1] & 0x80 > 0)) &&
            !(sa[32] & 0x80 > 0) &&
            !(sa[33] == 0 && !(sa[33] & 0x80 > 0));

        assert!(is_canonical);
    }
}
