use secp256k1::rand::{Rng, RngCore};
use secp256k1::rand::rngs::OsRng;
use hive_rs::crypto::private_key::PrivateKey;
use hive_rs::crypto::public_key::PublicKey;

#[test]
fn sign_and_verify_message() {
    let mut rng = OsRng::new().unwrap();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    let private_key = PrivateKey::from_seed(&seed).unwrap();
    let mut message = [0u8; 64];
    rng.fill_bytes(&mut message);

    let signature = private_key.sign_ecdsa_canonical(&message);
    let public_key = private_key.create_public(None);

    assert!(public_key.verify(&message, &signature));
}