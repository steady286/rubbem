extern crate secp256k1;

use self::secp256k1::Secp256k1;
use self::secp256k1::key::{PublicKey,SecretKey};

pub struct Curve {
    secp256k1: Secp256k1
}

impl Curve {
    pub fn new() -> Curve {
        Curve {
            secp256k1: Secp256k1::new()
        }
    }
}

pub fn create_public_key(curve: &Curve, private_bytes: &[u8; 32]) -> Result<[u8; 65], ()> {
    let private_key = SecretKey::from_slice(&curve.secp256k1, private_bytes).unwrap();
    let public_key = PublicKey::from_secret_key(&curve.secp256k1, &private_key).unwrap();
    let public_key_bytes = public_key.serialize_vec(&curve.secp256k1, false);

    let mut result: [u8; 65] = [0; 65];
    for i in 0..65 {
        result[i] = public_key_bytes[i];
    }

    Ok(result)
}
