use rand::{OsRng,Rng};
use elliptic::curve2::{Curve,create_public_key};

pub struct PublicKey {
    bytes: [u8; 65]
}

impl PublicKey {
    pub fn get_bytes(&self) -> [u8; 65] {
        let mut result: [u8; 65] = [0; 65];
        result.clone_from_slice(&self.bytes[..]);
        result
    }
}

pub struct PrivateKey {
    bytes: [u8; 32]
}

pub struct KeyPair {
    pub public: PublicKey,
    pub private: PrivateKey
}

pub fn create_key_pair(curve: &Curve) -> Result<KeyPair, ()> {
    let mut rng = OsRng::new().unwrap();
    let mut private_bytes: [u8; 32] = [0; 32];
    rng.fill_bytes(&mut private_bytes);

    let public_bytes = try!(create_public_key(curve, &private_bytes));

    Ok(KeyPair {
        public: PublicKey { bytes: public_bytes },
        private: PrivateKey { bytes: private_bytes }
    })
}

#[cfg(test)]
mod tests {
    use elliptic::curve2::Curve;
    use super::create_key_pair;

    #[test]
    fn test_create_key_pair() {
        let curve = Curve::new();
        let key_pair = create_key_pair(&curve);
    }
}