use rand::{OsRng,Rng};

#[derive(Clone)]
pub struct Config {
    user_agent: String,
    nonce: u64,
    port: u16,
    concurrent_connection_attempts: u16
}

impl Config {
    pub fn new() -> Config {
        Config {
            user_agent: concat!("Rubbem ", env!("CARGO_PKG_VERSION")).to_string(),
            nonce: create_nonce(),
            port: 8555,
            concurrent_connection_attempts: 8
        }
    }

    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn concurrent_connection_attempts(&self) -> u16 {
        self.concurrent_connection_attempts
    }
}

fn create_nonce() -> u64 {
    let mut rng = OsRng::new().unwrap();
    rng.next_u64()
}
