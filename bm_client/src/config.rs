#[derive(Clone)]
pub struct Config {
    user_agent: String,
    concurrent_connection_attempts: u16
}

impl Config {
    pub fn new() -> Config {
        Config {
            user_agent: concat!("Rubbem ", env!("CARGO_PKG_VERSION")).to_string(),
            concurrent_connection_attempts: 8
        }
    }

    pub fn concurrent_connection_attempts(&self) -> u16 {
        self.concurrent_connection_attempts
    }

    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }
}

