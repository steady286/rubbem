use config::Config;
use connection::{Connection,ConnectionState};
use known_nodes::KnownNodes;
use std::thread::{Builder,sleep_ms};

pub struct PeerConnector {
    config: Config,
    known_nodes: KnownNodes,
    nonce: u64
}

impl PeerConnector
{
    pub fn new(config: &Config, known_nodes: &KnownNodes, nonce: u64) -> PeerConnector {
        PeerConnector {
            config: config.clone(),
            known_nodes: known_nodes.clone(),
            nonce: nonce
        }
    }

    pub fn start(&mut self)
    {
        let connection_count_target = 1;
        let known_nodes = self.known_nodes.clone();
        let nonce = self.nonce;
        println!("Config says {} connections - we're only using 1", self.config.concurrent_connection_attempts());

        let name = "Peer Connector".to_string();
        Builder::new().name(name).spawn(move || {
            let mut connections: Vec<Connection> = vec![];

            loop {
                connections.retain(|connection|  {
                    let current_state = *connection.state.read().unwrap();
                    current_state != ConnectionState::Error && current_state != ConnectionState::Stale
                });

                while connections.len() < connection_count_target {
                    let known_node = known_nodes.get_random();
                    let connection = Connection::new(known_node.socket_addr, nonce);
                    connections.push(connection);
                }
                sleep_ms(100);
            }
        }).unwrap();
    }
}
