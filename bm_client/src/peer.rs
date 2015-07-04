use config::Config;
use connection::{Connection,ConnectionState};
use known_nodes::KnownNodes;
use std::thread::{Builder,sleep_ms};

pub struct PeerConnector {
    config: Config,
    known_nodes: KnownNodes
}

impl PeerConnector
{
    pub fn new(config: &Config, known_nodes: &KnownNodes) -> PeerConnector {
        PeerConnector {
            config: config.clone(),
            known_nodes: known_nodes.clone()
        }
    }

    pub fn start(&mut self)
    {
        let connection_count_target = 1;
        let config = self.config.clone();
        let known_nodes = self.known_nodes.clone();
        println!("Config says {} connections - we're only using 1", config.concurrent_connection_attempts());

        let name = "Peer Connector".to_string();
        Builder::new().name(name).spawn(move || {
            let mut connections: Vec<Connection> = vec![];

            loop {
                connections.retain(|connection|  {
                    let current_state = connection.state();
                    current_state != ConnectionState::Error && current_state != ConnectionState::Stale
                });

                while connections.len() < connection_count_target {
                    let known_node = known_nodes.get_random();
                    let connection = Connection::new(&config, known_node.socket_addr);
                    connections.push(connection);
                }
                sleep_ms(100);
            }
        }).unwrap();
    }
}
