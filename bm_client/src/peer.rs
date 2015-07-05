use config::Config;
use connection::{Connection,ConnectionState};
use known_nodes::KnownNodes;
use message::MessageResponder;
use std::net::SocketAddr;
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
                    let socket_addrs_in_use: Vec<SocketAddr> = (&connections).iter().filter_map(|connection| connection.peer_addr()).collect();
                    let known_node = break_on_none!(known_nodes.get_random_but_not(socket_addrs_in_use));
                    let peer_addr = known_node.socket_addr;
                    let message_responder = MessageResponder::new(&config, &known_nodes, peer_addr);
                    let connection = Connection::new(message_responder, peer_addr);
                    connections.push(connection);
                }
                sleep_ms(100);
            }
        }).unwrap();
    }
}
