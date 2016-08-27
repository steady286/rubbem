extern crate byteorder;
extern crate encoding;
extern crate rand;

mod macros;

mod address;
mod channel;
mod checksum;
mod chunk;
mod config;
mod connection;
mod elliptic;
mod inventory;
mod known_nodes;
mod message;
mod net;
mod peer;
mod persist;
mod serial;
mod timegen;

use config::Config;
use inventory::Inventory;
use known_nodes::KnownNodes;
use message::KnownNode;
use message::{Sender,MessageSendError};
use net::to_socket_addr;
use peer::PeerConnector;
use persist::Persister;
use std::time::SystemTime;

pub enum BMError {
    NoDiskAccess,
    Network
}

pub struct BMClient {
    known_nodes: KnownNodes,
    sender: Sender,
    peer_connector: PeerConnector
}

impl BMClient {
    pub fn new() -> BMClient {
        // TODO - Move this to a Result returned from new()
        // assert!(usize::max_value() >= u32::max_value(), "You must use at least a 32-bit system");

        let config = Config::new();
        let persister = Persister::new();

        let mut known_nodes = KnownNodes::new(persister.clone());
        bootstrap_known_nodes(&mut known_nodes);

        let inventory = Inventory::new(persister);
        let sender = Sender::new(inventory.clone());
        let peer_connector = PeerConnector::new(&config, &known_nodes, &inventory);

        BMClient {
            known_nodes: known_nodes,
            sender: sender,
            peer_connector: peer_connector
        }
    }

    pub fn start(&mut self) {
        bootstrap_known_nodes(&mut self.known_nodes);
        self.peer_connector.start();
    }

    pub fn send_message(&mut self, text: &str) -> Result<(), MessageSendError> {
        self.sender.send_message(text)
    }
}

fn bootstrap_known_nodes(known_nodes: &mut KnownNodes) {
    if known_nodes.len() == 0 {
        for known_node in bootstrap_nodes() {
            known_nodes.add_known_node(&known_node);
        }
    }
}

fn bootstrap_nodes() -> Vec<KnownNode> {
    vec![
        // "5.45.99.75:8444"
        KnownNode {
            last_seen: SystemTime::now(),
            stream: 1,
            services: 1,
            socket_addr: to_socket_addr("127.0.0.1:8444")
        }
    ]
}
