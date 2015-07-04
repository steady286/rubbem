extern crate byteorder;
extern crate encoding;
extern crate rand;
extern crate sodiumoxide;
extern crate time;

mod bm_time;
mod channel;
mod config;
mod connection;
mod crypto;
mod known_nodes;
mod message;
mod net;
mod peer;
mod persist;
mod timegen;

use config::Config;
use known_nodes::KnownNodes;
use message::KnownNode;
use net::to_socket_addr;
use peer::PeerConnector;
use persist::Persister;
use rand::OsRng;
use rand::Rng;
use time::get_time;

pub enum BMError {
    NoRng,
    NoDiskAccess,
    Network
}

pub struct BMClient {
    config: Config,
    known_nodes: KnownNodes
}

impl BMClient {
    pub fn new() -> BMClient {
        // Move this to a Result returned from new()
        // assert!(usize::max_value() >= u32::max_value(), "You must use at least a 32-bit system");

        let config = Config::new();
        let persister = Persister::new();
        let known_nodes = KnownNodes::new(persister);

        BMClient {
            config: config,
            known_nodes: known_nodes
        }
    }

    pub fn start(&mut self) {
        bootstrap_known_nodes(&mut self.known_nodes);

        let mut rng: Box<OsRng> = Box::new(OsRng::new().unwrap());
        let nonce = rng.next_u64();

        PeerConnector::new(&self.config, &self.known_nodes, nonce).start();
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
            last_seen: get_time(),
            stream: 1,
            services: 1,
            socket_addr: to_socket_addr("127.0.0.1:8444")
        }
    ]
}
