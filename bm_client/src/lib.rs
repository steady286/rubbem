extern crate byteorder;
extern crate encoding;
extern crate rand;
extern crate sodiumoxide;
extern crate time;

mod bm_time;
mod config;
mod crypto;
mod known_nodes;
mod message;
mod peer;
mod persist;

use config::Config;
use known_nodes::KnownNodes;
use peer::PeerConnector;
use persist::MemoryPersister;
use persist::Persister;
use rand::OsRng;
use rand::Rng;
use std::rc::Rc;
use std::sync::RwLock;

pub enum BMError {
    NoRng,
    NoDiskAccess,
    Network
}

pub struct BMClient {
    config: Rc<Box<Config>>,
    known_nodes: Rc<Box<KnownNodes>>
}

impl BMClient {
    pub fn new() -> BMClient {
        // Move this to a Result returned from new()
        // assert!(usize::max_value() >= u32::max_value(), "You must use at least a 32-bit system");

        let config = Rc::new(Box::new(Config::new()));
        let persister: Rc<RwLock<Box<Persister>>> = Rc::new(RwLock::new(Box::new(MemoryPersister::new())));
        let known_nodes = Rc::new(Box::new(KnownNodes::new(persister.clone())));

        BMClient {
            config: config,
            known_nodes: known_nodes
        }
    }

    pub fn start(&self) {
        let known_nodes_clone = self.known_nodes.clone();
        bootstrap_known_nodes(known_nodes_clone);

        let mut rng: Box<OsRng> = Box::new(OsRng::new().unwrap());
        let nonce = rng.next_u64();

        PeerConnector::new(self.config.clone(), self.known_nodes.clone(), nonce).start();
    }
}

fn bootstrap_known_nodes(known_nodes: Rc<Box<KnownNodes>>) {
    if known_nodes.len() == 0 {
        for (stream, services, address) in bootstrap_nodes() {
            known_nodes.add_known_node(stream, services, address).unwrap();
        }
    }
}

fn bootstrap_nodes() -> Vec<(u32, u64, &'static str)> {
    vec![
        //(1, 1, "5.45.99.75:8444")
        (1, 1, "127.0.0.1:8444")
    ]
}

