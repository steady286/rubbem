use message::KnownNode;
use persist::Persister;
use rand::OsRng;
use rand::Rng;
use std::io::{Error,ErrorKind,Result};
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::rc::Rc;
use std::sync::RwLock;
use time::get_time;
use time::Timespec;

pub struct KnownNodes {
    persister: Rc<RwLock<Box<Persister>>>
}

impl KnownNodes {
    pub fn new(persister: Rc<RwLock<Box<Persister>>>) -> KnownNodes {
        KnownNodes {
            persister: persister
        }
    }

    pub fn len(&self) -> usize {
        self.persister.read().unwrap().get_known_nodes().len()
    }

    pub fn get_random(&self) -> KnownNode {
        let persister = self.persister.read().unwrap();
        let known_nodes: &Vec<KnownNode> = persister.get_known_nodes();
        let mut rng = OsRng::new().unwrap();
        rng.choose(&known_nodes[..]).unwrap().clone()
    }

    pub fn add_known_node(&self, known_node: &KnownNode)
    {
        self.persister.write().unwrap().add_known_node(known_node);
    }
}
