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

    pub fn add_known_node<A: ToSocketAddrs>(&self, stream: u32, services: u64, address: A) -> Result<()>
    {
        let now = get_time();

        for socket_addr in try!(address.to_socket_addrs()) {
            let known_node = KnownNode::new(now, stream, services, socket_addr).unwrap();
            self.persister.write().unwrap().add_known_node(known_node);
        }

        Ok(())
    }
}

#[derive(Clone,Copy,Debug,PartialEq)]
pub struct KnownNode {
    last_seen: Timespec,
    stream: u32,
    services: u64,
    socket_addr: SocketAddr
}

impl KnownNode {
    pub fn new<A: ToSocketAddrs>(last_seen: Timespec, stream: u32, services: u64, address: A) -> Result<KnownNode> {
        for socket_addr in try!(address.to_socket_addrs()) {
            return Ok(KnownNode {
                last_seen: last_seen,
                stream: stream,
                services: services,
                socket_addr: socket_addr
            });
        }

        Err(Error::new(ErrorKind::AddrNotAvailable, "No address"))
    }

    pub fn last_seen(&self) -> Timespec {
        self.last_seen
    }

    pub fn stream(&self) -> u32 {
        self.stream
    }

    pub fn services(&self) -> u64 {
        self.services
    }

    pub fn socket_addr(&self) -> &SocketAddr {
        &self.socket_addr
    }
}

