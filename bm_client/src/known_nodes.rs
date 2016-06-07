use message::KnownNode;
use persist::Persister;
use rand::OsRng;
use rand::Rng;
use std::cmp::min;
use std::net::SocketAddr;

#[derive(Clone)]
pub struct KnownNodes {
    persister: Persister
}

impl KnownNodes {
    pub fn new(persister: Persister) -> KnownNodes {
        KnownNodes {
            persister: persister.clone()
        }
    }

    pub fn len(&self) -> usize {
        self.persister.get_known_nodes().len()
    }

    pub fn get_random_but_not(&self, exclude: Vec<SocketAddr>) -> Option<KnownNode> {
        let mut single_selection = self.get_random_selection_but_not(1, exclude);
        single_selection.pop()
    }

    pub fn get_random_selection_but_not(&self, at_most: usize, exclude: Vec<SocketAddr>) -> Vec<KnownNode> {
        let mut known_nodes: Vec<KnownNode> = self.persister.get_known_nodes();
        let mut rng = OsRng::new().unwrap();

        let capacity = min(at_most, known_nodes.len());

        let mut random_nodes: Vec<KnownNode> = Vec::with_capacity(capacity);
        while random_nodes.len() < at_most && !known_nodes.is_empty() {
            let index: usize = rng.gen_range(0, known_nodes.len());
            let random_node = known_nodes.swap_remove(index);
            let node_socket_addr = random_node.socket_addr;
            if !exclude.contains(&node_socket_addr) {
                random_nodes.push(random_node);
            }
        }

        random_nodes
    }

    pub fn add_known_node(&mut self, known_node: &KnownNode)
    {
        self.persister.add_known_node(known_node);
    }
}
