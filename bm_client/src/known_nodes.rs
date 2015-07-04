use message::KnownNode;
use persist::Persister;
use rand::OsRng;
use rand::Rng;
use std::cmp::min;

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

    pub fn get_random(&self) -> Option<KnownNode> {
        let mut single_selection = self.get_random_selection(1);
        single_selection.pop()
    }

    pub fn get_random_selection(&self, at_most: usize) -> Vec<KnownNode> {
        let mut known_nodes: Vec<KnownNode> = self.persister.get_known_nodes();
        let mut rng = OsRng::new().unwrap();

        let count = min(at_most, known_nodes.len());

        let mut random_nodes: Vec<KnownNode> = Vec::with_capacity(count);
        for _ in 0..count {
            let index: usize = rng.gen_range(0, known_nodes.len());
            let random_node = known_nodes.swap_remove(index);
            random_nodes.push(random_node);
        }

        random_nodes
    }

    pub fn add_known_node(&mut self, known_node: &KnownNode)
    {
        self.persister.add_known_node(known_node);
    }
}
