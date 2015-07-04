use message::KnownNode;
use persist::Persister;
use rand::OsRng;
use rand::Rng;

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

    pub fn get_random(&self) -> KnownNode {
        let known_nodes: Vec<KnownNode> = self.persister.get_known_nodes();
        let mut rng = OsRng::new().unwrap();
        rng.choose(&known_nodes).unwrap().clone()
    }

    pub fn add_known_node(&mut self, known_node: &KnownNode)
    {
        self.persister.add_known_node(known_node);
    }
}
