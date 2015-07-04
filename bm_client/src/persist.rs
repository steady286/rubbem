use message::KnownNode;
use std::sync::{Arc,RwLock};

#[derive(Clone)]
pub struct Persister {
    inner: Arc<RwLock<MemoryPersister>>
}

impl Persister {
    pub fn new() -> Persister {
        Persister {
            inner: Arc::new(RwLock::new(MemoryPersister::new()))
        }
    }

    pub fn get_known_nodes(&self) -> Vec<KnownNode> {
        let inner_read = self.inner.read().unwrap();
        inner_read.get_known_nodes()
    }

    pub fn add_known_node(&mut self, known_node: &KnownNode) {
        let mut inner_write = self.inner.write().unwrap();
        inner_write.add_known_node(known_node);
    }
}

pub struct MemoryPersister {
    known_nodes: Vec<KnownNode>
}

impl MemoryPersister {
    pub fn new() -> MemoryPersister {
        MemoryPersister {
            known_nodes: vec![]
        }
    }

    fn get_known_nodes(&self) -> Vec<KnownNode> {
        self.known_nodes.clone()
    }

    fn add_known_node(&mut self, known_node: &KnownNode) {
        self.known_nodes.push(known_node.clone());
    }
}
