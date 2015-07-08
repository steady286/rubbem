use message::{InventoryVector,KnownNode};
use std::sync::{Arc,RwLock};
use std::vec::IntoIter;

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

    pub fn inventory_iterator(&self) -> IntoIter<InventoryVector> {
        let inner_read = self.inner.read().unwrap();
        inner_read.inventory_iterator()
    }

    pub fn add_to_inventory(&mut self, inventory_vector: &InventoryVector) {
        let mut inner_write = self.inner.write().unwrap();
        inner_write.add_to_inventory(inventory_vector);
    }
}

pub struct MemoryPersister {
    known_nodes: Vec<KnownNode>,
    inventory: Vec<InventoryVector>
}

impl MemoryPersister {
    pub fn new() -> MemoryPersister {
        MemoryPersister {
            known_nodes: vec![],
            inventory: vec![]
        }
    }

    fn get_known_nodes(&self) -> Vec<KnownNode> {
        self.known_nodes.clone()
    }

    fn add_known_node(&mut self, known_node: &KnownNode) {
        self.known_nodes.push(known_node.clone());
    }

    pub fn inventory_iterator(&self) -> IntoIter<InventoryVector> {
        self.inventory.clone().into_iter()
    }

    fn add_to_inventory(&mut self, inventory_vector: &InventoryVector) {
        self.inventory.push(inventory_vector.clone());
    }
}
