use message::{InventoryVector,KnownNode,Message};
use std::collections::BTreeMap;
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

    pub fn inventory_iterator(&self) -> InventoryIterator {
        let inner_read = self.inner.read().unwrap();
        inner_read.inventory_iterator()
    }

    pub fn get_object_message(&self, inventory_vector: &InventoryVector) -> Option<Message> {
        let inner_read = self.inner.read().unwrap();
        inner_read.get_object_message(inventory_vector)
    }

    pub fn add_object_message(&mut self, inventory_vector: &InventoryVector, object_message: &Message) {
        let mut inner_write = self.inner.write().unwrap();
        inner_write.add_object_message(inventory_vector, object_message);
    }
}

pub struct MemoryPersister {
    objects: Arc<RwLock<BTreeMap<InventoryVector, Message>>>,
    known_nodes: Vec<KnownNode>
}

impl MemoryPersister {
    pub fn new() -> MemoryPersister {
        MemoryPersister {
            objects: Arc::new(RwLock::new(BTreeMap::new())),
            known_nodes: vec![]
        }
    }

    fn get_known_nodes(&self) -> Vec<KnownNode> {
        self.known_nodes.clone()
    }

    fn add_known_node(&mut self, known_node: &KnownNode) {
        self.known_nodes.push(known_node.clone());
    }

    pub fn inventory_iterator(&self) -> InventoryIterator {
        InventoryIterator::new(self.objects.clone())
    }

    pub fn get_object_message(&self, inventory_vector: &InventoryVector) -> Option<Message> {
        let read_objects = self.objects.read().unwrap();
        read_objects.get(inventory_vector).cloned()
    }

    fn add_object_message(&mut self, inventory_vector: &InventoryVector, object_message: &Message) {
        let mut write_objects = self.objects.write().unwrap();
        write_objects.insert(inventory_vector.clone(), object_message.clone());
    }
}

pub struct InventoryIterator {
    objects: Arc<RwLock<BTreeMap<InventoryVector, Message>>>,
    next_key: Option<InventoryVector>
}

impl InventoryIterator {
    fn new(objects: Arc<RwLock<BTreeMap<InventoryVector, Message>>>) -> InventoryIterator {
        let first_key = get_first_key(objects.clone());

        InventoryIterator {
            objects: objects,
            next_key: first_key
        }
    }

    fn get_new_next(&mut self, current_next: &Option<InventoryVector>) -> Option<InventoryVector> {
        if let &Some(ref current_key) = current_next {
            let read_objects = self.objects.read().unwrap();
            // TODO - should not need to rescan all the keys, but the BTreeMap API is currently a bit limited
            for key in read_objects.keys() {
                if key > &current_key {
                    return Some(key.clone())
                }
            }
        }

        None
    }
}

fn get_first_key(objects: Arc<RwLock<BTreeMap<InventoryVector, Message>>>) -> Option<InventoryVector> {
    let read_objects = objects.read().unwrap();
    read_objects.keys().next().cloned()
}

impl Iterator for InventoryIterator {
    type Item = InventoryVector;

    fn next(&mut self) -> Option<InventoryVector> {
        let next = self.next_key.clone();
        self.next_key = self.get_new_next(&next);
        next
    }
}
