use message::InventoryVector;
use persist::Persister;
use std::vec::IntoIter;

#[derive(Clone)]
pub struct Inventory {
    persister: Persister
}

impl Inventory {
    pub fn new(persister: Persister) -> Inventory {
        Inventory {
            persister: persister.clone()
        }
    }

    pub fn iterator(&self) -> IntoIter<InventoryVector> {
        self.persister.inventory_iterator()
    }

    pub fn unknown(&self, inventory_chunk: Vec<InventoryVector>) -> Vec<InventoryVector> {
        let mut unknown = Vec::with_capacity(inventory_chunk.len());

        for inventory_vector in inventory_chunk {
            if let None = self.persister.get_object(&inventory_vector) {
                unknown.push(inventory_vector);
            }
        }

        unknown.shrink_to_fit();

        unknown
    }

    pub fn add(&mut self, inventory_vector: &InventoryVector) {
        self.persister.add_to_inventory(inventory_vector);
    }
}
