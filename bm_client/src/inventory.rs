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

    pub fn add(&mut self, inventory_vector: &InventoryVector) {
        self.persister.add_to_inventory(inventory_vector);
    }
}
