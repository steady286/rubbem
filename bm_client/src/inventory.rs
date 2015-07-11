use crypto::{Sha512Digest,sha512};
use message::{InventoryVector,Message,write_message};
use persist::{InventoryIterator,Persister};

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

    pub fn iterator(&self) -> InventoryIterator {
        self.persister.inventory_iterator()
    }

    pub fn unknown(&self, inventory_chunk: Vec<InventoryVector>) -> Vec<InventoryVector> {
        let mut unknown = Vec::with_capacity(inventory_chunk.len());

        for inventory_vector in inventory_chunk {
            if let None = self.persister.get_object_message(&inventory_vector) {
                unknown.push(inventory_vector);
            }
        }

        unknown.shrink_to_fit();

        unknown
    }

    pub fn get_object_message(&mut self, inventory_vector: &InventoryVector) -> Option<Message> {
        self.persister.get_object_message(inventory_vector)
    }

    pub fn add_object_message(&mut self, object_message: &Message) {
        let inventory_vector = calculate_inventory_vector(object_message);
        self.persister.add_object_message(&inventory_vector, object_message);
    }
}

fn calculate_inventory_vector(object_message: &Message) -> InventoryVector {
    let mut message_bytes: Vec<u8> = vec![];
    write_message(&mut message_bytes, object_message);

    let Sha512Digest(round1) = sha512(&message_bytes);
    let Sha512Digest(round2) = sha512(&round1);
    let hash = &round2[0..32];

    InventoryVector {
        hash: hash.to_vec()
    }
}
