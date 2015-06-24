use std::io::Cursor;
use message::{InventoryVector,Message,ParseError,MAX_INV_COUNT};
use super::check_no_more_data;

pub struct InvMessage {
    inventory: Vec<InventoryVector>
}

impl InvMessage {
    pub fn new(inventory: Vec<InventoryVector>) -> InvMessage {
        assert!(inventory.len() <= MAX_INV_COUNT);
        InvMessage {
            inventory: inventory
        }
    }

    pub fn read(payload: Vec<u8>) -> Result<Box<InvMessage>,ParseError> {
        let mut cursor = Cursor::new(payload);

        let count = try!(super::read_var_int_usize(&mut cursor, MAX_INV_COUNT));

        let mut inventory: Vec<InventoryVector> = Vec::with_capacity(count);
        for _ in 0..count {
            let inv_vect_bytes = try!(super::read_bytes(&mut cursor, 32));

            assert_eq!(32, inv_vect_bytes.len());

            let inv_vect = InventoryVector::new(&inv_vect_bytes);

            inventory.push(inv_vect);
        }

        try!(check_no_more_data(&mut cursor));

        Ok(Box::new(InvMessage::new(inventory)))
    }

    pub fn inventory(&self) -> &Vec<InventoryVector> {
        &self.inventory
    }
}

impl Message for InvMessage {
    fn command(&self) -> String {
        "inv".to_string()
    }

    fn payload(&self) -> Vec<u8> {
        let mut payload = vec![];
        super::write_var_int_16(&mut payload, self.inventory.len() as u16);
        for inv_vect in &self.inventory {
            let hash = inv_vect.hash();
            payload.extend(hash.to_vec());
        }

        payload
    }
}

#[cfg(test)]
mod tests {
    use message::{InventoryVector,Message};
    use message::inv::InvMessage;
    use rand::{Rng,SeedableRng,XorShiftRng};
    use std::io::{Cursor,Read};

    #[test]
    fn test_inv_message_payload() {
        let mut rng: XorShiftRng = SeedableRng::from_seed([0, 0, 0, 1]);
        let hash1: Vec<u8> = rng.gen_iter::<u8>().take(32).collect();
        let hash2: Vec<u8> = rng.gen_iter::<u8>().take(32).collect();
        let inv_vect1 = InventoryVector::new(&hash1);
        let inv_vect2 = InventoryVector::new(&hash2);

        let inventory: Vec<InventoryVector> = vec![ inv_vect1, inv_vect2 ];
        let message = InvMessage::new(inventory);
        let payload = message.payload();

        assert_eq!("inv".to_string(), message.command());

        let mut expected = vec![ 2 ];
        expected.extend(hash1);
        expected.extend(hash2);

        assert_eq!(expected, payload);

        let roundtrip = InvMessage::read(payload).unwrap();

        assert_eq!("inv".to_string(), roundtrip.command());
        assert_eq!(&vec![inv_vect1, inv_vect2], roundtrip.inventory());
    }
}
