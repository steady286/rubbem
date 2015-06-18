use std::io::Read;
use message::{InventoryVector,Message,ParseError};

const MAX_GETDATA_COUNT: usize = 50000;

pub struct GetdataMessage {
	inventory: Vec<InventoryVector>
}

impl GetdataMessage {
    pub fn new(inventory: Vec<InventoryVector>) -> GetdataMessage {
        assert!(inventory.len() <= MAX_GETDATA_COUNT);
		GetdataMessage {
			inventory: inventory
        }
    }

    pub fn read(source: &mut Read) -> Result<Box<GetdataMessage>,ParseError> {
        let count = try!(super::read_var_int_usize(source, MAX_GETDATA_COUNT));

        let mut inventory: Vec<InventoryVector> = Vec::with_capacity(count);
        for _ in 0..count {
			let inv_vect_bytes = try!(super::read_bytes(source, 32));

			assert_eq!(32, inv_vect_bytes.len());

			let inv_vect = InventoryVector::new(&inv_vect_bytes);

			inventory.push(inv_vect);
        }

        Ok(Box::new(GetdataMessage::new(inventory)))
    }

	pub fn inventory(&self) -> &Vec<InventoryVector> {
		&self.inventory
	}
}

impl Message for GetdataMessage {
    fn command(&self) -> String {
        "getdata".to_string()
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
    use message::getdata::GetdataMessage;
	use rand::{Rng,SeedableRng,XorShiftRng};
	use std::io::{Cursor,Read};

    #[test]
    fn test_getdata_message_payload() {
		let mut rng: XorShiftRng = SeedableRng::from_seed([0, 0, 0, 1]);
		let hash1: Vec<u8> = rng.gen_iter::<u8>().take(32).collect();
		let hash2: Vec<u8> = rng.gen_iter::<u8>().take(32).collect();
		let inv_vect1 = InventoryVector::new(&hash1);
		let inv_vect2 = InventoryVector::new(&hash2);

		let inventory: Vec<InventoryVector> = vec![ inv_vect1, inv_vect2 ];
		let message = GetdataMessage::new(inventory);
        let payload = message.payload();

        assert_eq!("getdata".to_string(), message.command());

        let mut expected = vec![ 2 ];
		expected.extend(hash1);
		expected.extend(hash2);

        assert_eq!(expected, payload);

        let mut source_box: Box<Read> = Box::new(Cursor::new(payload));
        let source = &mut *source_box;
        let roundtrip = GetdataMessage::read(source).unwrap();

        assert_eq!("getdata".to_string(), roundtrip.command());
        assert_eq!(&vec![inv_vect1, inv_vect2], roundtrip.inventory());
    }
}
