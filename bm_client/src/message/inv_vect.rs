#[derive(Clone,Copy,Debug,PartialEq)]
pub struct InventoryVector {
	hash: [u8; 32]
}

impl InventoryVector {
	pub fn new(hash: &Vec<u8>) -> InventoryVector {
		InventoryVector {
			hash: vec_to_array_32(hash)
		}
	}

	pub fn hash(&self) -> &[u8; 32] {
		&self.hash
	}
}


fn vec_to_array_32(vec: &Vec<u8>) -> [u8; 32] {
	assert_eq!(32, vec.len());
	let mut result = [0u8; 32];
	for (i, v) in vec.iter().enumerate() { result[i] = *v; }

	result
}