use byteorder::{BigEndian,ReadBytesExt,WriteBytesExt};
use crypto::{Sha512Digest,sha512};
use std::io::Cursor;

const MAX_PAYLOAD_LENGTH: u32 = 262144; // 2^18 - maximum object length
const MAX_TTL: u32 = 2430000; // 28 days and 3 hours

#[derive(Debug,PartialEq)]
enum ProofOfWorkError {
	TargetTooLow
}

fn generate_pow(payload: &[u8], target: f64) -> Result<u64,ProofOfWorkError> {
	let Sha512Digest(initial_hash) = sha512(payload);
	assert!(initial_hash.len() == 64);

	let mut input = [0u8; 72];
	for i in 0..64 {
		input[i + 8] = initial_hash[i];
	}

	let mut nonce_cursor = Cursor::new(Vec::<u8>::with_capacity(8));

	for nonce in 0u64..u64::max_value() {
		nonce_cursor.set_position(0);
		nonce_cursor.write_u64::<BigEndian>(nonce).unwrap();
		let nonce_bytes: &Vec<u8> = nonce_cursor.get_ref();
		for i in 0..8 {
			input[i] = nonce_bytes[i];
		}

		let Sha512Digest(first_round) = sha512(&input);
		let Sha512Digest(second_round) = sha512(&first_round[..]);

		let mut output_cursor = Cursor::new(&second_round[0..8]);
		let trial_value = output_cursor.read_u64::<BigEndian>().unwrap();
		let trial_value_f64 = trial_value as f64;

		if trial_value_f64 <= target {
			return Ok(nonce);
		}
	}

	return Err(ProofOfWorkError::TargetTooLow);
}

fn target(trials_per_byte: u64, payload_length: u32, extra_bytes: u64, time_to_live: u32) -> f64 {
	assert!(trials_per_byte > 0);
	assert!(payload_length > 0);
	assert!(payload_length <= MAX_PAYLOAD_LENGTH);
	assert!(time_to_live > 0);
	assert!(time_to_live <= MAX_TTL);

	let trials_per_byte_f64 = trials_per_byte as f64;
	let payload_length_f64 = payload_length as f64;
	let extra_bytes_f64 = extra_bytes as f64;
	let time_to_live_f64 = time_to_live as f64;

	target_f64(trials_per_byte_f64, payload_length_f64, extra_bytes_f64, time_to_live_f64)
}

fn target_f64(trials_per_byte: f64, payload_length: f64, extra_bytes: f64, time_to_live: f64) -> f64 {
	let byte_count = payload_length + extra_bytes;
	2.0f64.powi(64) / (trials_per_byte * (byte_count + ((time_to_live * byte_count) / 2.0f64.powi(16))))
}


#[cfg(test)]
mod tests {
use super::generate_pow;
use super::target;

	#[test]
	fn test_generate_pow() {
		let payload = [ 0, 1, 2, 3 ];
		let pow = generate_pow(&payload, 100000000000000000.0).unwrap();
		assert_eq!(290, pow);
	}

	#[test]
	fn test_generate_pow_smaller_target() {
		let payload = [ 0, 1, 2, 3 ];
		let pow = generate_pow(&payload, 1000000000000000.0).unwrap();
		assert_eq!(2904, pow);
	}

    #[test]
    fn test_get_target_100_bytes() {
		let target = target(1000, 100, 2000, 345600);
		let expected = 1400215407362.1672;

		let difference = target - expected;
		assert!(difference.abs() < 0.001);
	}

    #[test]
    fn test_get_target_1000_bytes() {
		let target = target(1000, 1000, 2000, 345600);
		let expected = 980150785153.51709;

		let difference = target - expected;
		assert!(difference.abs() < 0.001);
	}
}
