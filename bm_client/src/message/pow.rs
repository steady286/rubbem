use byteorder::{BigEndian,ReadBytesExt,WriteBytesExt};
use checksum::sha512_hash;
use message::{MAX_PAYLOAD_LENGTH_FOR_OBJECT};
use std::cmp::max;
use std::io::Cursor;
use std::time::SystemTime;
use timegen::TimeGenerator;

#[derive(Debug,PartialEq)]
pub enum TimeToLiveError {
    ObjectAlreadyDied,
    ObjectLivesTooLong
}

pub struct ProofOfWorkConfig<T: TimeGenerator> {
    trials_per_byte: u64,
    extra_bytes: u64,
    minimum_ttl: i64,
    maximum_ttl: u32,
    tide_ttl: u32,
    time_fn: T
}

impl<T: TimeGenerator> ProofOfWorkConfig<T> {
    pub fn new(trials_per_byte: u64, extra_bytes: u64, minimum_ttl: i64, maximum_ttl: u32, tide_ttl: u32, time_fn: T) -> ProofOfWorkConfig<T> {
        assert!(tide_ttl > 0);
        assert!(trials_per_byte > 0);

        ProofOfWorkConfig::<T> {
            trials_per_byte: trials_per_byte,
            extra_bytes: extra_bytes,
            minimum_ttl: minimum_ttl,
            maximum_ttl: maximum_ttl,
            tide_ttl: tide_ttl,
            time_fn: time_fn
        }
    }

    pub fn trials_per_byte(&self) -> u64 {
        self.trials_per_byte
    }

    pub fn extra_bytes(&self) -> u64 {
        self.extra_bytes
    }

    pub fn ttl(&self, expiry: SystemTime) -> Result<u32,TimeToLiveError> {
        let now: SystemTime = self.time_fn.get_time();

        let ttl = match expiry.duration_since(now) {
            Ok(duration) => duration.as_secs(),
            Err(time_error) => -(time_error.duration().as_secs())
        }

        if ttl < self.minimum_ttl {
            return Err(TimeToLiveError::ObjectAlreadyDied);
        }

        if ttl > u32::max_value() as i64 {
            return Err(TimeToLiveError::ObjectLivesTooLong);
        }

        let positive_ttl = max(1u32, ttl as u32);

        if positive_ttl > self.maximum_ttl {
            return Err(TimeToLiveError::ObjectLivesTooLong);
        }

        Ok(max(self.tide_ttl, positive_ttl))
    }
}

#[derive(Debug,PartialEq)]
pub enum GenerateError {
    ObjectAlreadyDied,
    ObjectLivesTooLong,
    NoProofFound
}

fn to_generate_error(e: TimeToLiveError) -> GenerateError {
    match e {
        TimeToLiveError::ObjectAlreadyDied => GenerateError::ObjectAlreadyDied,
        TimeToLiveError::ObjectLivesTooLong => GenerateError::ObjectLivesTooLong
    }
}

pub fn generate_proof<T: TimeGenerator>(payload: &[u8], expiry: SystemTime, config: ProofOfWorkConfig<T>) -> Result<u64,GenerateError> {
    assert!((8 + payload.len()) <= u32::max_value() as usize);

    let full_payload_length = 8u32 + payload.len() as u32;
    let target = try!(target(full_payload_length, expiry, config).map_err(to_generate_error));
    generate_pow_given_target(payload, target)
}

#[derive(Debug,PartialEq)]
pub enum VerifyError {
    ObjectAlreadyDied,
    ObjectLivesTooLong,
    UnacceptableProof
}

fn to_verify_error(e: TimeToLiveError) -> VerifyError {
    match e {
        TimeToLiveError::ObjectAlreadyDied => VerifyError::ObjectAlreadyDied,
        TimeToLiveError::ObjectLivesTooLong => VerifyError::ObjectLivesTooLong
    }
}

pub fn verify_proof<T: TimeGenerator>(nonce: u64, payload: &[u8], expiry: SystemTime, config: ProofOfWorkConfig<T>) -> Result<(),VerifyError> {
    let target = try!(target(payload.len() as u32, expiry, config).map_err(to_verify_error));

    let initial_hash = sha512_hash(payload);
    assert!(initial_hash.len() == 64);

    let mut input_cursor = Cursor::new(Vec::<u8>::with_capacity(72));
    input_cursor.write_u64::<BigEndian>(nonce).unwrap();
    let mut input = input_cursor.into_inner();
    input.extend(initial_hash.to_vec());

    let trial_value = first_8_of_double_digest(&input);
    if trial_value > target {
        return Err(VerifyError::UnacceptableProof);
    }

    Ok(())
}

fn generate_pow_given_target(payload: &[u8], target: u64) -> Result<u64,GenerateError> {
    let initial_hash = sha512_hash(payload);
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

        let trial_value = first_8_of_double_digest(&input);

        if trial_value <= target {
            return Ok(nonce);
        }
    }

    return Err(GenerateError::NoProofFound);
}

fn first_8_of_double_digest(input: &[u8]) -> u64 {
    let first_round = sha512_hash(input);
    let second_round = sha512_hash(&first_round[..]);

    let mut output_cursor = Cursor::new(&second_round[0..8]);
    output_cursor.read_u64::<BigEndian>().unwrap()
}

fn target<T: TimeGenerator>(payload_length: u32, expiry: SystemTime, config: ProofOfWorkConfig<T>) -> Result<u64,TimeToLiveError> {
    assert!(payload_length > 0);
    assert!(payload_length <= MAX_PAYLOAD_LENGTH_FOR_OBJECT);
    let ttl = try!(config.ttl(expiry));

    Ok(target_from_ttl(payload_length, ttl, config.trials_per_byte(), config.extra_bytes()))
}


fn target_from_ttl(payload_length: u32, ttl: u32, trials_per_byte: u64, extra_bytes:u64) -> u64 {
    let payload_length_f64 = payload_length as f64;
    let ttl_f64 = ttl as f64;
    let trials_per_byte_f64 = trials_per_byte as f64;
    let extra_bytes_f64 = extra_bytes as f64;

    target_f64(payload_length_f64, ttl_f64, trials_per_byte_f64, extra_bytes_f64) as u64
}

fn target_f64(payload_length: f64, time_to_live: f64, trials_per_byte: f64, extra_bytes: f64) -> f64 {
    let byte_count = payload_length + extra_bytes;
    2.0f64.powi(64) / (trials_per_byte * (byte_count + ((time_to_live * byte_count) / 2.0f64.powi(16))))
}


#[cfg(test)]
mod tests {
    use super::generate_pow_given_target;
    use super::target_from_ttl;

    #[test]
    fn test_generate_pow_given_target() {
        let payload = [ 0, 1, 2, 3 ];
        let pow = generate_pow_given_target(&payload, 100000000000000000).unwrap();
        assert_eq!(290, pow);
    }

    #[test]
    fn test_generate_pow_given_smaller_target() {
        let payload = [ 0, 1, 2, 3 ];
        let pow = generate_pow_given_target(&payload, 1000000000000000).unwrap();
        assert_eq!(2904, pow);
    }

    #[test]
    fn test_get_target_100_bytes() {
        let target = target_from_ttl(100, 345600, 1000, 2000);
        let expected = 1400215407362;

        assert_eq!(expected, target);
    }

    #[test]
    fn test_get_target_1000_bytes() {
        let target = target_from_ttl(1000, 345600, 1000, 2000);
        let expected = 980150785153;

        assert_eq!(expected, target);
    }
}
