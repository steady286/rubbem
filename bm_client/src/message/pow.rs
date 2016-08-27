use byteorder::{BigEndian,ReadBytesExt,WriteBytesExt};
use checksum::sha512_hash;
use message::{ObjectData,MAX_PAYLOAD_LENGTH_FOR_OBJECT};
use serial::message::write_object_message_data;
use std::cmp::max;
use std::io::Cursor;
use std::time::SystemTime;
use timegen::{TimeType,get_time};

#[derive(Debug,PartialEq)]
pub enum TimeToLiveError {
    ObjectAlreadyDied,
    ObjectLivesTooLong
}

#[derive(Debug,PartialEq)]
pub enum GenerateError {
    ObjectAlreadyDied,
    ObjectLivesTooLong,
    NoProofFound
}

#[derive(Debug,PartialEq)]
pub enum VerifyError {
    ObjectAlreadyDied,
    ObjectLivesTooLong,
    UnacceptableProof
}

impl From<TimeToLiveError> for GenerateError {
    fn from(err: TimeToLiveError) -> GenerateError {
        match err {
            TimeToLiveError::ObjectAlreadyDied => GenerateError::ObjectAlreadyDied,
            TimeToLiveError::ObjectLivesTooLong => GenerateError::ObjectLivesTooLong
        }
    }
}

impl From<TimeToLiveError> for VerifyError {
    fn from(err: TimeToLiveError) -> VerifyError {
        match err {
            TimeToLiveError::ObjectAlreadyDied => VerifyError::ObjectAlreadyDied,
            TimeToLiveError::ObjectLivesTooLong => VerifyError::ObjectLivesTooLong
        }
    }
}

pub struct ProofOfWorkConfig {
    trials_per_byte: u64,
    extra_bytes: u64,
    minimum_ttl: i64,
    maximum_ttl: u32,
    tide_ttl: u32
}

pub fn network_pow_config() -> ProofOfWorkConfig {
    ProofOfWorkConfig {
        trials_per_byte: 1000,
        extra_bytes: 1000,
        minimum_ttl: -3600, // 1 hour ago
        maximum_ttl: 2430000, // 28 days and 3 hours
        tide_ttl: 300 // 5 minutes
    }
}

pub struct ProofOfWork {
    time_type: TimeType
}

impl ProofOfWork {
    pub fn new(time_type: TimeType) -> ProofOfWork {
        ProofOfWork {
            time_type: time_type
        }
    }

    pub fn generate(&self, object_data: &ObjectData, pow_config: ProofOfWorkConfig) -> Result<u64, GenerateError> {
        assert!(pow_config.tide_ttl > 0);
        assert!(pow_config.trials_per_byte > 0);

        let payload_with_nonce = payload_with_nonce(object_data);
        let payload_without_nonce = &payload_with_nonce[8..];

        assert!(payload_with_nonce.len() <= u32::max_value() as usize);
        let payload_with_nonce_length = payload_with_nonce.len() as u32;

        let expiry = object_data.expiry;
        let target = try!(self.target(payload_with_nonce_length, expiry, pow_config));

        generate_pow_given_target(payload_without_nonce, target)
    }

    pub fn verify(&self, object_data: &ObjectData, pow_config: ProofOfWorkConfig) -> Result<(), VerifyError> {
        assert!(pow_config.tide_ttl > 0);
        assert!(pow_config.trials_per_byte > 0);

        let payload_with_nonce = payload_with_nonce(object_data);
        let payload_without_nonce = &payload_with_nonce[8..];

        assert!(payload_with_nonce.len() <= u32::max_value() as usize);
        let payload_with_nonce_length = payload_with_nonce.len() as u32;

        let expiry = object_data.expiry;
        let target = try!(self.target(payload_with_nonce_length, expiry, pow_config));

        let initial_hash = sha512_hash(payload_without_nonce);
        assert!(initial_hash.len() == 64);

        let nonce = object_data.nonce;
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

    fn target(&self, payload_length: u32, expiry: SystemTime, pow_config: ProofOfWorkConfig) -> Result<u64, TimeToLiveError> {
        assert!(payload_length > 0);
        assert!(payload_length <= MAX_PAYLOAD_LENGTH_FOR_OBJECT);
        let ttl = try!(self.ttl(expiry, &pow_config));

        Ok(target_from_ttl(payload_length, ttl, pow_config.trials_per_byte, pow_config.extra_bytes))
    }

    fn ttl(&self, expiry: SystemTime, pow_config: &ProofOfWorkConfig) -> Result<u32, TimeToLiveError> {
        let now: SystemTime = get_time(&self.time_type);

        let ttl = match expiry.duration_since(now) {
            Ok(duration) => try!(fit_in_i64(duration.as_secs(), TimeToLiveError::ObjectLivesTooLong)),
            Err(time_error) => -(try!(fit_in_i64(time_error.duration().as_secs(), TimeToLiveError::ObjectLivesTooLong)))
        };

        if ttl < pow_config.minimum_ttl {
            return Err(TimeToLiveError::ObjectAlreadyDied);
        }

        if ttl > u32::max_value() as i64 {
            return Err(TimeToLiveError::ObjectLivesTooLong);
        }

        let positive_ttl = max(1u32, ttl as u32);

        if positive_ttl > pow_config.maximum_ttl {
            return Err(TimeToLiveError::ObjectLivesTooLong);
        }

        Ok(max(pow_config.tide_ttl, positive_ttl))
    }
}

fn payload_with_nonce(object_data: &ObjectData) -> Vec<u8> {
    let mut output = vec![];
    write_object_message_data(&mut output, object_data);
    output
}

fn generate_pow_given_target(payload: &[u8], target: u64) -> Result<u64, GenerateError> {
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

fn fit_in_i64(value: u64, error: TimeToLiveError) -> Result<i64, TimeToLiveError> {
    if value > i64::max_value() as u64 {
        return Err(error);
    }

    Ok(value as i64)
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
