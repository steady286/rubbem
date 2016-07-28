extern crate rust_base58;

use checksum::double_sha512_checksum_bytes;
use elliptic::keypair::{KeyPair,create_key_pair};
use message::read_var_int;
use message::write_var_int_64;
use self::rust_base58::base58::{FromBase58,FromBase58Error,ToBase58};
use std::io::{Cursor,Read};
use std::iter::repeat;

#[derive(Clone,Debug,PartialEq)]
pub struct Address {
    version: u64,
    stream: u64,
    ripe: Vec<u8>
}

#[derive(Clone,Debug)]
pub enum AddressDecodeError {
    NotBase58(FromBase58Error),
    NotLongEnough,
    ChecksumMismatch,
    MalformedVarint,
    UnknownVersion,
    RipeTooShort(usize),
    RipeTooLong(usize),
    RipeEncodingProblem
}

impl From<FromBase58Error> for AddressDecodeError {
    fn from(error: FromBase58Error) -> AddressDecodeError {
        AddressDecodeError::NotBase58(error)
    }
}

pub fn decode_address(input: &str) -> Result<Address, AddressDecodeError> {
    let trimmed_address = input.trim();

    let encoded_address = if trimmed_address.starts_with("BM-") {
        &trimmed_address[3..]
    } else {
        &trimmed_address[..]
    };

    let data_and_checksum = try!(encoded_address.from_base58());

    let length = data_and_checksum.len();
    if length < 5 {
        return Err(AddressDecodeError::NotLongEnough);
    }

    // Checksum is last four bytes
    let (data, expected_checksum) = data_and_checksum.split_at(length - 4);

    let actual_checksum = double_sha512_checksum_bytes(data);
    if actual_checksum != expected_checksum {
        return Err(AddressDecodeError::ChecksumMismatch);
    }

    let mut cursor = Cursor::new(data);
    let version = match try!(read_address_var_int(&mut cursor)) {
        0 => return Err(AddressDecodeError::UnknownVersion),
        value @ 1...4 => value,
        _ => return Err(AddressDecodeError::UnknownVersion)
    };

    let stream = try!(read_address_var_int(&mut cursor));

    let mut bytes: Vec<u8> = cursor.bytes().map(|b| b.unwrap()).collect();
    let byte_count = bytes.len();
    let ripe = match version {
        1 => {
            if byte_count < 20 {
                return Err(AddressDecodeError::RipeTooShort(byte_count));
            }

            // The last 20 bytes
            bytes.split_off(byte_count - 20)
        },
        2 | 3 => {
            match byte_count {
                0...17 => return Err(AddressDecodeError::RipeTooShort(byte_count)),
                18...20 => repeat(0).take(20 - byte_count).chain(bytes.into_iter()).collect(), // Pad with 0
                _ => return Err(AddressDecodeError::RipeTooLong(byte_count))
            }
        },
        4 => match bytes[0] {
            0 => return Err(AddressDecodeError::RipeEncodingProblem),
            _ => match byte_count {
                0...3 => return Err(AddressDecodeError::RipeTooShort(byte_count)),
                4...20 => repeat(0).take(20 - byte_count).chain(bytes.into_iter()).collect(), // Pad with 0
                _ => return Err(AddressDecodeError::RipeTooLong(byte_count))
            }
        },
        _ => unreachable!()
    };

    Ok(Address {
        version: version,
        stream: stream,
        ripe: ripe
    })
}

fn read_address_var_int<A: Read>(data_cursor: &mut A) -> Result<u64, AddressDecodeError> {
    read_var_int(data_cursor, u64::max_value()).
    map_err(|_| AddressDecodeError::MalformedVarint)
}

#[derive(Clone,Debug)]
pub enum AddressEncodeError {
    UnknownVersion,
    RipeTooShort,
    RipeTooLong,
    RipeTooCloseToZero
}

pub fn encode_address(address: &Address) -> Result<String, AddressEncodeError> {
    let ripe = address.ripe.clone();

    if ripe.len() < 20 {
        return Err(AddressEncodeError::RipeTooShort);
    }

    if ripe.len() > 20 {
        return Err(AddressEncodeError::RipeTooLong);
    }

    let encoded_ripe: Vec<u8> = match address.version {
        1 => ripe,
        2...3 => remove_one_leading_zero(remove_one_leading_zero(ripe)),
        4 => {
            let zero_stripped_ripe = remove_all_leading_zeros(ripe);

            if zero_stripped_ripe.len() < 4 {
                return Err(AddressEncodeError::RipeTooCloseToZero)
            }

            zero_stripped_ripe
        },
        _ => return Err(AddressEncodeError::UnknownVersion)
    };

    let mut binary_address: Vec<u8> = vec![];
    write_var_int_64(&mut binary_address, address.version);
    write_var_int_64(&mut binary_address, address.stream);
    binary_address.extend(encoded_ripe.into_iter());

    let checksum = double_sha512_checksum_bytes(&binary_address[..]);
    binary_address.extend(checksum.into_iter());

    let encoded_address = binary_address.to_base58();
    let prefixed_encoded_address: String = String::new() + "BM-" + &encoded_address;
    Ok(prefixed_encoded_address)
}

fn remove_one_leading_zero(mut ripe: Vec<u8>) -> Vec<u8> {
    if ripe[0] == 0  {
        ripe.remove(0);
    }

    ripe
}

fn remove_all_leading_zeros(ripe: Vec<u8>) -> Vec<u8> {
    ripe.into_iter().skip_while(|&b| b == 0).collect()
}

struct PrivateAddress {
    sign: KeyPair,
    encrypt: KeyPair
}

fn create_random_private_address(max_attempts: u64) -> PrivateAddress {
    loop {
        let sign = create_key_pair();
        let encrypt = create_key_pair();

        if sign.is_err() || encrypt.is_err() {
            continue;
        }

        return PrivateAddress {
            sign: sign.unwrap(),
            encrypt: encrypt.unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Address;
    use super::decode_address;
    use super::encode_address;

    #[test]
    fn test_decode_good_address() {
        let address = decode_address("BM-2cUHyNbNkrHzcxBCNhJdEAHzqka6SbefLT").unwrap();
        assert_eq!(address.stream, 1);
        assert_eq!(address.version, 4);
        assert_eq!(address.ripe, vec![
            0x00, 0x4D, 0x18, 0xA8, 0x51,
            0x5C, 0x47, 0x61, 0xAD, 0x8D,
            0x5F, 0xE6, 0x7B, 0xB3, 0x0C,
            0x99, 0x90, 0x26, 0xBF, 0x66
        ]);
    }

    #[test]
    fn test_encode_address() {
        let address = Address {
            version: 4,
            stream: 1,
            ripe: vec![
                0x00, 0x4D, 0x18, 0xA8, 0x51,
                0x5C, 0x47, 0x61, 0xAD, 0x8D,
                0x5F, 0xE6, 0x7B, 0xB3, 0x0C,
                0x99, 0x90, 0x26, 0xBF, 0x66
            ]
        };

        let encoded_address = encode_address(&address).unwrap();
        assert_eq!(encoded_address, "BM-2cUHyNbNkrHzcxBCNhJdEAHzqka6SbefLT");
    }
}
