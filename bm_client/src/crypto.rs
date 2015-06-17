use byteorder::{BigEndian,ReadBytesExt};
use sodiumoxide::crypto::hash::sha512::hash;
use std::io::Cursor;

pub fn sha512(input: &Vec<u8>) -> Vec<u8> {
    let digest = hash(&input[..]);

    let mut result = vec![];
    for &b in &digest[..] {
        result.push(b);
    }

    result
}

pub fn sha512_checksum(input: &Vec<u8>) -> u32 {
    let sha512 = sha512(input);

    assert!(sha512.len() >= 4);

    let mut cursor = Cursor::new(sha512);
    cursor.read_u32::<BigEndian>().unwrap()
}

