use byteorder::BigEndian;
use byteorder::ReadBytesExt;
use crypto::sha512_checksum;
use encoding::{DecoderTrap,Encoding};
use encoding::all::ASCII;
use std::io::{Cursor,Read};
use std::net::{Ipv6Addr,SocketAddr,SocketAddrV4,SocketAddrV6};
use time::Timespec;

use super::{InventoryVector,KnownNode,GetPubKey,PubKey,Broadcast,Object,Message};
use super::{MAGIC,MAX_GETDATA_COUNT,MAX_INV_COUNT,MAX_NODES_COUNT,MAX_PAYLOAD_LENGTH};

#[derive(Debug,PartialEq)]
pub enum ParseError {
    FailedMagic,
    PayloadLength,
    ChecksumMismatch,
    AsciiDecode,
    NonZeroPadding,
    UnknownCommand,
    BadAscii,
    PayloadWrongSize,
    MaxExceeded,
    UnexpectedPayloadEnd,
    UnknownObjectType,
    UnknownObjectVersion,
    // ObjectExpired,
    // ObjectLivesTooLong,
    // UnacceptablePow
}

pub fn read_message<A: Read>(source: &mut A) -> Result<Message,ParseError> {
    let magic = try!(read_u32(source));
    if magic != MAGIC {
        return Err(ParseError::FailedMagic);
    }

    let command = try!(read_command(source));
    let length_bytes = try!(read_u32(source));
    let expected_checksum = try!(read_u32(source));

    if length_bytes > MAX_PAYLOAD_LENGTH {
        return Err(ParseError::PayloadLength);
    }

    let payload = try!(read_bytes(source, length_bytes as usize));
    let calculated_checksum = sha512_checksum(&payload);
    if calculated_checksum != expected_checksum {
        return Err(ParseError::ChecksumMismatch);
    }

    read_payload(&command, &payload)
}

fn read_command<A: Read>(source: &mut A) -> Result<String,ParseError> {
    let command_bytes = try!(read_bytes(source, 12));
    let non_zero_bytes = try!(remove_zeros(command_bytes));
    ASCII.decode(&non_zero_bytes, DecoderTrap::Strict).map_err(|_| ParseError::AsciiDecode)
}

fn remove_zeros(bytes: Vec<u8>) -> Result<Vec<u8>,ParseError> {
    let mut split: Vec<&[u8]> = bytes.split(|&byte| byte == 0).collect();
    split.retain(|split| split.len() > 0);

    match split.len() {
        1 => Ok(split[0].to_vec()),
        _ => Err(ParseError::NonZeroPadding)
    }
}

fn read_payload(command: &str, bytes: &[u8]) -> Result<Message,ParseError> {
    Ok(match command {
        "addr" => try!(read_addr_message(bytes)),
        "getdata" => try!(read_getdata_message(bytes)),
        "inv" => try!(read_inv_message(bytes)),
        "version" => try!(read_version_message(bytes)),
        "verack" => try!(read_verack_message(bytes)),
        "object" => try!(read_object_message(bytes)),
        _ => return Err(ParseError::UnknownCommand)
    })
}

fn read_addr_message(bytes: &[u8]) -> Result<Message,ParseError> {
    let mut cursor = Cursor::new(bytes);

    let count = try!(read_var_int_usize(&mut cursor, MAX_NODES_COUNT));
    let mut addr_list: Vec<KnownNode> = Vec::with_capacity(count);

    for _ in 0..count {
        let known_node = try!(read_known_node(&mut cursor));
        addr_list.push(known_node);
    }

    Ok(Message::Addr {
        addr_list: addr_list
    })
}

fn read_known_node<A: Read>(source: &mut A) -> Result<KnownNode,ParseError> {
    let last_seen = try!(read_timestamp(source));
    let stream = try!(read_u32(source));
    let services = try!(read_u64(source));
    let socket_addr = try!(read_address_and_port(source));

    Ok(KnownNode {
        last_seen: last_seen,
        stream: stream,
        services: services,
        socket_addr: socket_addr
    })
}

fn read_getdata_message(bytes: &[u8]) -> Result<Message,ParseError> {
    let mut cursor = Cursor::new(bytes);

    let count = try!(read_var_int_usize(&mut cursor, MAX_GETDATA_COUNT));
    let mut inventory: Vec<InventoryVector> = Vec::with_capacity(count);

    for _ in 0..count {
        let inventory_vector = try!(read_inventory_vector(&mut cursor));
        inventory.push(inventory_vector);
    }

    Ok(Message::GetData {
        inventory: inventory
    })
}

fn read_inv_message(bytes: &[u8]) -> Result<Message,ParseError> {
    let mut cursor = Cursor::new(bytes);

    let count = try!(read_var_int_usize(&mut cursor, MAX_INV_COUNT));
    let mut inventory: Vec<InventoryVector> = Vec::with_capacity(count);

    for _ in 0..count {
        let inventory_vector = try!(read_inventory_vector(&mut cursor));
        inventory.push(inventory_vector);
    }

    Ok(Message::Inv {
        inventory: inventory
    })
}

fn read_inventory_vector<A: Read>(source: &mut A) -> Result<InventoryVector,ParseError> {
    let hash = try!(read_bytes(source, 32));
    Ok(InventoryVector {
        hash: hash
    })
}

fn read_version_message(bytes: &[u8]) -> Result<Message,ParseError> {
    let mut cursor = Cursor::new(bytes);

    let version = try!(read_u32(&mut cursor));
    let services = try!(read_u64(&mut cursor));
    let timestamp = try!(read_timestamp(&mut cursor));
    try!(read_u64(&mut cursor)); // recv_services
    let addr_recv = try!(read_address_and_port(&mut cursor));
    try!(read_u64(&mut cursor)); // from_services
    let addr_from = try!(read_address_and_port(&mut cursor));
    let nonce = try!(read_u64(&mut cursor));
    let user_agent = try!(read_var_str(&mut cursor, 5000));
    let streams = try!(read_var_int_list(&mut cursor, 160000));

    // TODO - check no more data - here and in other messages

    Ok(Message::Version {
        version: version,
        services: services,
        timestamp: timestamp,
        addr_recv: addr_recv,
        addr_from: addr_from,
        nonce: nonce,
        user_agent: user_agent,
        streams: streams
    })
}

fn read_verack_message(bytes: &[u8]) -> Result<Message,ParseError> {
    if bytes.len() != 0 {
        return Err(ParseError::PayloadWrongSize);
    }

    Ok(Message::Verack)
}

fn read_object_message(bytes: &[u8]) -> Result<Message,ParseError> {
    let mut cursor = Cursor::new(bytes);

    let nonce = try!(read_u64(&mut cursor));
    let expiry = try!(read_timestamp(&mut cursor));
    let object_type = try!(read_u32(&mut cursor));
    let version = try!(read_var_int(&mut cursor, u64::max_value()));
    let stream = try!(read_var_int(&mut cursor, u32::max_value() as u64)) as u32;

    let object_position = cursor.position() as usize;
    let object = try!(read_object(object_type, version, &bytes[object_position..]));

    Ok(Message::Object {
        nonce: nonce,
        expiry: expiry,
        version: version,
        stream: stream,
        object: object
    })
}

fn read_object(object_type: u32, version: u64, bytes: &[u8]) -> Result<Object,ParseError> {
    match object_type {
        0 => read_getpubkey(version, bytes),
        1 => read_pubkey(version, bytes),
        2 => read_msg(bytes),
        3 => read_broadcast(version, bytes),
        _ => Err(ParseError::UnknownObjectType)
    }
}

fn read_getpubkey(version: u64, bytes: &[u8]) -> Result<Object,ParseError> {
    match version {
        3 => Ok(Object::GetPubKey(try!(read_getpubkey_v3(bytes)))),
        4 => Ok(Object::GetPubKey(try!(read_getpubkey_v4(bytes)))),
        _ => Err(ParseError::UnknownObjectVersion)
    }
}

fn read_getpubkey_v3(bytes: &[u8]) -> Result<GetPubKey,ParseError> {
    if bytes.len() != 20 {
        return Err(ParseError::PayloadWrongSize);
    }

    Ok(GetPubKey::V3 { ripe: bytes.to_vec() })
}

fn read_getpubkey_v4(bytes: &[u8]) -> Result<GetPubKey,ParseError> {
    if bytes.len() != 32 {
        return Err(ParseError::PayloadWrongSize);
    }

    Ok(GetPubKey::V4 { tag: bytes.to_vec() })
}

fn read_pubkey(version: u64, bytes: &[u8]) -> Result<Object,ParseError> {
    match version {
        2 => Ok(Object::PubKey(try!(read_pubkey_v2(bytes)))),
        3 => Ok(Object::PubKey(try!(read_pubkey_v3(bytes)))),
        4 => Ok(Object::PubKey(try!(read_pubkey_v4(bytes)))),
        _ => Err(ParseError::UnknownObjectVersion)
    }
}

fn read_pubkey_v2(bytes: &[u8]) -> Result<PubKey,ParseError> {
    if bytes.len() != 132 {
        return Err(ParseError::PayloadWrongSize);
    }

    let mut cursor = Cursor::new(bytes);
    let behaviour_bitfield = try!(read_u32(&mut cursor));
    let public_signing_key = try!(read_bytes(&mut cursor, 64));
    let public_encryption_key = try!(read_bytes(&mut cursor, 64));

    Ok(PubKey::V2 {
        behaviour_bitfield: behaviour_bitfield,
        public_signing_key: public_signing_key,
        public_encryption_key: public_encryption_key
    })
}

fn read_pubkey_v3(bytes: &[u8]) -> Result<PubKey,ParseError> {
    if bytes.len() < 156 {
        return Err(ParseError::PayloadWrongSize);
    }

    let mut cursor = Cursor::new(bytes);
    let behaviour_bitfield = try!(read_u32(&mut cursor));
    let public_signing_key = try!(read_bytes(&mut cursor, 64));
    let public_encryption_key = try!(read_bytes(&mut cursor, 64));
    let nonce_trials_per_byte = try!(read_u64(&mut cursor));
    let extra_bytes = try!(read_u64(&mut cursor));
    let signature = try!(read_var_int_bytes(&mut cursor));

    Ok(PubKey::V3 {
        behaviour_bitfield: behaviour_bitfield,
        public_signing_key: public_signing_key,
        public_encryption_key: public_encryption_key,
        nonce_trials_per_byte: nonce_trials_per_byte,
        extra_bytes: extra_bytes,
        signature: signature
    })
}

fn read_pubkey_v4(bytes: &[u8]) -> Result<PubKey,ParseError> {
    if bytes.len() < 32 {
        return Err(ParseError::PayloadWrongSize);
    }

    let tag = bytes[0..32].to_vec();
    let encrypted = bytes[32..].to_vec();

    Ok(PubKey::V4 {
        tag: tag,
        encrypted: encrypted
    })
}

fn read_msg(bytes: &[u8]) -> Result<Object,ParseError> {
    let encrypted = bytes.to_vec();

    Ok(Object::Msg { encrypted: encrypted })
}

fn read_broadcast(version: u64, bytes: &[u8]) -> Result<Object,ParseError> {
    match version {
        4 => Ok(Object::Broadcast(try!(read_broadcast_v4(bytes)))),
        5 => Ok(Object::Broadcast(try!(read_broadcast_v5(bytes)))),
        _ => Err(ParseError::UnknownObjectVersion)
    }
}

fn read_broadcast_v4(bytes: &[u8]) -> Result<Broadcast,ParseError> {
    let encrypted = bytes.to_vec();

    Ok(Broadcast::V4 {
        encrypted: encrypted
    })
}

fn read_broadcast_v5(bytes: &[u8]) -> Result<Broadcast,ParseError> {
    if bytes.len() < 32 {
        return Err(ParseError::PayloadWrongSize);
    }

    let tag = bytes[0..32].to_vec();
    let encrypted = bytes[32..].to_vec();

    Ok(Broadcast::V5 {
        tag: tag,
        encrypted: encrypted
    })
}

const NO_FLOW: u32 = 0;
const GLOBAL_SCOPE: u32 = 0xe;

fn read_address_and_port<A: Read>(source: &mut A) -> Result<SocketAddr,ParseError> {
    let a = try!(read_u16(source));
    let b = try!(read_u16(source));
    let c = try!(read_u16(source));
    let d = try!(read_u16(source));
    let e = try!(read_u16(source));
    let f = try!(read_u16(source));
    let g = try!(read_u16(source));
    let h = try!(read_u16(source));
    let port = try!(read_u16(source));

    let v6_ip = Ipv6Addr::new(a, b, c, d, e, f, g, h);

    let socket_addr = match v6_ip.to_ipv4() {
        None => SocketAddr::V6(SocketAddrV6::new(v6_ip, port, NO_FLOW, GLOBAL_SCOPE)),
        Some(v4_ip) => SocketAddr::V4(SocketAddrV4::new(v4_ip, port))
    };

    Ok(socket_addr)
}

fn read_timestamp<A: Read>(source: &mut A) -> Result<Timespec,ParseError> {
    let secs = try!(read_i64(source));
    Ok(Timespec::new(secs, 0))
}

fn read_var_int_bytes<A: Read>(source: &mut A) -> Result<Vec<u8>,ParseError> {
    let byte_count = try!(read_var_int_usize(source, usize::max_value()));
    Ok(try!(read_bytes(source, byte_count)))
}

fn read_var_str<A: Read>(source: &mut A, max_length: usize) -> Result<String,ParseError> {
    let length = try!(read_var_int_usize(source, max_length));

    let string_bytes = try!(read_bytes(source, length));
    ASCII.decode(&string_bytes, DecoderTrap::Strict).map_err(|_| ParseError::BadAscii)
}

fn read_var_int_list<A: Read>(source: &mut A, max_count: usize) -> Result<Vec<u64>,ParseError> {
    let count = try!(read_var_int_usize(source, max_count));

    let mut int_list: Vec<u64> = Vec::with_capacity(count);
    for _ in 0..count {
        let int = try!(read_var_int(source, u64::max_value()));
        int_list.push(int);
    }

    Ok(int_list)
}

fn read_var_int_usize<A: Read>(source: &mut A, max_value: usize) -> Result<usize,ParseError> {
    read_var_int(source, max_value as u64).map(|v| v as usize)
}

fn read_var_int<A: Read>(source: &mut A, max_value: u64) -> Result<u64,ParseError> {
    let first_byte: u8 = try!(read_u8(source));

    let value = match first_byte {
        byte @ 0...0xfc => byte as u64,
        0xfd => try!(read_u16(source)) as u64,
        0xfe => try!(read_u32(source)) as u64,
        0xff => try!(read_u64(source)),
        _ => unreachable!()
    };

    if value > max_value {
        return Err(ParseError::MaxExceeded);
    }

    Ok(value)
}

fn read_bytes<A: Read>(source: &mut A, count: usize) -> Result<Vec<u8>,ParseError> {
    let mut take = source.take(count as u64);
    let mut bytes: Vec<u8> = Vec::with_capacity(count);
    let read_count = try!(take.read_to_end(&mut bytes).map_err(|_| ParseError::UnexpectedPayloadEnd));

    if read_count != count || bytes.len() != count {
        return Err(ParseError::UnexpectedPayloadEnd);
    }

    Ok(bytes)
}

fn read_remaining_bytes<A: Read>(source: &mut A) -> Result<Vec<u8>, ParseError> {
    let mut bytes: Vec<u8> = vec![];
    try!(source.read_to_end(&mut bytes).map_err(|_| ParseError::UnexpectedPayloadEnd));

    Ok(bytes)
}

fn read_u64<A: Read>(source: &mut A) -> Result<u64,ParseError> {
    source.read_u64::<BigEndian>().map_err(|_| ParseError::UnexpectedPayloadEnd)
}

fn read_i64<A: Read>(source: &mut A) -> Result<i64,ParseError> {
    source.read_i64::<BigEndian>().map_err(|_| ParseError::UnexpectedPayloadEnd)
}

fn read_u32<A: Read>(source: &mut A) -> Result<u32,ParseError> {
    source.read_u32::<BigEndian>().map_err(|_| ParseError::UnexpectedPayloadEnd)
}

fn read_u16<A: Read>(source: &mut A) -> Result<u16,ParseError> {
    source.read_u16::<BigEndian>().map_err(|_| ParseError::UnexpectedPayloadEnd)
}

fn read_u8<A: Read>(source: &mut A) -> Result<u8,ParseError> {
    source.read_u8().map_err(|_| ParseError::UnexpectedPayloadEnd)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::SocketAddr;
    use super::read_address_and_port;
    use super::read_timestamp;
    use super::read_var_int_bytes;
    use super::read_var_str;
    use super::read_var_int_list;
    use super::read_var_int_usize;
    use super::read_var_int;
    use super::read_bytes;
    use super::read_remaining_bytes;
    use super::read_u16;

    #[test]
    fn test_read_address_and_port_for_v4() {
        let bytes: Vec<u8> = vec![ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 11, 12, 13, 14, 21, 190 ];
        let mut source = Cursor::new(bytes);

        let socket_addr = match read_address_and_port(&mut source).unwrap() {
            SocketAddr::V6(_) => panic!("Expected V4"),
            SocketAddr::V4(v4) => v4
        };

        assert_eq!([11, 12, 13, 14], socket_addr.ip().octets());
        assert_eq!(5566, socket_addr.port());
    }

    #[test]
    fn test_read_address_and_port_for_v6() {
        let bytes: Vec<u8> = vec![ 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 25, 255 ];
        let mut source = Cursor::new(bytes);

        let socket_addr = match read_address_and_port(&mut source).unwrap() {
            SocketAddr::V4(_) => panic!("Expected V6"),
            SocketAddr::V6(v6) => v6
        };

        assert_eq!([0x102, 0x304, 0x506, 0x708, 0x90a, 0xb0c, 0xd0e, 0xf00], socket_addr.ip().segments());
        assert_eq!(6655, socket_addr.port());
    }

    #[test]
    fn test_read_timestamp() {
        let bytes: Vec<u8> = vec![ 8, 7, 6, 5, 4, 3, 2, 1 ];
        let mut source = Cursor::new(bytes);

        let sec = read_timestamp(&mut source).unwrap().sec;
        assert_eq!(0x0807060504030201, sec);
    }

    #[test]
    fn test_read_var_int_bytes() {
        let bytes: Vec<u8> = vec![ 2, 56, 62 ];
        let mut source = Cursor::new(bytes);

        let result = read_var_int_bytes(&mut source).unwrap();
        assert_eq!(vec![ 56, 62 ], result);
    }

    #[test]
    fn test_read_var_str() {
        let bytes: Vec<u8> = vec![ 3, 65, 66, 67 ];
        let mut source = Cursor::new(bytes);

        let string = read_var_str(&mut source, 3).unwrap();
        assert_eq!("ABC", &string);
    }

    #[test]
    fn test_read_var_str_too_long() {
        let bytes: Vec<u8> = vec![ 3, 65, 66, 67 ];
        let mut source = Cursor::new(bytes);

        assert!(read_var_str(&mut source, 2).is_err());
    }

    #[test]
    fn test_read_var_int_list() {
        let bytes: Vec<u8> = vec![ 3, 65, 66, 67 ];
        let mut source = Cursor::new(bytes);

        let int_list = read_var_int_list(&mut source, 3).unwrap();

        let expected: Vec<u64> = vec![ 65, 66, 67 ];
        assert_eq!(expected, int_list);
    }

    #[test]
    fn test_read_var_int_list_too_long() {
        let bytes: Vec<u8> = vec![ 3, 65, 66, 67 ];
        let mut source = Cursor::new(bytes);

        assert!(read_var_int_list(&mut source, 2).is_err());
    }

    #[test]
    fn test_read_var_int_usize() {
        let bytes: Vec<u8> = vec![ 0xfd, 5, 220 ];
        let mut source = Cursor::new(bytes);

        let var_int = read_var_int_usize(&mut source, 2000).unwrap();
        assert_eq!(1500, var_int);
    }

    #[test]
    fn test_read_var_int_u8() {
        let bytes: Vec<u8> = vec![ 0xfc ];
        let mut source = Cursor::new(bytes);

        let var_int = read_var_int(&mut source, 20000000).unwrap();
        assert_eq!(0xfc, var_int);
    }

    #[test]
    fn test_read_var_int_u16() {
        let bytes: Vec<u8> = vec![ 0xfd, 1, 2 ];
        let mut source = Cursor::new(bytes);

        let var_int = read_var_int(&mut source, 20000000).unwrap();
        assert_eq!(258, var_int);
    }

    #[test]
    fn test_read_var_int_u32() {
        let bytes: Vec<u8> = vec![ 0xfe, 1, 2, 3, 4 ];
        let mut source = Cursor::new(bytes);

        let var_int = read_var_int(&mut source, 20000000).unwrap();
        assert_eq!(0x1020304, var_int);
    }

    #[test]
    fn test_read_var_int_u64() {
        let bytes: Vec<u8> = vec![ 0xff, 1, 2, 3, 4, 5, 6, 7, 8 ];
        let mut source = Cursor::new(bytes);

        let var_int = read_var_int(&mut source, u64::max_value()).unwrap();
        assert_eq!(0x102030405060708, var_int);
    }

    #[test]
    fn test_read_bytes() {
        let bytes: Vec<u8> = vec![ 1, 2, 4 ];
        let mut source = Cursor::new(bytes);

        let bytes = read_bytes(&mut source, 2).unwrap();
        assert_eq!(vec![ 1, 2 ], bytes);
    }

    #[test]
    fn test_read_remaining_bytes() {
        let bytes: Vec<u8> = vec![ 1, 2, 3, 4, 5 ];
        let mut source = Cursor::new(bytes);

        read_u16(&mut source).unwrap();

        let remaining_bytes = read_remaining_bytes(&mut source).unwrap();
        assert_eq!(vec![ 3, 4, 5 ], remaining_bytes);
    }
}
