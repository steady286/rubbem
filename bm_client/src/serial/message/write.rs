use checksum::sha512_checksum;
use encoding::{Encoding,EncoderTrap};
use encoding::all::ASCII;
use serial::basic::write::*;
use std::net::SocketAddr;
use std::time::{SystemTime,UNIX_EPOCH};

use message::{InventoryVector,KnownNode,GetPubKey,PubKey,Broadcast,Object,Message,ObjectData,VersionData};
use serial::message::{MAGIC,MAX_PAYLOAD_LENGTH,MAX_NODES_COUNT,MAX_GETDATA_COUNT,MAX_INV_COUNT};

pub fn write_message(output: &mut Vec<u8>, message: &Message) {
    let mut payload = vec![];
    write_payload(&mut payload, message);

    assert!(payload.len() <= MAX_PAYLOAD_LENGTH as usize);
    assert!(MAX_PAYLOAD_LENGTH <= u32::max_value());

    let checksum = sha512_checksum(&payload);

    write_u32(output, MAGIC);
    write_command(output, message);
    write_u32(output, payload.len() as u32);
    write_u32(output, checksum);
    write_bytes_no_check(output, &payload);
}

fn write_command(output: &mut Vec<u8>, message: &Message) {
    let command = match message {
        &Message::Addr {..} => "addr",
        &Message::GetData {..} => "getdata",
        &Message::Inv {..} => "inv",
        &Message::Version(VersionData {..}) => "version",
        &Message::Verack => "verack",
        &Message::Object(ObjectData {..}) => "object"
    };

    let mut ascii_command = ASCII.encode(&command, EncoderTrap::Ignore).unwrap();
    ensure_size(&mut ascii_command, 12, 0);

    write_bytes(output, &ascii_command, 12);
}

fn ensure_size(bytes: &mut Vec<u8>, size: usize, padding: u8) {
    while bytes.len() > size {
        bytes.pop();
    }

    while bytes.len() < size {
        bytes.push(padding);
    }
}

fn write_payload(output: &mut Vec<u8>, message: &Message) {
    match message {
        &Message::Addr {
            ref addr_list
        } => write_addr_message(output, addr_list),

        &Message::GetData {
            ref inventory
        } => write_getdata_message(output, inventory),

        &Message::Inv {
            ref inventory
        } => write_inv_message(output, inventory),

        &Message::Version(VersionData {
            version,
            services,
            ref timestamp,
            ref addr_recv,
            ref addr_from,
            nonce,
            ref user_agent,
            ref streams
        }) => write_version_message(output, version, services, timestamp, addr_recv, addr_from, nonce, user_agent, streams),

        &Message::Verack => write_verack_message(output),

        &Message::Object(ObjectData {
            nonce,
            ref expiry,
            version,
            stream,
            ref object
        }) => write_object_message(output, nonce, expiry, version, stream, object)
    }
}

fn write_addr_message(output: &mut Vec<u8>, addr_list: &[KnownNode]) {
    assert!(addr_list.len() <= MAX_NODES_COUNT);
    assert!(MAX_NODES_COUNT <= u16::max_value() as usize);

    write_var_int_16(output, addr_list.len() as u16);

    for addr in addr_list {
        write_known_node(output, addr);
    }
}

fn write_known_node(output: &mut Vec<u8>, known_node: &KnownNode) {
    write_i64(output, get_secs_from_time(&known_node.last_seen));
    write_u32(output, known_node.stream);
    write_u64(output, known_node.services);
    write_address_and_port(output, &known_node.socket_addr);
}

fn write_getdata_message(output: &mut Vec<u8>, inventory: &[InventoryVector]) {
    write_inventory_vectors(output, inventory, MAX_GETDATA_COUNT);
}

fn write_inv_message(output: &mut Vec<u8>, inventory: &[InventoryVector]) {
    write_inventory_vectors(output, inventory, MAX_INV_COUNT);
}

fn write_inventory_vectors(output: &mut Vec<u8>, inventory: &[InventoryVector], max_length: usize) {
    assert!(max_length <= u16::max_value() as usize);
    assert!(inventory.len() <= max_length);

    write_var_int_16(output, inventory.len() as u16);

    for inventory_vector in inventory {
        write_inventory_vector(output, inventory_vector);
    }
}

fn write_inventory_vector(output: &mut Vec<u8>, inventory_vector: &InventoryVector) {
    write_bytes(output, &inventory_vector.hash, 32);
}

fn write_version_message(output: &mut Vec<u8>, version: u32, services: u64, timestamp: &SystemTime, addr_recv: &SocketAddr, addr_from: &SocketAddr, nonce: u64, user_agent: &str, streams: &[u64]) {
    write_u32(output, version);
    write_u64(output, services);
    write_i64(output, get_secs_from_time(timestamp));
    write_u64(output, services);
    write_address_and_port(output, addr_recv);
    write_u64(output, services);
    write_address_and_port(output, addr_from);
    write_u64(output, nonce);
    write_var_str(output, user_agent);
    write_var_int_list(output, streams);
}

fn write_verack_message(_: &mut Vec<u8>) {
}

pub fn write_object_message_data(output: &mut Vec<u8>, object_data: &ObjectData) {
    write_object_message(output, object_data.nonce, &object_data.expiry, object_data.version, object_data.stream, &object_data.object);
}

fn write_object_message(output: &mut Vec<u8>, nonce: u64, expiry: &SystemTime, version: u64, stream: u32, object: &Object) {
    write_u64(output, nonce);
    write_i64(output, get_secs_from_time(expiry));
    write_object_type(output, object);
    write_var_int_64(output, version);
    write_var_int_32(output, stream);
    write_object(output, object);
}

fn write_object_type(output: &mut Vec<u8>, object: &Object) {
    let object_type = match object {
        &Object::GetPubKey(_) => 0,
        &Object::PubKey(_) => 1,
        &Object::Msg { encrypted: _ } => 2,
        &Object::Broadcast(_) => 3
    };

    write_u32(output, object_type);
}

fn write_object(output: &mut Vec<u8>, object: &Object) {
    match object {
        &Object::GetPubKey(ref getpubkey) => write_getpubkey(output, getpubkey),
        &Object::PubKey(ref pubkey) => write_pubkey(output, pubkey),
        &Object::Msg { ref encrypted } => write_msg(output, encrypted),
        &Object::Broadcast(ref broadcast) => write_broadcast(output, broadcast)
    }
}

fn write_getpubkey(output: &mut Vec<u8>, getpubkey: &GetPubKey) {
    match getpubkey {
        &GetPubKey::V3 { ref ripe } => write_getpubkey_v3(output, ripe),
        &GetPubKey::V4 { ref tag } => write_getpubkey_v4(output, tag),
    }
}

fn write_getpubkey_v3(output: &mut Vec<u8>, ripe: &[u8]) {
    write_bytes(output, ripe, 20);
}

fn write_getpubkey_v4(output: &mut Vec<u8>, tag: &[u8]) {
    write_bytes(output, tag, 32);
}

fn write_pubkey(output: &mut Vec<u8>, pubkey: &PubKey) {
    match pubkey {
        &PubKey::V2 {
            behaviour_bitfield,
            ref public_signing_key,
            ref public_encryption_key
        } => write_pubkey_v2(output, behaviour_bitfield, public_signing_key, public_encryption_key),
        &PubKey::V3 {
            behaviour_bitfield,
            ref public_signing_key,
            ref public_encryption_key,
            nonce_trials_per_byte,
            extra_bytes,
            ref signature
        } => write_pubkey_v3(output, behaviour_bitfield, public_signing_key, public_encryption_key, nonce_trials_per_byte, extra_bytes, signature),
        &PubKey::V4 {
            ref tag,
            ref encrypted
        } => write_pubkey_v4(output, tag, encrypted)
    }
}

fn write_pubkey_v2(output: &mut Vec<u8>, behaviour_bitfield: u32, public_signing_key: &[u8], public_encryption_key: &[u8]) {
    write_u32(output, behaviour_bitfield);
    write_bytes(output, public_signing_key, 64);
    write_bytes(output, public_encryption_key, 64);
}

fn write_pubkey_v3(output: &mut Vec<u8>, behaviour_bitfield: u32, public_signing_key: &[u8], public_encryption_key: &[u8], nonce_trials_per_byte: u64, extra_bytes: u64, signature: &[u8]) {
    write_u32(output, behaviour_bitfield);
    write_bytes(output, public_signing_key, 64);
    write_bytes(output, public_encryption_key, 64);
    write_u64(output, nonce_trials_per_byte);
    write_u64(output, extra_bytes);
    write_var_int_bytes(output, signature);
}

fn write_pubkey_v4(output: &mut Vec<u8>, tag: &[u8], encrypted: &[u8]) {
    write_bytes(output, tag, 32);
    write_bytes_no_check(output, encrypted);
}

fn write_msg(output: &mut Vec<u8>, encrypted: &[u8]) {
    write_bytes_no_check(output, encrypted);
}

fn write_broadcast(output: &mut Vec<u8>, broadcast: &Broadcast) {
    match broadcast {
        &Broadcast::V4 {
            ref encrypted
        } => write_broadcast_v4(output, encrypted),
        &Broadcast::V5 {
            ref tag,
            ref encrypted
        } => write_broadcast_v5(output, tag, encrypted)
    }
}

fn write_broadcast_v4(output: &mut Vec<u8>, encrypted: &[u8]) {
    write_bytes_no_check(output, encrypted);
}

fn write_broadcast_v5(output: &mut Vec<u8>, tag: &[u8], encrypted: &[u8]) {
    write_bytes(output, tag, 32);
    write_bytes_no_check(output, encrypted);
}

fn write_address_and_port(output: &mut Vec<u8>, socket_addr: &SocketAddr) {
    let v6_ip = match socket_addr {
        &SocketAddr::V4(v4_addr) => v4_addr.ip().to_ipv6_mapped(),
        &SocketAddr::V6(v6_addr) => v6_addr.ip().to_owned()
    };

    for &segment in v6_ip.segments().iter() {
        write_u16(output, segment);
    }

    let port = socket_addr.port();
    write_u16(output, port);
}

fn get_secs_from_time(time: &SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i64,
        Err(time_error) => -(time_error.duration().as_secs() as i64)
    }
}

#[cfg(test)]
mod tests {
    use net::to_socket_addr;
    use super::write_address_and_port;

    #[test]
    fn test_write_address_and_port_for_v4() {
        let mut payload = vec![];
        let socket_addr = to_socket_addr("127.0.0.1:8444");
        write_address_and_port(&mut payload, &socket_addr);

        assert_eq!(payload, vec![ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1, 32, 252 ]);
    }

    #[test]
    fn test_write_address_and_port_for_v6() {
        let mut payload = vec![];
        let socket_addr = to_socket_addr("[2001:cdba:0:0:0:0:3257:9652]:8444");
        write_address_and_port(&mut payload, &socket_addr);

        assert_eq!(payload, vec![ 0x20, 0x01, 0xcd, 0xba, 0, 0, 0, 0, 0, 0, 0, 0, 0x32, 0x57, 0x96, 0x52, 32, 252 ]);
    }
}
