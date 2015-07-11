//mod pow;
mod read;
mod responder;
mod write;

pub use self::read::ParseError;
pub use self::responder::MessageResponder;
pub use self::read::read_message;
pub use self::write::write_message;

use channel::MemorySize;
use std::mem;
use std::net::SocketAddr;
use time::Timespec;

const MAGIC: u32 = 0xe9beb4d9;
const MAX_PAYLOAD_LENGTH: u32 = 1600003;
const MAX_NODES_COUNT: usize = 1000;
const MAX_GETDATA_COUNT: usize = 50000;
const MAX_INV_COUNT: usize = 50000;
const MAX_PAYLOAD_LENGTH_FOR_OBJECT: u32 = 262144; // 2^18 - maximum object length
// const MAX_TTL: u32 = 2430000; // 28 days and 3 hours
// const OBJECT_EXPIRY_CUTOFF: i64 = -3600; // 1 hour ago

#[derive(Clone,Debug,PartialEq,Eq,Hash,PartialOrd,Ord)]
pub struct InventoryVector {
    pub hash: Vec<u8> // 32 bytes
}

#[derive(Clone,Debug,PartialEq)]
pub struct KnownNode {
    pub last_seen: Timespec,
    pub stream: u32,
    pub services: u64,
    pub socket_addr: SocketAddr
}

#[derive(Clone,Debug,PartialEq)]
pub enum GetPubKey {
    V3 {
        ripe: Vec<u8> // 20 bytes
    },
    V4 {
        tag: Vec<u8> // 32 bytes
    }
}

#[derive(Clone,Debug,PartialEq)]
pub enum PubKey {
    V2 {
        behaviour_bitfield: u32,
        public_signing_key: Vec<u8>, // 64 bytes
        public_encryption_key: Vec<u8> // 64 bytes
    },
    V3 {
        behaviour_bitfield: u32,
        public_signing_key: Vec<u8>, // 64 bytes
        public_encryption_key: Vec<u8>, // 64 bytes
        nonce_trials_per_byte: u64,
        extra_bytes: u64,
        signature: Vec<u8>
    },
    V4 {
        tag: Vec<u8>, // 32 bytes
        encrypted: Vec<u8>
    }
}

#[derive(Clone,Debug,PartialEq)]
pub enum Broadcast {
    V4 {
        encrypted: Vec<u8>
    },
    V5 {
        tag: Vec<u8>, // 32 bytes
        encrypted: Vec<u8>
    },
}

#[derive(Clone,Debug,PartialEq)]
pub enum Object {
    GetPubKey(GetPubKey),
    PubKey(PubKey),
    Msg { encrypted: Vec<u8> },
    Broadcast(Broadcast)
}

#[derive(Clone,Debug,PartialEq)]
pub enum Message {
    Addr {
        addr_list: Vec<KnownNode>
    },
    GetData {
        inventory: Vec<InventoryVector>
    },
    Inv {
        inventory: Vec<InventoryVector>
    },
    Version {
        version: u32,
        services: u64,
        timestamp: Timespec,
        addr_recv: SocketAddr,
        addr_from: SocketAddr,
        nonce: u64,
        user_agent: String,
        streams: Vec<u64>
    },
    Verack,
    Object {
        nonce: u64,
        expiry: Timespec,
        version: u64,
        stream: u32,
        object: Object
    },
}

impl MemorySize for Message {
    fn byte_count(&self) -> usize {
        let extra_bytes = match self {
            &Message::Addr {ref addr_list } => 9 + (42 * addr_list.len()),
            &Message::GetData { ref inventory, .. } => 9 + (32 * inventory.len()),
            &Message::Inv { ref inventory, .. } => 9 + (32 * inventory.len()),
            &Message::Version { ref streams, ref user_agent, .. } => 86 + user_agent.len() + (8 * streams.len()),
            &Message::Verack => 0,
            &Message::Object { .. }=> MAX_PAYLOAD_LENGTH_FOR_OBJECT as usize
        };

        mem::size_of::<Message>() + extra_bytes
    }
}

#[cfg(test)]
mod tests {
    use net::to_socket_addr;
    use rand::{Rng,SeedableRng,XorShiftRng};
    use std::io::Cursor;
    use time::Timespec;
    use super::{InventoryVector,KnownNode,Message,Object,GetPubKey};
    use super::{read_message,write_message};

    #[test]
    fn test_addr() {
        let message = Message::Addr {
            addr_list: vec![
                KnownNode {
                    last_seen: Timespec::new(0x908070605, 0),
                    stream: 2,
                    services: 3,
                    socket_addr: to_socket_addr("12.13.14.15:1617")
                },
                KnownNode {
                    last_seen: Timespec::new(0x1918171615, 0),
                    stream: 4,
                    services: 5,
                    socket_addr: to_socket_addr("22.23.24.25:2627")
                }
            ]
        };

        let expected = vec![
            0xe9, 0xbe, 0xb4, 0xd9, // magic
            97, 100, 100, 114, // "addr"
            0, 0, 0, 0, 0, 0, 0, 0, // command padding
            0, 0, 0, 77, // payload length
            172, 52, 247, 80, // checksum
            2, // count
            0, 0, 0, 9, 8, 7, 6, 5, // last_seen
            0, 0, 0, 2, // stream
            0, 0, 0, 0, 0, 0, 0, 3, // services
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 12, 13, 14, 15, // ip
            6, 81, // port
            0, 0, 0, 0x19, 0x18, 0x17, 0x16, 0x15, // last_seen
            0, 0, 0, 4, // stream
            0, 0, 0, 0, 0, 0, 0, 5, // services
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 22, 23, 24, 25, // ip
            10, 67 // port
        ];

        run_message_read_write_test(message, expected);
    }

    #[test]
    fn test_getdata() {
        let mut rng: XorShiftRng = SeedableRng::from_seed([0, 0, 0, 1]);
        let hash1: Vec<u8> = rng.gen_iter::<u8>().take(32).collect();
        let hash2: Vec<u8> = rng.gen_iter::<u8>().take(32).collect();

        let message = Message::GetData {
            inventory: vec![
                InventoryVector {
                    hash: hash1.clone()
                },
                InventoryVector {
                    hash: hash2.clone()
                }
            ]
        };

        let mut expected = vec![
            0xe9, 0xbe, 0xb4, 0xd9, // magic
            103, 101, 116, 100, 97, 116, 97, // "getdata"
            0, 0, 0, 0, 0, // command padding
            0, 0, 0, 65, // payload length
            20, 214, 57, 221, // checksum
            2,
        ];
        expected.extend(hash1);
        expected.extend(hash2);

        run_message_read_write_test(message, expected);
    }

    #[test]
    fn test_inv() {
        let mut rng: XorShiftRng = SeedableRng::from_seed([0, 0, 0, 1]);
        let hash1: Vec<u8> = rng.gen_iter::<u8>().take(32).collect();
        let hash2: Vec<u8> = rng.gen_iter::<u8>().take(32).collect();

        let message = Message::Inv {
            inventory: vec![
                InventoryVector {
                    hash: hash1.clone()
                },
                InventoryVector {
                    hash: hash2.clone()
                }
            ]
        };

        let mut expected = vec![
            0xe9, 0xbe, 0xb4, 0xd9, // magic
            105, 110, 118, // "inv"
            0, 0, 0, 0, 0, 0, 0, 0, 0, // command padding
            0, 0, 0, 65, // payload length
            20, 214, 57, 221, // checksum
            2,
        ];
        expected.extend(hash1);
        expected.extend(hash2);

        run_message_read_write_test(message, expected);
    }

    #[test]
    fn test_version() {
        let message = Message::Version {
            version: 3,
            services: 1,
            timestamp: Timespec::new(0x504030201, 0),
            addr_recv: to_socket_addr("127.0.0.1:8444"),
            addr_from: to_socket_addr("11.22.33.44:8555"),
            nonce: 0x12345678,
            user_agent: "Rubbem".to_string(),
            streams: vec![ 1 ]
        };

        let expected = vec![
            0xe9, 0xbe, 0xb4, 0xd9, // magic
            118, 101, 114, 115, 105, 111, 110, // "version"
            0, 0, 0, 0, 0, // command padding
            0, 0, 0, 89, // payload length
            239, 233, 96, 8, // checksum
            0, 0, 0, 3, // version
            0, 0, 0, 0, 0, 0, 0, 1, // services
            0, 0, 0, 5, 4, 3, 2, 1, // timestamp
            0, 0, 0, 0, 0, 0, 0, 1, // recv_services
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1, // recv_addr
            32, 252, // recv_port
            0, 0, 0, 0, 0, 0, 0, 1, // from_services
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 11, 22, 33, 44, // from_addr
            33, 107, // from_port
            0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, // nonce
            6, 82, 117, 98, 98, 101, 109, // user_agent
            1, 1 // streams
        ];

        run_message_read_write_test(message, expected);
    }

    #[test]
    fn test_verack() {
        let message = Message::Verack;

        let expected = vec![
            0xe9, 0xbe, 0xb4, 0xd9, // magic
            118, 101, 114, 97, 99, 107, // "verack"
            0, 0, 0, 0, 0, 0, // command padding
            0, 0, 0, 0, // payload length
            0xcf, 0x83, 0xe1, 0x35 // checksum
        ];

        run_message_read_write_test(message, expected);
    }

    #[test]
    fn test_object() {
        let mut rng: XorShiftRng = SeedableRng::from_seed([0, 0, 0, 1]);
        let tag: Vec<u8> = rng.gen_iter::<u8>().take(32).collect();

        let message = Message::Object {
            nonce: 0xf29f6e8b9acd981d,
            expiry: Timespec::new(0x010203040506, 0),
            version: 4, // GetPubKey verion
            stream: 2,
            object: Object::GetPubKey(
                GetPubKey::V4 {
                    tag: tag.clone()
                }
            )
        };

        let mut expected = vec![
            0xe9, 0xbe, 0xb4, 0xd9, // magic
            111, 98, 106, 101, 99, 116, // "object"
            0, 0, 0, 0, 0, 0, // command padding
            0, 0, 0, 54, // payload length
            70, 53, 134, 89, // checksum
            0xf2, 0x9f, 0x6e, 0x8b, 0x9a, 0xcd, 0x98, 0x1d, // nonce
            0, 0, 1, 2, 3, 4, 5, 6, // expiry
            0, 0, 0, 0, // object_type for GetPubKey
            4, // version
            2, // stream
        ];
        expected.extend(tag);

        run_message_read_write_test(message, expected);
    }

    fn run_message_read_write_test(message: Message, expected: Vec<u8>) {
        let mut output = vec![];
        write_message(&mut output, &message);

        println!("");
        println!("Exp: {:?}", expected);
        println!("Out: {:?}", output);

        assert_eq!(expected, output);

        let mut cursor = Cursor::new(output);
        let roundtrip = read_message(&mut cursor).unwrap();

        assert_eq!(message, roundtrip);
    }
}
