mod handler;
mod pow;
mod responder;
mod sender;
mod verify;

pub use self::handler::MessageHandler;
pub use self::responder::MessageResponder;
pub use self::verify::MessageVerifier;
pub use self::sender::Sender;
pub use self::sender::MessageSendError;

use channel::MemorySize;
use std::mem;
use std::net::SocketAddr;
use std::time::SystemTime;

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
    pub last_seen: SystemTime,
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
pub struct VersionData {
    pub version: u32,
    pub services: u64,
    pub timestamp: SystemTime,
    pub addr_recv: SocketAddr,
    pub addr_from: SocketAddr,
    pub nonce: u64,
    pub user_agent: String,
    pub streams: Vec<u64>
}

#[derive(Clone,Debug,PartialEq)]
pub struct ObjectData {
    pub nonce: u64,
    pub expiry: SystemTime,
    pub version: u64,
    pub stream: u32,
    pub object: Object
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
    Version(VersionData),
    Verack,
    Object(ObjectData)
}

impl MemorySize for Message {
    fn byte_count(&self) -> usize {
        let extra_bytes = match self {
            &Message::Addr {ref addr_list } => 9 + (42 * addr_list.len()),
            &Message::GetData { ref inventory, .. } => 9 + (32 * inventory.len()),
            &Message::Inv { ref inventory, .. } => 9 + (32 * inventory.len()),
            &Message::Version(VersionData { ref streams, ref user_agent, .. }) => 86 + user_agent.len() + (8 * streams.len()),
            &Message::Verack => 0,
            &Message::Object(ObjectData { .. }) => MAX_PAYLOAD_LENGTH_FOR_OBJECT as usize
        };

        mem::size_of::<Message>() + extra_bytes
    }
}
