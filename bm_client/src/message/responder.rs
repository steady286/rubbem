use chunk::CreateChunk;
use config::Config;
use inventory::Inventory;
use known_nodes::KnownNodes;
use message::{InventoryVector,Message};
use net::to_socket_addr;
use std::sync::mpsc::SendError;
use std::net::{Ipv4Addr,SocketAddr,SocketAddrV4};
use time::{get_time};

use super::{MAX_INV_COUNT,MAX_NODES_COUNT};

pub struct MessageResponder {
    config: Config,
    known_nodes: KnownNodes,
    inventory: Inventory,
    peer_addr: SocketAddr
}

impl MessageResponder {
    pub fn new(config: &Config, known_nodes: &KnownNodes, inventory: &Inventory, peer_addr: SocketAddr) -> MessageResponder {
        MessageResponder {
            config: config.clone(),
            known_nodes: known_nodes.clone(),
            inventory: inventory.clone(),
            peer_addr: peer_addr
        }
    }

    pub fn send_version<F>(&self, f: F) -> Result<(), SendError<Message>>
        where F : Fn(Message) -> Result<(), SendError<Message>> {
        f(self.create_version_message())
    }

    pub fn respond<F>(&mut self, message: Message, send: F) -> Result<(), SendError<Message>>
        where F : Fn(Message) -> Result<(), SendError<Message>> {
        match message {
            Message::Version { .. } => {
                // TODO - record the peer as a known_node???
                // TODO - check the version, stream, timestamp, nonce, etc.???
                try!(send(Message::Verack));
            },
            Message::Verack => {
                try!(send(self.create_addr_message()));

                let inventory_iterator = self.inventory.iterator();
                let chunk_iterator = inventory_iterator.chunk(MAX_INV_COUNT);
                for inventory_chunk in chunk_iterator {
                    try!(send(self.create_inv_message(inventory_chunk)));
                }
            },
            Message::Addr { addr_list } => {
                for known_node in addr_list.iter() {
                    self.known_nodes.add_known_node(&known_node);
                }
            },
            Message::Inv { inventory: inventory_chunk } => {
                let get_data = self.inventory.unknown(inventory_chunk);
                try!(send(self.create_getdata_message(get_data)));
            },
            Message::GetData { inventory: inventory_chunk } => {
                for inventory_vector in inventory_chunk {
                    if let Some(object_message) = self.inventory.get_object_message(&inventory_vector) {
                        try!(send(object_message));
                    }
                }
            },
            m @ Message::Object { .. } => {
                self.inventory.add_object_message(&m);
            }
        };

        Ok(())
    }

    fn create_version_message(&self) -> Message {
        let port = self.config.port();
        let our_addr = to_socket_addr(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port));
        let nonce = self.config.nonce();
        let user_agent = self.config.user_agent().to_string();
        let streams = vec![ 1 ];

        Message::Version {
            version: 3,
            services: 1,
            timestamp: get_time(),
            addr_recv: self.peer_addr,
            addr_from: our_addr,
            nonce: nonce,
            user_agent: user_agent,
            streams: streams
        }
    }

    fn create_addr_message(&self) -> Message {
        let addr_list = self.known_nodes.get_random_selection_but_not(MAX_NODES_COUNT, vec![ self.peer_addr ]);
        Message::Addr {
            addr_list: addr_list
        }
    }

    fn create_inv_message(&self, inventory_chunk: Vec<InventoryVector>) -> Message {
        Message::Inv {
            inventory: inventory_chunk
        }
    }

    fn create_getdata_message(&self, inventory_chunk: Vec<InventoryVector>) -> Message {
        Message::GetData {
            inventory: inventory_chunk
        }
    }
}
