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

    pub fn respond<F>(&self, message: Message, send: F) -> Result<(), SendError<Message>>
        where F : Fn(Message) -> Result<(), SendError<Message>> {
        match message {
            Message::Version { .. } => {
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
            Message::Addr { .. } => {},
            Message::Inv { .. } => {},
//                    create_filtered_getdata_message
            Message::GetData { .. } => {},
//                    create object messages
            Message::Object { .. } => {}
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
}
