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

#[cfg(test)]
mod tests {
    use config::Config;
    use inventory::{Inventory,calculate_inventory_vector};
    use known_nodes::KnownNodes;
    use message::{InventoryVector,KnownNode,Message,Object,GetPubKey};
    use net::to_socket_addr;
    use persist::Persister;
    use std::sync::Mutex;
    use std::sync::mpsc::SendError;
    use time::{Timespec,get_time};
    use super::MessageResponder;

    struct Output {
        pub messages: Mutex<Vec<Message>>
    }

    impl Output {
        fn new() -> Output {
            Output {
                messages: Mutex::new(vec![])
            }
        }

        fn add(&self, message: Message) -> Result<(), SendError<Message>> {
            self.messages.lock().unwrap().push(message);
            Ok(())
        }

        fn get_messages(&self) -> Vec<Message> {
            self.messages.lock().unwrap().clone()
        }
    }

    #[test]
    fn test_get_version_send_verack() {
        let input = Message::Version {
            version: 3,
            services: 1,
            timestamp: get_time(),
            addr_recv: to_socket_addr("127.0.0.1:8555"),
            addr_from: to_socket_addr("127.0.0.1:8444"),
            nonce: 0x0102030405060708,
            user_agent: "test".to_string(),
            streams: vec![ 1 ]
        };
        let output = run_test(input, Persister::new());
        assert_eq!(1, output.len());

        let message = &output[0];
        match message {
            &Message::Verack => {},
            _ => panic!("Not a Verack message: {:?}", message)
        }
    }

    #[test]
    fn test_get_verack_empty_persister_send_empty_addr() {
        let input = Message::Verack;
        let output = run_test(input, Persister::new());
        assert_eq!(1, output.len());

        let message = &output[0];
        match message {
            &Message::Addr { ref addr_list } => { assert_eq!(0, addr_list.len()) },
            _ => panic!("Not an Addr message: {:?}", message)
        }
    }

    #[test]
    fn test_get_verack_populated_persister_send_addr_and_inv() {
        let mut persister = Persister::new();
        let known_node = KnownNode {
            last_seen: Timespec::new(5, 0),
            stream: 1,
            services: 1,
            socket_addr: to_socket_addr("12.13.14.15:1000")
        };
        persister.add_known_node(&known_node);
        let mut inventory = Inventory::new(persister.clone());
        let persisted_message = create_object_message();
        inventory.add_object_message(&persisted_message);

        let input = Message::Verack;
        let output = run_test(input, persister);
        assert_eq!(2, output.len());

        let message1 = &output[0];
        match message1 {
            &Message::Addr { ref addr_list } => {
                assert_eq!(1, addr_list.len());
                let output_node = &addr_list[0];
                assert_eq!(Timespec::new(5, 0), output_node.last_seen);
                assert_eq!(1, output_node.stream);
                assert_eq!(1, output_node.services);
                assert_eq!(to_socket_addr("12.13.14.15:1000"), output_node.socket_addr);
            },
            _ => panic!("Not an Addr message: {:?}", message1)
        }

        let message2 = &output[1];
        match message2 {
            &Message::Inv { ref inventory } => {
                assert_eq!(1, inventory.len());
                let inventory_vector = &inventory[0];
                assert_eq!(&calculate_inventory_vector(&persisted_message), inventory_vector);
            },
            _ => panic!("Not an Addr message: {:?}", message1)
        }
    }

    #[test]
    fn test_get_addr_populates_persister() {
        let persister = Persister::new();
        let known_node = KnownNode {
            last_seen: Timespec::new(6, 0),
            stream: 1,
            services: 1,
            socket_addr: to_socket_addr("22.33.44.55:6666")
        };
        let input = Message::Addr {
            addr_list: vec![ known_node.clone() ]
        };
        let output = run_test(input, persister.clone());
        assert_eq!(0, output.len());

        let known_nodes = persister.get_known_nodes();
        assert_eq!(1, known_nodes.len());

        let known_node_recovered = &known_nodes[0];
        assert_eq!(&known_node, known_node_recovered);
    }

    #[test]
    fn test_get_inv_empty_persister_send_getdata_for_all() {
        let inventory_vector1 = InventoryVector { hash: vec![1; 20] };
        let inventory_vector2 = InventoryVector { hash: vec![2; 20] };
        let input = Message::Inv {
            inventory: vec![
                inventory_vector1.clone(),
                inventory_vector2.clone()
            ]
        };
        let output = run_test(input, Persister::new());
        assert_eq!(1, output.len());

        let message = &output[0];
        match message {
            &Message::GetData { ref inventory } => {
                assert_eq!(2, inventory.len());
                assert_eq!(&inventory[0], &inventory_vector1);
                assert_eq!(&inventory[1], &inventory_vector2);
            },
            _ => panic!("Not an Inv message: {:?}", message)
        }
    }

    #[test]
    fn test_get_inv_only_getdata_for_vectors_not_in_persister() {
        let inventory_vector1 = InventoryVector { hash: vec![1; 20] };
        let inventory_vector2 = InventoryVector { hash: vec![2; 20] };
        let input = Message::Inv {
            inventory: vec![
                inventory_vector1.clone(),
                inventory_vector2.clone()
            ]
        };
        let mut persister = Persister::new();
        persister.add_object_message(&inventory_vector1, &create_object_message());
        let output = run_test(input, persister);
        assert_eq!(1, output.len());

        let message = &output[0];
        match message {
            &Message::GetData { ref inventory } => {
                assert_eq!(1, inventory.len());
                assert_eq!(&inventory[0], &inventory_vector2);
            },
            _ => panic!("Not an Inv message: {:?}", message)
        }
    }

    fn create_object_message() -> Message {
        Message::Object {
            nonce: 1,
            expiry: Timespec::new(2, 0),
            version: 3,
            stream: 1,
            object: Object::GetPubKey(GetPubKey::V3 { ripe: vec![4; 20] })
        }
    }

    fn run_test(input: Message, persister: Persister) -> Vec<Message> {
        let config = Config::new();
        let known_nodes = KnownNodes::new(persister.clone());
        let inventory = Inventory::new(persister.clone());
        let peer_addr = to_socket_addr("127.0.0.1:8444");
        let mut responder = MessageResponder::new(&config, &known_nodes, &inventory, peer_addr);

        let output = Output::new();
        responder.respond(input, |m| { output.add(m) } ).unwrap();

        output.get_messages()
    }
}
