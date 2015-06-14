use config::Config;
use known_nodes::KnownNodes;
use message::{Message, VersionMessage};
use parse::{MessageByteReader,MessageReader};
use std::io::{Error,Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::rc::Rc;
use std::thread::Builder;

pub trait MessageListener : Send {
    fn message(&self, message: Box<Message>);
}

pub struct PrintListener;

impl PrintListener {
    fn new() -> PrintListener {
        PrintListener
    }
}

impl MessageListener for PrintListener {
    fn message(&self, message: Box<Message>) {
       println!("Command received: {}", message.command());
    }
}

pub enum ConnectionState {
    TcpConnected,
    Failed
}

pub struct Connection {
    peer_addr: SocketAddr,
    tcp_stream: TcpStream,
    state: ConnectionState
}

impl Connection {
    pub fn new(peer_addr: SocketAddr) -> Result<Connection, Error> {
        let tcp_stream = try!(TcpStream::connect(peer_addr));
        Ok(Connection {
            peer_addr: peer_addr,
            tcp_stream: tcp_stream,
            state: ConnectionState::TcpConnected
        })
    }

    pub fn listen(&self, listener: Box<MessageListener>) -> Result<(), Error> {
        let tcp_stream = try!(self.tcp_stream.try_clone());

        let thread_name = format!("Connection {}", self.peer_addr);
        let builder = Builder::new().name(thread_name);
        match builder.spawn(move || { read(tcp_stream, listener) }) {
            Ok(_) => Ok(()),
            Err(e) => Err(e)
        }
    }

    pub fn send<'a>(&mut self, message: Box<Message + 'a>) {
        println!("Sending {}", message.command());
        let packet = message.packet();
        self.tcp_stream.write_all(&packet[..]).unwrap();
        println!("Sent {}", message.command());
    }

    pub fn set_state(&mut self, state: ConnectionState) {
        self.state = state;
    }
}

fn read(tcp_stream: TcpStream, listener: Box<MessageListener>) {
    let message_byte_listener = Box::new(MessageReader::new(listener));
    let mut message_byte_reader = MessageByteReader::new(Box::new(tcp_stream), message_byte_listener);
    message_byte_reader.start();
}

struct ConnectionFactory {
    nonce: u64
}

impl ConnectionFactory {
    fn new(nonce: u64) -> ConnectionFactory {
        ConnectionFactory {
            nonce: nonce
        }
    }

    fn connect(&self, peer_addr: SocketAddr) -> Connection {
        let mut connection = Connection::new(peer_addr).unwrap();

        let our_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8555));
        let user_agent = "Rubbem".to_string();
        let stream_numbers = vec![ 1 ];
        let version_message = VersionMessage::new(peer_addr, our_addr, self.nonce, user_agent, stream_numbers);

        connection.send(Box::new(version_message));
        match connection.listen(Box::new(PrintListener::new())) {
            Ok(_) => {},
            Err(_) => connection.set_state(ConnectionState::Failed)
        };

        connection
    }
}

pub struct PeerConnector {
    config: Rc<Box<Config>>,
    known_nodes: Rc<Box<KnownNodes>>,
    connection_factory: ConnectionFactory
}

impl PeerConnector
{
    pub fn new(config: Rc<Box<Config>>, known_nodes: Rc<Box<KnownNodes>>, nonce: u64) -> PeerConnector {
        PeerConnector {
            config: config,
            known_nodes: known_nodes,
            connection_factory: ConnectionFactory::new(nonce)
        }
    }

    pub fn start(&self)
    {
        println!("Max concurrent: {}", self.config.concurrent_connection_attempts());
        let known_node = self.known_nodes.get_random();

        let peer_addr = known_node.socket_addr().clone();
        self.connection_factory.connect(peer_addr);
    }
}
