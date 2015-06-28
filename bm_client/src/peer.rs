use config::Config;
use known_nodes::KnownNodes;
use message::{Message,MessageListener,MessageReader,write_message};
use std::io::{Error,Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::rc::Rc;
use std::thread::Builder;
use time::get_time;

pub struct PrintListener;

impl PrintListener {
    fn new() -> PrintListener {
        PrintListener
    }
}

impl MessageListener for PrintListener {
    fn message(&self, message: &Message) {
       println!("Command received: {:?}", message);
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

    pub fn listen<L: MessageListener + 'static>(&self, listener: L) -> Result<(), Error> {
        let tcp_stream = try!(self.tcp_stream.try_clone());

        let thread_name = format!("Connection {}", self.peer_addr);
        let builder = Builder::new().name(thread_name);
        match builder.spawn(move || { read(tcp_stream, listener); }) {
            Ok(_) => Ok(()),
            Err(e) => Err(e)
        }
    }

    pub fn send(&mut self, message: Message) {
        println!("Sending {:?}", message);
        let mut packet = vec![];
        write_message(&mut packet, &message);
        self.tcp_stream.write_all(&packet).unwrap();
        println!("Sent {:?}", message);
    }

    pub fn set_state(&mut self, state: ConnectionState) {
        self.state = state;
    }
}

fn read<A: MessageListener>(tcp_stream: TcpStream, listener: A) {
    let mut message_reader = MessageReader::new(tcp_stream, listener);
    message_reader.start();
}

struct ConnectionFactory {
    config: Rc<Box<Config>>,
    nonce: u64
}

impl ConnectionFactory {
    fn new(config: Rc<Box<Config>>, nonce: u64) -> ConnectionFactory {
        ConnectionFactory {
            config: config,
            nonce: nonce
        }
    }

    fn connect(&self, peer_addr: SocketAddr) -> Connection {
        let mut connection = Connection::new(peer_addr).unwrap();

        let our_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8555));
        let user_agent = self.config.user_agent().to_string();
        let streams = vec![ 1 ];
        let version_message = Message::Version {
            version: 3,
            services: 1,
            timestamp: get_time(),
            addr_recv: peer_addr,
            addr_from: our_addr,
            nonce: self.nonce,
            user_agent: user_agent,
            streams: streams
        };

        connection.send(version_message);
        let listener = PrintListener::new();
        match connection.listen(listener) {
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
            config: config.clone(),
            known_nodes: known_nodes,
            connection_factory: ConnectionFactory::new(config, nonce)
        }
    }

    pub fn start(&self)
    {
        println!("Max concurrent: {}", self.config.concurrent_connection_attempts());
        let known_node = self.known_nodes.get_random();

        let peer_addr = known_node.socket_addr;
        self.connection_factory.connect(peer_addr);
    }
}
