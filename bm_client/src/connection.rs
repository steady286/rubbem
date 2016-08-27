use channel::{ConstrainedReceiver,ConstrainedSender,constrained_channel};
use message::{Message,MessageHandler,VersionData};
use serial::message::{MessageSerialError,read_message,write_message};
use std::io::{Error,Write};
use std::net::{Shutdown,SocketAddr,TcpStream};
use std::sync::{Arc,RwLock};
use std::sync::mpsc::{Receiver,SyncSender,TryRecvError,sync_channel};
use std::time::{Duration,Instant};
use std::thread::{Builder,JoinHandle,sleep};

const MAX_WRITE_BUFFER: usize = 20_000_000;

#[derive(Debug,Clone,Copy,PartialEq)]
pub enum ConnectionState {
    Fresh(Instant),
    GotVerackAwaitingVersion(Instant),
    GotVersionAwaitingVerack(Instant),
    Established(Instant),
    Stale,
    Error
}

#[derive(Debug,Clone)]
pub struct StateHolder {
    state: Arc<RwLock<ConnectionState>>
}

impl StateHolder {
    fn new(state: ConnectionState) -> StateHolder {
        StateHolder {
            state: Arc::new(RwLock::new(state))
        }
    }

    fn get_state(&self) -> ConnectionState {
        *self.state.read().unwrap()
    }

    fn set_state(&self, new_value: ConnectionState) {
        let mut guard = self.state.write().unwrap();
        *guard = new_value;
    }
}

pub struct Connection {
    state: StateHolder,
    tcp_stream: Option<TcpStream>
}

impl Connection {
    pub fn new(message_handler: MessageHandler, socket_addr: SocketAddr) -> Connection {
        match TcpStream::connect(&socket_addr) {
            Ok(tcp_stream) => new_from_stream(message_handler, tcp_stream),
            Err(_) => error_connection(None)
        }
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        match self.tcp_stream {
            None => None,
            Some(ref s) => Some(s.peer_addr().unwrap())
        }
    }

    pub fn state(&self) -> ConnectionState {
        self.state.get_state()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        for tcp_stream in self.tcp_stream.iter() {
            let _ = tcp_stream.shutdown(Shutdown::Both);
        }
    }
}

fn new_from_stream(message_handler: MessageHandler, tcp_stream: TcpStream) -> Connection {
    let socket_addr = tcp_stream.peer_addr().unwrap();
    let state = StateHolder::new(ConnectionState::Fresh(Instant::now()));

    // Make channels for thread communication
    let (read_state_tx, read_state_rx) = sync_channel(0);
    let (state_handler_tx, state_handler_rx) = constrained_channel(MAX_WRITE_BUFFER);
    let (handler_write_tx, handler_write_rx) = sync_channel(0);

    // Make thread to read messages from the peer
    let read_name = format!("Connection {} - read", socket_addr);
    let read_tcp_stream = clone_stream(&tcp_stream);
    let read_thread = create_thread(read_name, state.clone(),
        || read_thread_body(read_tcp_stream, read_state_tx));

    // Make thread to manage the state of this connnection
    let state_name = format!("Connection {} - state", socket_addr);
    let state_thread_state = state.clone();
    let state_thread = create_thread(state_name, state.clone(),
        || state_thread_body(state_thread_state, read_state_rx, state_handler_tx));

    // Make thread to handle the messages - verifying them and creating appropriate response messages
    let handler_name = format!("Connection {} - verify/response", socket_addr);
    let handler_thread = create_thread(handler_name, state.clone(),
        || handler_thread_body(message_handler, state_handler_rx, handler_write_tx));

    // Make thread to write messages to the peer
    let write_name = format!("Connection {} - write", socket_addr);
    let write_tcp_stream = clone_stream(&tcp_stream);
    let write_thread = create_thread(write_name, state.clone(),
        || write_thread_body(write_tcp_stream, handler_write_rx));

    if read_thread.is_err() || state_thread.is_err() || handler_thread.is_err() || write_thread.is_err() {
        state.set_state(ConnectionState::Error);
        return error_connection(Some(tcp_stream));
    }

    Connection {
        state: state,
        tcp_stream: Some(tcp_stream)
    }
}

fn clone_stream(stream: &TcpStream) -> TcpStream {
    stream.try_clone().unwrap()
}

fn error_connection(tcp_stream: Option<TcpStream>) -> Connection {
    Connection {
        state: StateHolder::new(ConnectionState::Error),
        tcp_stream: tcp_stream
    }
}

fn create_thread<F>(name: String, state: StateHolder, thread_body: F) -> Result<JoinHandle<()>,Error>
    where F: FnOnce() -> (), F: Send + 'static {
    Builder::new().name(name).spawn(move || {
        thread_body();
        state.set_state(ConnectionState::Error);
    })
}

fn read_thread_body(mut stream: TcpStream, state_chan: SyncSender<Result<Message,MessageSerialError>>) -> () {
    loop {
        let message: Result<Message,MessageSerialError> = read_message(&mut stream);
        let parse_error = message.is_err();

        state_chan.send(message).unwrap();

        if parse_error {
            break;
        }
    }
}

fn state_thread_body(state_holder: StateHolder, read_chan: Receiver<Result<Message,MessageSerialError>>, handler_chan: ConstrainedSender<Message>) -> () {
    loop {
        let current_state = state_holder.get_state();

        let (new_state, forward_messages) = match (current_state, read_chan.try_recv()) {
            (_, Err(TryRecvError::Empty)) => (current_state, vec![]),
            (_, Err(TryRecvError::Disconnected)) => (ConnectionState::Error, vec![]),
            (_, Ok(Err(_))) => (ConnectionState::Error, vec![]),
            (ConnectionState::Fresh(_), Ok(Ok(m @ Message::Version(VersionData {..})))) => (ConnectionState::GotVersionAwaitingVerack(Instant::now()), vec![ m ]),
            (ConnectionState::Fresh(_), Ok(Ok(Message::Verack))) => (ConnectionState::GotVerackAwaitingVersion(Instant::now()), vec![]),
            (ConnectionState::Fresh(_), Ok(Ok(_))) => (ConnectionState::Error, vec![]),
            (ConnectionState::GotVersionAwaitingVerack(_), Ok(Ok(m @ Message::Verack))) => (ConnectionState::Established(Instant::now()), vec![ m ]),
            (ConnectionState::GotVersionAwaitingVerack(_), Ok(Ok(_))) => (ConnectionState::Error, vec![]),
            (ConnectionState::GotVerackAwaitingVersion(_), Ok(Ok(m @ Message::Version(VersionData {..})))) => (ConnectionState::Established(Instant::now()), vec![ m ]),
            (ConnectionState::GotVerackAwaitingVersion(_), Ok(Ok(_))) => (ConnectionState::Error, vec![]),
            (ConnectionState::Established(_), Ok(Ok(m))) => (ConnectionState::Established(Instant::now()), vec![ m ]),
            (_, Ok(Ok(_))) => (current_state, vec![])
        };

        state_holder.set_state(new_state);
        for forward_message in forward_messages.into_iter() {
            handler_chan.send(forward_message).unwrap();
        }

        match new_state {
            ConnectionState::Fresh(time) => check_staleness(&state_holder, time, Duration::from_secs(20)),
            ConnectionState::GotVersionAwaitingVerack(time) => check_staleness(&state_holder, time, Duration::from_secs(20)),
            ConnectionState::GotVerackAwaitingVersion(time) => check_staleness(&state_holder, time, Duration::from_secs(20)),
            ConnectionState::Established(time) => check_staleness(&state_holder, time, Duration::from_secs(10 * 60)),
            _ => {}
        }

        match state_holder.get_state() {
            ConnectionState::Stale => break,
            ConnectionState::Error => break,
            _ => {}
        }

        sleep(Duration::from_millis(100));
    }
}

fn check_staleness(state_holder: &StateHolder, time: Instant, duration: Duration) {
    let now = Instant::now();
    if now > time + duration {
        state_holder.set_state(ConnectionState::Stale);
    }
}

fn handler_thread_body(mut message_handler: MessageHandler, state_chan: ConstrainedReceiver<Message>, write_chan: SyncSender<Message>) -> () {
    return_on_err!(message_handler.send_version(|m| write_chan.send(m)));

    loop {
        let message = break_on_err!(state_chan.recv());
        break_on_err!(message_handler.handle(message, |m| write_chan.send(m)));
    }
}

fn write_thread_body(mut stream: TcpStream, handler_chan: Receiver<Message>) -> () {
    loop {
        let message = break_on_err!(handler_chan.recv());

        let mut message_bytes = vec![];
        write_message(&mut message_bytes, &message);

        break_on_err!(stream.write_all(&message_bytes));
    }
}
