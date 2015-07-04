use std::net::{SocketAddr,ToSocketAddrs};

pub fn to_socket_addr<A: ToSocketAddrs>(addr: A) -> SocketAddr {
    addr.to_socket_addrs().unwrap().next().unwrap()
}
