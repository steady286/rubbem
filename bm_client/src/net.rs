use std::net::{SocketAddr,ToSocketAddrs};

pub fn to_socket_addr(addr: &str) -> SocketAddr {
    addr.to_socket_addrs().unwrap().next().unwrap()
}