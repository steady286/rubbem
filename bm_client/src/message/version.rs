use byteorder::BigEndian;
use byteorder::WriteBytesExt;
use message::{Message,ParseError};
use std::io::Cursor;
use std::net::SocketAddr;
use time::Timespec;
use super::check_no_more_data;

pub struct VersionMessage {
    version: u32, // protocol version
    services: u64,
    timestamp: Timespec,
    addr_recv: SocketAddr,
    addr_from: SocketAddr,
    nonce: u64,
    user_agent: String,
    stream_numbers: Vec<u64>
}


impl VersionMessage {
    pub fn new(version: u32, services: u64, timestamp: Timespec,
               addr_recv: SocketAddr, addr_from: SocketAddr,
               nonce: u64, user_agent: String, stream_numbers: Vec<u64>) -> VersionMessage {
        VersionMessage {
            version: version,
            services: services,
            timestamp: timestamp,
            addr_recv: addr_recv,
            addr_from: addr_from,
            nonce: nonce,
            user_agent: user_agent,
            stream_numbers: stream_numbers
        }
    }

    pub fn read(payload: Vec<u8>) -> Result<Box<VersionMessage>,ParseError> {
        let mut cursor = Cursor::new(payload);

        let version = try!(super::read_u32(&mut cursor));
        let services = try!(super::read_u64(&mut cursor));
        let timestamp = try!(super::read_timestamp(&mut cursor));
        try!(super::read_u64(&mut cursor)); // recv_services
        let addr_recv = try!(super::read_address_and_port(&mut cursor));
        try!(super::read_u64(&mut cursor)); // from_services
        let addr_from = try!(super::read_address_and_port(&mut cursor));
        let nonce = try!(super::read_u64(&mut cursor));
        let user_agent = try!(super::read_var_str(&mut cursor, 5000));
        let stream_numbers = try!(super::read_var_int_list(&mut cursor, 160000));

        try!(check_no_more_data(&mut cursor));

        Ok(Box::new(VersionMessage::new(version, services, timestamp, addr_recv, addr_from, nonce, user_agent, stream_numbers)))
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn services(&self) -> u64 {
        self.services
    }

    pub fn timestamp(&self) -> Timespec {
        self.timestamp
    }

    pub fn addr_recv(&self) -> SocketAddr {
        self.addr_recv
    }

    pub fn addr_from(&self) -> SocketAddr {
        self.addr_from
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    pub fn stream_numbers(&self) -> &Vec<u64> {
        &self.stream_numbers
    }
}

impl Message for VersionMessage {
    fn command(&self) -> String {
        "version".to_string()
    }

    fn payload(&self) -> Vec<u8> {
        let mut payload = vec![];
        payload.write_u32::<BigEndian>(self.version).unwrap();
        payload.write_u64::<BigEndian>(self.services).unwrap();
        payload.write_i64::<BigEndian>(self.timestamp.sec).unwrap();
        payload.write_u64::<BigEndian>(self.services).unwrap();
        super::write_address_and_port(&mut payload, &self.addr_recv);
        payload.write_u64::<BigEndian>(self.services).unwrap();
        super::write_address_and_port(&mut payload, &self.addr_from);
        payload.write_u64::<BigEndian>(self.nonce).unwrap();
        super::write_var_str(&mut payload, &self.user_agent);
        super::write_var_int_list(&mut payload, &self.stream_numbers);

        payload
    }
}

#[cfg(test)]
mod tests {
    use message::Message;
    use message::version::VersionMessage;
    use std::net::ToSocketAddrs;
    use std::io::Read;
    use time::Timespec;

    #[test]
    fn test_version_message_payload() {
        let timestamp = Timespec::new(0x01020304, 0);
        let socket_addr1 = "127.0.0.1:8444".to_socket_addrs().unwrap().next().unwrap();
        let socket_addr2 = "11.22.33.44:8555".to_socket_addrs().unwrap().next().unwrap();
        let user_agent = "Rubbem".to_string();
        let stream_numbers = vec![ 1u64 ];
        let message = VersionMessage::new(3, 1, timestamp, socket_addr1, socket_addr2, 0x12345678, user_agent, stream_numbers);

        assert_eq!("version".to_string(), message.command());
        let payload = message.payload();


        let expected = vec![ 0, 0, 0, 3, // version
                             0, 0, 0, 0, 0, 0, 0, 1, // services
                             0, 0, 0, 0, 1, 2, 3, 4, // timestamp
                             0, 0, 0, 0, 0, 0, 0, 1, // recv_services
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1, // recv_addr
                             32, 252, // recv_port
                             0, 0, 0, 0, 0, 0, 0, 1, // from_services
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 11, 22, 33, 44, // from_addr
                             33, 107, // from_port
                             0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, // nonce
                             6, 82, 117, 98, 98, 101, 109, // user_agent
                             1, 1 // stream_numbers
                        ];

        assert_eq!(expected, payload);

        let roundtrip = VersionMessage::read(payload).unwrap();

        assert_eq!("version".to_string(), roundtrip.command());
        assert_eq!(3, roundtrip.version());
        assert_eq!(1, roundtrip.services());
        assert_eq!(timestamp, roundtrip.timestamp());
        assert_eq!(socket_addr1, roundtrip.addr_recv());
        assert_eq!(socket_addr2, roundtrip.addr_from());
        assert_eq!(0x12345678, roundtrip.nonce());
        assert_eq!("Rubbem", roundtrip.user_agent());
        assert_eq!(&vec![ 1 ], roundtrip.stream_numbers());
    }
}
