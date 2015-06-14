use byteorder::BigEndian;
use byteorder::WriteBytesExt;
use crypto::sha512;
use encoding::{Encoding,EncoderTrap};
use encoding::all::ASCII;
use std::net::SocketAddr;
use time::get_time;

//
// Message
//

static MAGIC: u32 = 0xe9beb4d9;

pub trait Message
{
    fn packet(&self) -> Vec<u8> {
        let command = self.command();
        let mut ascii_command = ASCII.encode(&command, EncoderTrap::Ignore).unwrap();
        pad(&mut ascii_command, 12, 0);

        let payload = self.payload();
        let payload_length = payload.len();
        let mut sha512 = sha512(&payload);
        pad(&mut sha512, 4, 0);

        let mut packet: Vec<u8> = vec![];
        packet.write_u32::<BigEndian>(MAGIC).unwrap();
        packet.extend(ascii_command);
        packet.write_u32::<BigEndian>(payload_length as u32).unwrap();
        packet.extend(sha512);
        packet.extend(payload);

        packet
    }

    fn command(&self) -> String;
    fn payload(&self) -> Vec<u8>;
}

fn pad(data: &mut Vec<u8>, size: usize, padding: u8) {
    while data.len() > size {
        data.pop();
    }

    while data.len() < size {
        data.push(padding);
    }
}

//
// version Message
//

pub struct VersionMessage {
    version: u32, // protocol version
    services: u64,
    addr_recv: SocketAddr,
    addr_from: SocketAddr,
    nonce: u64,
    user_agent: String,
    stream_numbers: Vec<u64>
}


impl VersionMessage {
    pub fn new(peer_addr: SocketAddr, our_addr: SocketAddr, nonce: u64,
               user_agent: String, stream_numbers: Vec<u64>) -> VersionMessage {
        VersionMessage {
            version: 3,
            services: 1,
            addr_recv: peer_addr,
            addr_from: our_addr,
            nonce: nonce,
            user_agent: user_agent,
            stream_numbers: stream_numbers
        }
    }
}

impl Message for VersionMessage {
    fn command(&self) -> String {
        "version".to_string()
    }

    fn payload(&self) -> Vec<u8> {
        let now = get_time().sec as u64;

        let mut payload = vec![];
        payload.write_u32::<BigEndian>(self.version).unwrap();
        payload.write_u64::<BigEndian>(self.services).unwrap();
        payload.write_u64::<BigEndian>(now).unwrap();
        payload.write_u64::<BigEndian>(self.services).unwrap();
        write_address_and_port(&mut payload, &self.addr_recv);
        payload.write_u64::<BigEndian>(self.services).unwrap();
        write_address_and_port(&mut payload, &self.addr_from);
        payload.write_u64::<BigEndian>(self.nonce).unwrap();
        write_var_str(&mut payload, &self.user_agent);
        write_var_int_list(&mut payload, &self.stream_numbers);

        payload
    }
}

//
// verack Message
//

pub struct VerackMessage;

impl VerackMessage {
    pub fn new() -> VerackMessage {
        VerackMessage
    }
}

impl Message for VerackMessage {
    fn command(&self) -> String {
        "verack".to_string()
    }

    fn payload(&self) -> Vec<u8> {
        vec![]
    }
}

//
// Write helpers
//

fn write_address_and_port(payload: &mut Vec<u8>, socket_addr: &SocketAddr) {
    let v6_ip = match socket_addr {
        &SocketAddr::V4(v4_addr) => v4_addr.ip().to_ipv6_mapped(),
        &SocketAddr::V6(v6_addr) => v6_addr.ip().to_owned()
    };

    for &segment in v6_ip.segments().iter() {
        payload.write_u16::<BigEndian>(segment).unwrap();
    }

    let port = socket_addr.port();
    payload.write_u16::<BigEndian>(port).unwrap();
}

fn write_var_str(payload: &mut Vec<u8>, user_agent: &str) {
    let ascii_user_agent = ASCII.encode(&user_agent, EncoderTrap::Ignore).unwrap();
    write_var_int_64(payload, ascii_user_agent.len() as u64);
    payload.extend(ascii_user_agent);
}

fn write_var_int_list(payload: &mut Vec<u8>, values: &[u64]) {
    write_var_int_64(payload, values.len() as u64);
    for &value in values {
        write_var_int_64(payload, value);
    }
}

fn write_var_int_64(payload: &mut Vec<u8>, value: u64) {
    if value <= 0xffffffff {
        write_var_int_32(payload, value as u32);
    } else {
        payload.push(0xff);
        payload.write_u64::<BigEndian>(value).unwrap();
    }
}

fn write_var_int_32(payload: &mut Vec<u8>, value: u32) {
    if value <= 0xffff {
        write_var_int_16(payload, value as u16);
    } else {
        payload.push(0xfe);
        payload.write_u32::<BigEndian>(value).unwrap();
    }
}

fn write_var_int_16(payload: &mut Vec<u8>, value: u16) {
    if value < 0xfd {
        write_var_int_8(payload, value as u8);
    } else {
        payload.push(0xfd);
        payload.write_u16::<BigEndian>(value).unwrap();
    }
}

fn write_var_int_8(payload: &mut Vec<u8>, value: u8) {
    if value < 0xfd {
        payload.push(value);
    } else {
        write_var_int_16(payload, value as u16);
    }
}

#[cfg(test)]
mod tests {
    use super::Message;
    use super::VersionMessage;
    use super::VerackMessage;
    use super::write_address_and_port;
    use super::write_var_str;
    use super::write_var_int_list;
    use super::write_var_int_64;
    use super::write_var_int_32;
    use super::write_var_int_16;
    use super::write_var_int_8;
    use byteorder::{BigEndian,ReadBytesExt};
    use std::net::ToSocketAddrs;
    use time::{Duration,Timespec};
    use time::get_time;

    #[test]
    fn test_message_packet() {
        let socket_addr1 = "127.0.0.1:8444".to_socket_addrs().unwrap().next().unwrap();
        let socket_addr2 = "11.22.33.44:8555".to_socket_addrs().unwrap().next().unwrap();
        let user_agent = "Rubbem".to_string();
        let stream_numbers = vec![ 1u64 ];
        let message = VersionMessage::new(socket_addr1, socket_addr2, 0x12345678, user_agent, stream_numbers);
        let packet = message.packet();

        assert_eq!(24 + 89, packet.len());
    }

    #[test]
    fn test_version_message_payload() {
        let socket_addr1 = "127.0.0.1:8444".to_socket_addrs().unwrap().next().unwrap();
        let socket_addr2 = "11.22.33.44:8555".to_socket_addrs().unwrap().next().unwrap();
        let user_agent = "Rubbem".to_string();
        let stream_numbers = vec![ 1u64 ];
        let message = VersionMessage::new(socket_addr1, socket_addr2, 0x12345678, user_agent, stream_numbers);
        let payload = message.payload();

        assert_eq!(89, payload.len());

        let part1 = vec![ 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1 ];
        assert_eq!(&payload[0..12], &part1[..]);

        let mut generated_time_bytes = &payload[12..20];
        let generated_time_seconds = generated_time_bytes.read_u64::<BigEndian>().unwrap() as i64;
        let generated_time = Timespec::new(generated_time_seconds, 0);
        let difference = get_time() - generated_time;
        assert!(difference < Duration::minutes(1));

        let part2 = vec![ 0, 0, 0, 0, 0, 0, 0, 1,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1,
                          32, 252,
                          0, 0, 0, 0, 0, 0, 0, 1,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 11, 22, 33, 44,
                          33, 107,
                          0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78,
                          6, 82, 117, 98, 98, 101, 109,
                          1, 1 ];
        assert_eq!(&payload[20..89], &part2[..]);
    }

    #[test]
    fn test_verack_message_payload() {
        let message = VerackMessage::new();
        let payload = message.payload();

        assert_eq!("verack".to_string(), message.command());
        assert_eq!(0, payload.len());
    }

    #[test]
    fn test_write_address_and_port_for_v4() {
        let mut payload = vec![];
        let socket_addr = "127.0.0.1:8444".to_socket_addrs().unwrap().next().unwrap();
        write_address_and_port(&mut payload, &socket_addr);

        assert_eq!(payload, vec![ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1, 32, 252 ]);
    }

    #[test]
    fn test_write_address_and_port_for_v6() {
        let mut payload = vec![];
        let socket_addr = "[2001:cdba:0:0:0:0:3257:9652]:8444".to_socket_addrs().unwrap().next().unwrap();
        write_address_and_port(&mut payload, &socket_addr);

        assert_eq!(payload, vec![ 0x20, 0x01, 0xcd, 0xba, 0, 0, 0, 0, 0, 0, 0, 0, 0x32, 0x57, 0x96, 0x52, 32, 252 ]);
    }

    #[test]
    fn test_write_var_str() {
        let mut payload1 = vec![];
        write_var_str(&mut payload1, "ABC");
        assert_eq!(payload1, vec![ 3, 65, 66, 67 ]);

        let mut payload2 = vec![];
        write_var_str(&mut payload2, "");
        assert_eq!(payload2, vec![ 0 ]);
    }

    #[test]
    fn test_write_var_int_list() {
        let mut payload1 = vec![];
        write_var_int_list(&mut payload1, &[ 1u64 ]);
        assert_eq!(payload1, vec![ 1, 1 ]);

        let mut payload2 = vec![];
        write_var_int_list(&mut payload2, &[]);
        assert_eq!(payload2, vec![ 0 ]);

        let mut payload3 = vec![];
        write_var_int_list(&mut payload3, &[ 0xfeu64, 4, 5 ]);
        assert_eq!(payload3, vec![ 3, 0xfd, 0, 0xfe, 4, 5]);

        let mut list: Vec<u64> = vec![];
        let mut expected: Vec<u8> = vec![ 0xfd, 0, 0xff];
        for i1 in 0..0xfd {
            list.push(i1);
            expected.push(i1 as u8);
        }
        for i2 in 0xfdu64..0x100 {
            list.push(i2);
            expected.push(0xfd);
            expected.push(0);
            expected.push(i2 as u8);
        }
        let mut payload4 = vec![];
        write_var_int_list(&mut payload4, &list[..]);
    }

    #[test]
    fn test_write_var_int_one_byte() {
        for v in 0..0xfd {
            let expected = vec![ v ];

            let mut payload_8 = vec![];
            write_var_int_8(&mut payload_8, v);
            assert_eq!(payload_8, expected);

            let mut payload_16 = vec![];
            write_var_int_16(&mut payload_16, v as u16);
            assert_eq!(payload_16, expected);

            let mut payload_32 = vec![];
            write_var_int_32(&mut payload_32, v as u32);
            assert_eq!(payload_32, expected);

            let mut payload_64 = vec![];
            write_var_int_64(&mut payload_64, v as u64);
            assert_eq!(payload_64, expected);
        }
    }

    #[test]
    fn test_write_var_int_three_bytes_low() {
        for v in 0xfdu64..0x100 {
            let expected = vec![ 0xfd, 0, v as u8 ];

            let mut payload_8 = vec![];
            write_var_int_8(&mut payload_8, v as u8);
            assert_eq!(payload_8, expected);

            let mut payload_16 = vec![];
            write_var_int_16(&mut payload_16, v as u16);
            assert_eq!(payload_16, expected);

            let mut payload_32 = vec![];
            write_var_int_32(&mut payload_32, v as u32);
            assert_eq!(payload_32, expected);

            let mut payload_64 = vec![];
            write_var_int_64(&mut payload_64, v as u64);
            assert_eq!(payload_64, expected);
        }
    }

    #[test]
    fn test_write_var_int_three_bytes_high() {
        let mut test_values: Vec<u16> = vec![];
        for test_value in 256..1000 {
            test_values.push(test_value);
        }
        test_values.push(u16::max_value() - 1);
        test_values.push(u16::max_value());

        for v in test_values {
            let expected = vec![0xfd, (v / 256) as u8, (v % 256) as u8 ];

            let mut payload_16 = vec![];
            write_var_int_16(&mut payload_16, v);
            assert_eq!(payload_16, expected);

            let mut payload_32 = vec![];
            write_var_int_32(&mut payload_32, v as u32);
            assert_eq!(payload_32, expected);

            let mut payload_64 = vec![];
            write_var_int_64(&mut payload_64, v as u64);
            assert_eq!(payload_64, expected);
        }
    }

    #[test]
    fn test_write_var_int_five_bytes() {
        let mut test_values: Vec<u32> = vec![];
        test_values.push(u16::max_value() as u32 + 1);
        test_values.push(100000);
        test_values.push(1000000);
        test_values.push(1000000000);
        test_values.push(u32::max_value() - 1);
        test_values.push(u32::max_value());

        for v in test_values {
            let pow3 = 256 * 256 * 256;
            let pow2 = 256 * 256;
            let expected = vec![0xfe, (v / pow3) as u8, ((v % pow3) / pow2) as u8, ((v % pow2) / 256) as u8, (v % 256) as u8 ];

            let mut payload_32 = vec![];
            write_var_int_32(&mut payload_32, v);
            assert_eq!(payload_32, expected);

            let mut payload_64 = vec![];
            write_var_int_64(&mut payload_64, v as u64);
            assert_eq!(payload_64, expected);
        }
    }

    #[test]
    fn test_write_var_int_nine_bytes() {
        let mut payload1 = vec![];
        write_var_int_64(&mut payload1, u32::max_value() as u64 + 1);
        assert_eq!(payload1, vec![ 0xff, 0, 0, 0, 1, 0 , 0 , 0, 0]);

        let mut payload2 = vec![];
        write_var_int_64(&mut payload2, u64::max_value());
        assert_eq!(payload2, vec![ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff ]);
    }
}
