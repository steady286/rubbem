mod addr;
mod verack;
mod version;
mod inv;

pub use self::addr::AddrMessage;
pub use self::inv::InvMessage;
pub use self::verack::VerackMessage;
pub use self::version::VersionMessage;

use byteorder::BigEndian;
use byteorder::{ReadBytesExt,WriteBytesExt};
use crypto::sha512_checksum;
use encoding::{DecoderTrap,Encoding,EncoderTrap};
use encoding::all::ASCII;
use std::io::{Cursor,Read};
use std::net::{Ipv6Addr,SocketAddr,SocketAddrV4,SocketAddrV6};
use time::Timespec;

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
        let checksum = sha512_checksum(&payload);

        let mut packet: Vec<u8> = vec![];
        packet.write_u32::<BigEndian>(MAGIC).unwrap();
        packet.extend(ascii_command);
        packet.write_u32::<BigEndian>(payload_length as u32).unwrap();
        packet.write_u32::<BigEndian>(checksum).unwrap();
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
// MessageReader
//

#[derive(Debug,PartialEq)]
pub enum ParseError {
	FailedMagic,
	PayloadLength,
	ChecksumMismatch,
	AsciiDecode,
	NonZeroPadding,
	UnknownCommand,
    BadAscii,
	PayloadTooBig,
    MaxExceeded,
    UnexpectedEof
}

pub trait MessageListener : Send {
    fn message(&self, message: Box<Message>);
}

pub struct MessageReader {
	source: Box<Read>,
	listener: Box<MessageListener>
}

impl MessageReader {
	pub fn new(source: Box<Read>, listener: Box<MessageListener>) -> MessageReader {
		MessageReader {
			source: source,
			listener: listener
		}
	}

	pub fn start(&mut self) {
        let source = &mut *self.source;

		loop {
            match read_message(source) {
                Ok(m) => self.listener.message(m),
                Err(_) => break
            }
		}
	}
}

fn read_message(source: &mut Read) -> Result<Box<Message>,ParseError> {
    let magic = try!(read_u32(source));
    if magic != MAGIC {
        return Err(ParseError::FailedMagic);
    }

    let command = try!(read_command(source));
    let length_bytes = try!(read_u32(source));
    let expected_checksum = try!(read_u32(source));

    if length_bytes > 1600003 {
        return Err(ParseError::PayloadLength);
    }

    let payload = try!(read_bytes(source, length_bytes as usize));
    let calculated_checksum = sha512_checksum(&payload);
    if calculated_checksum != expected_checksum {
        return Err(ParseError::ChecksumMismatch);
    }

    read_payload(command, payload)
}

fn read_command(source: &mut Read) -> Result<String,ParseError> {
    let command_bytes = try!(read_bytes(source, 12));

	assert!(command_bytes.len() == 12);

	let non_zero_bytes = try!(remove_zeros(&command_bytes[..]));
	ASCII.decode(non_zero_bytes, DecoderTrap::Strict).map_err(|_| ParseError::AsciiDecode)
}

fn remove_zeros(bytes: &[u8]) -> Result<&[u8],ParseError> {
	let mut split: Vec<&[u8]> = bytes.split(|&byte| byte == 0).collect();
	split.retain(|split| split.len() > 0);

	match split.len() {
		1 => Ok(split[0]),
		_ => Err(ParseError::NonZeroPadding)
	}
}

fn read_payload(command: String, message_bytes: Vec<u8>) -> Result<Box<Message>,ParseError> {
	let mut source_box: Box<Read> = Box::new(Cursor::new(message_bytes));
	let source = &mut *source_box;

	let message = match &command[..] {
		"version" => try!(VersionMessage::read(source)) as Box<Message>,
		"verack" => try!(VerackMessage::read(source)) as Box<Message>,
		"addr" => try!(AddrMessage::read(source)) as Box<Message>,
        "inv" => try!(InvMessage::read(source)) as Box<Message>,
		_ => return Err(ParseError::UnknownCommand)
	};

	let mut remaining: Vec<u8> = vec![];
	let remaining_count = source.read_to_end(&mut remaining).unwrap();
	if remaining_count > 0 {
		return Err(ParseError::PayloadTooBig);
	}

	Ok(message)
}

//
// Read helpers
//

const NO_FLOW: u32 = 0;
const GLOBAL_SCOPE: u32 = 0xe;

fn read_address_and_port(source: &mut Read) -> Result<SocketAddr,ParseError> {
	let a = try!(read_u16(source));
	let b = try!(read_u16(source));
	let c = try!(read_u16(source));
	let d = try!(read_u16(source));
	let e = try!(read_u16(source));
	let f = try!(read_u16(source));
	let g = try!(read_u16(source));
	let h = try!(read_u16(source));
	let port = try!(read_u16(source));

	let v6_ip = Ipv6Addr::new(a, b, c, d, e, f, g, h);

	let socket_addr = match v6_ip.to_ipv4() {
		None => SocketAddr::V6(SocketAddrV6::new(v6_ip, port, NO_FLOW, GLOBAL_SCOPE)),
		Some(v4_ip) => SocketAddr::V4(SocketAddrV4::new(v4_ip, port))
	};

	Ok(socket_addr)
}

fn read_timestamp(source: &mut Read) -> Result<Timespec,ParseError> {
	let secs = try!(read_i64(source));
	Ok(Timespec::new(secs, 0))
}

fn read_var_str(source: &mut Read, max_length: usize) -> Result<String,ParseError> {
	let length = try!(read_var_int_usize(source, max_length));

	let string_bytes = try!(read_bytes(source, length));
	ASCII.decode(&string_bytes, DecoderTrap::Strict).map_err(|_| ParseError::BadAscii)
}

fn read_var_int_list(source: &mut Read, max_count: usize) -> Result<Vec<u64>,ParseError> {
	let count = try!(read_var_int_usize(source, max_count));

	let mut int_list: Vec<u64> = Vec::with_capacity(count);
	for _ in 0..count {
		let int = try!(read_var_int(source, u64::max_value()));
		int_list.push(int);
	}

	Ok(int_list)
}

fn read_var_int_usize(source: &mut Read, max_value: usize) -> Result<usize,ParseError> {
	read_var_int(source, max_value as u64).map(|v| v as usize)
}

fn read_var_int(source: &mut Read, max_value: u64) -> Result<u64,ParseError> {
	let first_byte: u8 = try!(read_u8(source));

	let value = match first_byte {
		byte @ 0...0xfc => byte as u64,
		0xfd => try!(read_u16(source)) as u64,
		0xfe => try!(read_u32(source)) as u64,
		0xff => try!(read_u64(source)),
		_ => unreachable!()
	};

	if value > max_value {
		return Err(ParseError::MaxExceeded);
	}

	Ok(value)
}

fn read_bytes(source: &mut Read, count: usize) -> Result<Vec<u8>,ParseError> {
    let mut take = source.take(count as u64);
    let mut bytes: Vec<u8> = Vec::with_capacity(count);
    let read_count = try!(take.read_to_end(&mut bytes).map_err(|_| ParseError::UnexpectedEof));

    if read_count != count || bytes.len() != count {
        return Err(ParseError::UnexpectedEof);
    }

    Ok(bytes)
}

fn read_u64(source: &mut Read) -> Result<u64,ParseError> {
	source.read_u64::<BigEndian>().map_err(|_| ParseError::UnexpectedEof)
}

fn read_i64(source: &mut Read) -> Result<i64,ParseError> {
    source.read_i64::<BigEndian>().map_err(|_| ParseError::UnexpectedEof)
}

fn read_u32(source: &mut Read) -> Result<u32,ParseError> {
	source.read_u32::<BigEndian>().map_err(|_| ParseError::UnexpectedEof)
}

fn read_u16(source: &mut Read) -> Result<u16,ParseError> {
	source.read_u16::<BigEndian>().map_err(|_| ParseError::UnexpectedEof)
}

fn read_u8(source: &mut Read) -> Result<u8,ParseError> {
	source.read_u8().map_err(|_| ParseError::UnexpectedEof)
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
    use message::Message;
    use message::VersionMessage;
    use message::read_message;
    use message::read_address_and_port;
    use message::read_timestamp;
    use message::read_var_str;
    use message::read_var_int_list;
    use message::read_var_int_usize;
    use message::read_var_int;
    use message::read_bytes;
    use message::write_address_and_port;
    use message::write_var_str;
    use message::write_var_int_list;
    use message::write_var_int_64;
    use message::write_var_int_32;
    use message::write_var_int_16;
    use message::write_var_int_8;
    use std::io::{Cursor,Read};
    use std::net::{SocketAddr,ToSocketAddrs};
    use time::Timespec;

    #[test]
    fn test_message_packet() {
        let timestamp = Timespec::new(0x01020304, 0);
        let socket_addr1 = "127.0.0.1:8444".to_socket_addrs().unwrap().next().unwrap();
        let socket_addr2 = "11.22.33.44:8555".to_socket_addrs().unwrap().next().unwrap();
        let user_agent = "Rubbem".to_string();
        let stream_numbers = vec![ 1u64 ];
        let message = VersionMessage::new(3, 1, timestamp, socket_addr1, socket_addr2, 0x12345678, user_agent, stream_numbers);
        let packet = message.packet();

        let expected = vec![ 0xe9, 0xbe, 0xb4, 0xd9, // magic
                             118, 101, 114, 115, 105, 111, 110, // "version"
                             0, 0, 0, 0, 0, // command padding
                             0, 0, 0, 89, // payload length
                             73, 143, 152, 217, // payload checksum
                             0, 0, 0, 3, // version
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

        assert_eq!(expected, packet);
    }

	#[test]
	fn test_read_verack() {
		let bytes = vec![
			0xe9, 0xbe, 0xb4, 0xd9, // magic
			118, 101, 114, 97, 99, 107, // "verack"
			0, 0, 0, 0, 0, 0, // command padding
			0, 0, 0, 0, // payload length
			0xcf, 0x83, 0xe1, 0x35 // checksum
		];
        let mut source_box: Box<Read> = Box::new(Cursor::new(bytes));
        let source = &mut *source_box;

        let message = read_message(source).unwrap();

        assert_eq!("verack", message.command());
	}

    #[test]
    fn test_read_address_and_port_for_v4() {
        let bytes: Vec<u8> = vec![ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 11, 12, 13, 14, 21, 190 ];
        let mut source_box: Box<Read> = Box::new(Cursor::new(bytes));
        let source = &mut *source_box;

        let socket_addr = match read_address_and_port(source).unwrap() {
            SocketAddr::V6(_) => panic!("Expected V4"),
            SocketAddr::V4(v4) => v4
        };

        assert_eq!([11, 12, 13, 14], socket_addr.ip().octets());
        assert_eq!(5566, socket_addr.port());
    }

    #[test]
    fn test_read_address_and_port_for_v6() {
        let bytes: Vec<u8> = vec![ 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 25, 255 ];
        let mut source_box: Box<Read> = Box::new(Cursor::new(bytes));
        let source = &mut *source_box;

        let socket_addr = match read_address_and_port(source).unwrap() {
            SocketAddr::V4(_) => panic!("Expected V6"),
            SocketAddr::V6(v6) => v6
        };

        assert_eq!([0x102, 0x304, 0x506, 0x708, 0x90a, 0xb0c, 0xd0e, 0xf00], socket_addr.ip().segments());
        assert_eq!(6655, socket_addr.port());
    }

    #[test]
    fn test_read_timestamp() {
        let bytes: Vec<u8> = vec![ 8, 7, 6, 5, 4, 3, 2, 1 ];
        let mut source_box: Box<Read> = Box::new(Cursor::new(bytes));
        let source = &mut *source_box;

        let sec = read_timestamp(source).unwrap().sec;
        assert_eq!(0x0807060504030201, sec);
    }

    #[test]
    fn test_read_var_str() {
        let bytes: Vec<u8> = vec![ 3, 65, 66, 67 ];
        let mut source_box: Box<Read> = Box::new(Cursor::new(bytes));
        let source = &mut *source_box;

        let string = read_var_str(source, 3).unwrap();
        assert_eq!("ABC", &string);
    }

    #[test]
    fn test_read_var_str_too_long() {
        let bytes: Vec<u8> = vec![ 3, 65, 66, 67 ];
        let mut source_box: Box<Read> = Box::new(Cursor::new(bytes));
        let source = &mut *source_box;

        assert!(read_var_str(source, 2).is_err());
    }

    #[test]
    fn test_read_var_int_list() {
        let bytes: Vec<u8> = vec![ 3, 65, 66, 67 ];
        let mut source_box: Box<Read> = Box::new(Cursor::new(bytes));
        let source = &mut *source_box;

        let int_list = read_var_int_list(source, 3).unwrap();

        let expected: Vec<u64> = vec![ 65, 66, 67 ];
        assert_eq!(expected, int_list);
    }

    #[test]
    fn test_read_var_int_list_too_long() {
        let bytes: Vec<u8> = vec![ 3, 65, 66, 67 ];
        let mut source_box: Box<Read> = Box::new(Cursor::new(bytes));
        let source = &mut *source_box;

        assert!(read_var_int_list(source, 2).is_err());
    }

    #[test]
    fn test_read_var_int_usize() {
        let bytes: Vec<u8> = vec![ 0xfd, 5, 220 ];
        let mut source_box: Box<Read> = Box::new(Cursor::new(bytes));
        let source = &mut *source_box;

        let var_int = read_var_int_usize(source, 2000).unwrap();
        assert_eq!(1500, var_int);
    }

    #[test]
    fn test_read_var_int_u8() {
        let bytes: Vec<u8> = vec![ 0xfc ];
        let mut source_box: Box<Read> = Box::new(Cursor::new(bytes));
        let source = &mut *source_box;

        let var_int = read_var_int(source, 20000000).unwrap();
        assert_eq!(0xfc, var_int);
    }

    #[test]
    fn test_read_var_int_u16() {
        let bytes: Vec<u8> = vec![ 0xfd, 1, 2 ];
        let mut source_box: Box<Read> = Box::new(Cursor::new(bytes));
        let source = &mut *source_box;

        let var_int = read_var_int(source, 20000000).unwrap();
        assert_eq!(258, var_int);
    }

    #[test]
    fn test_read_var_int_u32() {
        let bytes: Vec<u8> = vec![ 0xfe, 1, 2, 3, 4 ];
        let mut source_box: Box<Read> = Box::new(Cursor::new(bytes));
        let source = &mut *source_box;

        let var_int = read_var_int(source, 20000000).unwrap();
        assert_eq!(0x1020304, var_int);
    }

    #[test]
    fn test_read_var_int_u64() {
        let bytes: Vec<u8> = vec![ 0xff, 1, 2, 3, 4, 5, 6, 7, 8 ];
        let mut source_box: Box<Read> = Box::new(Cursor::new(bytes));
        let source = &mut *source_box;

        let var_int = read_var_int(source, u64::max_value()).unwrap();
        assert_eq!(0x102030405060708, var_int);
    }

    #[test]
    fn test_read_bytes() {
        let bytes: Vec<u8> = vec![ 1, 2, 4 ];
        let mut source_box: Box<Read> = Box::new(Cursor::new(bytes));
        let source = &mut *source_box;

        let bytes = read_bytes(source, 2).unwrap();
        assert_eq!(vec![ 1, 2 ], bytes);
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
