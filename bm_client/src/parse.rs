use byteorder::{BigEndian,ReadBytesExt};
use crypto::sha512;
use encoding::{Encoding, DecoderTrap};
use encoding::all::ASCII;
use message::{Message,VerackMessage};
use peer::MessageListener;
use std::io::{Cursor,Read};

#[derive(Debug,PartialEq)]
pub enum ParseError {
SourceRead,
FailedMagic,
PayloadLength,
ChecksumMismatch,
AsciiDecode,
NonZeroPadding,
UnknownCommand,
BadPayload
}

pub trait MessageByteListener {
	fn message_bytes(&mut self, command: String, message_bytes: Vec<u8>) -> Result<(),ParseError>;

	fn error(&mut self);
}

pub struct MessageReader {
	listener: Box<MessageListener>
}

impl MessageReader {
	pub fn new(listener: Box<MessageListener>) -> MessageReader {
		MessageReader {
			listener: listener
		}
	}
}

impl MessageByteListener for MessageReader {
	fn message_bytes(&mut self, command: String, message_bytes: Vec<u8>) -> Result<(),ParseError> {
		let message = match &command[..] {
			"verack" => try!(parse_verack(message_bytes)),
			_ => return Err(ParseError::UnknownCommand)
		};

		self.listener.message(message);

		Ok(())
	}

	fn error(&mut self) {
	}
}

fn parse_verack(message_bytes: Vec<u8>) -> Result<Box<Message>,ParseError> {
	if message_bytes.len() != 0 {
		return Err(ParseError::BadPayload);
	}

	Ok(Box::new(VerackMessage::new()))
}

pub struct MessageByteReader {
	source: Box<Read>,
	listener: Box<MessageByteListener>
}

impl MessageByteReader {
	pub fn new(source: Box<Read>, listener: Box<MessageByteListener>) -> MessageByteReader {
		MessageByteReader {
			source: source,
			listener: listener
		}
	}

	pub fn start(&mut self) {
		loop {
			if self.read_message().is_err() {
				self.listener.error();
				break;
			}
		}
	}

	pub fn read_message(&mut self) -> Result<(),ParseError> {
		let header = try!(self.read(24));

		assert!(header.len() == 24);

		if !is_magic(&header[0..4]) {
			return Err(ParseError::FailedMagic);
		}

		let command = match parse_command(&header[4..16]) {
			Ok(command) => command,
			Err(e) => return Err(e)
		};
		let length_bytes = parse_length(&header[16..20]);
		let checksum = &header[20..24];

		if length_bytes > 1600003 {
			return Err(ParseError::PayloadLength);
		}

		let payload = try!(self.read(length_bytes as u64));
		let sha512 = sha512(&payload);
		if &sha512[0..4] != checksum {
			return Err(ParseError::ChecksumMismatch);
		}

		self.listener.message_bytes(command, payload)
	}

	fn read(&mut self, count: u64) -> Result<Vec<u8>,ParseError> {
		let mut source = &mut self.source;
		let mut take = source.take(count);

		let mut bytes = vec![];
		match take.read_to_end(&mut bytes) {
			Ok(_) => Ok(bytes),
			Err(_) => Err(ParseError::SourceRead)
		}
	}
}

fn is_magic(magic_bytes: &[u8]) -> bool {
	assert!(magic_bytes.len() == 4);
	magic_bytes == [0xe9, 0xbe, 0xb4, 0xd9]
}

fn parse_command(command_bytes: &[u8]) -> Result<String,ParseError> {
	assert!(command_bytes.len() == 12);

	let non_zero_bytes = match remove_zeros(command_bytes) {
		Ok(b) => b,
		Err(e) => return Err(e)
	};

	match ASCII.decode(non_zero_bytes, DecoderTrap::Strict) {
		Ok(command) => Ok(command),
		Err(_) => Err(ParseError::AsciiDecode)
	}
}

fn remove_zeros(bytes: &[u8]) -> Result<&[u8],ParseError> {
	let mut split: Vec<&[u8]> = bytes.split(|&byte| byte == 0).collect();
	split.retain(|split| split.len() > 0);

	match split.len() {
		1 => Ok(split[0]),
		_ => Err(ParseError::NonZeroPadding)
	}
}

fn parse_length(length_bytes: &[u8]) -> u32 {
	assert!(length_bytes.len() == 4);

	let mut cursor = Cursor::new(length_bytes);
	cursor.read_u32::<BigEndian>().unwrap()
}

#[cfg(test)]
mod tests {
	use super::{MessageByteListener,MessageByteReader,ParseError};
	use std::borrow::Borrow;
	use std::io::Cursor;
	use std::rc::Rc;
	use std::sync::Mutex;

	struct TestMessageByteListener {
		command: Rc<Mutex<String>>,
		message_bytes: Rc<Mutex<Vec<u8>>>
	}

	impl TestMessageByteListener {
		fn new(command: Rc<Mutex<String>>, message_bytes: Rc<Mutex<Vec<u8>>>) -> TestMessageByteListener {
			TestMessageByteListener {
				command: command,
				message_bytes: message_bytes
			}
		}
	}

	impl MessageByteListener for TestMessageByteListener {
		fn message_bytes(&mut self, command: String, message_bytes: Vec<u8>) -> Result<(),ParseError> {
			let mut self_command = self.command.lock().unwrap();
			self_command.clear();
			self_command.push_str(command.borrow());

			let mut self_message_bytes = self.message_bytes.lock().unwrap();
			self_message_bytes.clear();
			self_message_bytes.extend(message_bytes.into_iter());

			Ok(())
		}

		fn error(&mut self) {
			println!("ERROR");
		}
	}

	#[test]
	fn test_parse_verack() {
		let bytes = vec![
			0xe9, 0xbe, 0xb4, 0xd9, // magic
			118, 101, 114, 97, 99, 107, // verack
			0, 0, 0, 0, 0, 0, // padding
			0, 0, 0, 0, // payload length
			0xcf, 0x83, 0xe1, 0x35 // checksum
		];

		let command = Rc::new(Mutex::new(String::new()));
		let message_bytes = Rc::new(Mutex::new(vec![]));

		let listener: Box<MessageByteListener> = Box::new(TestMessageByteListener::new(command.clone(), message_bytes.clone()));
		let mut reader = MessageByteReader::new(Box::new(Cursor::new(bytes)), listener);

		assert_eq!(Ok(()), reader.read_message());

		assert_eq!("verack", *command.lock().unwrap());
		let empty_vec: Vec<u8> = vec![];
		assert_eq!(empty_vec, *message_bytes.lock().unwrap());
	}
}