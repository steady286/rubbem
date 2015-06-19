use byteorder::BigEndian;
use byteorder::WriteBytesExt;
use message::{Message,ParseError};
use std::io::Read;
use time::Timespec;

#[derive(Clone,Copy,Debug,PartialEq)]
pub enum ObjectType {
	GetPubKey,
	PubKey,
	Msg,
	Broadcast
}

pub struct ObjectMessage {
	nonce: u64,
	expiry: Timespec,
	object_type: ObjectType,
	version: u64,
	stream_number: u64
}

impl ObjectMessage {
    pub fn new(nonce: u64, expiry: Timespec, object_type: ObjectType, version: u64, stream_number: u64) -> ObjectMessage {
        ObjectMessage {
			nonce: nonce,
			expiry: expiry,
			object_type: object_type,
			version: version,
			stream_number: stream_number
		}
    }

    pub fn read(source: &mut Read) -> Result<Box<ObjectMessage>,ParseError> {
		let nonce = try!(super::read_u64(source));
		let expiry = try!(super::read_timestamp(source));
		let object_type_code = try!(super::read_u32(source));
		let object_type = try!(parse_object_type_code(object_type_code));
		let version = try!(super::read_var_int(source, u64::max_value()));
		let stream_number = try!(super::read_var_int(source, u64::max_value()));

        Ok(Box::new(ObjectMessage::new(nonce, expiry, object_type, version, stream_number)))
    }

	pub fn nonce(&self) -> u64 {
		self.nonce
	}

	pub fn expiry(&self) -> Timespec {
		self.expiry
	}

	pub fn object_type(&self) -> ObjectType {
		self.object_type
	}

	pub fn version(&self) -> u64 {
		self.version
	}

	pub fn stream_number(&self) -> u64 {
		self.stream_number
	}
}

impl Message for ObjectMessage {
    fn command(&self) -> String {
        "object".to_string()
    }

    fn payload(&self) -> Vec<u8> {
        let mut payload = vec![];
		payload.write_u64::<BigEndian>(self.nonce).unwrap();
		payload.write_i64::<BigEndian>(self.expiry.sec).unwrap();
		payload.write_u32::<BigEndian>(object_type_code(self.object_type)).unwrap();
		super::write_var_int_64(&mut payload, self.version);
		super::write_var_int_64(&mut payload, self.stream_number);

        payload
    }
}

fn parse_object_type_code(code: u32) -> Result<ObjectType,ParseError> {
	match code {
		0 => Ok(ObjectType::GetPubKey),
		1 => Ok(ObjectType::PubKey),
		2 => Ok(ObjectType::Msg),
		3 => Ok(ObjectType::Broadcast),
		_ => Err(ParseError::UnknownObjectType)
	}
}

fn object_type_code(object_type: ObjectType) -> u32 {
	match object_type {
		ObjectType::GetPubKey => 0,
		ObjectType::PubKey => 1,
		ObjectType::Msg => 2,
		ObjectType::Broadcast => 3
	}
}

#[cfg(test)]
mod tests {
    use message::Message;
    use message::object::{ObjectMessage,ObjectType};
    use std::io::{Cursor,Read};
	use time::Timespec;

    #[test]
    fn test_object_message_payload() {
		let nonce = 0x0807060504030201;
		let expiry = Timespec::new(0x0304030405060506, 0);
		let object_type = ObjectType::Msg;
		let version = 255;
		let stream_number = 254;
		let message = ObjectMessage::new(nonce, expiry, object_type, version, stream_number);
        let payload = message.payload();

        assert_eq!("object".to_string(), message.command());

        let expected = vec![
            8, 7, 6, 5, 4, 3, 2, 1, // nonce
			3, 4, 3, 4, 5, 6, 5, 6, // expiry
			0, 0, 0, 2, // object_type
			0xfd, 0, 255, // version
			0xfd, 0, 254 // stream_number
        ];
        assert_eq!(expected, payload);

        let mut source_box: Box<Read> = Box::new(Cursor::new(payload));
        let source = &mut *source_box;
        let roundtrip = ObjectMessage::read(source).unwrap();

        assert_eq!("object".to_string(), roundtrip.command());
		assert_eq!(nonce, roundtrip.nonce());
		assert_eq!(expiry, roundtrip.expiry());
		assert_eq!(object_type, roundtrip.object_type());
		assert_eq!(version, roundtrip.version());
		assert_eq!(stream_number, roundtrip.stream_number());
    }
}
