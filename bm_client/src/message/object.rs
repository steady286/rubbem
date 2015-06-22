use bm_time::StdTimeGenerator;
use byteorder::{BigEndian,WriteBytesExt};
use message::{Message,ParseError,MAX_PAYLOAD_LENGTH_FOR_OBJECT,MAX_TTL,OBJECT_EXPIRY_CUTOFF};
use message::pow::{generate_proof,GenerateError,ProofOfWorkConfig,verify_proof,VerifyError};
use std::io::Read;
use bm_time::TimeFn;
use time::{Duration,Timespec};

//
// ObjectType
//

#[derive(Clone,Copy,Debug,PartialEq)]
pub enum ObjectType {
	GetPubKey,
	PubKey,
	Msg,
	Broadcast
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

//
// ObjectMessage
//

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

	pub fn read(payload_length: u32, source: &mut Read) -> Result<Box<ObjectMessage>,ParseError> {
		let time_fn = Box::new(StdTimeGenerator::new());
		ObjectMessage::read_with_time(time_fn, payload_length, source)
	}

    fn read_with_time(time_fn: TimeFn, payload_length: u32, source: &mut Read) -> Result<Box<ObjectMessage>,ParseError> {
		if payload_length > MAX_PAYLOAD_LENGTH_FOR_OBJECT {
			return Err(ParseError::PayloadTooBig);
		}

		let nonce = try!(super::read_u64(source));
		let expiry = try!(super::read_timestamp(source));

		let verify_config = ProofOfWorkConfig::new(1000, 1000, OBJECT_EXPIRY_CUTOFF, MAX_TTL, 300, time_fn);
		try!(verify_proof(nonce, payload_length, expiry, verify_config).map_err(verify_to_parse_error));

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

fn verify_to_parse_error(e: VerifyError) -> ParseError {
	match e {
		VerifyError::ObjectAlreadyDied => ParseError::ObjectExpired,
		VerifyError::ObjectLivesTooLong => ParseError::ObjectLivesTooLong,
		VerifyError::UnacceptableProof => ParseError::UnacceptablePow
	}
}

impl Message for ObjectMessage {
    fn command(&self) -> String {
        "object".to_string()
    }

    fn payload(&self) -> Vec<u8> {
		let mut payload = vec![];
		payload.write_u64::<BigEndian>(self.nonce).unwrap();
		payload.extend(create_object_message_payload(self.expiry, self.object_type, self.version, self.stream_number));

        payload
    }
}

fn create_object_message_payload(expiry: Timespec, object_type: ObjectType, version: u64, stream_number: u64) -> Vec<u8> {
	let mut payload = vec![];

	payload.write_i64::<BigEndian>(expiry.sec).unwrap();
	payload.write_u32::<BigEndian>(object_type_code(object_type)).unwrap();
	super::write_var_int_64(&mut payload, version);
	super::write_var_int_64(&mut payload, stream_number);

	payload
}

//
// OutboundObjectMessage
//

pub struct OutboundObjectMessage {
	ttl: Duration,
	object_type: ObjectType,
	version: u64,
	stream_number: u64
}

impl OutboundObjectMessage {
	pub fn new(ttl: Duration, object_type: ObjectType, version: u64, stream_number: u64) -> OutboundObjectMessage {
		assert!(ttl.num_seconds() < u32::max_value() as i64);

		OutboundObjectMessage {
			ttl: ttl,
			object_type: object_type,
			version: version,
			stream_number: stream_number
		}
	}

	pub fn create_object_message(&self, time_fn: TimeFn) -> Result<ObjectMessage,GenerateError>  {
		let expiry = time_fn.get_time() + self.ttl;
		let payload = create_object_message_payload(expiry, self.object_type, self.version, self.stream_number);
		let nonce = try!(calculate_nonce(&payload[..], expiry, time_fn));

		Ok(ObjectMessage::new(nonce, expiry, self.object_type, self.version, self.stream_number))
	}
}

fn calculate_nonce(payload: &[u8], expiry: Timespec, time_fn: TimeFn) -> Result<u64,GenerateError> {
	let generate_config = ProofOfWorkConfig::new(1000, 1000, 60, MAX_TTL, 300, time_fn);
	generate_proof(payload, expiry, generate_config)
}

#[cfg(test)]
mod tests {
	use bm_time::StaticTimeGenerator;
	use byteorder::{BigEndian,ReadBytesExt,WriteBytesExt};
    use message::{Message,read_bytes};
    use message::object::{ObjectMessage,ObjectType};
    use std::io::{Cursor,Read};
	use time::{Duration,Timespec,get_time};

    #[test]
    fn test_object_message_payload() {
		let nonce = 0x37d8a; // precalculated to be a proof for the following data
		let expiry = Timespec::new(0x007060504030201, 0);
		let now = expiry - Duration::seconds(300);
		let object_type = ObjectType::Msg;
		let version = 255;
		let stream_number = 254;
		let message = ObjectMessage::new(nonce, expiry, object_type, version, stream_number);
		let payload = message.payload();

		assert_eq!("object".to_string(), message.command());

		let expected = vec![
			0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x7d, 0x8a, // nonce
			0, 7, 6, 5, 4, 3, 2, 1, // expiry
			0, 0, 0, 2, // object_type
			0xfd, 0, 255, // version
			0xfd, 0, 254, // stream_number
		];
		assert_eq!(expected, payload);


		let payload_length = payload.len();
		let mut source_box: Box<Read> = Box::new(Cursor::new(payload));
		let source = &mut *source_box;
		let time_fn = Box::new(StaticTimeGenerator::new(now));
		let roundtrip = ObjectMessage::read_with_time(time_fn, payload_length as u32, source).unwrap();

        assert_eq!("object".to_string(), roundtrip.command());
		assert_eq!(nonce, roundtrip.nonce());
		assert_eq!(0x007060504030201, roundtrip.expiry().sec);
		assert_eq!(object_type, roundtrip.object_type());
		assert_eq!(version, roundtrip.version());
		assert_eq!(stream_number, roundtrip.stream_number());
    }

	fn doit() {
		print_time(Box::new(get_time));
		print_time(Box::new(|| { Timespec::new(1, 0) }))
	}

	fn print_time(time_fn: Box<Fn() -> Timespec>) {
		println!("sec {}", time_fn().sec);
	}
}
