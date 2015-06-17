use message::{Message,ParseError};
use std::io::Read;

pub struct VerackMessage;

impl VerackMessage {
	pub fn new() -> VerackMessage {
		VerackMessage
	}

	pub fn read(_: &mut Read) -> Result<Box<Message>,ParseError> {
			Ok(Box::new(VerackMessage::new()))
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

#[cfg(test)]
mod tests {
    use message::Message;
    use message::verack::VerackMessage;

    #[test]
    fn test_verack_message_payload() {
        let message = VerackMessage::new();
        let payload = message.payload();

        assert_eq!("verack".to_string(), message.command());
        assert_eq!(0, payload.len());
    }
}
