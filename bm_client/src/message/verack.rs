use message::{Message,ParseError};
use std::io::Cursor;
use super::check_no_more_data;

pub struct VerackMessage;

impl VerackMessage {
    pub fn new() -> VerackMessage {
        VerackMessage
    }

    pub fn read(payload: Vec<u8>) -> Result<Box<VerackMessage>,ParseError> {
        let mut cursor = Cursor::new(payload);
        try!(check_no_more_data(&mut cursor));
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
    use std::io::Read;

    #[test]
    fn test_verack_message_payload() {
        let message = VerackMessage::new();
        let payload = message.payload();

        assert_eq!("verack".to_string(), message.command());
        assert_eq!(0, payload.len());

        let roundtrip = VerackMessage::read(payload).unwrap();

        assert_eq!("verack".to_string(), roundtrip.command());
    }
}
