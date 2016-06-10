use super::Message;
use super::responder::{MessageResponder,ResponderError};
use super::verify::{MessageVerifier,MessageVerifierError};
use std::sync::mpsc::SendError;

pub enum MessageHandlingError {
    VerificationError,
    ResponseError
}

impl From<ResponderError> for MessageHandlingError {
    fn from(_: ResponderError) -> MessageHandlingError {
        MessageHandlingError::ResponseError
    }
}

impl From<MessageVerifierError> for MessageHandlingError {
    fn from(_: MessageVerifierError) -> MessageHandlingError {
        MessageHandlingError::VerificationError
    }
}

pub struct MessageHandler {
    message_verifier: MessageVerifier,
    message_responder: MessageResponder
}

impl MessageHandler {
    pub fn new(message_verifier: MessageVerifier, message_responder: MessageResponder) -> MessageHandler {
        MessageHandler {
            message_verifier: message_verifier,
            message_responder: message_responder
        }
    }

    pub fn send_version<F>(&self, f: F) -> Result<(), SendError<Message>>
        where F : Fn(Message) -> Result<(), SendError<Message>>
    {
        self.message_responder.send_version(f)
    }

    pub fn handle<F>(&mut self, message: Message, send: F) -> Result<(), MessageHandlingError>
        where F : Fn(Message) -> Result<(), SendError<Message>>
    {
        try!(self.message_verifier.verify(&message));
        try!(self.message_responder.respond(message, send));
        Ok(())
    }
}
