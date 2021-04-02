use inventory::Inventory;
use message::{Message,Object,ObjectData};
use message::pow::{ProofOfWork,GenerateError,network_pow_config};
use std::time::{Duration,SystemTime};
use timegen::TimeType;

pub enum MessageSendError {
    UnableToCreatePow(GenerateError)
}

impl From<GenerateError> for MessageSendError {
    fn from(err: GenerateError) -> MessageSendError {
        MessageSendError::UnableToCreatePow(err)
    }
}

pub struct Sender {
    inventory: Inventory
}

impl Sender {
    pub fn new(inventory: Inventory) -> Sender {
        Sender {
            inventory: inventory
        }
    }

    pub fn send_message(&mut self, text: &str) -> Result<(), MessageSendError> {
        let object_data_wrong_nonce = ObjectData {
            nonce: 0,
            expiry: SystemTime::now() + Duration::from_secs(345600), // 4 days
            version: 1,
            stream: 1,
            object: Object::Msg { encrypted: text.bytes().collect() } // Very bad!!!
        };

        let pow = ProofOfWork::new(TimeType::Real);
        let nonce = pow.generate(&object_data_wrong_nonce, network_pow_config())?;

        let object_data_with_nonce = ObjectData { nonce: nonce, .. object_data_wrong_nonce };

        self.inventory.add_object_message(&Message::Object(object_data_with_nonce));

        Ok(())
    }
}
