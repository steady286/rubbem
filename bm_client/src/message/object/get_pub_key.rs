use message::ParseError;
use super::Object;
use super::ObjectType;
use std::io::Read;

pub struct GetPubKeyV4;

impl GetPubKeyV4 {
    pub fn new() -> GetPubKeyV4 {
        GetPubKeyV4
    }

    pub fn read(source: &mut Read) -> Result<Box<GetPubKeyV4>,ParseError> {
        Ok(Box::new(GetPubKeyV4))
    }
}

impl Object for GetPubKeyV4 {
    fn object_type(&self) -> ObjectType {
        ObjectType::GetPubKey
    }

    fn version(&self) -> u64 {
        4
    }

    fn payload(&self) -> Vec<u8> {
        vec![]
    }
}