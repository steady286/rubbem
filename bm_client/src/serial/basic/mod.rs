pub mod read;
pub mod write;

#[derive(Debug,PartialEq)]
pub enum BasicSerialError {
    OutOfData,
    BadAscii,
    MaximumValueExceeded
}
