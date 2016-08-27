use byteorder::BigEndian;
use byteorder::ReadBytesExt;
use encoding::{Encoding,DecoderTrap};
use encoding::all::ASCII;
use serial::basic::BasicSerialError;
use std::io::Read;

pub fn read_var_int_bytes<A: Read>(source: &mut A) -> Result<Vec<u8>,BasicSerialError> {
    let byte_count = try!(read_var_int_usize(source, usize::max_value()));
    Ok(try!(read_bytes(source, byte_count)))
}

pub fn read_var_str<A: Read>(source: &mut A, max_length: usize) -> Result<String,BasicSerialError> {
    let length = try!(read_var_int_usize(source, max_length));

    let string_bytes = try!(read_bytes(source, length));
    ASCII.decode(&string_bytes, DecoderTrap::Strict).map_err(|_| BasicSerialError::BadAscii)
}

pub fn read_var_int_list<A: Read>(source: &mut A, max_count: usize) -> Result<Vec<u64>,BasicSerialError> {
    let count = try!(read_var_int_usize(source, max_count));

    let mut int_list: Vec<u64> = Vec::with_capacity(count);
    for _ in 0..count {
        let int = try!(read_var_int(source, u64::max_value()));
        int_list.push(int);
    }

    Ok(int_list)
}

pub fn read_var_int_usize<A: Read>(source: &mut A, max_value: usize) -> Result<usize,BasicSerialError> {
    read_var_int(source, max_value as u64).map(|v| v as usize)
}

pub fn read_var_int<A: Read>(source: &mut A, max_value: u64) -> Result<u64,BasicSerialError> {
    let first_byte: u8 = try!(read_u8(source));

    let value = match first_byte {
        byte @ 0...0xfc => byte as u64,
        0xfd => try!(read_u16(source)) as u64,
        0xfe => try!(read_u32(source)) as u64,
        0xff => try!(read_u64(source)),
        _ => unreachable!()
    };

    if value > max_value {
        return Err(BasicSerialError::MaximumValueExceeded);
    }

    Ok(value)
}

pub fn read_bytes<A: Read>(source: &mut A, count: usize) -> Result<Vec<u8>,BasicSerialError> {
    let mut take = source.take(count as u64);
    let mut bytes: Vec<u8> = Vec::with_capacity(count);
    let read_count = try!(take.read_to_end(&mut bytes).map_err(|_| BasicSerialError::OutOfData));

    if read_count != count || bytes.len() != count {
        return Err(BasicSerialError::OutOfData);
    }

    Ok(bytes)
}

pub fn read_u64<A: Read>(source: &mut A) -> Result<u64,BasicSerialError> {
    source.read_u64::<BigEndian>().map_err(|_| BasicSerialError::OutOfData)
}

pub fn read_i64<A: Read>(source: &mut A) -> Result<i64,BasicSerialError> {
    source.read_i64::<BigEndian>().map_err(|_| BasicSerialError::OutOfData)
}

pub fn read_u32<A: Read>(source: &mut A) -> Result<u32,BasicSerialError> {
    source.read_u32::<BigEndian>().map_err(|_| BasicSerialError::OutOfData)
}

pub fn read_u16<A: Read>(source: &mut A) -> Result<u16,BasicSerialError> {
    source.read_u16::<BigEndian>().map_err(|_| BasicSerialError::OutOfData)
}

pub fn read_u8<A: Read>(source: &mut A) -> Result<u8,BasicSerialError> {
    source.read_u8().map_err(|_| BasicSerialError::OutOfData)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use super::read_var_int_bytes;
    use super::read_var_str;
    use super::read_var_int_list;
    use super::read_var_int_usize;
    use super::read_var_int;
    use super::read_bytes;

    #[test]
    fn test_read_var_int_bytes() {
        let bytes: Vec<u8> = vec![ 2, 56, 62 ];
        let mut source = Cursor::new(bytes);

        let result = read_var_int_bytes(&mut source).unwrap();
        assert_eq!(vec![ 56, 62 ], result);
    }

    #[test]
    fn test_read_var_str() {
        let bytes: Vec<u8> = vec![ 3, 65, 66, 67 ];
        let mut source = Cursor::new(bytes);

        let string = read_var_str(&mut source, 3).unwrap();
        assert_eq!("ABC", &string);
    }

    #[test]
    fn test_read_var_str_too_long() {
        let bytes: Vec<u8> = vec![ 3, 65, 66, 67 ];
        let mut source = Cursor::new(bytes);

        assert!(read_var_str(&mut source, 2).is_err());
    }

    #[test]
    fn test_read_var_int_list() {
        let bytes: Vec<u8> = vec![ 3, 65, 66, 67 ];
        let mut source = Cursor::new(bytes);

        let int_list = read_var_int_list(&mut source, 3).unwrap();

        let expected: Vec<u64> = vec![ 65, 66, 67 ];
        assert_eq!(expected, int_list);
    }

    #[test]
    fn test_read_var_int_list_too_long() {
        let bytes: Vec<u8> = vec![ 3, 65, 66, 67 ];
        let mut source = Cursor::new(bytes);

        assert!(read_var_int_list(&mut source, 2).is_err());
    }

    #[test]
    fn test_read_var_int_usize() {
        let bytes: Vec<u8> = vec![ 0xfd, 5, 220 ];
        let mut source = Cursor::new(bytes);

        let var_int = read_var_int_usize(&mut source, 2000).unwrap();
        assert_eq!(1500, var_int);
    }

    #[test]
    fn test_read_var_int_u8() {
        let bytes: Vec<u8> = vec![ 0xfc ];
        let mut source = Cursor::new(bytes);

        let var_int = read_var_int(&mut source, 20000000).unwrap();
        assert_eq!(0xfc, var_int);
    }

    #[test]
    fn test_read_var_int_u16() {
        let bytes: Vec<u8> = vec![ 0xfd, 1, 2 ];
        let mut source = Cursor::new(bytes);

        let var_int = read_var_int(&mut source, 20000000).unwrap();
        assert_eq!(258, var_int);
    }

    #[test]
    fn test_read_var_int_u32() {
        let bytes: Vec<u8> = vec![ 0xfe, 1, 2, 3, 4 ];
        let mut source = Cursor::new(bytes);

        let var_int = read_var_int(&mut source, 20000000).unwrap();
        assert_eq!(0x1020304, var_int);
    }

    #[test]
    fn test_read_var_int_u64() {
        let bytes: Vec<u8> = vec![ 0xff, 1, 2, 3, 4, 5, 6, 7, 8 ];
        let mut source = Cursor::new(bytes);

        let var_int = read_var_int(&mut source, u64::max_value()).unwrap();
        assert_eq!(0x102030405060708, var_int);
    }

    #[test]
    fn test_read_bytes() {
        let bytes: Vec<u8> = vec![ 1, 2, 4 ];
        let mut source = Cursor::new(bytes);

        let bytes = read_bytes(&mut source, 2).unwrap();
        assert_eq!(vec![ 1, 2 ], bytes);
    }
}
