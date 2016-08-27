use byteorder::{BigEndian,WriteBytesExt};
use encoding::{Encoding,EncoderTrap};
use encoding::all::ASCII;

pub fn write_var_int_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    let bytes_length = bytes.len();
    write_var_int_usize(output, bytes_length);
    write_bytes_no_check(output, bytes);
}

pub fn write_bytes(output: &mut Vec<u8>, bytes: &[u8], expected_size: usize) {
    assert!(bytes.len() == expected_size);
    write_bytes_no_check(output, bytes);
}

pub fn write_bytes_no_check(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend(bytes.to_vec());
}

pub fn write_var_str(output: &mut Vec<u8>, user_agent: &str) {
    let ascii_user_agent = ASCII.encode(user_agent, EncoderTrap::Ignore).unwrap();
    write_var_int_64(output, ascii_user_agent.len() as u64);
    output.extend(ascii_user_agent);
}

pub fn write_var_int_list(output: &mut Vec<u8>, values: &[u64]) {
    write_var_int_64(output, values.len() as u64);
    for &value in values {
        write_var_int_64(output, value);
    }
}

pub fn write_var_int_usize(output: &mut Vec<u8>, value: usize) {
    write_var_int_64(output, value as u64);
}

pub fn write_var_int_64(output: &mut Vec<u8>, value: u64) {
    if value <= 0xffffffff {
        write_var_int_32(output, value as u32);
    } else {
        output.push(0xff);
        write_u64(output, value);
    }
}

pub fn write_var_int_32(output: &mut Vec<u8>, value: u32) {
    if value <= 0xffff {
        write_var_int_16(output, value as u16);
    } else {
        output.push(0xfe);
        write_u32(output, value);
    }
}

pub fn write_var_int_16(output: &mut Vec<u8>, value: u16) {
    if value < 0xfd {
        write_small_var_int_8(output, value as u8);
    } else {
        output.push(0xfd);
        write_u16(output, value);
    }
}

pub fn write_small_var_int_8(output: &mut Vec<u8>, value: u8) {
    output.push(value);
}

pub fn write_u64(output: &mut Vec<u8>, value: u64) {
    output.write_u64::<BigEndian>(value).unwrap();
}

pub fn write_i64(output: &mut Vec<u8>, value: i64) {
    output.write_i64::<BigEndian>(value).unwrap();
}

pub fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.write_u32::<BigEndian>(value).unwrap();
}

pub fn write_u16(output: &mut Vec<u8>, value: u16) {
    output.write_u16::<BigEndian>(value).unwrap();
}

pub fn write_u8(output: &mut Vec<u8>, value: u8) {
    output.write_u8(value).unwrap();
}

#[cfg(test)]
mod tests {
    use super::write_var_str;
    use super::write_var_int_list;
    use super::write_var_int_64;
    use super::write_var_int_32;
    use super::write_var_int_16;

    #[test]
    fn test_write_var_str() {
        let mut payload1 = vec![];
        write_var_str(&mut payload1, "ABC");
        assert_eq!(payload1, vec![ 3, 65, 66, 67 ]);

        let mut payload2 = vec![];
        write_var_str(&mut payload2, "");
        assert_eq!(payload2, vec![ 0 ]);
    }

    #[test]
    fn test_write_var_int_list() {
        let mut payload1 = vec![];
        write_var_int_list(&mut payload1, &[ 1u64 ]);
        assert_eq!(payload1, vec![ 1, 1 ]);

        let mut payload2 = vec![];
        write_var_int_list(&mut payload2, &[]);
        assert_eq!(payload2, vec![ 0 ]);

        let mut payload3 = vec![];
        write_var_int_list(&mut payload3, &[ 0xfeu64, 4, 5 ]);
        assert_eq!(payload3, vec![ 3, 0xfd, 0, 0xfe, 4, 5]);

        let mut list: Vec<u64> = vec![];
        let mut expected: Vec<u8> = vec![ 0xfd, 0, 0xff];
        for i1 in 0..0xfd {
            list.push(i1);
            expected.push(i1 as u8);
        }
        for i2 in 0xfdu64..0x100 {
            list.push(i2);
            expected.push(0xfd);
            expected.push(0);
            expected.push(i2 as u8);
        }
        let mut payload4 = vec![];
        write_var_int_list(&mut payload4, &list[..]);
    }

    #[test]
    fn test_write_var_int_one_byte() {
        for v in 0..0xfd {
            let expected = vec![ v ];

            let mut payload_16 = vec![];
            write_var_int_16(&mut payload_16, v as u16);
            assert_eq!(payload_16, expected);

            let mut payload_32 = vec![];
            write_var_int_32(&mut payload_32, v as u32);
            assert_eq!(payload_32, expected);

            let mut payload_64 = vec![];
            write_var_int_64(&mut payload_64, v as u64);
            assert_eq!(payload_64, expected);
        }
    }

    #[test]
    fn test_write_var_int_three_bytes_low() {
        for v in 0xfdu64..0x100 {
            let expected = vec![ 0xfd, 0, v as u8 ];

            let mut payload_16 = vec![];
            write_var_int_16(&mut payload_16, v as u16);
            assert_eq!(payload_16, expected);

            let mut payload_32 = vec![];
            write_var_int_32(&mut payload_32, v as u32);
            assert_eq!(payload_32, expected);

            let mut payload_64 = vec![];
            write_var_int_64(&mut payload_64, v as u64);
            assert_eq!(payload_64, expected);
        }
    }

    #[test]
    fn test_write_var_int_three_bytes_high() {
        let mut test_values: Vec<u16> = vec![];
        for test_value in 256..1000 {
            test_values.push(test_value);
        }
        test_values.push(u16::max_value() - 1);
        test_values.push(u16::max_value());

        for v in test_values {
            let expected = vec![0xfd, (v / 256) as u8, (v % 256) as u8 ];

            let mut payload_16 = vec![];
            write_var_int_16(&mut payload_16, v);
            assert_eq!(payload_16, expected);

            let mut payload_32 = vec![];
            write_var_int_32(&mut payload_32, v as u32);
            assert_eq!(payload_32, expected);

            let mut payload_64 = vec![];
            write_var_int_64(&mut payload_64, v as u64);
            assert_eq!(payload_64, expected);
        }
    }

    #[test]
    fn test_write_var_int_five_bytes() {
        let mut test_values: Vec<u32> = vec![];
        test_values.push(u16::max_value() as u32 + 1);
        test_values.push(100000);
        test_values.push(1000000);
        test_values.push(1000000000);
        test_values.push(u32::max_value() - 1);
        test_values.push(u32::max_value());

        for v in test_values {
            let pow3 = 256 * 256 * 256;
            let pow2 = 256 * 256;
            let expected = vec![0xfe, (v / pow3) as u8, ((v % pow3) / pow2) as u8, ((v % pow2) / 256) as u8, (v % 256) as u8 ];

            let mut payload_32 = vec![];
            write_var_int_32(&mut payload_32, v);
            assert_eq!(payload_32, expected);

            let mut payload_64 = vec![];
            write_var_int_64(&mut payload_64, v as u64);
            assert_eq!(payload_64, expected);
        }
    }

    #[test]
    fn test_write_var_int_nine_bytes() {
        let mut payload1 = vec![];
        write_var_int_64(&mut payload1, u32::max_value() as u64 + 1);
        assert_eq!(payload1, vec![ 0xff, 0, 0, 0, 1, 0 , 0 , 0, 0]);

        let mut payload2 = vec![];
        write_var_int_64(&mut payload2, u64::max_value());
        assert_eq!(payload2, vec![ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff ]);
    }
}
