use sodiumoxide::crypto::hash::sha512::hash;

pub fn sha512(input: &Vec<u8>) -> Vec<u8> {
    let digest = hash(&input[..]);

    let mut result = vec![];
    for &b in &digest[..] {
        result.push(b);
    }

    result
}

