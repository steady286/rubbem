extern crate num;

use self::num::bigint::BigUint;
use self::num::integer::Integer;
use self::num::traits::{Zero,One,Num};
use std::iter;

pub fn create_public_key(private_bytes: &[u8; 32]) -> Result<[u8; 65], ()> {
    let private_bignum = BigUint::from_bytes_be(&private_bytes[..]);

    let curve = Curve::secp256k1();
    let base_point = curve.get_base_point();
    let public_point = curve.multiply(&base_point, &private_bignum);

    if public_point.is_infinity() {
        return Err(())
    }

    // get_x() and get_y() can only return None when the point is infinity
    let x_bytes = padded_bytes(curve.get_x(&public_point).unwrap());
    let y_bytes = padded_bytes(curve.get_y(&public_point).unwrap());

    Ok(to_array_65(x_bytes, y_bytes))
}

fn to_array_65(x_bytes: Vec<u8>, y_bytes: Vec<u8>) -> [u8; 65] {
    let mut result: [u8; 65] = [0; 65];

    for (i, b) in
        iter::once(4)
        .chain(x_bytes.into_iter())
        .chain(y_bytes.into_iter()).enumerate() {
            result[i] = b;
    }

    result
}

fn padded_bytes(value: BigUint) -> Vec<u8> {
    pad(value.to_bytes_be(), 32)
}

fn pad(mut bytes: Vec<u8>, size: usize) -> Vec<u8> {
    while bytes.len() < size {
        bytes.insert(0, 0);
    }
    bytes
}

#[derive(Debug, Clone)]
enum PointType {
    Infinity,
    Normal(BigUint, BigUint, BigUint)
}

#[derive(Debug, Clone)]
struct Point {
    internal: PointType
}

impl Point {
    fn from_xy(x: &BigUint, y: &BigUint) -> Point {
        Point {
            internal: PointType::Normal(x.clone(), y.clone(), BigUint::one())
        }
    }

    fn from_xyz(x: &BigUint, y: &BigUint, z: &BigUint) -> Point {
        Point {
            internal: PointType::Normal(x.clone(), y.clone(), z.clone())
        }
    }

    fn infinity() -> Point {
        Point {
            internal: PointType::Infinity
        }
    }

    fn is_infinity(&self) -> bool {
        match &self.internal {
            &PointType::Infinity => true,
            &PointType::Normal(_, _, _) => false
        }
    }
}

// Using the finite field of integers modulo p where p is prime,
// the elliptic curve consists of points satisfying: y^2 = x^3 + ax + b (mod p)
// G is the base point (Gx and Gy are the x and y components)
// n is the order of the point G
// h is the cofactor (n*h = order of the curve) - always 1 in a prime group
struct Curve {
    p: BigUint,
    a: BigUint,
    b: BigUint,
    Gx: BigUint,
    Gy: BigUint,
    n: BigUint,
    h: BigUint
}

impl Curve {
    fn secp256k1() -> Curve {
        // Values from https://en.bitcoin.it/wiki/Secp256k1
        Curve {
            p: big_uint_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
            a: BigUint::zero(),
            b: big_uint_hex("7"),
            Gx: big_uint_hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
            Gy: big_uint_hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
            n: big_uint_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
            h: BigUint::one()
        }
    }

    fn get_base_point(&self) -> Point {
        Point::from_xy(&self.Gx , &self.Gy) // No need to mod p as Gx and Gy must be < p
    }

    fn get_x(&self, point: &Point) -> Option<BigUint> {
        match &point.internal {
            &PointType::Infinity => None,
            &PointType::Normal(ref x, _, ref z) => Some(self.unproject(x, z))
        }
    }

    fn get_y(&self, point: &Point) -> Option<BigUint> {
        match &point.internal {
            &PointType::Infinity => None,
            &PointType::Normal(_, ref y, ref z) => Some(self.unproject(y, z))
        }
    }

    fn unproject(&self, value: &BigUint, z: &BigUint) -> BigUint {
        let z_inverse = self.inverse(z);
        (value * z_inverse) % &self.p
    }

    fn negate(&self, value: BigUint) -> BigUint {
        &self.p  - (&value % &self.p)
    }

    // http://stackoverflow.com/questions/14093417/find-the-inverse-of-a-number-modulo-a-prime
    fn inverse(&self, value: &BigUint) -> BigUint {
        let (mut x, mut a, mut b, mut u) = (value.clone(), BigUint::zero(), self.p.clone(), BigUint::one());

        while x > BigUint::zero() {
            let (q, r) = b.div_rem(&x);

            let (xc, ac, uc) = (x.clone(), a.clone(), u.clone());

            x = r.clone();
            a = uc.clone();
            b = xc.clone();
            u = ac + self.negate(q * uc);
        }

        assert!(b == BigUint::one(), "Curve does not have a prime modulus: {}", &self.p);

        return a % &self.p
    }

    fn equal(&self, point1: &Point, point2: &Point) -> bool {
        match (&point1.internal, &point2.internal) {
            (&PointType::Normal(ref x1, ref y1, ref z1), &PointType::Normal(ref x2, ref y2, ref z2)) => {
                ((x1 * z2 + self.negate(x2 * z1)) % &self.p).is_zero() &&
                ((y1 * z2 + self.negate(y2 * z1)) % &self.p).is_zero()
            },
            (&PointType::Infinity, &PointType::Infinity) => true,
            _ => false
        }
    }

    fn add(&self, point1: &Point, point2: &Point) -> Point {
        match (&point1.internal, &point2.internal) {
            (&PointType::Infinity, &PointType::Infinity) => Point::infinity(),
            (&PointType::Infinity, &PointType::Normal(ref x, ref y, ref z)) => Point::from_xyz(x, y, z),
            (&PointType::Normal(ref x, ref y, ref z), &PointType::Infinity) => Point::from_xyz(x, y, z),
            (&PointType::Normal(ref x1, ref y1, ref z1), &PointType::Normal(ref x2, ref y2, ref z2)) => {
                let u = &((y2 * z1 + self.negate(y1 * z2)) % &self.p);
                let v = &((x2 * z1 + self.negate(x1 * z2)) % &self.p);

                if v.is_zero() {
                    if u.is_zero() {
                        return self.double(point1);
                    }

                    return Point::infinity();
                }

                Point::from_xyz(
                    &(((((z1 * u * u  + self.negate((x1 * v * v) << 1)) * z2) + self.negate(v * v * v)) * v) % &self.p),
                    &(((((three() * x1 * v * v * u + self.negate(y1 * v * v * v)) + self.negate(z1 * u * u * u)) * z2) + u * v * v * v) % &self.p),
                    &((v * v * v * z1 * z2) % &self.p)
                )
            },
        }
    }

    fn double(&self, point: &Point) -> Point {
        match &point.internal {
            &PointType::Infinity => Point::infinity(),
            &PointType::Normal(ref x, ref y, ref z) => {
                match y.is_zero() {
                    true => Point::infinity(),
                    false => {
                        let w = &((three() * x * x + &self.a * z * z) % &self.p);

                        Point::from_xyz(
                            &((two() * y * z * (w * w + self.negate(eight() * x * y * y * z))) % &self.p),
                            &((four() * y * y * z * (three() * w * x + self.negate(two() * y * y * z)) + self.negate(w * w * w)) % &self.p),
                            &((eight() * y * y * y * z * z * z) % &self.p)
                        )
                    }
                }
            }
        }
    }

    fn multiply(&self, point: &Point, multiplicand: &BigUint) -> Point {
        match &point.internal {
            &PointType::Infinity => Point::infinity(),
            &PointType::Normal(ref x, ref y, ref z) => {
                let mut result = Point::infinity();

                let binary_multiplicand = multiplicand.to_str_radix(2);
                let final_digit_index = binary_multiplicand.len() - 1;
                for (index, digit) in binary_multiplicand.chars().enumerate() {
                    let increment = match digit {
                        '0' => Point::infinity(),
                        '1' => Point::from_xyz(&x, &y, &z),
                        _ => unreachable!()
                    };

                    result = self.add(&result, &increment);

                    if index != final_digit_index {
                        result = self.double(&result);
                    }
                }

                result
            }
        }
    }
}

fn two() -> BigUint {
    big_uint_hex("2")
}

fn three() -> BigUint {
    big_uint_hex("3")
}

fn four() -> BigUint {
    big_uint_hex("4")
}

fn eight() -> BigUint {
    big_uint_hex("8")
}

fn big_uint_hex(s: &str) -> BigUint {
    BigUint::from_str_radix(s, 16).unwrap()
}


#[cfg(test)]
mod tests {
    use super::Curve;
    use super::num::bigint::BigUint;
    use super::num::traits::Num;
    use super::{big_uint_hex,create_public_key};

    #[test]
    fn check_inverse() {
        let mut curve = Curve::secp256k1();
        let expected = BigUint::from_str_radix("77194726158210796949047323339125271902179989777093709359638389338605889781109", 10).unwrap();
        let actual = curve.inverse(&(BigUint::from_str_radix("3", 10).unwrap()));
        assert_eq!(expected, actual);
    }

    #[test]
    fn check_base_point() {
        let mut curve = Curve::secp256k1();
        let base_point = curve.get_base_point();
        let x = curve.get_x(&base_point).unwrap();
        let y = curve.get_y(&base_point).unwrap();
        assert_eq!(curve.Gx, x);
        assert_eq!(curve.Gy, y);
    }

    #[test]
    fn check_double() {
        let mut curve = Curve::secp256k1();
        let base_point = curve.get_base_point();
        let double_point = curve.double(&base_point);
        let x = curve.get_x(&double_point).unwrap();
        let y = curve.get_y(&double_point).unwrap();
        assert_eq!(x, big_uint_hex("C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5"));
        assert_eq!(y, big_uint_hex("1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A"));
    }

    #[test]
    fn check_multiply_zero() {
        let mut curve = Curve::secp256k1();
        let base_point = curve.get_base_point();
        let multiplied_point = curve.multiply(&base_point, &big_uint_hex("0"));
        assert!(multiplied_point.is_infinity());
    }

    #[test]
    fn check_multiply_one() {
        let mut curve = Curve::secp256k1();
        let base_point = curve.get_base_point();
        let multiplied_point = curve.multiply(&base_point, &big_uint_hex("1"));
        let x = curve.get_x(&multiplied_point).unwrap();
        let y = curve.get_y(&multiplied_point).unwrap();
        assert_eq!(x, big_uint_hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"));
        assert_eq!(y, big_uint_hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"));
    }

    #[test]
    fn check_multiply_two() {
        let mut curve = Curve::secp256k1();
        let base_point = curve.get_base_point();
        let multiplied_point = curve.multiply(&base_point, &big_uint_hex("2"));
        let x = curve.get_x(&multiplied_point).unwrap();
        let y = curve.get_y(&multiplied_point).unwrap();
        assert_eq!(x, big_uint_hex("C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5"));
        assert_eq!(y, big_uint_hex("1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A"));
    }

    #[test]
    fn example_private_key() {
        let input: [u8; 32] = hex_to_bytes_32("7b41aabed5fd0b963edf33e1faf5ce6baa10f89a001cf94cec959ed7ed6f73d4");
        let expected: [u8; 65] = hex_to_bytes_65("0444d87d627c6eeff1490bb61f5c26325a068fc9fad655849002816e803ecaf2a94b8c077269bd4b1cfa818c32c2fb37ebab14d129c8761b675e6409423acbe358");

        let output = create_public_key(&input).unwrap();
        assert_eq!(&expected[0], &output[0]);
        assert_eq!(&expected[1..33], &output[1..33]);
        assert_eq!(&expected[33..65], &output[33..65]);
    }

    fn hex_to_bytes_32(hex: &str) -> [u8; 32] {
        let bytes = bytes_from_hex(hex);
        assert_eq!(32, bytes.len());
        let mut result: [u8; 32] = [0; 32];
        result.clone_from_slice(&bytes[..]);
        result
    }

    fn hex_to_bytes_65(hex: &str) -> [u8; 65] {
        let bytes = bytes_from_hex(hex);
        assert_eq!(65, bytes.len());
        let mut result: [u8; 65] = [0; 65];
        result.clone_from_slice(&bytes[..]);
        result
    }

    fn bytes_from_hex(hex: &str) -> Vec<u8> {
        let hex_big_uint: BigUint = BigUint::from_str_radix(hex, 16).unwrap();
        hex_big_uint.to_bytes_be()
    }
}
