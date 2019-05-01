/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use super::traits::Hash;
use arithmetic::traits::Converter;
use elliptic::curves::traits::{ECPoint, ECScalar};
//use ring::digest::{Context, SHA256};

use cryptoxide::digest::Digest;
use cryptoxide::sha2::Sha256;

use BigInt;
use {FE, GE};

pub struct HSha256;

impl Hash for HSha256 {
fn create_hash(big_ints: &[&BigInt]) -> BigInt {
        let mut hasher = Sha256::new();

        let mut flatten_array: Vec<u8> = Vec::new();
        for value in big_ints {
            let bytes: Vec<u8> = BigInt::to_vec(value); //value.borrow().into();
            flatten_array.extend_from_slice(&bytes);
        }

        hasher.input(&flatten_array);
        let mut result = [0; 32]; //TODO: parametrize 32/64 usize to fit both SHA256/512 algorithms
        hasher.result(&mut result);
        BigInt::from(result.as_ref())
    }

    fn create_hash_from_ge(ge_vec: &[&GE]) -> FE {
        let mut hasher = Sha256::new();

        let mut flatten_array: Vec<u8> = Vec::new();
        for value in ge_vec {
            let bytes = &value.pk_to_key_slice();
            flatten_array.extend_from_slice(bytes);
        }

        hasher.input(&flatten_array);
        let mut result_buf = [0; 32]; //TODO: parametrize 32/64 usize to fit both SHA256/512 algorithms
        hasher.result(&mut result_buf);
        let result = BigInt::from(result_buf.as_ref());
        ECScalar::from(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::HSha256;
    use super::Hash;
    use elliptic::curves::traits::ECPoint;
    use elliptic::curves::traits::ECScalar;
    use BigInt;
    use GE;

    #[test]
    // Very basic test here, TODO: suggest better testing
    fn create_hash_test() {
        HSha256::create_hash(&vec![]);

        let result = HSha256::create_hash(&vec![&BigInt::one(), &BigInt::zero()]);
        assert!(result > BigInt::zero());
    }

    #[test]
    fn create_hash_from_ge_test() {
        let point = GE::base_point2();
        let result1 = HSha256::create_hash_from_ge(&vec![&point, &GE::generator()]);
        assert!(result1.to_big_int().to_str_radix(2).len() > 240);
        let result2 = HSha256::create_hash_from_ge(&vec![&GE::generator(), &point]);
        assert_ne!(result1, result2);
        let result3 = HSha256::create_hash_from_ge(&vec![&GE::generator(), &point]);
        assert_eq!(result2, result3);
    }
}
