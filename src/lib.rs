//! Toy RSA Library
//!
//! Rohan Singh 2023

use toy_rsa_lib::*;

/// LCM function
fn lambda(p: u64, q: u64) -> u64 {
    lcm(p - 1, q - 1)
}

/// Fixed RSA encryption exponent.
pub const EXP: u64 = 65_537;

/// Generate a pair of primes in the range `2**31..2**32`
/// suitable for RSA encryption with exponent.
pub fn genkey() -> (u32, u32) {
    let mut key: (u32, u32) = (0, 0);
    while EXP < lambda(key.0.into(), key.1.into())
        && gcd(EXP, lambda(key.0.into(), key.1.into())) == 1
    {
        key.0 = rsa_prime();
        key.1 = rsa_prime();
    }
    key
}

/// Encrypt the plaintext `msg` using the RSA public `key`
/// and return the ciphertext.
pub fn encrypt(key: u64, msg: u32) -> u64 {
    modexp(msg.into(), EXP, key)
}

/// Decrypt the cipertext `msg` using the RSA private `key`
/// and return the resulting plaintext.
pub fn decrypt(key: (u32, u32), msg: u64) -> u32 {
    let d = modinverse(EXP, lambda(key.0 as u64, key.1 as u64));
    modexp(msg, d, key.0 as u64 * key.1 as u64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lambda() {
        assert_eq!(lambda(11, 16), 30);
        assert_eq!(lambda(21, 26), 100);
    }

    #[test]
    fn test_encrypt() {
        assert_eq!(encrypt(2, 2), 0);
        assert_eq!(encrypt(0xde9c5816141c8ba9, 0x12345f), 0x6418280e0c4d7675)
    }

    #[test]
    fn test_decrypt() {
        assert_eq!(
            decrypt((0xed23e6cd, 0xf050a04d), 0x6418280e0c4d7675),
            0x12345f
        );
    }
}
