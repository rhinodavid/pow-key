extern crate byteorder;
extern crate crypto;
extern crate rustc_serialize as serialize;

use lib::byteorder::{LittleEndian, WriteBytesExt};
use lib::crypto::digest::Digest;
use lib::crypto::sha2::Sha256;
use lib::serialize::hex::{FromHex, ToHex};
use std::result::Result::Err;

// BASE: string
// HASH: 32-bytes (SHA-256)
// NONCE: 8-byte/32-bit (c unsigned int -- little endian) max: 4294967295

#[derive(Debug)]
pub struct Sha256Hasher<'a> {
    base: &'a [u8],
}

impl<'a> Sha256Hasher<'a> {
    pub fn new(base: &'a [u8]) -> Sha256Hasher {
        Sha256Hasher { base: base }
    }

    pub fn hash(&self) -> Sha256Hash {
        Sha256Hasher::hash_impl(self.base)
    }

    fn hash_impl(base: &[u8]) -> Sha256Hash {
        let mut sha = Sha256::new();
        sha.input(base);
        let mut result = [0x00; 32];
        sha.result(&mut result);
        Sha256Hash { value: result }
    }

    pub fn hash_with_nonce(&self, nonce: u32) -> Sha256Hash {
        let mut cat = vec![];
        cat.extend_from_slice(self.base);
        let x = nonce_to_bytes(nonce);
        // println!("{}", x.to_hex());
        cat.extend_from_slice(&x);
        // println!("{}", cat.as_slice().to_hex());
        Sha256Hasher::hash_impl(cat.as_slice())
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Sha256Hash {
    pub value: [u8; 32],
}

impl Sha256Hash {
    pub fn from_hex_string(s: &String) -> Result<Sha256Hash, String> {
        if s.len() != 64 {
            return Err("Input must be 64 characters".to_string());
        }
        let mut result: [u8; 32] = [0; 32];
        match s.from_hex() {
            Ok(r) => {
                for (i, &v) in r.iter().enumerate() {
                    result[i] = v;
                }
                Ok(Sha256Hash { value: result })
            }
            Err(e) => Err(format!("Serialization failed: {:?}", e)),
        }
    }
    pub fn to_hex(&self) -> String {
        format!("{}", self.value.to_hex())
    }
}

fn nonce_to_bytes(nonce: u32) -> [u8; 4] {
    let mut result = [0u8; 4];
    result
        .as_mut()
        .write_u32::<LittleEndian>(nonce)
        .expect("Unable to write");
    result
}

#[cfg(test)]
mod tests {
    use Sha256Hash;
    use Sha256Hasher;
    #[test]
    fn it_creates_sha_hashes_from_hex() {
        let hash = Sha256Hash::from_hex_string(
            &"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string(),
        ).unwrap();
        assert_eq!(
            Sha256Hash {
                value: [
                    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d,
                    0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10,
                    0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
                ],
            },
            hash
        );
    }

    #[test]
    fn it_fails_to_create_hash_with_wrong_length() {
        assert!(Sha256Hash::from_hex_string(&"aa00bb".to_string()).is_err());
    }

    #[test]
    fn it_hashes_abc() {
        let hasher = Sha256Hasher::new(b"abc");
        let answer = Sha256Hash {
            value: [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ],
        }; // ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
        assert_eq!(answer, hasher.hash());
    }

    #[test]
    fn it_hashes_empty_string() {
        let hasher = Sha256Hasher::new(b"");
        let answer = Sha256Hash {
            value: [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ],
        }; // e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855
        assert_eq!(answer, hasher.hash());
    }

    #[test]
    fn it_hashes_with_a_small_nonce() {
        let hasher = Sha256Hasher::new(b"helloworld");
        let answer = Sha256Hash {
            value: [
                0x12, 0x17, 0x92, 0x8f, 0x62, 0x4a, 0x1e, 0xf0, 0x61, 0xf8, 0x4a, 0x9c, 0x02, 0xf7,
                0xed, 0x2a, 0x6c, 0x7f, 0xdc, 0x92, 0xaa, 0x5f, 0xa8, 0x29, 0x3b, 0x61, 0x84, 0xf3,
                0xeb, 0xb4, 0xf5, 0xec,
            ],
        }; // 1217928f624a1ef061f84a9c02f7ed2a6c7fdc92aa5fa8293b6184f3ebb4f5ec
        assert_eq!(answer, hasher.hash_with_nonce(0));
    }

    #[test]
    fn it_hashes_with_a_large_nonce() {
        let hasher = Sha256Hasher::new(b"abc");
        let answer = Sha256Hash {
            value: [
                0x99, 0x9c, 0xc8, 0x59, 0x99, 0xf1, 0x5f, 0x52, 0xeb, 0x1e, 0xe9, 0x82, 0xf3, 0x70,
                0x1b, 0x67, 0x41, 0x30, 0x4d, 0x9e, 0x2c, 0x3a, 0x80, 0xdb, 0x79, 0xa9, 0x1c, 0x62,
                0xf1, 0x8c, 0xc1, 0xe2,
            ],
        }; // 999cc85999f15f52eb1ee982f3701b6741304d9e2c3a80db79a91c62f18cc1e2
        assert_eq!(answer, hasher.hash_with_nonce(4294967295));
    }
}
