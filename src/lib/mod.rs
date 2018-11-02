extern crate byteorder;
extern crate crypto;
extern crate rustc_serialize as serialize;

use lib::byteorder::{LittleEndian, WriteBytesExt};
use lib::crypto::digest::Digest;
use lib::crypto::sha2::Sha256;
use lib::serialize::hex::{FromHex, ToHex};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Instant;

// BASE: string
// HASH: 32-bytes (SHA-256)
// NONCE: 8-byte/32-bit (c unsigned int -- little endian) max: 4294967295

pub type Nonce = u32;

#[derive(Debug, Clone)]
pub struct Sha256Hasher {
    base: Vec<u8>,
}

impl Sha256Hasher {
    pub fn new(base: Vec<u8>) -> Sha256Hasher {
        Sha256Hasher { base: base }
    }

    pub fn hash(&self) -> Sha256Hash {
        Sha256Hasher::hash_impl(&self.base)
    }

    fn hash_impl(base: &[u8]) -> Sha256Hash {
        let mut sha = Sha256::new();
        sha.input(base);
        let mut result = [0x00; 32];
        sha.result(&mut result);
        Sha256Hash { value: result }
    }

    pub fn hash_with_nonce(&self, nonce: Nonce) -> Sha256Hash {
        let mut cat = vec![];
        cat.extend_from_slice(&self.base);
        let x = nonce_to_bytes(nonce);
        cat.extend_from_slice(&x);
        Sha256Hasher::hash_impl(cat.as_slice())
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Sha256Hash {
    pub value: [u8; 32],
}

impl std::fmt::Display for Sha256Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.value.to_hex())
    }
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
}

pub struct HashSolution {
    pub nonce: Nonce,
    pub hash: Sha256Hash,
}

#[derive(Clone)]
struct HashWorker {
    start_nonce: Nonce,
    end_nonce: Nonce, // not inclusive
    hasher: Sha256Hasher,
    out_handle: Sender<HashResponse>,
    target: Sha256Hash,
}

impl HashWorker {
    fn solve(&self) -> () {
        let mut n = self.start_nonce;
        while n < self.end_nonce {
            let hash_result = self.hasher.hash_with_nonce(n);
            if hash_result < self.target {
                self.out_handle
                    .send(HashResponse::Success(HashSolution {
                        hash: hash_result,
                        nonce: n,
                    })).unwrap_or_else(|_| return);
                return;
            } else {
                self.out_handle
                    .send(HashResponse::Miss)
                    .unwrap_or_else(|_| return);
            }
            n += 1;
        }
        self.out_handle
            .send(HashResponse::NoSolution)
            .unwrap_or_else(|_| return);
    }
}

enum HashResponse {
    Success(HashSolution),
    Miss,       // worker attempted a hash but it wasn't successful
    NoSolution, // worker went through assigned nonce range with no solution
}

pub struct HashWorkerFarm {
    workers: Vec<HashWorker>,
    reply_handle: Receiver<HashResponse>,
}

impl HashWorkerFarm {
    pub fn new(base: Vec<u8>, target: Sha256Hash, num_workers: u8) -> HashWorkerFarm {
        let (response_sender, response_receiver) = channel();
        let mut workers = Vec::new();
        let mut nonce_marker: u32 = 0;
        let range_per_nonce = std::u32::MAX / num_workers as u32;
        for i in 0..num_workers {
            let base_clone = base.clone();
            workers.push(HashWorker {
                start_nonce: nonce_marker,
                end_nonce: match i + 1 == num_workers {
                    false => nonce_marker + range_per_nonce as u32,
                    true => std::u32::MAX,
                },
                target: target.clone(),
                hasher: Sha256Hasher::new(base_clone),
                out_handle: response_sender.clone(),
            });
            nonce_marker = nonce_marker + range_per_nonce;
        }
        HashWorkerFarm {
            workers: workers,
            reply_handle: response_receiver,
        }
    }
    pub fn solve(&self) -> Option<HashSolution> {
        let mut attempt_count: u32 = 0;
        let mut completed_workers: u8 = 0;
        let start_time = Instant::now();

        for i in 0..self.workers.len() {
            let worker = self.workers[i].clone();
            std::thread::spawn(move || {
                worker.solve();
            });
        }

        for response in self.reply_handle.iter() {
            match response {
                HashResponse::Success(solution) => {
                    return Some(solution);
                }
                HashResponse::Miss => {
                    attempt_count += 1;
                }
                HashResponse::NoSolution => {
                    completed_workers += 1;
                    if completed_workers == self.workers.len() as u8 {
                        return None;
                    }
                }
            }

            if attempt_count % 500000 == 0 {
                // print debug info
                let elapsed = start_time.elapsed();
                let hash_rate = attempt_count as f64 / elapsed.as_secs() as f64;
                let percent_total = attempt_count as f64 / std::u32::MAX as f64 * 100.0;
                println!(
                    "{:.1}% through all possibilities; hashrate: {:.2}k/s",
                    percent_total,
                    hash_rate / 1000.0
                )
            }
        }
        None
    }
}

fn nonce_to_bytes(nonce: Nonce) -> [u8; 4] {
    let mut result = [0u8; 4];
    result
        .as_mut()
        .write_u32::<LittleEndian>(nonce)
        .expect("Unable to write");
    result
}

#[cfg(test)]
mod tests {
    use lib::Sha256Hash;
    use lib::Sha256Hasher;
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
        let hasher = Sha256Hasher::new(b"abc".to_vec());
        let answer = Sha256Hash::from_hex_string(
            &"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string(),
        ).unwrap();
        assert_eq!(answer, hasher.hash());
    }

    #[test]
    fn it_hashes_empty_string() {
        let hasher = Sha256Hasher::new(b"".to_vec());
        let answer = Sha256Hash::from_hex_string(
            &"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ).unwrap();
        assert_eq!(answer, hasher.hash());
    }

    #[test]
    fn it_hashes_with_a_small_nonce() {
        let hasher = Sha256Hasher::new(b"helloworld".to_vec());
        let answer = Sha256Hash::from_hex_string(
            &"1217928f624a1ef061f84a9c02f7ed2a6c7fdc92aa5fa8293b6184f3ebb4f5ec".to_string(),
        ).unwrap();
        assert_eq!(answer, hasher.hash_with_nonce(0));
    }

    #[test]
    fn it_hashes_with_a_large_nonce() {
        let hasher = Sha256Hasher::new(b"abc".to_vec());
        let answer = Sha256Hash::from_hex_string(
            &"999cc85999f15f52eb1ee982f3701b6741304d9e2c3a80db79a91c62f18cc1e2".to_string(),
        ).unwrap();
        assert_eq!(answer, hasher.hash_with_nonce(4294967295));
    }
}
