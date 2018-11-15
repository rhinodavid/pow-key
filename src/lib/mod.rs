extern crate byteorder;
extern crate crypto;
extern crate rustc_serialize as serialize;
extern crate uint;

use lib::uint::U256;
use lib::byteorder::{LittleEndian, WriteBytesExt};
use lib::crypto::digest::Digest;
use lib::crypto::sha2::Sha256;
use lib::serialize::hex::{FromHex, ToHex};
use std::str::FromStr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Instant;

// BASE: string
// HASH: 32-bytes (SHA-256)
// NONCE: 8-byte

pub type Nonce = u64;

pub trait TNonce {
    fn as_hex_bytes(&self) -> String;
}
impl TNonce for u64 {
    fn as_hex_bytes(&self) -> String {
        nonce_to_bytes(*self).to_hex()
    }
}

#[derive(Debug, Clone)]
pub struct Sha256Hasher {
    base: Vec<u8>,
}

impl Sha256Hasher {
    pub fn new(base: Vec<u8>) -> Sha256Hasher {
        Sha256Hasher { base: base }
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

impl FromStr for Sha256Hash {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
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

impl Sha256Hash {
    fn target_for_difficulty(difficulty: u64) -> Self {
        let difficulty_1_target = U256::from_str(
            &"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        ).unwrap();
        let target_u256 = difficulty_1_target / U256::from(difficulty);
        let mut result: [u8; 32] = [0; 32];
        target_u256.to_big_endian(&mut result);
        Sha256Hash { value: result }
    }

    fn get_difficulty(&self) -> u64 {
        let difficulty_1_target = U256::from_str(
            &"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        ).unwrap();

        let self_as_bigint = U256::from(self.value);

        let difficulty = difficulty_1_target / self_as_bigint;

        difficulty.as_u64()
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
                    }))
                    .unwrap_or_else(|_| return);
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
        let mut nonce_marker: u64 = 0;
        let range_per_nonce = std::u64::MAX / num_workers as u64;
        for i in 0..num_workers {
            let base_clone = base.clone();
            workers.push(HashWorker {
                start_nonce: nonce_marker,
                end_nonce: match i + 1 == num_workers {
                    false => nonce_marker + range_per_nonce as u64,
                    true => std::u64::MAX,
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
        let mut attempt_count: u64 = 0;
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
                let percent_total = attempt_count as f64 / std::u64::MAX as f64 * 100.0;
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

fn nonce_to_bytes(nonce: Nonce) -> [u8; 8] {
    let mut result = [0u8; 8];
    result
        .as_mut()
        .write_u64::<LittleEndian>(nonce)
        .expect("Unable to write");
    result
}

fn expected_hashes_for_difficulty(difficulty: u64) -> u128 {
    difficulty as u128 * 2_u128.pow(32)
}

fn difficulty_for_expected_hashes(expected_hashes: u128) -> u64 {
    (expected_hashes / 2_u128.pow(32)) as u64
}

#[cfg(test)]
mod tests {
    use lib::difficulty_for_expected_hashes;
    use lib::expected_hashes_for_difficulty;
    use lib::Sha256Hash;
    use lib::Sha256Hasher;
    use std::str::FromStr;
    #[test]
    fn it_creates_sha_hashes_from_hex() {
        let hash = Sha256Hash::from_str(
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
        assert!(Sha256Hash::from_str(&"aa00bb".to_string()).is_err());
    }

    #[test]
    fn it_creates_hash_for_difficulty() {
        let difficulty_1_target = Sha256Hash::from_str(
            &"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        ).unwrap();
        assert_eq!(difficulty_1_target, Sha256Hash::target_for_difficulty(1));
    }

    #[test]
    fn it_hashes_abc() {
        let hasher = Sha256Hasher::new(b"abc".to_vec());
        let answer = Sha256Hash::from_str(
            &"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string(),
        ).unwrap();
        assert_eq!(answer, Sha256Hasher::hash_impl(&hasher.base));
    }

    #[test]
    fn it_hashes_empty_string() {
        let hasher = Sha256Hasher::new(b"".to_vec());
        let answer = Sha256Hash::from_str(
            &"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ).unwrap();
        assert_eq!(answer, Sha256Hasher::hash_impl(&hasher.base));
    }

    #[test]
    fn it_hashes_with_a_small_nonce() {
        let hasher = Sha256Hasher::new(b"helloworld".to_vec());
        let answer = Sha256Hash::from_str(
            &"c81ee5e927e9d7987e1ad7c92eb63ecb78d9a7a5949de5462f5f1d79d6b5d0d1".to_string(),
        ).unwrap();
        assert_eq!(answer, hasher.hash_with_nonce(0));
    }

    #[test]
    fn it_hashes_with_a_large_nonce() {
        let hasher = Sha256Hasher::new(b"abc".to_vec());
        let answer = Sha256Hash::from_str(
            &"bd2154c71c7a42c66269709fc3508b587bbd61cce9c977fe0c9d313e7a47fb55".to_string(),
        ).unwrap();
        assert_eq!(answer, hasher.hash_with_nonce(4294967295));
    }

    #[test]
    fn it_computes_its_difficulty() {
        // see https://en.bitcoin.it/wiki/Difficulty
        let target = Sha256Hash::from_str(
            &"00000000000404cb000000000000000000000000000000000000000000000000".to_string(),
        ).unwrap();
        assert_eq!(16307, target.get_difficulty());
    }

    #[test]
    fn it_computes_expected_hashes_for_difficulty() {
        let difficulty = 10;
        assert_eq!(42_949_672_960, expected_hashes_for_difficulty(difficulty));
    }

    #[test]
    fn it_computes_difficulty_for_expected_hashes() {
        // see https://en.bitcoin.it/wiki/Difficulty
        let expected_hashes: u128 = (23.85 * ((10_u128.pow(9) * 60 * 60) as f64)) as u128;
        let difficulty = 20000;
        // approximating
        let approximate_error = (difficulty_for_expected_hashes(expected_hashes) as i64
            - difficulty as i64) as f64 / difficulty as f64;
        assert!(approximate_error.abs() < 0.1);
    }
}
