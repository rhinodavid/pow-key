use rustc_serialize as serialize;

use self::serialize::hex::{FromHex, ToHex};
use byteorder::{LittleEndian, WriteBytesExt};
use console::Term;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use indicatif::{ProgressBar, ProgressStyle};
use std::str::FromStr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;
use std::time::Instant;
use uint::U256;

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
    fn target_for_hash_attempts_expected(hash_attempts_expected: u64) -> Self {
        // see discussion on geometic distribution here:
        // https://en.wikipedia.org/wiki/Geometric_distribution
        let max_attempts = U256::from_str(
            &"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        )
        .unwrap();
        let target_u256 = max_attempts / U256::from(hash_attempts_expected);
        let mut result: [u8; 32] = [0; 32];
        target_u256.to_big_endian(&mut result);
        Sha256Hash { value: result }
    }

    pub fn target_for_duration(duration: String, hash_rate: u64 /* hashes/s */) -> Self {
        let d: Duration = duration.parse::<humantime::Duration>().unwrap().into();
        let expected_hashes: u64 = d.as_secs() as u64 * hash_rate;
        println!("Expected hashes: {}", expected_hashes);
        Sha256Hash::target_for_hash_attempts_expected(expected_hashes)
    }

    pub fn expected_attempts_to_solve(&self) -> u64 {
        let max_attempts = U256::from_str(
            &"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        )
        .unwrap();
        let target_u256 = U256::from(self.value);
        (max_attempts / target_u256).as_u64()
    }

    /**
     * 90% of cases will require less than this number of attempts to solve
     */
    pub fn p90_attempts_to_solve(&self) -> u64 {
        let expected = self.expected_attempts_to_solve();
        let std_dev = self.standard_deviation_for_expected_attempts();
        (expected + (1.28 * std_dev as f64) as u64)
    }

    /**
     * 99% of cases will require less than this number of attempts to solve
     */
    pub fn p99_attempts_to_solve(&self) -> u64 {
        let expected = self.expected_attempts_to_solve();
        let std_dev = self.standard_deviation_for_expected_attempts();
        (expected + (2.33 * std_dev as f64) as u64)
    }

    fn standard_deviation_for_expected_attempts(&self) -> u64 {
        let max_attempts = U256::from_str(
            &"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        )
        .unwrap();
        let target_u256 = U256::from(self.value);
        let p_inv = max_attempts / target_u256;
        let p = 1.0 / p_inv.as_u64() as f64;
        let variance = (1.0 - p) / (p * p);
        let std_dev = variance.sqrt();
        std_dev as u64
    }
}

pub struct HashSolution {
    pub nonce: Nonce,
    pub attempts: u64, // hash attempts conducted to find solution
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
                        attempts: 0,
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
    Miss,                // worker attempted a hash but it wasn't successful
    NoSolution,          // worker went through assigned nonce range with no solution
    ProgressMessageTick, // sent at a consistent interval to print a progress message
}

pub struct HashWorkerFarm {
    reply_handle: Receiver<HashResponse>,
    response_sender: Sender<HashResponse>,
    target: Sha256Hash,
    workers: Vec<HashWorker>,
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
            reply_handle: response_receiver,
            response_sender: response_sender,
            target: target,
            workers: workers,
        }
    }

    pub fn solve(&self) -> Option<HashSolution> {
        let mut attempt_count: u64 = 0;
        let mut completed_workers: u8 = 0;
        let start_time = Instant::now();

        let expected_attempts = self.target.expected_attempts_to_solve();
        let p90_attempts = self.target.p90_attempts_to_solve();
        let p99_attempts = self.target.p99_attempts_to_solve();
        let all_attempts = std::u64::MAX;

        // progress bar
        let console = Term::stdout();
        let progress_bar_style = ProgressStyle::default_bar().template(
            "{spinner:.green} {prefix} [{elapsed_precise}] [{bar:32.cyan/blue}] {percent}% ({eta})",
        );
        let mut first_run = true;

        let expected_progress_bar = ProgressBar::new(expected_attempts);
        let p90_progress_bar = ProgressBar::new(p90_attempts);
        let p99_progress_bar = ProgressBar::new(p99_attempts);
        let all_progress_bar = ProgressBar::new(all_attempts);

        let progress_bars = vec![
            expected_progress_bar,
            p90_progress_bar,
            p99_progress_bar,
            all_progress_bar,
        ];

        let prefixes = vec![
            "Average expected attempts:\t",
            "p90 expected attempts:\t",
            "p99 expected attempts:\t",
            "All possible attempts:\t",
        ];

        for i in 0..progress_bars.len() {
            progress_bars[i].set_style(progress_bar_style.clone());
            progress_bars[i].set_prefix(prefixes[i]);
            // progress_bars[i].enable_steady_tick(500);
            progress_bars[i].set_position(0);
            for _ in 0..rand::random::<u8>() {
                progress_bars[i].tick();
            }
        }

        // run workers
        for i in 0..self.workers.len() {
            let worker = self.workers[i].clone();
            std::thread::spawn(move || {
                worker.solve();
            });
        }

        // timer tick setup
        let timer_sender_handle = self.response_sender.clone();

        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(250));
            timer_sender_handle
                .send(HashResponse::ProgressMessageTick)
                .unwrap_or_else(|_| return);
        });

        // handle worker responses
        for response in self.reply_handle.iter() {
            match response {
                HashResponse::Success(solution) => {
                    return Some(HashSolution {
                        nonce: solution.nonce,
                        attempts: attempt_count,
                        hash: solution.hash,
                    });
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
                HashResponse::ProgressMessageTick => {
                    // print debug info
                    let elapsed = start_time.elapsed();
                    let hash_rate = attempt_count as f64 / elapsed.as_secs() as f64;
                    progress_bars[0].println(format!("Hash Rate: {:.1}kh/s", hash_rate / 1000.0));
                    for progress_bar in &progress_bars {
                        console.clear_line().unwrap();
                        progress_bar.set_position(attempt_count);
                        if !first_run {
                            console.move_cursor_down(1).unwrap();
                        }
                    }
                    first_run = false;
                    console.move_cursor_up(4).unwrap();
                    if attempt_count < expected_attempts {
                        // do we need to do something?
                    } else if attempt_count < p90_attempts {
                        progress_bars[0]
                            .finish_with_message("Complete with average expected attempts");
                    } else if attempt_count < p99_attempts {
                        progress_bars[1].finish_with_message("Complete with p90 expected attempts");
                    } else {
                        progress_bars[2].finish_with_message("Complete with p99 expected attempts");
                    }
                }
            }
        }
        None
    }

    // builds a farm used to test the hashrate of the machine
    pub fn new_test(num_workers: u8) -> HashWorkerFarm {
        let (response_sender, response_receiver) = channel();
        let base = b"anarbitrarystring".to_vec();
        let target = Sha256Hash::from_str(
            &"0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        )
        .unwrap(); // impossible to solve
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
            reply_handle: response_receiver,
            response_sender: response_sender,
            target: target,
            workers: workers,
        }
    }

    // runs the test worker farm and returns the hashrate in H/s
    pub fn run_test(&self, test_length_s: u64) -> u32 {
        let mut attempt_count: u64 = 0;
        let start_time = Instant::now();

        for i in 0..self.workers.len() {
            let worker = self.workers[i].clone();
            std::thread::spawn(move || {
                worker.solve();
            });
        }

        for response in self.reply_handle.iter() {
            match response {
                HashResponse::Success(_) => {
                    // this is impossible with a properly formed test worker farm
                    unreachable!("A worker found a solution in a test farm")
                }
                HashResponse::Miss => {
                    attempt_count += 1;
                }
                HashResponse::NoSolution => {
                    // this shouldn't happen in the time frame allowed;
                    // we don't want workers to exaust their nonce range
                    unreachable!("A worker completed work in a test farm")
                }
                HashResponse::ProgressMessageTick => (), // TODO: add some output while test is running
            }

            if attempt_count % 10000 == 0 {
                let elapsed = start_time.elapsed();
                if elapsed.as_secs() > test_length_s {
                    let hash_rate = attempt_count as f64 / elapsed.as_secs() as f64;
                    return hash_rate as u32;
                }
            }
        }
        unreachable!();
    }
}

pub fn nonce_to_bytes(nonce: Nonce) -> [u8; 8] {
    let mut result = [0u8; 8];
    result
        .as_mut()
        .write_u64::<LittleEndian>(nonce)
        .expect("Unable to write");
    result
}

#[cfg(test)]
mod tests {
    use super::{Sha256Hash, Sha256Hasher};
    use std::str::FromStr;
    #[test]
    fn it_creates_sha_hashes_from_hex() {
        let hash = Sha256Hash::from_str(
            &"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string(),
        )
        .unwrap();
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
    fn it_hashes_abc() {
        let hasher = Sha256Hasher::new(b"abc".to_vec());
        let answer = Sha256Hash::from_str(
            &"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string(),
        )
        .unwrap();
        assert_eq!(answer, Sha256Hasher::hash_impl(&hasher.base));
    }

    #[test]
    fn it_hashes_empty_string() {
        let hasher = Sha256Hasher::new(b"".to_vec());
        let answer = Sha256Hash::from_str(
            &"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        )
        .unwrap();
        assert_eq!(answer, Sha256Hasher::hash_impl(&hasher.base));
    }

    #[test]
    fn it_hashes_with_a_small_nonce() {
        let hasher = Sha256Hasher::new(b"helloworld".to_vec());
        let answer = Sha256Hash::from_str(
            &"c81ee5e927e9d7987e1ad7c92eb63ecb78d9a7a5949de5462f5f1d79d6b5d0d1".to_string(),
        )
        .unwrap();
        assert_eq!(answer, hasher.hash_with_nonce(0));
    }

    #[test]
    fn it_hashes_with_a_large_nonce() {
        let hasher = Sha256Hasher::new(b"abc".to_vec());
        let answer = Sha256Hash::from_str(
            &"bd2154c71c7a42c66269709fc3508b587bbd61cce9c977fe0c9d313e7a47fb55".to_string(),
        )
        .unwrap();
        assert_eq!(answer, hasher.hash_with_nonce(4294967295));
    }

    #[test]
    fn it_computes_hash_targets_for_expected_attempts() {
        let answer = Sha256Hash::from_str(
            &"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        )
        .unwrap();
        assert_eq!(answer, Sha256Hash::target_for_hash_attempts_expected(1));

        assert!(
            Sha256Hash::target_for_hash_attempts_expected(1)
                > Sha256Hash::target_for_hash_attempts_expected(2)
        );

        assert!(
            Sha256Hash::target_for_hash_attempts_expected(10)
                > Sha256Hash::target_for_hash_attempts_expected(100)
        );
    }

    #[test]
    fn it_computes_hash_targets_for_expected_duration() {
        assert_eq!(
            Sha256Hash::target_for_hash_attempts_expected(100),
            Sha256Hash::target_for_duration("10s".to_string(), 10) // 10 h/s for 10s = 100 hashes
        );
    }

    #[test]
    fn it_computes_expected_hash_attempts_for_target_max() {
        let target = Sha256Hash::from_str(
            &"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        )
        .unwrap();
        assert_eq!(target.expected_attempts_to_solve(), 1);
    }

    #[test]
    fn it_computes_expected_hash_attempts_for_target() {
        let target = Sha256Hash::from_str(
            &"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        )
        .unwrap();
        assert_eq!(target.expected_attempts_to_solve(), 4_294_967_296);
    }
}
