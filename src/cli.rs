use crate::hash::{nonce_to_bytes, HashWorkerFarm, Sha256Hash, TNonce};
use crate::net::{PowLockError, PowServer};
use std::time::Instant;

pub fn solve(base_string: String, target_hash: Sha256Hash, num_workers: u8) -> () {
    let base = base_string.as_bytes().to_vec();
    let hash_farm = HashWorkerFarm::new(base, target_hash.clone(), num_workers);
    let start_time = Instant::now();
    let result = HashWorkerFarm::solve(Box::from(hash_farm));
    match result {
                Some(result) => println!(
                    "Base string: {},\nSolved with nonce: {},\nAs bytes: {},\nHash: {}\nTarget: {}\nAttempts: {}\nTime (s): {}",
                    base_string,
                    result.nonce,
                    result.nonce.as_hex_bytes(),
                    result.hash,
                    target_hash,
                    result.attempts,
                    start_time.elapsed().as_secs()
                ),
                None => println!("No solution found"),
    }
}

pub fn make_target(duration_string: String, hash_rate: u64) -> () {
    let result = Sha256Hash::target_for_duration(duration_string, hash_rate);
    println!("{}", result);
}

pub fn hashrate_test(num_workers: u8, length: u64) -> () {
    if length < 20 {
        println!("Run the hashrate test for at least 20 seconds");
        return;
    }
    let test_hash_farm = HashWorkerFarm::new_test(num_workers);
    println!("Hashrate: {} H/s", test_hash_farm.run_test(length));
}

pub fn get_status(mut server: PowServer) -> () {
    match server.get_status() {
        Ok(s) => println!("{}", s),
        Err(e) => match e {
            PowLockError::Connection => println!("Error connecting with lock"),
            _ => println!("Unknown error"),
        },
    }
}

pub fn unlock(mut server: PowServer, nonce: u64) -> () {
    println!("nonce: {}", nonce);
    nonce_to_bytes(nonce);
    match server.unlock(nonce) {
        Ok(_) => println!("Unlocked"),
        Err(e) => match e {
            PowLockError::Unsuccessful => {
                println!("Unsuccessful. Hash of base and nonce not less than target.")
            }
            _ => println!("Unknown error"),
        },
    }
}

pub fn open(mut server: PowServer) -> () {
    match server.open() {
        Ok(_) => println!("Lock opened"),
        Err(e) => match e {
            PowLockError::InvalidOperationWhenLocked => println!("Lock is locked; cannot open"),
            _ => println!("Unknown error"),
        },
    }
}

pub fn base(mut server: PowServer) -> () {
    match server.get_base() {
        Ok(b) => println!("{}", b),
        Err(e) => match e {
            PowLockError::InvalidOperationWhenUnlocked => {
                println!("Lock is unlocked; there is no base")
            }
            _ => println!("Unknown error"),
        },
    }
}

pub fn target(mut server: PowServer) -> () {
    match server.get_target() {
        Ok(b) => println!("{}", b),
        Err(e) => match e {
            PowLockError::InvalidOperationWhenUnlocked => {
                println!("Lock is unlocked; there is no target")
            }
            _ => println!("Unknown error"),
        },
    }
}

pub fn lock(mut server: PowServer, target: String) -> () {
    if target.len() != 64 {
        println!("Targets must be a 64 character hex string representing a SHA 256 hash");
    }
    match server.lock(target) {
        Ok(b) => println!("Locked. Base string is:\n{}", b),
        Err(e) => match e {
            PowLockError::InvalidOperationWhenLocked => {
                println!("Lock is already locked; cannot lock it again")
            }
            _ => println!("Unknown error"),
        },
    }
}
