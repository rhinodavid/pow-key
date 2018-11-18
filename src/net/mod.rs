extern crate rustc_serialize as serialize;

use self::serialize::hex::FromHex;
use std::io::prelude::*;
use std::io::{BufRead, BufReader};
use std::net::TcpStream;

pub enum PowLockError {
    InvalidOperationWhenLocked,
    InvalidOperationWhenUnlocked,
    Connection,
    Unknown,
}

pub struct PowServer {
    stream: TcpStream,
}

impl PowServer {
    pub fn new(addr: String, port: String) -> Self {
        let stream =
            TcpStream::connect(format!("{}:{}", addr, port)).expect("Failed to connect to server");
        PowServer { stream: stream }
    }

    pub fn open(&mut self) -> Result<(), PowLockError> {
        let _ = try!(
            self.stream
                .write(b"O\n")
                .map_err(|_| PowLockError::Connection)
        );
        let mut reader = BufReader::new(&self.stream);
        let mut response = String::new();
        try!(
            reader
                .read_line(&mut response)
                .map_err(|_| PowLockError::Unknown)
        );
        if response.starts_with("ERROR") {
            return Err(PowLockError::InvalidOperationWhenLocked);
        }
        if response.starts_with("1") {
            return Ok(());
        }
        Err(PowLockError::Unknown)
    }

    pub fn get_status(&mut self) -> Result<String, PowLockError> {
        let _ = try!(
            self.stream
                .write(b"s\n")
                .map_err(|_| PowLockError::Connection)
        );
        let mut reader = BufReader::new(&self.stream);
        let mut response = String::new();
        try!(
            reader
                .read_line(&mut response)
                .map_err(|_| PowLockError::Unknown)
        );
        if response.starts_with("1") {
            return Ok("Locked".to_string());
        }
        if response.starts_with("0") {
            return Ok("Unlocked".to_string());
        }
        Err(PowLockError::Unknown)
    }

    pub fn get_base(&mut self) -> Result<String, PowLockError> {
        let _ = try!(
            self.stream
                .write(b"b\n")
                .map_err(|_| PowLockError::Connection)
        );
        let mut reader = BufReader::new(&self.stream);
        let mut response = String::new();
        try!(
            reader
                .read_line(&mut response)
                .map_err(|_| PowLockError::Unknown)
        );
        if response.starts_with("ERROR") {
            return Err(PowLockError::InvalidOperationWhenUnlocked);
        }
        Ok(response)
    }

    pub fn get_target(&mut self) -> Result<String, PowLockError> {
        let _ = try!(
            self.stream
                .write(b"t\n")
                .map_err(|_| PowLockError::Connection)
        );
        let mut reader = BufReader::new(&self.stream);
        let mut response = String::new();
        try!(
            reader
                .read_line(&mut response)
                .map_err(|_| PowLockError::Unknown)
        );
        if response.starts_with("ERROR") {
            return Err(PowLockError::InvalidOperationWhenUnlocked);
        }
        Ok(response)
    }

    // locks a lock given a target hash
    // returns the base string the lock generated
    pub fn lock(&mut self, target: String) -> Result<String, PowLockError> {
        if target.len() != 64 {
            println!("Expected 64 chars for target representing a SHA256 hash in hex");
            return Err(PowLockError::Unknown);
        }

        let mut hash: [u8; 32] = [0; 32];
        match target.from_hex() {
            Ok(r) => {
                for (i, &v) in r.iter().enumerate() {
                    hash[i] = v;
                }
            }
            Err(e) => {
                println!("Serialization failed for target: {}", target);
                return Err(PowLockError::Unknown);
            }
        }

        let mut message = vec![];

        message.extend(b"l");
        message.extend(hash.iter());
        message.extend(b"\n");

        let _ = try!(
            self.stream
                .write(&message)
                .map_err(|_| PowLockError::Connection)
        );

        let mut reader = BufReader::new(&self.stream);
        let mut response = String::new();

        try!(
            reader
                .read_line(&mut response)
                .map_err(|_| PowLockError::Unknown)
        );

        if response.starts_with("ERROR") {
            return Err(PowLockError::InvalidOperationWhenLocked);
        }
        Ok(response)
    }
}
