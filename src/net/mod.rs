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
}
