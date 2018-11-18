use std::io::prelude::*;
use std::net::TcpStream;
use std::str;

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
        let mut buffer = vec![0; 33];
        let _ = try!(
            self.stream
                .write(b"O\n")
                .map_err(|_| PowLockError::Connection)
        );
        let _ = try!(
            self.stream
                .read(&mut buffer)
                .map_err(|_| PowLockError::Connection)
        );
        if buffer[0] == b"E"[0] {
            return Err(PowLockError::InvalidOperationWhenLocked);
        }
        if buffer[0] == b"1"[0] {
            return Ok(());
        }
        Err(PowLockError::Unknown)
    }

    pub fn get_base(&mut self) -> Result<String, PowLockError> {
        let mut buffer = vec![0; 33];
        let _ = try!(
            self.stream
                .write(b"b\n")
                .map_err(|_| PowLockError::Connection)
        );
        let _ = try!(
            self.stream
                .read(&mut buffer)
                .map_err(|_| PowLockError::Connection)
        );
        if buffer[0..4] == b"ERROR"[0..4] {
            return Err(PowLockError::InvalidOperationWhenUnlocked);
        }
        let result = str::from_utf8(&buffer).unwrap();
        Ok(result.to_string())
    }
}
