use std::{
    io::{BufRead, BufReader},
    net::TcpStream,
};

use crate::{config::SshConfig, error::SshResult};

pub struct Transport {
    pub stream: TcpStream,
    pub config: SshConfig,
    is_client: bool,
}

impl Transport {
    pub fn new(stream: TcpStream, config: SshConfig, is_client: bool) -> Self {
        Transport {
            stream,
            config,
            is_client,
        }
    }

    pub fn read_line(&mut self, line: &mut String) -> SshResult<()> {
        let mut reader = BufReader::new(&self.stream);
        reader.read_line(line)?;
        Ok(())
    }

    pub fn send(&mut self) {
        // Placeholder
    }

    pub fn receive(&mut self) {
        // Placeholder
    }
}

