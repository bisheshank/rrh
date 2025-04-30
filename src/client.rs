use log::{debug, info};

use crate::{
    constants::PROTOCOL_VERSION,
    error::{Result, SSHError},
};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

pub struct Client {
    stream: TcpStream,
    server_version: String,
}

impl Client {
    pub fn connect(addr: &str) -> Result<Self> {
        info!("Connecting to {}", addr);

        let stream = TcpStream::connect(addr)?;

        let mut client = Client {
            stream,
            server_version: String::new(),
        };

        client.exchange_versions()?;

        return Ok(client);
    }

    fn exchange_versions(&mut self) -> Result<()> {
        debug!("Exchanging versions");

        let version_string = format!("{}\r\n", PROTOCOL_VERSION);
        self.stream.write_all(version_string.as_bytes())?;

        debug!("Sent version string");

        let mut reader = BufReader::new(&self.stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;

        debug!("Received version string");

        self.server_version = line.trim_end().to_string();

        if !self.server_version.starts_with("SSH-2.0") {
            return Err(SSHError::Protocol(format!(
                "Incompatible SSH version: {}",
                self.server_version
            )));
        }

        info!("Server version: {}", self.server_version);

        return Ok(());
    }
}
