use log::{debug, info};

use crate::{
    constants::PROTOCOL_VERSION,
    error::{Result, SSHError},
};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::TcpStream;

pub struct Client {
    reader: BufReader<TcpStream>,
    writer: BufWriter<TcpStream>,
    server_version: String,
}

impl Client {
    pub fn connect(addr: &str) -> Result<Self> {
        info!("Connecting to {}", addr);

        let stream = TcpStream::connect(addr)?;
        let reader = BufReader::new(stream.try_clone()?);
        let writer = BufWriter::new(stream);

        let mut client = Client {
            reader,
            writer,
            server_version: String::new(),
        };

        client.exchange_versions()?;

        return Ok(client);
    }

    fn exchange_versions(&mut self) -> Result<()> {
        debug!("Exchanging versions");

        let version_string = format!("{}\r\n", PROTOCOL_VERSION);
        self.writer.write_all(version_string.as_bytes())?;
        self.writer.flush()?;

        debug!("Sent version string");

        let mut line = String::new();
        self.reader.read_line(&mut line)?;

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
