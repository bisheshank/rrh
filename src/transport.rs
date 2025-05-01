use std::{
    io::{BufRead, BufReader, Write},
    net::TcpStream,
};

use crate::{config::SshConfig, error::SshResult};

pub struct Transport {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
    pub config: SshConfig,
    is_client: bool,
}

impl Transport {
    pub fn new(stream: TcpStream, config: SshConfig, is_client: bool) -> SshResult<Self> {
        let reader = BufReader::new(stream.try_clone()?); // Clone for buffered reading

        Ok(Transport {
            stream,
            reader,
            config,
            is_client,
        })
    }

    pub fn read_line(&mut self, line: &mut String) -> SshResult<()> {
        self.reader.read_line(line)?;
        Ok(())
    }

    pub fn write_all(&mut self, buf: &[u8]) -> SshResult<()> {
        let inner = self.reader.get_mut();
        inner.write_all(buf)?;
        inner.flush()?;
        Ok(())
    }
    pub fn is_client(&self) -> bool {
        self.is_client
    }
}

