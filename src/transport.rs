use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, split},
    net::TcpStream,
};

use crate::{config::SshConfig, error::SshResult};

pub struct Transport {
    reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: tokio::io::WriteHalf<TcpStream>,
    pub config: SshConfig,
    is_client: bool,
}

impl Transport {
    pub async fn new(stream: TcpStream, config: SshConfig, is_client: bool) -> SshResult<Self> {
        // Split the TcpStream into a ReadHalf and WriteHalf
        let (reader, writer) = split(stream);

        // Create a BufReader for the reader half
        let reader = BufReader::new(reader);

        Ok(Transport {
            reader,
            writer,
            config,
            is_client,
        })
    }

    pub async fn read_line(&mut self, line: &mut String) -> SshResult<()> {
        self.reader.read_line(line).await?;
        Ok(())
    }

    pub async fn write_all(&mut self, buf: &[u8]) -> SshResult<()> {
        self.writer.write_all(buf).await?;
        self.writer.flush().await?;
        Ok(())
    }

    pub fn is_client(&self) -> bool {
        self.is_client
    }
}

