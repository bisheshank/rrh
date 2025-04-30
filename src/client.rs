use crate::error::Result;
use std::net::TcpStream;

pub struct Client {
    stream: TcpStream,
    server_version: String,
}

impl Client {
    pub fn connect(addr: &str) -> Result<Self> {
        println!("Connecting to {}", addr);

        let stream = TcpStream::connect(addr)?;

        let mut client = Client {
            stream,
            server_version: String::new(),
        };

        client.exchange_versions()?;

        return Ok(client);
    }

    fn exchange_versions(&mut self) -> Result<()> {
        return Ok(());
    }
}
