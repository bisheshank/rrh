use log::{debug, info};

use crate::{
    constants::PROTOCOL_VERSION,
    error::{Result, SSHError},
    constants::msg::KEXINIT
};
use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    thread,
};

pub struct Server {
    listener: TcpListener,
}

impl Server {
    pub fn listen(addr: &str) -> Result<Self> {
        info!("Listening on {}", addr);

        let listener = TcpListener::bind(addr)?;

        let server = Server { listener };

        return Ok(server);
    }

    pub fn run(&self) -> Result<()> {
        info!("Server running, waiting for connections...");

        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    let peer_addr = stream.peer_addr()?;
                    info!("New connection from {}", peer_addr);

                    // Handle each one in a new thread
                    thread::spawn(move || {
                        if let Err(e) = handle_client(stream) {
                            eprintln!("Error handling client {}: {}", peer_addr, e)
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Connection failed: {}", e);
                }
            }
        }

        Ok(())
    }
}

fn handle_client(mut stream: TcpStream) -> Result<()> {
    // Exchange protocol versions
    exchange_versions(&mut stream)?;

    //exchange KEXINIT messages
    kexinit_exchange(&mut stream)?;

    //need to start dh process

    Ok(())
}

fn exchange_versions(stream: &mut TcpStream) -> Result<()> {
    debug!("Exchanging versions");

    let version_string = format!("{}\r\n", PROTOCOL_VERSION);
    stream.write_all(version_string.as_bytes())?;
    stream.flush()?;

    debug!("Sent version string");

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    debug!("Received version string");

    let client_version = line.trim_end().to_string();

    if !client_version.starts_with("SSH-2.0") {
        return Err(SSHError::Protocol(format!(
            "Incompatible SSH version: {}",
            client_version
        )));
    }

    info!("Client version: {}", client_version);

    Ok(())
}

fn kexinit_exchange(stream: &mut TcpStream) -> Result<()> {
    //want server to send kexinit message
    debug!("Sending KEXINIT message");

    let kexinit_string = format!("{}\r\n", KEXINIT);
    stream.write_all(kexinit_string.as_bytes())?;
    stream.flush()?;

    debug!("Sent KEXINIT message");

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    debug!("Received KEXINIT message");

    let client_kexinit = line.trim_end().to_string();

    if !client_kexinit.starts_with("20") {
        return Err(SSHError::Protocol(format!(
            "Did not receive KEXINIT message: {}",
            client_kexinit
        )));
    }

    info!("KEXINIT: {}", client_kexinit);
    Ok(())
}