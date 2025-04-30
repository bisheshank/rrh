use crate::error::Result;
use std::{
    net::{TcpListener, TcpStream},
    thread,
};

pub struct Server {
    listener: TcpListener,
}

impl Server {
    pub fn listen(addr: &str) -> Result<Self> {
        println!("Listening on {}", addr);

        let listener = TcpListener::bind(addr)?;

        let server = Server { listener };

        return Ok(server);
    }

    pub fn run(&self) -> Result<()> {
        println!("Server running, waiting for connections...");

        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    let peer_addr = stream.peer_addr()?;
                    println!("New connection from {}", peer_addr);

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

    // TODO: Continue with key exchange, etc.

    Ok(())
}

fn exchange_versions(stream: &mut TcpStream) -> Result<()> {
    Ok(())
}
