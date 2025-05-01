use log::{debug, info};

use crate::{
    config::SshConfig,
    error::SshResult,
    state::{SshEvent, SshStateMachine},
};
use std::{
    net::{TcpListener, TcpStream},
    thread,
};

pub struct SshServer {
    config: SshConfig,
    // Have different sessions
}

impl SshServer {
    pub fn new(config: SshConfig) -> Self {
        SshServer { config }
    }
    pub fn listen(&self, address: &str) -> SshResult<()> {
        println!("Starting SSH server on {}", address);

        let listener = TcpListener::bind(address)?;

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let config = self.config.clone();

                    // Handle each connection in a new thread
                    thread::spawn(move || {
                        if let Err(e) = handle_connection(stream, config) {
                            eprintln!("Error handling connection: {}", e);
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

/// Handles a client connection
fn handle_connection(stream: TcpStream, config: SshConfig) -> SshResult<()> {
    let peer_addr = stream.peer_addr()?;
    println!("New connection from {}", peer_addr);

    let mut state_machine = SshStateMachine::new(stream, config, false)?;

    // Start the connection process
    state_machine.process_event(SshEvent::ReceiveVersion)?;

    state_machine.process_event(SshEvent::SendKexInit)?;
    state_machine.process_event(SshEvent::ReceiveKexInit)?;

    println!("[{}] Version exchange completed", peer_addr);

    // Complete the key exchange

    Ok(())
}
