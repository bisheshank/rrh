use log::{debug, info};

use crate::{
    config::SshConfig,
    error::SshResult,
    state::{SshEvent, SshStateMachine},
};
use tokio::{
    net::{TcpListener, TcpStream},
    task,
};

pub struct SshServer {
    config: SshConfig,
    // Have different sessions
}

impl SshServer {
    pub fn new(config: SshConfig) -> Self {
        SshServer { config }
    }

    pub async fn listen(&self, address: &str) -> SshResult<()> {
        println!("Starting SSH server on {}", address);

        let listener = TcpListener::bind(address).await?;

        loop {
            let (stream, addr) = listener.accept().await?;
            println!("New connection from {}", addr);

            let config = self.config.clone();

            // Handle each connection in a new task
            task::spawn(async move {
                if let Err(e) = handle_connection(stream, config).await {
                    eprintln!("Error handling connection: {}", e);
                }
            });
        }
    }
}

/// Handles a client connection
async fn handle_connection(stream: TcpStream, config: SshConfig) -> SshResult<()> {
    let peer_addr = stream.peer_addr()?;
    println!("New connection from {}", peer_addr);

    let mut state_machine = SshStateMachine::new(stream, config, false).await?;

    // Start the connection process
    state_machine
        .process_event(SshEvent::ReceiveVersion)
        .await?;
    state_machine.process_event(SshEvent::SendVersion).await?;

    state_machine.process_event(SshEvent::SendKexInit).await?;
    state_machine
        .process_event(SshEvent::ReceiveKexInit)
        .await?;

    println!("[{}] Version exchange completed", peer_addr);

    // Complete the key exchange
    state_machine.process_event(SshEvent::ReceiveDhInit).await?;
    state_machine.process_event(SshEvent::SendDhReply).await?;

    //activate new keys
    state_machine.process_event(SshEvent::SendNewKeys).await?;
    state_machine.process_event(SshEvent::ReceiveNewKeys).await?;

    Ok(())
}