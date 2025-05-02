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