use log::info;

use crate::{
    config::SshConfig,
    error::SshResult,
    state::{SshEvent, SshState, SshStateMachine},
};
use tokio::net::TcpStream;

pub struct SshClient {
    state_machine: SshStateMachine,
}

impl SshClient {
    pub async fn connect(address: &str, config: SshConfig) -> SshResult<Self> {
        println!("Connecting to {}", address);

        let stream = TcpStream::connect(address).await?;

        let mut state_machine = SshStateMachine::new(stream, config, true).await?;

        // 1. Version exchange
        // 2. Key exchange (KEXINIT, DH exchange, NEWKEYS)
        state_machine.process_event(SshEvent::SendVersion).await?;
        state_machine.process_event(SshEvent::SendKexInit).await?;

        // Expect to receive KEXINIT from server
        if state_machine.state() != SshState::KexInitReceived {
            state_machine
                .process_event(SshEvent::ReceiveKexInit)
                .await?;
        }

        // Complete DH key exchange
        state_machine.process_event(SshEvent::SendDhInit).await?;
        state_machine
            .process_event(SshEvent::ReceiveDhReply)
            .await?;

        info!("Version exchange successful");

        //activate new keys
        state_machine.process_event(SshEvent::SendNewKeys).await?;
        state_machine.process_event(SshEvent::ReceiveNewKeys).await?;

        state_machine.process_event(SshEvent::RequestAuth).await?;
        state_machine.process_event(SshEvent::SendAuthMethod).await?;

        println!("Successfully connected to {}", address);
        //maybe can send an open channel message here which just essentially begins a repl
        //client sends encrypted messages with the command they want to execute to server
        //server decrypts the message, parses command string, executes it, sends encrypted message with
        //result back to client
        //display result in repl
        state_machine.process_event(SshEvent::OpenChannel).await?;
        state_machine.process_event(SshEvent::StartSession).await?;

        Ok(Self { state_machine })
    }
}

//need to clean up states and then just start the terminal and then done