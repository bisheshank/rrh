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

        info!("Version exchange successful");

        Ok(Self { state_machine })
    }
}

