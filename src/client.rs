use log::info;

use crate::{
    config::SshConfig,
    error::SshResult,
    state::{SshEvent, SshState, SshStateMachine},
};
use std::net::TcpStream;

pub struct SshClient {
    state_machine: SshStateMachine,
}

impl SshClient {
    pub fn connect(address: &str, config: SshConfig) -> SshResult<Self> {
        println!("Connecting to {}", address);

        let stream = TcpStream::connect(address)?;

        let mut state_machine = SshStateMachine::new(stream, config, true);

        // 1. Version exchange
        // 2. Key exchange (KEXINIT, DH exchange, NEWKEYS)
        state_machine.process_event(SshEvent::SendVersion)?;
        state_machine.process_event(SshEvent::SendKexInit)?;

        // Expect to receive KEXINIT from server
        if state_machine.state() != SshState::KexInitReceived {
            state_machine.process_event(SshEvent::ReceiveKexInit)?;
        }

        info!("Version exchange successful");

        Ok(Self { state_machine })
    }
}
