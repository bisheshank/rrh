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

        println!("Successfully connected to {}", address);

        Ok(Self { state_machine })
    }

    fn kexinit_exchange(&mut self) -> Result<()> {
        //want server to send kexinit message
        debug!("Sending KEXINIT message");
    
        let kexinit_string = format!("{}\r\n", KEXINIT);
        self.writer.write_all(kexinit_string.as_bytes())?;
        self.writer.flush()?;
    
        debug!("Sent KEXINIT message");
    
        let mut line = String::new();
        self.reader.read_line(&mut line)?;
    
        debug!("Received KEXINIT message");
    
        let server_kexinit = line.trim_end().to_string();
    
        if !server_kexinit.starts_with("20") {
            return Err(SSHError::Protocol(format!(
                "Did not receive KEXINIT message: {}",
                server_kexinit
            )));
        }
    
        info!("KEXINIT: {}", server_kexinit);
        Ok(())
    }
}
