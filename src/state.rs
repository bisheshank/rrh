use log::debug;

use core::fmt;
use std::io::Write;
use tokio::net::TcpStream;

use crate::{
    config::SshConfig,
    error::{SshError, SshResult},
    transport::Transport,
};

#[derive(PartialEq, Clone, Copy)]
pub enum SshState {
    // Transport states
    Initial,
    VersionExchanged,
    KexInitSent,
    KexInitReceived,

    // Authentication states

    // Connection states
    ChannelOpening,
    ChannelOpen,
    SessionStarted,

    // Error states
    Error,
    Disconnecting,
    Closed,
}

impl fmt::Display for SshState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshState::Initial => write!(f, "Initial"),
            SshState::VersionExchanged => write!(f, "VersionExchanged"),
            SshState::KexInitSent => write!(f, "KexInitSent"),
            SshState::KexInitReceived => write!(f, "KexInitReceived"),
            SshState::ChannelOpening => write!(f, "ChannelOpening"),
            SshState::ChannelOpen => write!(f, "ChannelOpen"),
            SshState::SessionStarted => write!(f, "SessionStarted"),
            SshState::Error => write!(f, "Error"),
            SshState::Disconnecting => write!(f, "Disconnecting"),
            SshState::Closed => write!(f, "Closed"),
        }
    }
}

pub enum SshEvent {
    // Transport events
    SendVersion,
    ReceiveVersion,
    SendKexInit,
    ReceiveKexInit,

    // Authentication events

    // Channel events
    OpenChannel,

    // Error events
    Error(String),
    Disconnect,
}

impl fmt::Display for SshEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SshEvent::SendVersion => write!(f, "SendVersion"),
            SshEvent::ReceiveVersion => write!(f, "ReceiveVersion"),
            SshEvent::SendKexInit => write!(f, "SendKexInit"),
            SshEvent::ReceiveKexInit => write!(f, "ReceiveKexInit"),
            SshEvent::OpenChannel => write!(f, "OpenChannel"),
            SshEvent::Error(msg) => write!(f, "Error({})", msg),
            SshEvent::Disconnect => write!(f, "Disconnect"),
        }
    }
}

pub struct SshStateMachine {
    state: SshState,
    transport: Transport,
    is_client: bool,
}

impl SshStateMachine {
    pub async fn new(stream: TcpStream, config: SshConfig, is_client: bool) -> SshResult<Self> {
        let transport = Transport::new(stream, config, is_client).await?;

        Ok(SshStateMachine {
            state: SshState::Initial,
            transport,
            is_client,
        })
    }

    pub fn state(&self) -> SshState {
        self.state
    }

    pub async fn process_event(&mut self, event: SshEvent) -> SshResult<()> {
        println!("Processing event {} in state {}", event, self.state);

        // Handle state transitions
        match (self.state, &event) {
            // Initial state transitions
            (SshState::Initial, SshEvent::SendVersion) => {
                self.send_version().await?;
                self.state = SshState::VersionExchanged;
            }
            (SshState::Initial, SshEvent::ReceiveVersion) => {
                self.receive_version().await?;
                self.state = SshState::VersionExchanged;
            }

            // Version exchanged transitions
            (SshState::VersionExchanged, SshEvent::SendVersion) => {
                self.send_version().await?;
                // No state change as we're already in VersionExchanged
            }
            (SshState::VersionExchanged, SshEvent::SendKexInit) => {
                self.send_kexinit().await?;
                self.state = SshState::KexInitSent;
            }
            (SshState::VersionExchanged, SshEvent::ReceiveKexInit) => {
                self.receive_kexinit().await?;
                self.state = SshState::KexInitReceived;
            }

            (SshState::KexInitSent, SshEvent::ReceiveKexInit) => {
                self.receive_kexinit().await?;
                self.state = SshState::KexInitReceived;
            }

            // Error and disconnect transitions
            (_, SshEvent::Error(_)) => {
                self.state = SshState::Error;
            }
            (_, SshEvent::Disconnect) => {
                self.disconnect().await?;
                self.state = SshState::Closed;
            }

            // Invalid transitions
            _ => {
                return Err(SshError::InvalidTransition(
                    format!("{}", self.state),
                    format!("{}", event),
                ));
            }
        }

        Ok(())
    }

    pub async fn process_next(&mut self) -> SshResult<()> {
        match self.state {
            SshState::Initial => {
                if self.is_client {
                    self.process_event(SshEvent::SendVersion).await?;
                } else {
                    self.process_event(SshEvent::ReceiveVersion).await?;
                }
            }
            SshState::VersionExchanged => {
                if self.is_client {
                    self.process_event(SshEvent::SendKexInit).await?;
                } else {
                    self.process_event(SshEvent::ReceiveKexInit).await?;
                }
            }
            _ => {
                return Err(SshError::NotImplemented(format!(
                    "Auto-processing for state {} not implemented",
                    self.state
                )));
            }
        }

        Ok(())
    }

    async fn send_version(&mut self) -> SshResult<()> {
        let version = match self.is_client {
            true => self.transport.config.client_version.as_deref(),
            false => self.transport.config.server_version.as_deref(),
        }
        .ok_or(SshError::MissingVersion)?;

        println!("Sending version: {}", version);

        // Make sure to use \r\n as per RFC 4253
        let version_string = format!("{}\r\n", version);
        self.transport.write_all(version_string.as_bytes()).await?;

        // If we're the client, we need to receive the server's version
        if self.is_client && self.transport.config.remote_version.is_none() {
            self.receive_version().await?;
        }

        Ok(())
    }

    async fn receive_version(&mut self) -> SshResult<()> {
        // NOTE: only accept 255 byte strings

        let mut remote_version = String::new();
        self.transport.read_line(&mut remote_version).await?;

        // Trim any whitespace, especially trailing \r\n
        let remote_version = remote_version.trim();

        if remote_version.is_empty() {
            return Err(SshError::Protocol(
                "Received empty version string".to_string(),
            ));
        }

        if !remote_version.starts_with("SSH-2.0") {
            return Err(SshError::Protocol(format!(
                "Remote version string doesn't start with SSH-2.0: {}",
                remote_version
            )));
        }

        println!("Received version: {}", remote_version);

        self.transport.config.remote_version = Some(remote_version.to_string());

        if self.is_client {
            self.transport.config.server_version = Some(remote_version.to_string());
        } else {
            self.transport.config.client_version = Some(remote_version.to_string());
        }

        Ok(())
    }

    async fn send_kexinit(&mut self) -> SshResult<()> {
        println!("Sending KEXINIT");

        // TODO: Implement

        Ok(())
    }

    async fn receive_kexinit(&mut self) -> SshResult<()> {
        println!("Receiving KEXINIT");

        // TODO: Implement

        Ok(())
    }

    async fn disconnect(&mut self) -> SshResult<()> {
        println!("Disconnecting");

        // TODO: Send disconnect message

        Ok(())
    }
}
