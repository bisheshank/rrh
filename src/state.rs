use log::{debug, info};

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

    // Diffie-Hellman states
    DhInitSent,      // Client only
    DhReplyReceived, // Client only
    DhInitReceived,  // Server only
    DhReplySent,     // Server only

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
            SshState::DhInitSent => write!(f, "DhInitSent"),
            SshState::DhReplyReceived => write!(f, "DhReplyReceived"),
            SshState::DhInitReceived => write!(f, "DhInitReceived"),
            SshState::DhReplySent => write!(f, "DhReplySent"),
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

    // Diffie-Hellman events
    SendDhInit,     // Client only
    ReceiveDhReply, // Client only
    ReceiveDhInit,  // Server only
    SendDhReply,    // Server only

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
            SshEvent::SendDhInit => write!(f, "SendDhInit"),
            SshEvent::ReceiveDhReply => write!(f, "ReceiveDhReply"),
            SshEvent::ReceiveDhInit => write!(f, "ReceiveDhInit"),
            SshEvent::SendDhReply => write!(f, "SendDhReply"),
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
        info!("Processing event {} in state {}", event, self.state);

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

            // Key exchange transitions (client)
            (SshState::KexInitSent, SshEvent::ReceiveKexInit) if self.is_client => {
                self.receive_kexinit().await?;
                self.state = SshState::KexInitReceived;
            }
            (SshState::KexInitReceived, SshEvent::SendDhInit) if self.is_client => {
                self.send_dh_init().await?;
                self.state = SshState::DhInitSent;
            }
            (SshState::DhInitSent, SshEvent::ReceiveDhReply) if self.is_client => {
                self.receive_dh_reply().await?;
                self.state = SshState::DhReplyReceived;
            }

            // Key exchange transitions (server)
            (SshState::KexInitSent, SshEvent::ReceiveKexInit) if !self.is_client => {
                self.receive_kexinit().await?;
                self.state = SshState::KexInitReceived;
            }
            (SshState::KexInitReceived, SshEvent::ReceiveDhInit) if !self.is_client => {
                self.receive_dh_init().await?;
                self.state = SshState::DhInitReceived;
            }
            (SshState::DhInitReceived, SshEvent::SendDhReply) if !self.is_client => {
                self.send_dh_reply().await?;
                self.state = SshState::DhReplySent;
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

        info!("Sending version: {}", version);

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

        info!("Received version: {}", remote_version);

        self.transport.config.remote_version = Some(remote_version.to_string());

        if self.is_client {
            self.transport.config.server_version = Some(remote_version.to_string());
        } else {
            self.transport.config.client_version = Some(remote_version.to_string());
        }

        Ok(())
    }

    async fn send_kexinit(&mut self) -> SshResult<()> {
        info!("Sending KEXINIT");

        // TODO: Implement

        Ok(())
    }

    async fn receive_kexinit(&mut self) -> SshResult<()> {
        info!("Receiving KEXINIT");

        // TODO: Implement

        Ok(())
    }

    async fn send_dh_init(&mut self) -> SshResult<()> {
        if !self.is_client {
            return Err(SshError::Protocol(
                "Only clients can send KEXDH_INIT".into(),
            ));
        }

        info!("Sending KEXDH_INIT");

        // TODO: Implement Diffie-Hellman key exchange
        // This would generate a DH key pair, send public key

        Err(SshError::NotImplemented(
            "KEXDH_INIT not implemented".into(),
        ))
    }

    async fn receive_dh_reply(&mut self) -> SshResult<()> {
        if !self.is_client {
            return Err(SshError::Protocol(
                "Only clients can receive KEXDH_REPLY".into(),
            ));
        }

        info!("Receiving KEXDH_REPLY");

        // TODO: Implement DH key exchange completion
        // This would process the server's reply, verify host key, compute shared secret

        Err(SshError::NotImplemented(
            "KEXDH_REPLY not implemented".into(),
        ))
    }

    async fn receive_dh_init(&mut self) -> SshResult<()> {
        if self.is_client {
            return Err(SshError::Protocol(
                "Only servers can receive KEXDH_INIT".into(),
            ));
        }

        info!("Receiving KEXDH_INIT");

        // TODO: Implement server-side DH key exchange
        // This would receive client's public key

        Err(SshError::NotImplemented(
            "KEXDH_INIT receive not implemented".into(),
        ))
    }

    async fn send_dh_reply(&mut self) -> SshResult<()> {
        if self.is_client {
            return Err(SshError::Protocol(
                "Only servers can send KEXDH_REPLY".into(),
            ));
        }

        info!("Sending KEXDH_REPLY");

        // TODO: Implement server's DH reply
        // This would sign and send the server's host key and public key

        Err(SshError::NotImplemented(
            "KEXDH_REPLY not implemented".into(),
        ))
    }

    async fn disconnect(&mut self) -> SshResult<()> {
        info!("Disconnecting");

        // TODO: Send disconnect message

        Ok(())
    }
}
