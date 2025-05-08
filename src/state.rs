use bytes::{BufMut, BytesMut, Bytes, Buf};
use log::info;
use sha1::{Sha1, Digest};

use core::fmt;
use tokio::net::TcpStream;

use crate::{
    config::SshConfig, constants::{host_keys::{PRIVATE_SERVER_HOST_KEY, PUBLIC_SERVER_HOST_KEY}, reason_codes::{self, SSH_DISCONNECT_BY_APPLICATION, SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE}}, error::{SshError, SshResult}, kex::create_kexinit_message, message::Message, ssh_codec::SshPacket, transport::Transport, transport::NewKeys
};

use x25519_dalek::PublicKey;
use ed25519_dalek::{SigningKey, Signature, Verifier, Signer, VerifyingKey};
use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use crate::kex::{generate_public_private, generate_shared, generate_new_key};

type Aes128Ctr = ctr::Ctr128BE<Aes128>;
type HmacSha1 = Hmac<Sha1>;


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
    NewKeysSent,
    NewKeysReceived,
    KeysExchanged,

    // Authentication states
    AuthRequested,
    AuthMethodNegotiated,
    AuthInProgress,
    AuthSuccess,

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
            SshState::NewKeysSent => write!(f, "NewKeysSent"),
            SshState::NewKeysReceived => write!(f, "NewKeysReceived"),
            SshState::KeysExchanged => write!(f, "KeysExchanged"),
            SshState::AuthRequested => write!(f, "AuthRequested"),
            SshState::AuthMethodNegotiated => write!(f, "AuthMethodNegotiated"),
            SshState::AuthInProgress => write!(f, "AuthInProgress"),
            SshState::AuthSuccess => write!(f, "AuthSuccess"),
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
    SendNewKeys,
    ReceiveNewKeys,

    // Authentication events
    RequestAuth,
    SendAuthMethod,
    ReceiveAuthRequest,
    SendAuthSuccess,
    SendAuthFailure,

    // Channel events
    OpenChannel,
    ReceiveChannelOpen,
    SendChannelOpenConfirmation,

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
            SshEvent::SendNewKeys => write!(f, "SendNewKeys"),
            SshEvent::ReceiveNewKeys => write!(f, "ReceiveNewKeys"),
            SshEvent::RequestAuth => write!(f, "RequestAuth"),
            SshEvent::SendAuthMethod => write!(f, "SendAuthMethod"),
            SshEvent::ReceiveAuthRequest => write!(f, "ReceiveAuthRequest"),
            SshEvent::SendAuthSuccess => write!(f, "SendAuthSuccess"),
            SshEvent::SendAuthFailure => write!(f, "SendAuthFailure"),
            SshEvent::OpenChannel => write!(f, "OpenChannel"),
            SshEvent::ReceiveChannelOpen => write!(f, "ReceiveChannelOpen"),
            SshEvent::SendChannelOpenConfirmation => write!(f, "SendChannelOpenConfirmation"),
            SshEvent::Error(msg) => write!(f, "Error({})", msg),
            SshEvent::Disconnect => write!(f, "Disconnect"),
        }
    }
}

pub struct SshStateMachine {
    state: SshState,
    transport: Transport,
    is_client: bool
}

impl SshStateMachine {
    pub async fn new(stream: TcpStream, config: SshConfig, is_client: bool) -> SshResult<Self> {
        let transport = Transport::new(stream, config, is_client).await?;

        Ok(SshStateMachine {
            state: SshState::Initial,
            transport,
            is_client
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

            //new keys transition (client)
            (SshState::DhReplyReceived, SshEvent::SendNewKeys) if self.is_client => {
                self.send_newkeys().await?;
                self.state = SshState::NewKeysSent;
            }

            //new keys transition (server)
            (SshState::DhReplySent, SshEvent::SendNewKeys) if !self.is_client => {
                self.send_newkeys().await?;
                self.state = SshState::NewKeysSent;
            }

            //sent to receive new keys transition
            (SshState::NewKeysSent, SshEvent::ReceiveNewKeys) => {
                self.receive_newkeys().await?;
                self.state = SshState::NewKeysReceived;
            }

            //client only
            (SshState::NewKeysReceived, SshEvent::RequestAuth) if self.is_client => {
                self.send_service_request("auth".into()).await?;
                self.state = SshState::AuthRequested;
            }

            //server only
            (SshState::NewKeysReceived, SshEvent::ReceiveAuthRequest) if !self.is_client => {
                self.receive_service_request().await?;
                self.state = SshState::AuthInProgress;
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

        let kexinit_message = create_kexinit_message()?;
        let packet = kexinit_message.to_packet()?;

        if self.is_client {
            self.transport.config.client_kexinit = Some(packet.payload.to_vec());
        } else {
            self.transport.config.server_kexinit = Some(packet.payload.to_vec());
        }

        self.transport.send_message(kexinit_message).await?;

        self.try_negotiate_kex().await?;

        Ok(())
    }

    async fn receive_kexinit(&mut self) -> SshResult<()> {
        info!("Receiving KEXINIT");

        let kexinit_msg = self.transport.receive_message().await?;

        let packet = match &kexinit_msg {
            Message::KexInit { .. } => kexinit_msg.to_packet()?,
            _ => return Err(SshError::Protocol("Expected KEXINIT message".into())),
        };

        if self.is_client {
            self.transport.config.server_kexinit = Some(packet.payload.to_vec());
        } else {
            self.transport.config.client_kexinit = Some(packet.payload.to_vec());
        }

        self.try_negotiate_kex().await?;

        Ok(())
    }

    async fn try_negotiate_kex(&mut self) -> SshResult<()> {
        let (client_kexinit, server_kexinit) = match (
            &self.transport.config.client_kexinit,
            &self.transport.config.server_kexinit,
        ) {
            (Some(c), Some(s)) => (c.clone(), s.clone()),
            _ => return Ok(()), // Not ready to negotiate
        };

        let client_msg = Message::from_packet(&SshPacket {
            sequence_number: 0,
            payload: Bytes::from(client_kexinit),
            msg_type: crate::constants::msg::KEXINIT,
        })?;

        let server_msg = Message::from_packet(&SshPacket {
            sequence_number: 0,
            payload: Bytes::from(server_kexinit),
            msg_type: crate::constants::msg::KEXINIT,
        })?;

        let negotiated = crate::kex::negotiate_algorithms(&client_msg, &server_msg)?;

        self.transport.config.negotiated = negotiated;

        info!("Algorithm negotiation completed successfully");

        if log::log_enabled!(log::Level::Info) {
            info!("KEX algorithm: {}", self.transport.config.negotiated.kex);
            info!(
                "Host key algorithm: {}",
                self.transport.config.negotiated.host_key
            );
            info!(
                "C2S encryption: {}",
                self.transport.config.negotiated.encryption_c2s
            );
            info!(
                "S2C encryption: {}",
                self.transport.config.negotiated.encryption_s2c
            );
        }

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

        // TODO: Need to store client secret key
        let (secret, public) = generate_public_private();

        self.transport.session.secret = Some(secret);

        self.transport.session.client_public = Some(*public.as_bytes());
        let public_bytes = public.as_bytes().to_vec(); 
        let dhinit_message = Message::KexDhInit { e: (public_bytes) };

        self.transport.send_message(dhinit_message).await?;

        Ok(())
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
        let dhreply_msg = self.transport.receive_message().await?;

        match dhreply_msg {
            //verify host key
            Message::KexDhReply { k_s, f, signature } => {
                if k_s != PUBLIC_SERVER_HOST_KEY.as_ref() {
                    return Err(SshError::Protocol("Server host key verification failed".into()));
                }

                let slice_u8: &[u8; 32];
                if k_s.len() == 32 {
                    slice_u8 = k_s.as_slice().try_into().expect("Failed to convert");
                } else {
                    return Err(SshError::Protocol("Host key received was not of the right length".into()));
                }

                let verification_key = VerifyingKey::from_bytes(&slice_u8).expect("Failed to convert public key bytes");
                //would now need to verify the signature by recomputing the hash, and verifying against 
                //the signature received

                let client_secret = self.transport.session.secret
                    .take()
                    .ok_or(SshError::Protocol("Missing client secret".into()))?;

                let server_key_bytes = <[u8; 32]>::try_from(f.as_slice())
                    .map_err(|_| SshError::Protocol("Invalid key length".into()))?;
                let server_public = PublicKey::from(server_key_bytes);

                let shared_secret = generate_shared(client_secret, server_public);

                let mut hasher = Sha1::new();

                let v_c = self.transport.config.client_version.as_deref().unwrap_or("").as_bytes();
                let v_s = self.transport.config.server_version.as_deref().unwrap_or("").as_bytes();


                let i_c = self.transport.config.client_kexinit.as_deref().unwrap_or(&[]);
                let i_s = self.transport.config.server_kexinit.as_deref().unwrap_or(&[]);

                let k_s = &PUBLIC_SERVER_HOST_KEY;
                
                let e = self.transport.session.client_public.as_ref()
                    .map(|val| val as &[u8]).unwrap_or(&[]);
                let f = server_public.as_bytes();

                let k = shared_secret.as_bytes();

                hasher.update(v_c);
                hasher.update(v_s);
                hasher.update(i_c);
                hasher.update(i_s);
                hasher.update(k_s);
                hasher.update(e);
                hasher.update(f);
                hasher.update(k);

                let hash_result = hasher.finalize();
                let signature_hash = hash_result.to_vec();

                let signature_array: [u8; 64] = signature.try_into()
                    .expect("Failed to convert Vec<u8> to [u8; 64]");

                // Convert the signature bytes to a Signature
                let signature = Signature::from_bytes(&signature_array);

                verification_key.verify(&signature_hash, &signature)
                    .map_err(|_| SshError::Protocol("Signature verification failed".into()))?;

                //signature verified, shared_key computed
                self.transport.session.shared_key = Some(*shared_secret.as_bytes());
                
                self.transport.session.exchange_hash = Some(signature_hash.clone());

                if self.transport.session.session_id == None {
                    self.transport.session.session_id = Some(signature_hash);
                }
            },
            _ => {
                return Err(SshError::Protocol("Expected KEXDH_REPLY".into()));
            }
        }


        Ok(())
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
        let dhinit_msg = self.transport.receive_message().await?;

        //after receiving dhinit message from client, stores client_public in session
        match dhinit_msg {
            Message::KexDhInit { e } => {
                // Ensure the key is 32 bytes
                let key_bytes: [u8; 32] = e.as_slice().try_into().map_err(|_| {
                    SshError::Protocol("Invalid client public key size".into())
                })?;
    
                self.transport.session.client_public = Some(key_bytes);
            }
            _ => return Err(SshError::Protocol("Expected KEXDH_INIT message".into())),
        };

        Ok(())
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

        let (server_secret, server_public) = generate_public_private();
        let public_bytes = server_public.as_bytes().to_vec(); 

        let mut hasher = Sha1::new();

        let v_c = self.transport.config.client_version.as_deref().unwrap_or("").as_bytes();
        let v_s = self.transport.config.server_version.as_deref().unwrap_or("").as_bytes();


        let i_c = self.transport.config.client_kexinit.as_deref().unwrap_or(&[]);
        let i_s = self.transport.config.server_kexinit.as_deref().unwrap_or(&[]);

        let k_s = &PUBLIC_SERVER_HOST_KEY;
        
        let e = self.transport.session.client_public.as_ref().map(|val| val as &[u8]).unwrap_or(&[]);
        let f = server_public.as_bytes();

        let client_pub_bytes = self.transport.session.client_public.as_ref().expect("Missing client key");

        let client_public = PublicKey::from(*client_pub_bytes);
        let shared_secret = generate_shared(server_secret, client_public);
        
        let k = shared_secret.as_bytes();

        hasher.update(v_c);
        hasher.update(v_s);
        hasher.update(i_c);
        hasher.update(i_s);
        hasher.update(k_s);
        hasher.update(e);
        hasher.update(f);
        hasher.update(k);

        let hash_result = hasher.finalize();
        let signature_hash = hash_result.to_vec();

        let signing_key = SigningKey::from_bytes(&PRIVATE_SERVER_HOST_KEY);
        let signature = signing_key.sign(&signature_hash).to_bytes().to_vec();

        let dh_reply_message = Message::KexDhReply { 
            k_s: PUBLIC_SERVER_HOST_KEY.to_vec(), 
            f: public_bytes, 
            signature: signature 
        };

        self.transport.session.exchange_hash = Some(signature_hash.clone());

        if self.transport.session.session_id == None {
            self.transport.session.session_id = Some(signature_hash);
        }

        self.transport.session.shared_key = Some(*k);

        self.transport.send_message(dh_reply_message).await?;

        Ok(())
    }

    async fn send_newkeys(&mut self) -> SshResult<()> {
        info!("Sending SSH_MSG_NEWKEYS");

        self.transport.send_message(Message::NewKeys).await?;

        Ok(())
    }

    async fn receive_newkeys(&mut self) -> SshResult<()> {
        info!("Receiving SSH_MSG_NEWKEYS");

        let newkeys_msg = self.transport.receive_message().await?;

        match newkeys_msg {
            Message::NewKeys => {
                //if this is received, should activate all the new keys: iv, enc, mac
                let k = self.transport.session.shared_key
                    .as_ref()
                    .ok_or_else(|| SshError::Protocol("Missing shared key".into()))?
                    .clone();

                let exchange_hash = self.transport.session.exchange_hash
                    .as_ref()
                    .ok_or_else(|| SshError::Protocol("Missing exchange hash".into()))?
                    .clone();

                let session_id = self.transport.session.session_id
                    .as_ref()
                    .ok_or_else(|| SshError::Protocol("Missing session ID".into()))?
                    .clone();

                let iv_c2s;
                let iv_s2c;
                let key_c2s;
                let key_s2c;
                let mac_c2s;
                let mac_s2c;

                if self.is_client {
                    iv_c2s = generate_new_key(&k, &exchange_hash, &session_id, b'A');
                    iv_s2c = generate_new_key(&k, &exchange_hash, &session_id, b'B');
                    key_c2s = generate_new_key(&k, &exchange_hash, &session_id, b'C');
                    key_s2c = generate_new_key(&k, &exchange_hash, &session_id, b'D');
                    mac_c2s = generate_new_key(&k, &exchange_hash, &session_id, b'E');
                    mac_s2c = generate_new_key(&k, &exchange_hash, &session_id, b'F');
                } else {
                    iv_c2s = generate_new_key(&k, &exchange_hash, &session_id, b'B');
                    iv_s2c = generate_new_key(&k, &exchange_hash, &session_id, b'A');
                    key_c2s = generate_new_key(&k, &exchange_hash, &session_id, b'D');
                    key_s2c = generate_new_key(&k, &exchange_hash, &session_id, b'C');
                    mac_c2s = generate_new_key(&k, &exchange_hash, &session_id, b'F');
                    mac_s2c = generate_new_key(&k, &exchange_hash, &session_id, b'E');
                }

                let new_keys = NewKeys {
                    iv_c2s: Some(iv_c2s),
                    iv_s2c: Some(iv_s2c),
                    key_c2s: Some(key_c2s),
                    key_s2c: Some(key_s2c),
                    mac_c2s: Some(mac_c2s),
                    mac_s2c: Some(mac_s2c),
                };

                //now server and client has all the new keys that just got computed
                //should be the same for both server and client
                self.transport.session.new_keys = new_keys;
            },
            _ => return Err(SshError::Protocol("Expected SSH_MSG_NEWKEYS message".into())),
        }

        Ok(())
    }

    async fn send_service_request(&mut self, service_name: String) -> SshResult<()> {
        if !self.is_client {
            return Err(SshError::Protocol(
                "Only clients can send service requests".into(),
            ));
        }
        
        info!("Sending SERVICE_REQUEST for service: {}", service_name);

        let service_request = Message::ServiceRequest { service_name: service_name };
        let mut packet = service_request.to_packet()?;

        let payload = packet.payload;
        
        let key = self.transport.session.new_keys.key_c2s.as_ref().ok_or(SshError::Protocol("Missing encryption key".into()))?;
        let iv = self.transport.session.new_keys.iv_c2s.as_ref().ok_or(SshError::Protocol("Missing IV".into()))?;
        let mac_key = self.transport.session.new_keys.mac_c2s.as_ref().ok_or(SshError::Protocol("Missing MAC key".into()))?;

        let block_size = 16;
        let padding_len = block_size - ((1 + payload.len()) % block_size);
        let packet_len = 1 + payload.len() + padding_len;

        let mut packet_buf = BytesMut::with_capacity(4 + packet_len);
        packet_buf.put_u32(packet_len as u32);  
        packet_buf.put_u8(padding_len as u8);      
        packet_buf.extend_from_slice(&payload);    
        packet_buf.extend_from_slice(&vec![0u8; padding_len]); 

        let mut encrypted = packet_buf.split_off(4);
        let mut cipher = Aes128Ctr::new_from_slices(key, iv).map_err(|_| SshError::Protocol("Bad IV or key".into()))?;
        cipher.apply_keystream(&mut encrypted);

        let mut output = BytesMut::with_capacity(4 + encrypted.len() + 32);
        output.put_u32(packet_len as u32); 
        output.extend_from_slice(&encrypted);

        let mut mac = HmacSha1::new_from_slice(mac_key).map_err(|_| SshError::Protocol("Bad MAC key".into()))?;
        let mut seq_buf = [0u8; 4];
        seq_buf.copy_from_slice(&packet.sequence_number.to_be_bytes());

        mac.update(&seq_buf);
        mac.update(&output);

        let mac_bytes = mac.finalize().into_bytes();
        output.extend_from_slice(&mac_bytes);

        let encrypted_payload = output.freeze();
        packet.payload = encrypted_payload;

        self.transport.send_encrypted_message(service_request, packet).await?;

        Ok(())
    }

    async fn receive_service_request(&mut self) -> SshResult<()> {
        if self.is_client {
            return Err(SshError::Protocol(
                "Only the server can receive service requests".into(),
            ));
        }

        let mut packet = self.transport.receive_packet().await?;
        let encrypted_payload = packet.payload;

        let key = self.transport.session.new_keys.key_s2c.as_ref().ok_or(SshError::Protocol("Missing decryption key".into()))?;
        let iv = self.transport.session.new_keys.iv_s2c.as_ref().ok_or(SshError::Protocol("Missing IV".into()))?;
        let mac_key = self.transport.session.new_keys.mac_s2c.as_ref().ok_or(SshError::Protocol("Missing MAC key".into()))?;
        
        let mut cursor = std::io::Cursor::new(&encrypted_payload);

        let packet_len = cursor.get_u32() as usize;

        let encrypted_part_len = packet_len; 
        let total_len = 4 + encrypted_part_len;
        let mac_len = 20; // for SHA1

        if encrypted_payload.len() < total_len + mac_len {
            return Err(SshError::Protocol("Packet too short".into()));
        }

        let encrypted_data = &encrypted_payload[4..total_len];
        let received_mac = &encrypted_payload[total_len..(total_len + mac_len)];

        let mut mac = HmacSha1::new_from_slice(mac_key).map_err(|_| SshError::Protocol("Bad MAC key".into()))?;
        let mut seq_buf = [0u8; 4];
        seq_buf.copy_from_slice(&packet.sequence_number.to_be_bytes());

        mac.update(&seq_buf);
        mac.update(&encrypted_payload[..total_len]);

        let expected_mac = mac.finalize().into_bytes();
        if expected_mac.as_slice() != received_mac {
            return Err(SshError::Protocol("MAC verification failed".into()));
        }

        // Decrypt
        let mut decrypted = encrypted_data.to_vec();
        let mut cipher = Aes128Ctr::new_from_slices(key, iv).map_err(|_| SshError::Protocol("Bad IV or key".into()))?;
        cipher.apply_keystream(&mut decrypted);

        let padding_len = decrypted[0] as usize;

        if decrypted.len() < 1 + padding_len {
            return Err(SshError::Protocol("Decrypted data too short".into()));
        }
        let payload = &decrypted[1..(decrypted.len() - padding_len)];
        let payload_bytes = Bytes::copy_from_slice(payload);

        packet.payload = payload_bytes;

        let message = Message::from_packet(&packet)?;

        match message {
            Message::ServiceRequest { service_name } => {
                println!("Received SERVICE_REQUEST for service: {}", service_name);
            },
            _ => {
                return Err(SshError::Protocol("Expected SERVICE_REQUEST message".into()))
            }
        }

        Ok(())
    }

    async fn disconnect(&mut self) -> SshResult<()> {
        info!("Disconnecting");

        // TODO: Send disconnect message
        let description;

        if self.is_client {
            description = "Client is disconnecting".to_string();
        } else {
            description = "Server is disconnecting".to_string();
        }

        let disconnect_message = Message::Disconnect { 
            reason_code: (SSH_DISCONNECT_BY_APPLICATION), 
            description: (description), 
            language_tag: ("en-US".to_string()) 
        };

        self.transport.send_message(disconnect_message).await?;

        Ok(())
    }

    // async fn custom_disconnect(&mut self, reason_code: u32, description: String, language_tag: String) -> SshResult<()> {
    //     info!("Disconnecting");

    //     let disconnect_message = Message::Disconnect { 
    //         reason_code: (reason_code), 
    //         description: (description), 
    //         language_tag: (language_tag) 
    //     };

    //     self.transport.send_message(disconnect_message).await?;

    //     Ok(())
    // }
}