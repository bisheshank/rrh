use std::{fmt, str::from_utf8};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{
    constants::{KEX_COOKIE_SIZE, msg},
    error::{SshError, SshResult},
    ssh_codec::SshPacket,
};

#[derive(Debug)]
pub enum Message {
    Disconnect {
        reason_code: u32,
        description: String,
        language_tag: String,
    },
    Unimplemented {
        sequence_number: u32,
    },
    KexInit {
        cookie: [u8; 16],
        kex_algorithms: Vec<String>,
        server_host_key_algorithms: Vec<String>,
        encryption_algorithms_client_to_server: Vec<String>,
        encryption_algorithms_server_to_client: Vec<String>,
        mac_algorithms_client_to_server: Vec<String>,
        mac_algorithms_server_to_client: Vec<String>,
        compression_algorithms_client_to_server: Vec<String>,
        compression_algorithms_server_to_client: Vec<String>,
        languages_client_to_server: Vec<String>,
        languages_server_to_client: Vec<String>,
        first_kex_packet_follows: bool,
        reserved: u32,
    },
    KexDhInit {
        e: Vec<u8>, // Client's ephemeral public key
    },
    KexDhReply {
        k_s: Vec<u8>,       // Server's public host key
        f: Vec<u8>,         // Server's ephemeral public key
        signature: Vec<u8>, // Signature of the exchange hash
    },
    NewKeys,
    ServiceRequest {
        service_name: String,
    }, 
    ServiceAccept {
        service_name: String
    },
    UsernamePassword {
        username: String,
        password: String,
    },
    AuthVerified,
    OpenChannel {
        channel_type: String,
    },
    ChannelOpenConfirmation,
    ExecuteCommand {
        command: String,
    },
    CommandResult {
        result: String
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::Disconnect { .. } => write!(f, "DISCONNECT"),
            Message::Unimplemented { .. } => write!(f, "UNIMPLEMENTED"),
            Message::KexInit { .. } => write!(f, "KEXINIT"),
            Message::KexDhInit { .. } => write!(f, "KEXDH_INIT"),
            Message::KexDhReply { .. } => write!(f, "KEXDH_REPLY"),
            Message::NewKeys { .. } => write!(f, "SSH_MSG_NEWKEYS"),
            Message::ServiceRequest { .. } => write!(f, "SERVICE_REQUEST"),
            Message::ServiceAccept { .. } => write!(f, "SERVICE_ACCEPT"),
            Message::UsernamePassword { .. } => write!(f, "USERNAME_PASSWORD"),
            Message::AuthVerified { .. } => write!(f, "AUTH_VERIFIED"),
            Message::OpenChannel { .. } => write!(f, "OPEN_CHANNEL"),
            Message::ChannelOpenConfirmation { .. } => write!(f, "CHANNEL_OPEN_CONFIRMATION"),
            Message::ExecuteCommand { .. } => write!(f, "EXECUTE_COMMAND"),
            Message::CommandResult { .. } => write!(f, "COMMAND_RESULT"),
        }
    }
}

impl Message {
    pub fn to_packet(&self) -> SshResult<SshPacket> {
        match self {
            Message::Unimplemented { sequence_number } => {
                let mut buffer = BytesMut::new();
                buffer.put_u32(*sequence_number);

                Ok(SshPacket::new(msg::UNIMPLEMENTED, buffer.freeze()))
            },
            Message::KexInit {
                cookie,
                kex_algorithms,
                server_host_key_algorithms,
                encryption_algorithms_client_to_server,
                encryption_algorithms_server_to_client,
                mac_algorithms_client_to_server,
                mac_algorithms_server_to_client,
                compression_algorithms_client_to_server,
                compression_algorithms_server_to_client,
                languages_client_to_server,
                languages_server_to_client,
                first_kex_packet_follows,
                reserved,
            } => {
                let mut buffer = BytesMut::new();

                buffer.put_slice(cookie);

                fn put_name_list(buffer: &mut BytesMut, list: &[String]) {
                    let joined = list.join(",");
                    buffer.put_u32(joined.len() as u32);
                    buffer.put_slice(joined.as_bytes());
                }

                put_name_list(&mut buffer, kex_algorithms);
                put_name_list(&mut buffer, server_host_key_algorithms);
                put_name_list(&mut buffer, encryption_algorithms_client_to_server);
                put_name_list(&mut buffer, encryption_algorithms_server_to_client);
                put_name_list(&mut buffer, mac_algorithms_client_to_server);
                put_name_list(&mut buffer, mac_algorithms_server_to_client);
                put_name_list(&mut buffer, compression_algorithms_client_to_server);
                put_name_list(&mut buffer, compression_algorithms_server_to_client);
                put_name_list(&mut buffer, languages_client_to_server);
                put_name_list(&mut buffer, languages_server_to_client);

                buffer.put_u8(*first_kex_packet_follows as u8);

                buffer.put_u32(*reserved);

                Ok(SshPacket::new(msg::KEXINIT, buffer.freeze()))
            },
            Message::KexDhInit { e } => {
                let mut buffer = BytesMut::new();
                buffer.put_u32(e.len() as u32);
                buffer.put_slice(e);

                Ok(SshPacket::new(msg::KEXDH_INIT, buffer.freeze()))
            },
            Message::KexDhReply { k_s, f, signature } => {
                let mut buffer = BytesMut::new();

                buffer.put_u32(k_s.len() as u32); 
                buffer.put_slice(k_s); 

                buffer.put_u32(f.len() as u32); 
                buffer.put_slice(f); 

                buffer.put_u32(signature.len() as u32); 
                buffer.put_slice(signature); 
               
                Ok(SshPacket::new(msg::KEXDH_REPLY, buffer.freeze()))
            },
            Message::NewKeys => {
                Ok(SshPacket::new(msg::SSH_MSG_NEWKEYS, Bytes::new()))
            },
            Message::ServiceRequest { service_name} => {
                let mut buffer = BytesMut::new();

                buffer.put_u32(service_name.len() as u32);
                buffer.put_slice(service_name.as_bytes());
                
                Ok(SshPacket::new(msg::SERVICE_REQUEST, buffer.freeze()))
            },
            Message::ServiceAccept { service_name} => {
                let mut buffer = BytesMut::new();

                buffer.put_u32(service_name.len() as u32);
                buffer.put_slice(service_name.as_bytes());
                
                Ok(SshPacket::new(msg::SERVICE_ACCEPT, buffer.freeze()))
            },
            Message::UsernamePassword { username, password } => {
                let mut buffer = BytesMut::new();

                buffer.put_u32(username.len() as u32);
                buffer.put_slice(username.as_bytes());

                buffer.put_u32(password.len() as u32);
                buffer.put_slice(password.as_bytes());
                
                Ok(SshPacket::new(msg::USERNAME_PASSWORD, buffer.freeze()))
            },
            Message::AuthVerified=> {
                Ok(SshPacket::new(msg::AUTH_VERIFIED, Bytes::new()))
            },
            Message::OpenChannel{ channel_type } => {
                let mut buffer = BytesMut::new();

                buffer.put_u32(channel_type.len() as u32);
                buffer.put_slice(channel_type.as_bytes());
                
                Ok(SshPacket::new(msg::SSH_MSG_CHANNEL_OPEN, buffer.freeze()))
            },
            Message::ChannelOpenConfirmation => {
                Ok(SshPacket::new(msg::SSH_MSG_CHANNEL_OPEN_CONFIRMATION, Bytes::new()))
            },
            Message::ExecuteCommand{ command } => {
                let mut buffer = BytesMut::new();

                buffer.put_u32(command.len() as u32);
                buffer.put_slice(command.as_bytes());
                
                Ok(SshPacket::new(msg::EXECUTE_COMMAND, buffer.freeze()))
            },
            Message::CommandResult{ result } => {
                let mut buffer = BytesMut::new();

                buffer.put_u32(result.len() as u32);
                buffer.put_slice(result.as_bytes());
                
                Ok(SshPacket::new(msg::COMMAND_RESULT, buffer.freeze()))
            },
            _ => Ok(SshPacket::new(1, Bytes::default())),
        }
    }

    pub fn from_packet(packet: &SshPacket) -> SshResult<Self> {
        let payload = &packet.payload;

        if payload.len() < 1 {
            return Err(SshError::Protocol("Empty packet payload".to_string()));
        }

        let msg_type = payload[0];
        let data = payload.slice(1..);

        match msg_type {
            msg::UNIMPLEMENTED => {
                if data.len() < 4 {
                    return Err(SshError::Protocol(
                        "UNIMPLEMENTED message too short".to_string(),
                    ));
                }

                let sequence_number = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

                Ok(Message::Unimplemented { sequence_number })
            },
            msg::KEXINIT => {
                if data.len() < KEX_COOKIE_SIZE {
                    return Err(SshError::Protocol("KEXINIT message too short".to_string()));
                }

                let mut reader = Bytes::copy_from_slice(&data);

                let mut cookie = [0u8; KEX_COOKIE_SIZE];
                reader.copy_to_slice(&mut cookie);

                fn parse_name_list(reader: &mut Bytes) -> SshResult<Vec<String>> {
                    if reader.remaining() < 4 {
                        return Err(SshError::Protocol("Name-list field truncated".to_string()));
                    }

                    let len = reader.get_u32() as usize;

                    if reader.remaining() < len {
                        return Err(SshError::Protocol("Name-list field truncated".to_string()));
                    }

                    let bytes = reader.split_to(len);

                    let s = from_utf8(&bytes)
                        .map_err(|_| SshError::Protocol("Invalid UTF-8 in name-list".into()))?;

                    Ok(if s.is_empty() {
                        Vec::new()
                    } else {
                        s.split(',').map(|s| s.to_string()).collect()
                    })
                }

                // Parse all the name-lists
                let kex_algorithms = parse_name_list(&mut reader)?;
                let server_host_key_algorithms = parse_name_list(&mut reader)?;
                let encryption_algorithms_client_to_server = parse_name_list(&mut reader)?;
                let encryption_algorithms_server_to_client = parse_name_list(&mut reader)?;
                let mac_algorithms_client_to_server = parse_name_list(&mut reader)?;
                let mac_algorithms_server_to_client = parse_name_list(&mut reader)?;
                let compression_algorithms_client_to_server = parse_name_list(&mut reader)?;
                let compression_algorithms_server_to_client = parse_name_list(&mut reader)?;
                let languages_client_to_server = parse_name_list(&mut reader)?;
                let languages_server_to_client = parse_name_list(&mut reader)?;

                if reader.remaining() < 5 {
                    return Err(SshError::Protocol(
                        "KEXINIT message truncated at flags".to_string(),
                    ));
                }

                let first_kex_packet_follows = reader.get_u8() != 0;
                let reserved = reader.get_u32();

                Ok(Message::KexInit {
                    cookie,
                    kex_algorithms,
                    server_host_key_algorithms,
                    encryption_algorithms_client_to_server,
                    encryption_algorithms_server_to_client,
                    mac_algorithms_client_to_server,
                    mac_algorithms_server_to_client,
                    compression_algorithms_client_to_server,
                    compression_algorithms_server_to_client,
                    languages_client_to_server,
                    languages_server_to_client,
                    first_kex_packet_follows,
                    reserved,
                })
            },
            msg::KEXDH_INIT => {
                if data.len() < 4 {
                    return Err(SshError::Protocol("KEXDH_INIT message too short".to_string()));
                }
            
                let mut reader = Bytes::copy_from_slice(&data);
            
                let len = reader.get_u32() as usize;
            
                if reader.remaining() < len {
                    return Err(SshError::Protocol("KEXDH_INIT e field truncated".to_string()));
                }
            
                let e = reader.split_to(len).to_vec();
            
                Ok(Message::KexDhInit { e })
            },
            msg::KEXDH_REPLY => {
                if data.len() < 12 { 
                    return Err(SshError::Protocol("KEXDH_REPLY message too short".to_string()));
                }

                let mut reader = Bytes::copy_from_slice(&data);

                let k_s_len = reader.get_u32() as usize;

                if reader.remaining() < k_s_len {
                    return Err(SshError::Protocol("KEXDH_REPLY k_s field truncated".to_string()));
                }

                let k_s = reader.split_to(k_s_len).to_vec();

                let f_len = reader.get_u32() as usize;
                
                if reader.remaining() < f_len {
                    return Err(SshError::Protocol("KEXDH_REPLY f field truncated".to_string()));
                }

                let f = reader.split_to(f_len).to_vec();

                let signature_len = reader.get_u32() as usize;
                
                if reader.remaining() < signature_len {
                    return Err(SshError::Protocol("KEXDH_REPLY signature field truncated".to_string()));
                }

                let signature = reader.split_to(signature_len).to_vec();

                Ok(Message::KexDhReply { k_s: k_s, f: f, signature: signature })
            },
            msg::SSH_MSG_NEWKEYS => {
                Ok(Message::NewKeys)
            },
            msg::SERVICE_REQUEST => {
                if data.len() < 4 {
                    return Err(SshError::Protocol("SERVICE_REQUEST message too short".to_string()));
                }
            
                let mut reader = Bytes::copy_from_slice(&data);
            
                let service_len = reader.get_u32() as usize;
            
                if reader.remaining() < service_len {
                    return Err(SshError::Protocol("SERVICE_REQUEST service name truncated".to_string()));
                }
            
                let service_name_bytes = reader.split_to(service_len);
                let service_name = match std::str::from_utf8(&service_name_bytes) {
                    Ok(s) => s.to_string(),
                    Err(_) => {
                        return Err(SshError::Protocol("SERVICE_REQUEST service name is not valid UTF-8".to_string()));
                    }
                };
            
                Ok(Message::ServiceRequest { service_name })
            },
            msg::SERVICE_ACCEPT => {
                if data.len() < 4 {
                    return Err(SshError::Protocol("SERVICE_ACCEPT message too short".to_string()));
                }
            
                let mut reader = Bytes::copy_from_slice(&data);
            
                let service_len = reader.get_u32() as usize;
            
                if reader.remaining() < service_len {
                    return Err(SshError::Protocol("SERVICE_ACCEPT service name truncated".to_string()));
                }
            
                let service_name_bytes = reader.split_to(service_len);
                let service_name = match std::str::from_utf8(&service_name_bytes) {
                    Ok(s) => s.to_string(),
                    Err(_) => {
                        return Err(SshError::Protocol("SERVICE_ACCEPT service name is not valid UTF-8".to_string()));
                    }
                };
            
                Ok(Message::ServiceAccept { service_name })
            },
            msg::USERNAME_PASSWORD => {
                let mut reader = Bytes::copy_from_slice(&data);
            
                if reader.remaining() < 4 {
                    return Err(SshError::Protocol("USERNAME_PASSWORD message too short for username length".to_string()));
                }
            
                let username_len = reader.get_u32() as usize;
                if reader.remaining() < username_len + 4 {
                    return Err(SshError::Protocol("USERNAME_PASSWORD message too short for username or password length".to_string()));
                }
            
                let username_bytes = reader.split_to(username_len);
                let username = match std::str::from_utf8(&username_bytes) {
                    Ok(s) => s.to_string(),
                    Err(_) => {
                        return Err(SshError::Protocol("USERNAME_PASSWORD username is not valid UTF-8".to_string()));
                    }
                };
            
                let password_len = reader.get_u32() as usize;
                if reader.remaining() < password_len {
                    return Err(SshError::Protocol("USERNAME_PASSWORD message too short for password".to_string()));
                }
            
                let password_bytes = reader.split_to(password_len);
                let password = match std::str::from_utf8(&password_bytes) {
                    Ok(s) => s.to_string(),
                    Err(_) => {
                        return Err(SshError::Protocol("USERNAME_PASSWORD password is not valid UTF-8".to_string()));
                    }
                };
            
                Ok(Message::UsernamePassword { username, password })
            },
            msg::AUTH_VERIFIED => {
                Ok(Message::AuthVerified)
            },
            msg::SSH_MSG_CHANNEL_OPEN => {
                if data.len() < 4 {
                    return Err(SshError::Protocol("SSH_MSG_CHANNEL_OPEN message too short".to_string()));
                }
            
                let mut reader = Bytes::copy_from_slice(&data);
            
                let session_len = reader.get_u32() as usize;
            
                if reader.remaining() < session_len {
                    return Err(SshError::Protocol("SSH_MSG_CHANNEL_OPEN session type truncated".to_string()));
                }
            
                let session_type = reader.split_to(session_len);
                let session_name = match std::str::from_utf8(&session_type) {
                    Ok(s) => s.to_string(),
                    Err(_) => {
                        return Err(SshError::Protocol("SSH_MSG_CHANNEL_OPEN session type is not valid UTF-8".to_string()));
                    }
                };
            
                Ok(Message::OpenChannel { channel_type: session_name })
            },
            msg::SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                Ok(Message::ChannelOpenConfirmation)
            },
            msg::EXECUTE_COMMAND => {
                if data.len() < 4 {
                    return Err(SshError::Protocol("EXECUTE_COMMAND message too short".to_string()));
                }
            
                let mut reader = Bytes::copy_from_slice(&data);
            
                let command_len = reader.get_u32() as usize;
            
                if reader.remaining() < command_len {
                    return Err(SshError::Protocol("EXECUTE_COMMAND command is truncated".to_string()));
                }
            
                let command_bytes = reader.split_to(command_len);
                let command = match std::str::from_utf8(&command_bytes) {
                    Ok(s) => s.to_string(),
                    Err(_) => {
                        return Err(SshError::Protocol("EXECUTE_COMMAND command is not valid UTF-8".to_string()));
                    }
                };
            
                Ok(Message::ExecuteCommand { command: command })
            },
            msg::COMMAND_RESULT => {
                if data.len() < 4 {
                    return Err(SshError::Protocol("COMMAND_RESULT message too short".to_string()));
                }
            
                let mut reader = Bytes::copy_from_slice(&data);
            
                let result_len = reader.get_u32() as usize;
            
                if reader.remaining() < result_len {
                    return Err(SshError::Protocol("COMMAND_RESULT result truncated".to_string()));
                }
            
                let result_bytes = reader.split_to(result_len);
                let result = match std::str::from_utf8(&result_bytes) {
                    Ok(s) => s.to_string(),
                    Err(_) => {
                        return Err(SshError::Protocol("COMMAND_RESULT result is not valid UTF-8".to_string()));
                    }
                };
            
                Ok(Message::CommandResult { result: result })
            },
            _ => Ok(Message::Unimplemented { sequence_number: 0 }),
        }
    }
}
