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
            _ => Ok(Message::Unimplemented { sequence_number: 0 }),
        }
    }
}
