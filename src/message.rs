use std::fmt;

use bytes::{BufMut, Bytes, BytesMut};

use crate::{
    constants::msg,
    error::{SshError, SshResult},
    ssh_codec::SshPacket,
};

pub enum Message {
    Disconnect {
        reason_code: u32,
        description: String,
        langauge_tag: String,
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
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::Disconnect { .. } => write!(f, "DISCONNECT"),
            Message::Unimplemented { .. } => write!(f, "UNIMPLEMENTED"),
            Message::KexInit { .. } => write!(f, "KEXINIT"),
            Message::KexDhInit { .. } => write!(f, "KEXDH_INIT"),
            Message::KexDhReply { .. } => write!(f, "KEXDH_REPLY"),
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
            }
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
            }
            _ => Ok(Message::Unimplemented { sequence_number: 0 }),
        }
    }
}
