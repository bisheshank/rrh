use std::fmt;

pub enum Message {
    Disconnect {
        reason_code: u32,
        description: String,
        langauge_tag: String,
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
            Message::KexInit { .. } => write!(f, "KEXINIT"),
            Message::KexDhInit { .. } => write!(f, "KEXDH_INIT"),
            Message::KexDhReply { .. } => write!(f, "KEXDH_REPLY"),
        }
    }
}
