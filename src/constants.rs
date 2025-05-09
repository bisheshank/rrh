// Protocol version number
// SSH-protoversion-softwareversion SP comments CR LF
pub const PROTOCOL_VERSION: &str = concat!("SSH-2.0-RRH_", env!("CARGO_PKG_VERSION"));

// Maximum packet size
pub const MAX_PACKET_SIZE: u32 = 35000;

/// Size of the random cookie used in key exchange
pub const KEX_COOKIE_SIZE: usize = 16;

/// SSH message numbers as defined in RFC 4250, 4252, 4253, etc.
pub mod msg {
    pub const DISCONNECT: u8 = 1;
    pub const IGNORE: u8 = 2;
    pub const UNIMPLEMENTED: u8 = 3;
    pub const DEBUG: u8 = 4;
    pub const SERVICE_REQUEST: u8 = 5;
    pub const SERVICE_ACCEPT: u8 = 6;
    pub const KEXINIT: u8 = 20;
    pub const SSH_MSG_NEWKEYS: u8 = 21;
    pub const KEXDH_INIT: u8 = 30;
    pub const KEXDH_REPLY: u8 = 31;
    pub const USERNAME_PASSWORD: u8 = 50; //random val as a placeholder
    pub const AUTH_VERIFIED: u8 = 49; //random val as a placeholder
    pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;
    pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
    pub const EXECUTE_COMMAND: u8 = 97; //random val as a placeholder
    pub const COMMAND_RESULT: u8 = 98; //random val as a placeholder
}

pub mod host_keys {
    pub const PUBLIC_SERVER_HOST_KEY: [u8; 32] = [
        68, 213, 207, 136, 140, 222, 73, 155, 
        23, 115, 24, 173, 1, 104, 161, 18, 
        187, 183, 178, 3, 66, 50, 12, 234, 
        56, 157, 139, 214, 233, 44, 102, 99
    ];

    pub const PRIVATE_SERVER_HOST_KEY: [u8; 32] = [
        115, 99, 6, 172, 208, 21, 38, 100, 
        59, 210, 179, 79, 27, 51, 216, 20, 
        117, 163, 57, 146, 161, 211, 59, 28, 
        11, 146, 189, 137, 151, 133, 175, 194
    ];
}

pub mod reason_codes {
    pub const SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT: u32 = 1;
    pub const SSH_DISCONNECT_PROTOCOL_ERROR: u32 = 2;
    pub const SSH_DISCONNECT_KEY_EXCHANGE_FAILED: u32 = 3;
    pub const SSH_DISCONNECT_RESERVED: u32 = 4;
    pub const SSH_DISCONNECT_MAC_ERROR: u32 = 5;
    pub const SSH_DISCONNECT_COMPRESSION_ERROR: u32 = 6;
    pub const SSH_DISCONNECT_SERVICE_NOT_AVAILABLE: u32 = 7;
    pub const SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED: u32 = 8;
    pub const SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE: u32 = 9;
    pub const SSH_DISCONNECT_CONNECTION_LOST: u32 = 10;
    pub const SSH_DISCONNECT_BY_APPLICATION: u32 = 11;
    pub const SSH_DISCONNECT_TOO_MANY_CONNECTIONS: u32 = 12;
    pub const SSH_DISCONNECT_AUTH_CANCELLED_BY_USER: u32 = 13;
    pub const SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE: u32 = 14;
    pub const SSH_DISCONNECT_ILLEGAL_USER_NAME: u32 = 15;
}