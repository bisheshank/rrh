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
    pub const NEWKEYS: u8 = 21;
    // KEX specific messages start at 30
}
