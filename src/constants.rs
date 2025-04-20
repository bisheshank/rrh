// Protocol version number
// SSH-protoversion-softwareversion SP comments CR LF
pub const PROTOCOL_VERSION: &str = concat!("SSH-2.0-RRH_", env!("CARGO_PKG_VERSION"));

// Maximum packet size
pub const MAX_PACKET_SIZE: u32 = 35000;
