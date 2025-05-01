use bytes::{BufMut, Bytes, BytesMut};

use crate::error::SshResult;

/// SSH Binary Packet Format (RFC 4253, section 6)
///
/// uint32    packet_length
/// byte      padding_length
/// byte[n1]  payload; n1 = packet_length - padding_length - 1
/// byte[n2]  random padding; n2 = padding_length
/// byte[m]   mac (Message Authentication Code); m = mac_length
pub struct SshPacket {
    // Sequence number for MAC calculation
    pub sequence_number: u32,
    // Message payload
    pub payload: Bytes,
    // Message type (first byte of payload)
    pub msg_type: u8,
}

impl SshPacket {
    pub fn new(msg_type: u8, payload: Bytes) -> Self {
        let mut full_payload = BytesMut::with_capacity(payload.len() + 1);
        full_payload.put_u8(msg_type);
        full_payload.extend_from_slice(&payload);

        SshPacket {
            sequence_number: 0, // Will be set by the transport
            payload: full_payload.freeze(),
            msg_type,
        }
    }

    pub fn new_simple(msg_type: u8) -> Self {
        let mut payload = BytesMut::with_capacity(1);
        payload.put_u8(msg_type);

        SshPacket {
            sequence_number: 0,
            payload: payload.freeze(),
            msg_type,
        }
    }

    pub fn encode(&self) -> BytesMut {
        let mut buffer = BytesMut::with_capacity(1);

        buffer
    }

    pub fn decode(mut buffer: Bytes) -> SshResult<Self> {
        let payload = Bytes::default();
        let msg_type = u8::default();

        Ok(SshPacket {
            sequence_number: 0, // Will be set by the transport
            payload,
            msg_type,
        })
    }
}
