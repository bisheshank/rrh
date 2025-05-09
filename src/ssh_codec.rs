use bytes::{Buf, BufMut, Bytes, BytesMut};
use rand::Rng;

use crate::error::{SshError, SshResult};

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

    pub fn encode(&self) -> SshResult<BytesMut> {
        let payload_len = self.payload.len();

        let mut padding_len = 8 - ((payload_len + 5) % 8);
        if padding_len < 4 {
            padding_len += 8;
        }

        let packet_len = payload_len + padding_len + 1;

        let mut buffer = BytesMut::with_capacity(4 + packet_len + 20);

        buffer.put_u32(packet_len as u32);
        buffer.put_u8(padding_len as u8);
        buffer.extend_from_slice(&self.payload);

        let mut padding = vec![0u8; padding_len];
        rand::rng().fill(&mut padding[..]);
        buffer.extend_from_slice(&padding);

        // TODO: Add mac here

        Ok(buffer)
    }

    pub fn decode(mut buffer: Bytes) -> SshResult<Self> {
        if buffer.len() < 5 {
            return Err(SshError::Protocol("Packet too short".to_string()));
        }

        let packet_length_bytes = buffer.slice(0..4);
        let packet_len = u32::from_be_bytes([
            packet_length_bytes[0],
            packet_length_bytes[1],
            packet_length_bytes[2],
            packet_length_bytes[3],
        ]);

        // TODO: Need to add mac size here
        let mac_len = 0;
        let total_len = 4 + packet_len as usize + mac_len;
        if total_len > buffer.len() {
            return Err(SshError::Protocol(format!(
                "Message too short: expected {}, got {}",
                total_len,
                buffer.len(),
            )));
        }

        // TODO: Process mac before packet processing

        let mut packet_buffer = buffer.slice(0..buffer.len() - mac_len);
        packet_buffer.advance(4);

        let padding_len = packet_buffer[0] as usize;
        packet_buffer.advance(1);

        let payload_len = packet_len as usize - padding_len - 1;

        if payload_len < 1 {
            return Err(SshError::Protocol("Payload too short".to_string()));
        }

        let payload = packet_buffer.slice(0..payload_len);
        let msg_type = payload[0];

        Ok(SshPacket {
            sequence_number: 0, // Will be set by the transport
            payload,
            msg_type,
        })
    }
}
