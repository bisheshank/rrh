use bytes::{BufMut, BytesMut};
use log::debug;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, split},
    net::TcpStream,
};

use crate::{
    config::SshConfig,
    constants::MAX_PACKET_SIZE,
    error::{SshError, SshResult},
    message::Message,
    ssh_codec::SshPacket,
};

pub struct Transport {
    // All config values
    pub config: SshConfig,
    // TcpStream split into reader and writer
    reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: tokio::io::WriteHalf<TcpStream>,
    // Client/ server differentiation
    is_client: bool,
    // Packet sequencing
    send_sequence_number: u32,
    recv_sequence_number: u32,
    pub session_keys: SessionKeys
}

//new struct for server to store necessary keys
pub struct SessionKeys {
    pub shared_key: Option<[u8; 32]>, 
    pub client_public: Option<[u8; 32]>,
}

impl Transport {
    pub async fn new(stream: TcpStream, config: SshConfig, is_client: bool) -> SshResult<Self> {
        // Split the TcpStream into a ReadHalf and WriteHalf
        let (reader, writer) = split(stream);

        // Create a BufReader for the reader half
        let reader = BufReader::new(reader);

        let session_keys = SessionKeys {
            shared_key: None,
            client_public: None,
        };

        Ok(Transport {
            reader,
            writer,
            config,
            is_client,
            send_sequence_number: 0,
            recv_sequence_number: 0,
            session_keys
        })
    }

    pub async fn read_line(&mut self, line: &mut String) -> SshResult<()> {
        match self.reader.read_line(line).await {
            Ok(bytes_read) => {
                debug!("Read {} bytes: {:?}", bytes_read, line.as_bytes());
                if bytes_read == 0 {
                    return Err(SshError::Protocol("Connection closed by peer".to_string()));
                }
                Ok(())
            }
            Err(e) => {
                debug!("Error reading line: {:?}", e);
                Err(e.into())
            }
        }
    }

    pub async fn write_all(&mut self, buf: &[u8]) -> SshResult<()> {
        self.writer.write_all(buf).await?;
        self.writer.flush().await?;
        Ok(())
    }

    pub fn is_client(&self) -> bool {
        self.is_client
    }

    pub async fn send_message(&mut self, message: Message) -> SshResult<()> {
        debug!("Sending message: {}", message);

        let mut packet = message.to_packet()?;
        packet.sequence_number = self.send_sequence_number;
        let data = packet.encode()?;

        self.writer.write_all(&data).await?;
        self.writer.flush().await?;

        self.send_sequence_number = self.send_sequence_number.wrapping_add(1);

        Ok(())
    }

    pub async fn receive_message(&mut self) -> SshResult<Message> {
        let mut length_buf = [0u8; 4];
        self.reader.read_exact(&mut length_buf).await?;

        let packet_length = u32::from_be_bytes(length_buf);

        if packet_length > MAX_PACKET_SIZE {
            return Err(SshError::Protocol(format!(
                "Packet too large: {} > {}",
                packet_length, MAX_PACKET_SIZE
            )));
        }

        let mut packet_buf = BytesMut::with_capacity(packet_length as usize);
        packet_buf.resize(packet_length as usize, 0);
        self.reader.read_exact(&mut packet_buf).await?;

        let mut full_packet = BytesMut::with_capacity(4 + packet_length as usize);
        full_packet.put_u32(packet_length);
        full_packet.extend_from_slice(&packet_buf);

        let mut packet = SshPacket::decode(full_packet.freeze())?;

        packet.sequence_number = self.recv_sequence_number;
        self.recv_sequence_number = self.recv_sequence_number.wrapping_add(1);

        let message = Message::from_packet(&packet)?;
        debug!("Received message: {}", message);

        Ok(message)
    }
}
