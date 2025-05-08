use std::collections::{HashMap, HashSet};

use rand08::rngs::OsRng as OsRng08;
use rand::{rngs::OsRng, TryRngCore};
use x25519_dalek::{EphemeralSecret, PublicKey};
use x25519_dalek::SharedSecret;

use crate::{
    constants::KEX_COOKIE_SIZE,
    error::{SshError, SshResult},
    message::Message,
};

use sha1::{Sha1, Digest};

#[derive(Debug, Clone)]
pub struct Algorithms {
    pub kex: Vec<String>,
    pub server_host_key: Vec<String>,
    pub encryption_c2s: Vec<String>,
    pub encryption_s2c: Vec<String>,
    pub mac_c2s: Vec<String>,
    pub mac_s2c: Vec<String>,
    pub compression_c2s: Vec<String>,
    pub compression_s2c: Vec<String>,
    pub languages_c2s: Vec<String>,
    pub languages_s2c: Vec<String>,
}

impl Default for Algorithms {
    fn default() -> Self {
        Algorithms {
            kex: vec![
                "diffie-hellman-group14-sha1".to_string(),
                "diffie-hellman-group1-sha1".to_string(),
            ],
            server_host_key: vec!["ssh-rsa".to_string(), "ssh-ed25519".to_string()],
            encryption_c2s: vec!["aes128-ctr".to_string(), "aes256-ctr".to_string()],
            encryption_s2c: vec!["aes128-ctr".to_string(), "aes256-ctr".to_string()],
            mac_c2s: vec!["hmac-sha2-256".to_string(), "hmac-sha1".to_string()],
            mac_s2c: vec!["hmac-sha2-256".to_string(), "hmac-sha1".to_string()],
            compression_c2s: vec!["none".to_string()],
            compression_s2c: vec!["none".to_string()],
            languages_c2s: vec![],
            languages_s2c: vec![],
        }
    }
}

pub fn create_kexinit_message() -> SshResult<Message> {
    let mut cookie = [0x8; KEX_COOKIE_SIZE];
    OsRng.try_fill_bytes(&mut cookie)?;

    let algorithms = Algorithms::default();

    Ok(Message::KexInit {
        cookie,
        kex_algorithms: algorithms.kex,
        server_host_key_algorithms: algorithms.server_host_key,
        encryption_algorithms_client_to_server: algorithms.encryption_c2s,
        encryption_algorithms_server_to_client: algorithms.encryption_s2c,
        mac_algorithms_client_to_server: algorithms.mac_c2s,
        mac_algorithms_server_to_client: algorithms.mac_s2c,
        compression_algorithms_client_to_server: algorithms.compression_c2s,
        compression_algorithms_server_to_client: algorithms.compression_s2c,
        languages_client_to_server: algorithms.languages_c2s,
        languages_server_to_client: algorithms.languages_s2c,
        first_kex_packet_follows: false,
        reserved: 0,
    })
}

#[derive(Clone, Debug)]
pub struct NegotiatedAlgorithms {
    pub kex: String,
    pub host_key: String,
    pub encryption_c2s: String,
    pub encryption_s2c: String,
    pub mac_c2s: String,
    pub mac_s2c: String,
    pub compression_c2s: String,
    pub compression_s2c: String,
}

impl Default for NegotiatedAlgorithms {
    fn default() -> Self {
        Self {
            kex: String::new(),
            host_key: String::new(),
            encryption_c2s: String::new(),
            encryption_s2c: String::new(),
            mac_c2s: String::new(),
            mac_s2c: String::new(),
            compression_c2s: String::new(),
            compression_s2c: String::new(),
        }
    }
}

pub fn negotiate_algorithms(
    client_algorithms: &Message,
    server_algorithms: &Message,
) -> SshResult<NegotiatedAlgorithms> {
    let mut negotiated = NegotiatedAlgorithms::default();

    match (client_algorithms, server_algorithms) {
        (
            Message::KexInit {
                kex_algorithms: client_kex,
                server_host_key_algorithms: client_host_key,
                encryption_algorithms_client_to_server: client_enc_c2s,
                encryption_algorithms_server_to_client: client_enc_s2c,
                mac_algorithms_client_to_server: client_mac_c2s,
                mac_algorithms_server_to_client: client_mac_s2c,
                compression_algorithms_client_to_server: client_comp_c2s,
                compression_algorithms_server_to_client: client_comp_s2c,
                ..
            },
            Message::KexInit {
                kex_algorithms: server_kex,
                server_host_key_algorithms: server_host_key,
                encryption_algorithms_client_to_server: server_enc_c2s,
                encryption_algorithms_server_to_client: server_enc_s2c,
                mac_algorithms_client_to_server: server_mac_c2s,
                mac_algorithms_server_to_client: server_mac_s2c,
                compression_algorithms_client_to_server: server_comp_c2s,
                compression_algorithms_server_to_client: server_comp_s2c,
                ..
            },
        ) => {
            // Find matches and handle errors
            negotiated.kex = find_match(client_kex, server_kex)
                .ok_or_else(|| SshError::Protocol("No matching KEX algorithm".to_string()))?;

            negotiated.host_key = find_match(client_host_key, server_host_key)
                .ok_or_else(|| SshError::Protocol("No matching host key algorithm".to_string()))?;

            negotiated.encryption_c2s =
                find_match(client_enc_c2s, server_enc_c2s).ok_or_else(|| {
                    SshError::Protocol("No matching encryption C2S algorithm".to_string())
                })?;

            negotiated.encryption_s2c =
                find_match(client_enc_s2c, server_enc_s2c).ok_or_else(|| {
                    SshError::Protocol("No matching encryption S2C algorithm".to_string())
                })?;

            negotiated.mac_c2s = find_match(client_mac_c2s, server_mac_c2s)
                .ok_or_else(|| SshError::Protocol("No matching MAC C2S algorithm".to_string()))?;

            negotiated.mac_s2c = find_match(client_mac_s2c, server_mac_s2c)
                .ok_or_else(|| SshError::Protocol("No matching MAC S2C algorithm".to_string()))?;

            negotiated.compression_c2s =
                find_match(client_comp_c2s, server_comp_c2s).ok_or_else(|| {
                    SshError::Protocol("No matching compression C2S algorithm".to_string())
                })?;

            negotiated.compression_s2c =
                find_match(client_comp_s2c, server_comp_s2c).ok_or_else(|| {
                    SshError::Protocol("No matching compression S2C algorithm".to_string())
                })?;

            Ok(negotiated)
        }
        _ => Err(SshError::Protocol(
            "Expected KEX_INIT messages for negotiation".to_string(),
        )),
    }
}

fn find_match(client_list: &[String], server_list: &[String]) -> Option<String> {
    let server_set: HashSet<&String> = server_list.iter().collect();
    client_list
        .iter()
        .find(|algo| server_set.contains(*algo))
        .cloned()
}

pub fn generate_public_private() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::new(OsRng08);
    let public = PublicKey::from(&secret);

    (secret, public)
}

pub fn generate_shared(secret: EphemeralSecret, other_pub: PublicKey) -> SharedSecret {
    secret.diffie_hellman(&other_pub)
}

pub fn generate_new_key(k: &[u8; 32], exchange_hash: &Vec<u8>, session_id: &Vec<u8>, id_byte: u8) -> Vec<u8>{
    let mut hasher = Sha1::new();

    hasher.update(&k);
    hasher.update(&exchange_hash);
    hasher.update(&[id_byte]);
    hasher.update(&session_id);

    let new_key = hasher.finalize().to_vec();

    return new_key;
}