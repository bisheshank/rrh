use crate::kex::{Algorithms, NegotiatedAlgorithms};

#[derive(Clone, Debug)]
pub struct SshConfig {
    pub client_id: Option<String>,
    pub server_id: Option<String>,
    pub client_version: Option<String>,
    pub server_version: Option<String>,
    pub remote_version: Option<String>,

    pub client_kexinit: Option<Vec<u8>>,
    pub server_kexinit: Option<Vec<u8>>,

    pub local_algorithms: Algorithms,
    pub negotiated: NegotiatedAlgorithms,
}

impl Default for SshConfig {
    fn default() -> Self {
        SshConfig {
            client_id: None,
            server_id: None,
            client_version: None,
            server_version: None,
            remote_version: None,
            client_kexinit: None,
            server_kexinit: None,
            local_algorithms: Algorithms::default(),
            negotiated: NegotiatedAlgorithms::default(),
        }
    }
}
