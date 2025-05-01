#[derive(Clone)]
pub struct SshConfig {
    pub client_id: Option<String>,
    pub server_id: Option<String>,
    pub client_version: Option<String>,
    pub server_version: Option<String>,
    pub remote_version: Option<String>,
    // Need to add negotiated algorithms and such
}

impl Default for SshConfig {
    fn default() -> Self {
        SshConfig {
            client_id: None,
            server_id: None,
            client_version: None,
            server_version: None,
            remote_version: None,
        }
    }
}
