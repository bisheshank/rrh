use std::env;
use std::process;

use log::info;
use rrh::client::SshClient;
use rrh::config::SshConfig;
use rrh::constants::PROTOCOL_VERSION;
use rrh::error::SshResult;
use rrh::server::SshServer;

fn print_usage() {
    println!(
        r#"Usage: rrh [client|server] <address>

Options:
    client          Run in SSH client mode.
    server          Run in SSH server mode.
    <address>       Optional. IP:PORT to connect to or listen on.
                    Defaults to 127.0.0.1:3000 if not provided.

Examples:
    rrh server 0.0.0.0:2222
    rrh client 127.0.0.1:2222
"#
    );
}

fn run_server(address: &str) -> SshResult<()> {
    println!("Starting SSH server...");

    let mut config = SshConfig::default();
    config.server_version = Some(String::from(PROTOCOL_VERSION));

    let server = SshServer::new(config);

    server.listen(address)?;

    println!("SSH server finished");

    Ok(())
}

fn run_client(address: &str) -> SshResult<()> {
    println!("Starting SSH client...");

    let mut config = SshConfig::default();
    config.client_version = Some(String::from(PROTOCOL_VERSION));

    let _client = SshClient::connect(address, config)?;

    Ok(())
}

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    let mode = &args[1];
    let address = if args.len() >= 3 && !args[2].trim().is_empty() {
        args[2].clone()
    } else {
        String::from("127.0.0.1:3000")
    };

    let result = match mode.as_str() {
        "client" => run_client(&address),
        "server" => run_server(&address),
        _ => {
            eprintln!("Invalid mode: {}", mode);
            print_usage();
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
