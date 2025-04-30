use std::env;
use std::process;

use rrh::client::Client;
use rrh::server::Server;

fn print_usage() {
    println!("Usage: rrh [client|server]")
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

    match mode.as_str() {
        "client" => {
            println!("Running client, connecting to {}", address);

            match Client::connect(&address) {
                Ok(_client) => {
                    println!("Connected successfully!")

                    // TODO: Continue with the key exchange
                }
                Err(e) => {
                    eprintln!("Failed to connect: {}", e);
                    process::exit(1);
                }
            }
        }
        "server" => {
            println!("Running server, listening on {}", address);

            match Server::listen(&address) {
                Ok(server) => {
                    if let Err(e) = server.run() {
                        eprintln!("Failed to run server: {}", e);
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to connect: {}", e);
                    process::exit(1);
                }
            }
        }
        _ => {
            println!("Unknown mode: {}", mode);
            print_usage();
            process::exit(1);
        }
    }
}
