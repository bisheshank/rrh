use std::env;
use std::process;
use std::net::{TcpStream, TcpListener};
use std::thread;
use std::io::{Read, Write};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rand::rngs::OsRng;

fn print_usage() {
    println!("Usage: rrh [client|server]")
}

fn handle_client(mut stream: TcpStream) {
    println!("New connection: {}", stream.peer_addr().unwrap());

    let mut buffer = [0; 512];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => {
                println!("Connection closed");
                break;
            }
            Ok(n) => {
                println!("Received: {}", String::from_utf8_lossy(&buffer[..n]));
                stream.write_all(&buffer[..n]).unwrap(); 
            }
            Err(e) => {
                println!("Error: {}", e);
                break;
            }
        }
    }
}

fn generate_keypair(bits: usize) -> (RsaPrivateKey, RsaPublicKey) {
    let private_key = RsaPrivateKey::new(&mut OsRng, bits)
        .expect("Key generation failed");
    let public_key = RsaPublicKey::from(&private_key);
    (private_key, public_key)
}

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        print_usage();
        process::exit(1);
    }

    let mode = &args[1];
    let address = &args[2];

    match mode.as_str() {
        "client" => {
            println!("Running client, listening on {}", address);
            // TODO: Implement client
        }
        "server" => {
            println!("Running server, listening on {}", address);

            let listener = TcpListener::bind(address).expect("Could not bind address");

            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        generate_keypair(2048);
                        thread::spawn(|| {
                            handle_client(stream);
                        });
                    }
                    Err(e) => {
                        println!("Connection failed: {}", e);
                    }
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
