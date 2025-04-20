use std::env;
use std::process;

fn print_usage() {
    println!("Usage: rrh [client|server]")
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
            // TODO: Implement server
        }
        _ => {
            println!("Unknown mode: {}", mode);
            print_usage();
            process::exit(1);
        }
    }
}
