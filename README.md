# rrh: Rust SSH Implementation

Secure Shell implementation of the [RFC4251|RFC4252|RFC4253](https://www.rfc-editor.org/rfc/rfc4253) in Rust.

## Features

- Pure Rust implementation
- Support for both client and server modes
- Asynchronous I/O using Tokio
- State machine-based architecture

## Usage

### Client Mode

```bash
rrh client 192.168.1.100:22
```

### Server Mode

```bash
rrh server 0.0.0.0:2222
```

## Building

```bash
cargo build --release
```

## Project Structure

- `client.rs` - SSH client implementation
- `server.rs` - SSH server implementation
- `constants.rs` - Protocol constants and message types
- `kex.rs` - Key exchange algorithm implementation
- `message.rs` - SSH message formats
- `ssh_codec.rs` - Binary packet encoding/decoding
- `state.rs` - SSH protocol state machine
- `transport.rs` - Low-level transport layer
- `error.rs` - Error types and handling
- `config.rs` - Configuration options

## Security Considerations

This implementation is intended for educational purposes. For production use, consider established libraries that have undergone security audits.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
