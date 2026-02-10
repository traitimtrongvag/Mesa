![Mesa](.github/assets/cover.png)

[![Build Status](https://github.com/traitimtrongvag/Mesa/actions/workflows/build.yml/badge.svg)](https://github.com/traitimtrongvag/Mesa/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.md)
[![Rust Version](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

# Mesa

Mesa is a privacy-focused, end-to-end encrypted messaging platform built with Rust. It prioritizes security and user privacy by implementing zero-knowledge architecture where even the server cannot decrypt your messages.

### How does Mesa work?

- **End-to-End Encryption:** All messages are encrypted on the client side using RSA-2048 and AES-256-GCM. The server acts as a relay and cannot decrypt any messages.
- **Zero-Knowledge Architecture:** The server has zero knowledge of message content. Only the intended recipient can decrypt messages using their private key.
- **Lightweight and Fast:** Built with Rust for performance and memory safety. The WebSocket-based architecture ensures low latency message delivery.
- **Privacy First:** No message storage on the server. Messages are relayed in real-time and never persisted on the backend.

### Security Features

Mesa implements military-grade encryption to protect your communications:

- **RSA-2048 Key Exchange:** Asymmetric encryption ensures secure key distribution between clients
- **AES-256-GCM Encryption:** Symmetric encryption for message content with authenticated encryption
- **Perfect Forward Secrecy:** Each conversation uses unique session keys
- **Nonce-Based Protection:** Counter-based nonce generation prevents replay attacks

### Architecture

The platform consists of two main components:

- **Server:** A WebSocket relay built with Warp framework that routes encrypted messages between clients without the ability to decrypt them
- **Client:** A terminal-based client with full E2EE capabilities, supporting real-time encrypted messaging

## Installation

### Prerequisites

- Rust 1.75 or higher
- Cargo package manager

### Building from Source

```bash
git clone https://github.com/traitimtrongvag/Mesa.git
cd Mesa
cargo build --release
```

### Running the Server

```bash
cargo run --bin server
```

The server will start on `ws://0.0.0.0:8081/ws` by default.

### Running the Client

```bash
cargo run --bin client
```

Or connect to a custom server:

```bash
WS_URL=wss://your-server.com/ws cargo run --bin client
```

## Usage

### Client Commands

Once connected, you can use these commands:

- `/to <token> <message>` - Send encrypted message to a specific user
- `/list` - Show online users
- `exit` or `quit` - Disconnect from server

### Example Session

```
$ cargo run --bin client
Connecting to ws://127.0.0.1:8081/ws...
Connected
Your token: abc123xyz

Online: ["abc123xyz", "def456uvw"]

/to def456uvw Hello, this message is encrypted!
```

## Documentation

### Message Protocol

Mesa uses a JSON-based protocol with the following message types:

- **Token:** Authentication token assignment
- **PublicKey:** RSA public key distribution
- **KeyExchange:** Encrypted AES session key exchange
- **ChatMessage:** Encrypted message content
- **ClientList:** Online users list

### Encryption Flow

```
Client A                    Server                    Client B
   |                          |                          |
   |-- RSA Public Key ------->|------- Relay ----------->|
   |                          |                          |
   |<----- Encrypted AES -----|<----- Encrypted AES -----|
   |                          |                          |
   |-- Encrypted Message ---->|------- Relay ----------->|
   |                          |                          |
   Server CANNOT decrypt messages (zero-knowledge)
```

### Deployment

Mesa can be easily deployed on cloud platforms. See `.render.yaml` for Render deployment configuration.

## Project Structure

```
Mesa/
├── src/
│   ├── lib.rs          # Shared library root
│   ├── protocol.rs     # Message protocol definitions
│   ├── token.rs        # Token generation utilities
│   ├── server.rs       # WebSocket server
│   └── client.rs       # Terminal client
├── Cargo.toml          # Dependencies
└── .render.yaml        # Deployment configuration
```

## About Mesa

Mesa was built with the belief that privacy is a fundamental right. In an era of increasing surveillance and data breaches, Mesa provides a secure communication channel where your conversations remain truly private.

The project is open source and welcomes contributions from the community to make private communication accessible to everyone.

## Contributing

Contributions are welcome. Please follow these guidelines:

- Fork the repository
- Create a feature branch
- Write clean, documented code
- Add tests for new functionality
- Submit a pull request

For major changes, please open an issue first to discuss what you would like to change.

## Security

If you discover a security vulnerability, please email security concerns to the maintainers rather than using the issue tracker.

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.

## Acknowledgments

Mesa is built on top of excellent open-source projects:

- [Warp](https://github.com/seanmonstar/warp) - Web server framework
- [Tokio](https://github.com/tokio-rs/tokio) - Asynchronous runtime
- [RSA](https://github.com/RustCrypto/RSA) - RSA encryption
- [AES-GCM](https://github.com/RustCrypto/AEADs) - Authenticated encryption
