// src/main.rs
use anyhow::Result;
use bytes::BufMut;
use clap::Parser;
use dirs::config_dir;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use snow::Builder;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_hdr_async, tungstenite::handshake::server::Request};
use futures_util::{SinkExt, StreamExt};

// CONFIG
const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const KEYFILE: &str = "rust_message_identity.key";

// --- key load/save (reuse your format)
#[derive(Serialize, Deserialize)]
struct Keypair {
    privkey_b64: String,
}

fn get_keypath() -> PathBuf {
    if let Some(mut d) = config_dir() {
        d.push("rust_message");
        fs::create_dir_all(&d).ok();
        d.push(KEYFILE);
        d
    } else {
        PathBuf::from(KEYFILE)
    }
}

fn save_privkey(privkey: &[u8]) -> Result<()> {
    use base64::{engine::general_purpose, Engine as _};
    let kp = Keypair {
        privkey_b64: general_purpose::STANDARD.encode(privkey),
    };
    let p = get_keypath();
    let s = serde_json::to_string(&kp)?;
    fs::write(p, s)?;
    Ok(())
}

fn load_privkey() -> Result<Vec<u8>> {
    use base64::{engine::general_purpose, Engine as _};
    let p = get_keypath();
    if !p.exists() {
        let mut sk = [0u8; 32];
        OsRng.fill_bytes(&mut sk);
        save_privkey(&sk)?;
        println!("Gateway generated key at {:?}", p);
    }
    let s = fs::read_to_string(p)?;
    let kp: Keypair = serde_json::from_str(&s)?;
    Ok(general_purpose::STANDARD.decode(kp.privkey_b64)?)
}

/// Write length-prefixed buf to TcpStream (u16 BE)
async fn write_lp_tcp(stream: &mut TcpStream, buf: &[u8]) -> Result<()> {
    let len = buf.len() as u16;
    let mut tmp = Vec::with_capacity(2 + buf.len());
    tmp.put_u16(len);
    tmp.extend_from_slice(buf);
    stream.write_all(&tmp).await?;
    Ok(())
}

/// Read length-prefixed buf from TcpStream
async fn read_lp_tcp(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut lenbuf = [0u8; 2];
    stream.read_exact(&mut lenbuf).await?;
    let len = u16::from_be_bytes(lenbuf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Perform Noise XX initiator handshake with the backend TCP server.
/// This code is similar to your initiator function but adapted for reuse here.
async fn noise_handshake_initiator_tcp(stream: &mut TcpStream, privkey: &[u8]) -> Result<snow::TransportState> {
    let builder = Builder::new(PATTERN.parse()?);
    let mut noise = builder
        .local_private_key(privkey)
        .build_initiator()?;

    let mut buf = vec![0u8; 65535];

    // -> msg_0
    let len = noise.write_message(&[], &mut buf)?;
    write_lp_tcp(stream, &buf[..len]).await?;

    // <- msg_1
    let resp = read_lp_tcp(stream).await?;
    let _ = noise.read_message(&resp, &mut buf)?;

    // -> msg_2
    let len2 = noise.write_message(&[], &mut buf)?;
    write_lp_tcp(stream, &buf[..len2]).await?;

    let transport = noise.into_transport_mode()?;
    Ok(transport)
}

/// Bridge a single websocket connection to a single Noise/TCP connection to backend.
async fn handle_ws_client(ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>, backend_addr: &str, privkey: Vec<u8>) -> Result<()> {
    let (mut ws_sink, mut ws_stream) = ws.split();

    // Connect to backend TCP server
    let mut tcp = TcpStream::connect(backend_addr).await?;
    // perform Noise handshake as initiator
    let mut transport = noise_handshake_initiator_tcp(&mut tcp, &privkey).await?;
    // Wrap transport in Arc<Mutex> for safety (not necessary with single task, but ok)
    let transport = Arc::new(Mutex::new(transport));
    let tcp_for_read = tcp.try_clone()?; // clone for read loop (requires tokio::net::TcpStream supports try_clone)
    let mut tcp_read = tcp_for_read;

    // Task A: Forward websocket -> backend (plaintext from client)
    let transport_tx = Arc::clone(&transport);
    let mut tcp_write = tcp; // owned tcp for writing
    let backend_writer = tokio::spawn(async move {
        while let Some(msg) = ws_stream.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    let plaintext = text.as_bytes();
                    let mut cipher_buf = vec![0u8; plaintext.len() + 1024];
                    let len = {
                        let mut t = transport_tx.lock().await;
                        t.write_message(plaintext, &mut cipher_buf)
                    }.map_err(|e| anyhow::anyhow!("noise write error: {:?}", e))?;
                    // send length-prefixed cipher to backend
                    write_lp_tcp(&mut tcp_write, &cipher_buf[..len]).await?;
                }
                Ok(Message::Binary(bin)) => {
                    let plaintext = bin.as_slice();
                    let mut cipher_buf = vec![0u8; plaintext.len() + 1024];
                    let len = {
                        let mut t = transport_tx.lock().await;
                        t.write_message(plaintext, &mut cipher_buf)
                    }.map_err(|e| anyhow::anyhow!("noise write error: {:?}", e))?;
                    write_lp_tcp(&mut tcp_write, &cipher_buf[..len]).await?;
                }
                Ok(Message::Close(_)) | Err(_) => {
                    break;
                }
                _ => {}
            }
        }
        // close backend tcp
        let _ = tcp_write.shutdown().await;
        Ok::<(), anyhow::Error>(())
    });

    // Task B: Forward backend -> websocket
    let transport_rx = Arc::clone(&transport);
    let backend_reader = tokio::spawn(async move {
        loop {
            let ct = match read_lp_tcp(&mut tcp_read).await {
                Ok(b) => b,
                Err(e) => {
                    // backend closed or error
                    //println!("backend read error: {:?}", e);
                    break;
                }
            };
            let mut pt = vec![0u8; ct.len() + 1024];
            let len = {
                let mut t = transport_rx.lock().await;
                match t.read_message(&ct, &mut pt) {
                    Ok(l) => l,
                    Err(e) => {
                        eprintln!("noise read error: {:?}", e);
                        break;
                    }
                }
            };
            // send plaintext to websocket client as text
            let plain_slice = &pt[..len];
            if ws_sink.send(Message::Text(String::from_utf8_lossy(plain_slice).to_string())).await.is_err() {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let _ = tokio::try_join!(backend_writer, backend_reader);
    Ok(())
}

#[derive(Parser)]
struct Args {
    /// backend address (host:port)
    #[arg(long, default_value = "127.0.0.1:10000")]
    backend: String,
    /// listen port for gateway (use $PORT in Render)
    #[arg(long, default_value = "8080")]
    port: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let privkey = load_privkey()?; // gateway will use same key format and do noise with backend

    // Listen TCP for WebSocket handshake (HTTP)
    let listen_port = std::env::var("PORT").unwrap_or(args.port.clone());
    let addr = format!("0.0.0.0:{}", listen_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("WebSocket gateway listening on {}", addr);
    println!("Forwarding to backend {}", args.backend);

    loop {
        let (stream, peer) = listener.accept().await?;
        let backend = args.backend.clone();
        let pk = privkey.clone();
        // Accept WebSocket handshake
        tokio::spawn(async move {
            // Use accept_hdr_async to accept any origin
            let ws = match tokio_tungstenite::accept_async(stream).await {
                Ok(ws) => ws,
                Err(e) => {
                    eprintln!("ws accept error: {:?}", e);
                    return;
                }
            };
            if let Err(e) = handle_ws_client(ws, &backend, pk).await {
                eprintln!("bridge error for {}: {:?}", peer, e);
            }
        });
    }
}