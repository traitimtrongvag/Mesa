use anyhow::Result;
use bytes::BufMut; // xóa BytesMut vì không dùng
use clap::{Parser, Subcommand};
use dirs::config_dir;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use snow::Builder;
use std::fs;
use std::io::{self};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::io::AsyncBufReadExt;

const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const KEYFILE: &str = "rust_message_identity.key";

#[derive(Parser)]
#[command(name = "rust-message")]
#[command(about = "PoC Noise chat (terminal)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Server { listen: String },
    Connect { addr: String },
    GenKey,
}

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
        // nếu key chưa tồn tại -> tạo mới
        let mut sk = [0u8; 32];
        OsRng.fill_bytes(&mut sk);
        save_privkey(&sk)?;
        println!("Generated new key at {:?}", p);
    }
    let s = fs::read_to_string(p)?;
    let kp: Keypair = serde_json::from_str(&s)?;
    Ok(general_purpose::STANDARD.decode(kp.privkey_b64)?)
}


/// Write a length-prefixed message
async fn write_lp(stream: &mut TcpStream, buf: &[u8]) -> Result<()> {
    let len = buf.len() as u16;
    let mut tmp = Vec::with_capacity(2 + buf.len());
    tmp.put_u16(len);
    tmp.extend_from_slice(buf);
    stream.write_all(&tmp).await?;
    Ok(())
}

/// Read length-prefixed message (u16)
async fn read_lp(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut lenbuf = [0u8; 2];
    stream.read_exact(&mut lenbuf).await?;
    let len = u16::from_be_bytes(lenbuf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Do Noise XX handshake: returns transport_state
async fn noise_handshake_initiator(stream: &mut TcpStream) -> Result<snow::TransportState> {
    let privkey = load_privkey()?; // load key từ file

    let builder = Builder::new(PATTERN.parse()?);
    let mut noise = builder
        .local_private_key(&privkey)  // <--- thêm dòng này
        .build_initiator()?;

    let mut buf = vec![0u8; 65535];

    // -> msg_0
    let len = noise.write_message(&[], &mut buf)?;
    write_lp(stream, &buf[..len]).await?;

    // <- msg_1
    let resp = read_lp(stream).await?;
    let _ = noise.read_message(&resp, &mut buf)?;

    // -> msg_2
    let len2 = noise.write_message(&[], &mut buf)?;
    write_lp(stream, &buf[..len2]).await?;

    let transport = noise.into_transport_mode()?;
    Ok(transport)
}

async fn noise_handshake_responder(stream: &mut TcpStream) -> Result<snow::TransportState> {
    let privkey = load_privkey()?; // load key từ file

    let builder = Builder::new(PATTERN.parse()?);
    let mut noise = builder
        .local_private_key(&privkey)  // <--- thêm dòng này
        .build_responder()?;

    let mut buf = vec![0u8; 65535];

    // <- msg_0
    let m0 = read_lp(stream).await?;
    let _ = noise.read_message(&m0, &mut buf)?;

    // -> msg_1
    let len1 = noise.write_message(&[], &mut buf)?;
    write_lp(stream, &buf[..len1]).await?;

    // <- msg_2
    let m2 = read_lp(stream).await?;
    let _ = noise.read_message(&m2, &mut buf)?;

    let transport = noise.into_transport_mode()?;
    Ok(transport)
}
async fn handle_conn(mut stream: TcpStream, is_server: bool) -> Result<()> {
    // handshake
    let transport = if is_server {
        noise_handshake_responder(&mut stream).await?
    } else {
        noise_handshake_initiator(&mut stream).await?
    };

    // Wrap transport in Arc<Mutex> để share giữa tasks
    let transport = Arc::new(Mutex::new(transport));
    
    let (mut read_half, mut write_half) = stream.into_split();
    
    // Clone Arc cho receiver task
    let transport_recv = Arc::clone(&transport);
    
    // Spawn receiver
    let recv_task = tokio::spawn(async move {
        loop {
            let mut lenbuf = [0u8; 2];
            if read_half.read_exact(&mut lenbuf).await.is_err() {
                break;
            }
            let len = u16::from_be_bytes(lenbuf) as usize;
            let mut ct = vec![0u8; len];
            if read_half.read_exact(&mut ct).await.is_err() {
                break;
            }
            
            let mut pt = vec![0u8; ct.len() + 1024];
            let result = {
                let mut t = transport_recv.lock().await;
                t.read_message(&ct, &mut pt)
            };
            
            match result {
                Ok(len) => {
                    let msg = String::from_utf8_lossy(&pt[..len]);
                    println!("\n<< {}", msg);
                    print!(">> ");
                    let _ = io::Write::flush(&mut io::stdout());
                }
                Err(e) => {
                    eprintln!("decrypt error: {:?}", e);
                    break;
                }
            }
        }
    });

    // sender loop - đọc từ stdin
    println!("You can type messages. Ctrl+C to exit.");
    let stdin = tokio::io::stdin();
    let mut reader = tokio::io::BufReader::new(stdin);
    
    loop {
        print!(">> ");
        io::Write::flush(&mut io::stdout())?;
        
        let mut input = String::new();
        match reader.read_line(&mut input).await {
            Ok(0) => break, // EOF
            Ok(_) => {
                if input.trim().is_empty() {
                    continue;
                }
                
                let plaintext = input.trim().as_bytes();
                let mut buf = vec![0u8; plaintext.len() + 1024];
                
                let len = {
                    let mut t = transport.lock().await;
                    t.write_message(plaintext, &mut buf)?
                };
                
                // Write length prefix
                let msg_len = len as u16;
                write_half.write_u16(msg_len).await?;
                write_half.write_all(&buf[..len]).await?;
            }
            Err(e) => {
                eprintln!("stdin error: {:?}", e);
                break;
            }
        }
    }

    let _ = recv_task.await;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Kiểm tra biến môi trường RENDER hoặc PORT
    let is_render = std::env::var("PORT").is_ok();

    // Nếu chạy trên Render, tự tạo server subcommand
    let cli_cmd = if is_render {
        Commands::Server { 
            listen: format!("0.0.0.0:{}", std::env::var("PORT").unwrap()) 
        }
    } else {
        Cli::parse().cmd
    };

    match cli_cmd {
        Commands::GenKey => {
            let mut sk = [0u8; 32];
            OsRng.fill_bytes(&mut sk);
            save_privkey(&sk)?;
            println!("Saved key to {:?}", get_keypath());
        }
        Commands::Server { listen } => {
            // server tự sinh key nếu chưa có
            let _ = load_privkey()?;
            let listener = TcpListener::bind(&listen).await?;
            println!("Listening on {}", listen);
            loop {
                let (stream, addr) = listener.accept().await?;
                println!("Accepted from {}", addr);
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, true).await {
                        eprintln!("conn error: {:?}", e);
                    }
                });
            }
        }
        Commands::Connect { addr } => {
            println!("Connecting to {}", addr);
            let stream = TcpStream::connect(&addr).await?;
            handle_conn(stream, false).await?;
        }
    }

    Ok(())
}