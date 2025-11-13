use tokio_tungstenite::connect_async;
use tokio::io::{self, AsyncBufReadExt};
use futures::{SinkExt, StreamExt};
use tungstenite::Message;
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use rand::Rng;

#[derive(Serialize, Deserialize)]
struct KeyExchange { pub public_key: String }

#[derive(Serialize, Deserialize)]
struct AESKeyMessage { pub encrypted_aes_key: String }

#[derive(Serialize, Deserialize)]
struct EncryptedMessage { pub encrypted_data: String, pub nonce: String }

struct ClientState {
    token: String,
    server_public_key: Option<RsaPublicKey>,
    client_private_key: RsaPrivateKey,
    client_public_key: RsaPublicKey,
    aes_key: Option<[u8; 32]>,
    aes_ready: bool,
}

#[tokio::main]
async fn main() {
    let url = std::env::var("WS_URL").unwrap_or_else(|_| "ws://127.0.0.1:8080/ws".to_string());
    println!("Connecting to {}", url);

    let (ws_stream, _) = match connect_async(&url).await {
        Ok(v) => v,
        Err(e) => { eprintln!("Failed to connect: {:?}", e); return; }
    };
    println!("Connected to {}", url);

    let mut rng = rand::thread_rng();
    let client_priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let client_pub_key = RsaPublicKey::from(&client_priv_key);

    let state = tokio::sync::Arc::new(tokio::sync::Mutex::new(ClientState {
        token: String::new(),
        server_public_key: None,
        client_private_key: client_priv_key,
        client_public_key: client_pub_key,
        aes_key: None,
        aes_ready: false,
    }));

    let (mut write, mut read) = ws_stream.split();
    let state_clone = state.clone();

    // Task nhận message từ server
    tokio::spawn(async move {
        while let Some(msg) = read.next().await {
            match msg {
                Ok(m) => {
                    if let Ok(txt) = m.to_text() {
                        let mut state = state_clone.lock().await;

                        if txt.starts_with("[Token]:") {
                            state.token = txt[8..].to_string();
                            println!("Your token: {}", state.token);
                            continue;
                        }

                        if txt.starts_with("[KeyExchange]:") {
                            let key_data = txt.strip_prefix("[KeyExchange]:").unwrap();
                            if let Ok(key_exchange) = serde_json::from_str::<KeyExchange>(key_data) {
                                if let Ok(key_bytes) = general_purpose::STANDARD.decode(&key_exchange.public_key) {
                                    if let Ok(server_pub) = rsa::pkcs8::DecodePublicKey::from_public_key_der(&key_bytes) {
                                        state.server_public_key = Some(server_pub.clone());
                                        println!("Server public key received");

                                        // Gửi ClientPublicKey ngay lập tức
                                        let client_pub_der = rsa::pkcs8::EncodePublicKey::to_public_key_der(&state.client_public_key).unwrap();
                                        let client_pub_b64 = general_purpose::STANDARD.encode(client_pub_der.as_bytes());
                                        let key_msg = KeyExchange { public_key: client_pub_b64 };
                                        drop(state); // unlock trước khi gửi
                                        write.send(Message::text(format!("[ClientPublicKey]:{}", serde_json::to_string(&key_msg).unwrap()))).await.unwrap();
                                        println!("Client public key sent to server");

                                        // Gửi AES key ngay sau đó
                                        let mut state = state_clone.lock().await;
                                        if let Some(server_pub_key) = &state.server_public_key {
                                            let aes_key: [u8; 32] = rand::thread_rng().gen();
                                            state.aes_key = Some(aes_key);

                                            let encrypted_aes = server_pub_key.encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, &aes_key).unwrap();
                                            let aes_msg = AESKeyMessage { encrypted_aes_key: general_purpose::STANDARD.encode(&encrypted_aes) };
                                            write.send(Message::text(format!("[AESKey]:{}", serde_json::to_string(&aes_msg).unwrap()))).await.unwrap();
                                            println!("AES-256 key sent to server");
                                        }
                                    }
                                }
                            }
                            continue;
                        }

                        if txt.starts_with("[AESReady]:") {
                            state.aes_ready = true;
                            println!("E2EE encryption ready");
                            print!("[{} (you)]: ", state.token);
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                            continue;
                        }

                        if txt.starts_with("[Encrypted]:") {
                            let encrypted_data = txt.strip_prefix("[Encrypted]:").unwrap();
                            if let Ok(encrypted_msg) = serde_json::from_str::<EncryptedMessage>(encrypted_data) {
                                if let Some(aes_key) = state.aes_key {
                                    let encrypted_bytes = general_purpose::STANDARD.decode(&encrypted_msg.encrypted_data).unwrap();
                                    let nonce_bytes = general_purpose::STANDARD.decode(&encrypted_msg.nonce).unwrap();
                                    if nonce_bytes.len() == 12 {
                                        let cipher = Aes256Gcm::new(&aes_key.into());
                                        let nonce = Nonce::from_slice(&nonce_bytes);
                                        if let Ok(decrypted) = cipher.decrypt(nonce, encrypted_bytes.as_ref()) {
                                            let text = String::from_utf8_lossy(&decrypted);
                                            println!("\n{}", text);
                                            print!("[{} (you)]: ", state.token);
                                            let _ = std::io::Write::flush(&mut std::io::stdout());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => { eprintln!("Read error: {:?}", e); break; }
            }
        }
    });

    // Gửi message từ stdin
    let stdin = io::BufReader::new(io::stdin());
    let mut lines = stdin.lines();

    loop {
        if let Ok(Some(line)) = lines.next_line().await {
            let state = state.lock().await;
            if !state.aes_ready {
                println!("Encryption not ready yet, please wait...");
                print!("[{} (you)]: ", state.token);
                let _ = std::io::Write::flush(&mut std::io::stdout());
                continue;
            }

            if let Some(aes_key) = state.aes_key {
                let cipher = Aes256Gcm::new(&aes_key.into());
                let nonce_bytes: [u8; 12] = rand::thread_rng().gen();
                let nonce = Nonce::from_slice(&nonce_bytes);
                let encrypted = cipher.encrypt(nonce, line.as_bytes()).unwrap();
                let encrypted_msg = EncryptedMessage {
                    encrypted_data: general_purpose::STANDARD.encode(&encrypted),
                    nonce: general_purpose::STANDARD.encode(&nonce_bytes),
                };
                if write.send(Message::text(format!("[Encrypted]:{}", serde_json::to_string(&encrypted_msg).unwrap()))).await.is_err() {
                    println!("Connection closed");
                    break;
                }
            }

            print!("[{} (you)]: ", state.token);
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }
    }
}