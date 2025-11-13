use tokio_tungstenite::connect_async;
use tokio::io::{self, AsyncBufReadExt};
use futures::{SinkExt, StreamExt};
use tungstenite::Message;
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use rand::Rng;

#[derive(Serialize, Deserialize)]
struct KeyExchange {
    public_key: String,
}

#[derive(Serialize, Deserialize)]
struct AESKeyMessage {
    encrypted_aes_key: String,
}

#[derive(Serialize, Deserialize)]
struct EncryptedMessage {
    encrypted_data: String,
    nonce: String,
}

struct ClientState {
    token: String,
    server_public_key: Option<RsaPublicKey>,
    client_private_key: RsaPrivateKey,
    client_public_key: RsaPublicKey,
    aes_key: Option<[u8; 32]>,
    aes_ready: bool,
}

pub async fn run_client() {
    let url = std::env::var("WS_URL").unwrap_or_else(|_| "ws://127.0.0.1:8080/ws".to_string());
    println!("Connecting to {}", url);

    let (ws_stream, _) = match connect_async(&url).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to connect: {:?}", e);
            return;
        }
    };
    println!("Connected to {}", url);

    // Generate RSA-2048 key pair for this client
    let mut rng = rand::thread_rng();
    let client_priv_key = match RsaPrivateKey::new(&mut rng, 2048) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Failed to generate RSA key: {:?}", e);
            return;
        }
    };
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

    // Task to receive messages from server
    let state_clone = state.clone();
    tokio::spawn(async move {
        while let Some(msg) = read.next().await {
            match msg {
                Ok(m) => {
                    if let Ok(txt) = m.to_text() {
                        let mut state = state_clone.lock().await;
                        
                        // Handle token
                        if txt.starts_with("[Token]:") {
                            state.token = txt[8..].to_string();
                            println!("Your token: {}", state.token);
                            continue;
                        }
                        
                        // Handle server public key
                        if txt.starts_with("[KeyExchange]:") {
                            if let Some(key_data) = txt.strip_prefix("[KeyExchange]:") {
                                if let Ok(key_exchange) = serde_json::from_str::<KeyExchange>(key_data) {
                                    if let Ok(key_bytes) = general_purpose::STANDARD.decode(&key_exchange.public_key) {
                                        if let Ok(server_pub) = rsa::pkcs8::DecodePublicKey::from_public_key_der(&key_bytes) {
                                            state.server_public_key = Some(server_pub);
                                            println!("Server public key received");
                                            
                                            // Send client public key back to server
                                            let client_pub_der = rsa::pkcs8::EncodePublicKey::to_public_key_der(&state.client_public_key)
                                                .expect("Failed to encode client public key");
                                            let client_pub_b64 = general_purpose::STANDARD.encode(client_pub_der.as_bytes());
                                            
                                            let key_exchange = KeyExchange {
                                                public_key: client_pub_b64,
                                            };
                                            
                                            drop(state);
                                            // Need to send this outside the lock
                                            // This will be handled by creating a channel
                                        }
                                    }
                                }
                            }
                            continue;
                        }
                        
                        // Handle AES ready confirmation
                        if txt.starts_with("[AESReady]:") {
                            state.aes_ready = true;
                            println!("E2EE encryption ready");
                            print!("[{} (you)]: ", state.token);
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                            continue;
                        }
                        
                        // Handle encrypted message
                        if txt.starts_with("[Encrypted]:") {
                            if let Some(encrypted_data) = txt.strip_prefix("[Encrypted]:") {
                                if let Ok(encrypted_msg) = serde_json::from_str::<EncryptedMessage>(encrypted_data) {
                                    if let Some(aes_key) = state.aes_key {
                                        if let Ok(encrypted_bytes) = general_purpose::STANDARD.decode(&encrypted_msg.encrypted_data) {
                                            if let Ok(nonce_bytes) = general_purpose::STANDARD.decode(&encrypted_msg.nonce) {
                                                if nonce_bytes.len() == 12 {
                                                    let cipher = Aes256Gcm::new(&aes_key.into());
                                                    let nonce = Nonce::from_slice(&nonce_bytes);
                                                    
                                                    if let Ok(decrypted) = cipher.decrypt(nonce, encrypted_bytes.as_ref()) {
                                                        let decrypted_text = String::from_utf8_lossy(&decrypted);
                                                        println!("\n{}", decrypted_text);
                                                        print!("[{} (you)]: ", state.token);
                                                        let _ = std::io::Write::flush(&mut std::io::stdout());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            continue;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Read error: {:?}", e);
                    break;
                }
            }
        }
    });

    // Wait a bit for key exchange
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Send client public key to server
    {
        let state = state.lock().await;
        if state.server_public_key.is_some() {
            let client_pub_der = rsa::pkcs8::EncodePublicKey::to_public_key_der(&state.client_public_key)
                .expect("Failed to encode client public key");
            let client_pub_b64 = general_purpose::STANDARD.encode(client_pub_der.as_bytes());
            
            let key_exchange = KeyExchange {
                public_key: client_pub_b64,
            };
            
            let _ = write.send(Message::text(format!("[ClientPublicKey]:{}", 
                serde_json::to_string(&key_exchange).unwrap()))).await;
            
            println!("Client public key sent to server");
        }
    }

    // Wait a bit more
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

    // Generate and send AES key
    {
        let mut state = state.lock().await;
        if let Some(server_pub_key) = &state.server_public_key {
            // Generate random AES-256 key
            let mut rng = rand::thread_rng();
            let aes_key: [u8; 32] = rng.gen();
            state.aes_key = Some(aes_key);
            
            // Encrypt AES key with server's RSA public key
            if let Ok(encrypted_aes) = server_pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &aes_key) {
                let encrypted_b64 = general_purpose::STANDARD.encode(&encrypted_aes);
                
                let aes_msg = AESKeyMessage {
                    encrypted_aes_key: encrypted_b64,
                };
                
                let _ = write.send(Message::text(format!("[AESKey]:{}", 
                    serde_json::to_string(&aes_msg).unwrap()))).await;
                
                println!("AES-256 key sent to server");
            }
        }
    }

    // Wait for AES ready
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

    // Task to send messages from stdin
    let stdin = io::BufReader::new(io::stdin());
    let mut lines = stdin.lines();

    // Initial prompt
    {
        let state = state.lock().await;
        print!("[{} (you)]: ", state.token);
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }

    while let Ok(Some(line)) = lines.next_line().await {
        let state = state.lock().await;
        
        if !state.aes_ready {
            println!("Encryption not ready yet, please wait...");
            print!("[{} (you)]: ", state.token);
            let _ = std::io::Write::flush(&mut std::io::stdout());
            continue;
        }
        
        if let Some(aes_key) = state.aes_key {
            // Encrypt message with AES-256-GCM
            let cipher = Aes256Gcm::new(&aes_key.into());
            
            let mut rng = rand::thread_rng();
            let nonce_bytes: [u8; 12] = rng.gen();
            let nonce = Nonce::from_slice(&nonce_bytes);
            
            if let Ok(encrypted) = cipher.encrypt(nonce, line.as_bytes()) {
                let encrypted_b64 = general_purpose::STANDARD.encode(&encrypted);
                let nonce_b64 = general_purpose::STANDARD.encode(&nonce_bytes);
                
                let encrypted_msg = EncryptedMessage {
                    encrypted_data: encrypted_b64,
                    nonce: nonce_b64,
                };
                
                if write.send(Message::text(format!("[Encrypted]:{}", 
                    serde_json::to_string(&encrypted_msg).unwrap()))).await.is_err() {
                    println!("Connection closed");
                    break;
                }
            }
        }
        
        print!("[{} (you)]: ", state.token);
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
}