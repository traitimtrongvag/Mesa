use tokio_tungstenite::connect_async;
use tokio::io::{self, AsyncBufReadExt};
use futures::{SinkExt, StreamExt};
use tungstenite::Message;
use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::{EncodePublicKey, DecodePublicKey, LineEnding};
use rsa::pkcs1v15::{Encryptor, Decryptor};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rand::RngCore;
use base64::{Engine as _, engine::general_purpose};

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
enum WsMessage {
    #[serde(rename = "pubkey")]
    PublicKey { token: String, key: String },
    #[serde(rename = "key_exchange")]
    KeyExchange { to: String, from: String, payload: String },
    #[serde(rename = "msg")]
    ChatMessage { to: String, from: String, n: u64, data: String },
    #[serde(rename = "token")]
    Token { token: String },
    #[serde(rename = "clients")]
    ClientList { clients: Vec<String> },
}

struct Session {
    token: String,
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
    peer_keys: Arc<Mutex<std::collections::HashMap<String, RsaPublicKey>>>,
    aes_keys: Arc<Mutex<std::collections::HashMap<String, (Vec<u8>, Vec<u8>, u64)>>>,
}

#[tokio::main]
async fn main() {
    let url = std::env::var("WS_URL")
        .unwrap_or_else(|_| "ws://127.0.0.1:8081/ws".to_string());

    println!("Connecting to {}", url);

    let (ws_stream, _) = match connect_async(&url).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to connect: {:?}", e);
            return;
        }
    };

    println!("Connected");

    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate key");
    let public_key = RsaPublicKey::from(&private_key);

    let session = Arc::new(Mutex::new(Session {
        token: String::new(),
        private_key,
        public_key: public_key.clone(),
        peer_keys: Arc::new(Mutex::new(std::collections::HashMap::new())),
        aes_keys: Arc::new(Mutex::new(std::collections::HashMap::new())),
    }));

    let (write, mut read) = ws_stream.split();

    let session_clone = session.clone();
    let write_clone = Arc::new(Mutex::new(write));
    let write_for_handler = write_clone.clone();

    tokio::spawn(async move {
        while let Some(msg) = read.next().await {
            match msg {
                Ok(m) => {
                    if let Ok(txt) = m.to_text() {
                        handle_message(txt, &session_clone, &write_for_handler).await;
                    }
                }
                Err(e) => {
                    eprintln!("Read error: {:?}", e);
                    break;
                }
            }
        }
    });

    let stdin = io::BufReader::new(io::stdin());
    let mut lines = stdin.lines();

    loop {
        if let Ok(Some(line)) = lines.next_line().await {
            if line.starts_with("/to ") {
                let parts: Vec<&str> = line.splitn(3, ' ').collect();
                if parts.len() == 3 {
                    let to = parts[1];
                    let text = parts[2];
                    let mut w = write_clone.lock().await;
                    send_encrypted_message(&mut *w, &session, to, text).await;
                }
            } else {
                println!("Usage: /to <token> <message>");
            }
        }
    }
}

async fn handle_message(
    text: &str,
    session: &Arc<Mutex<Session>>,
    write: &Arc<Mutex<futures::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>>>,
) {
    let ws_msg = match serde_json::from_str::<WsMessage>(text) {
        Ok(m) => m,
        Err(_) => return,
    };

    match ws_msg {
        WsMessage::Token { token } => {
            let mut s = session.lock().await;
            s.token = token.clone();
            println!("Your token: {}", token);

            if let Ok(public_key_pem) = s.public_key.to_public_key_pem(LineEnding::LF) {
                let pubkey_msg = WsMessage::PublicKey {
                    token: token.clone(),
                    key: public_key_pem,
                };
                if let Ok(json) = serde_json::to_string(&pubkey_msg) {
                    let mut w = write.lock().await;
                    let _ = w.send(Message::text(json)).await;
                }
            }
        }
        WsMessage::ClientList { clients } => {
            println!("Online: {:?}", clients);
        }
        WsMessage::PublicKey { token, key } => {
            let s = session.lock().await;
            let my_token = s.token.clone();
            let peer_keys = s.peer_keys.clone();
            drop(s);

            if token != my_token {
                match RsaPublicKey::from_public_key_pem(&key) {
                    Ok(pub_key) => {
                        let mut pk = peer_keys.lock().await;
                        pk.insert(token.clone(), pub_key);
                        println!("Received public key from {}", token);
                    }
                    Err(e) => {
                        eprintln!("Failed to parse public key from {}: {:?}", token, e);
                    }
                }
            }
        }
        WsMessage::KeyExchange { from, payload, .. } => {
            let s = session.lock().await;
            let private_key = s.private_key.clone();
            let aes_keys = s.aes_keys.clone();
            drop(s);

            let encrypted = match general_purpose::STANDARD.decode(&payload) {
                Ok(e) => e,
                Err(_) => {
                    eprintln!("Failed to decode key exchange from {}", from);
                    return;
                }
            };

            let decryptor = Decryptor::new(&private_key);
            let decrypted = match decryptor.decrypt(&encrypted) {
                Ok(d) => d,
                Err(_) => {
                    eprintln!("Failed to decrypt key exchange from {}", from);
                    return;
                }
            };

            if decrypted.len() < 44 {
                eprintln!("Invalid key exchange payload from {}", from);
                return;
            }

            let aes_key = decrypted[0..32].to_vec();
            let nonce_seed = decrypted[32..44].to_vec();

            let mut keys = aes_keys.lock().await;
            keys.insert(from.clone(), (aes_key, nonce_seed, 0));
            println!("Key exchange completed with {}", from);
        }
        WsMessage::ChatMessage { from, n, data, .. } => {
            let s = session.lock().await;
            let aes_keys = s.aes_keys.clone();
            drop(s);

            let mut keys = aes_keys.lock().await;

            if let Some((aes_key, nonce_seed, counter)) = keys.get_mut(&from) {
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));

                let mut nonce_bytes = nonce_seed.clone();
                let counter_bytes = n.to_le_bytes();
                nonce_bytes.extend_from_slice(&counter_bytes[0..4]);

                if nonce_bytes.len() < 12 {
                    eprintln!("Invalid nonce length");
                    return;
                }

                let nonce = Nonce::from_slice(&nonce_bytes[0..12]);

                let ciphertext = match general_purpose::STANDARD.decode(&data) {
                    Ok(c) => c,
                    Err(_) => {
                        eprintln!("Failed to decode message from {}", from);
                        return;
                    }
                };

                match cipher.decrypt(nonce, ciphertext.as_ref()) {
                    Ok(plaintext) => {
                        if let Ok(message) = String::from_utf8(plaintext) {
                            println!("{}: {}", from, message);
                            *counter = n + 1;
                        } else {
                            eprintln!("Failed to decode UTF-8 from {}", from);
                        }
                    }
                    Err(_) => {
                        eprintln!("Failed to decrypt message from {}", from);
                    }
                }
            } else {
                eprintln!("No AES key for {}", from);
            }
        }
    }
}

async fn send_encrypted_message(
    write: &mut futures::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>,
    session: &Arc<Mutex<Session>>,
    to: &str,
    text: &str,
) {
    let s = session.lock().await;
    let my_token = s.token.clone();
    let peer_keys = s.peer_keys.clone();
    let aes_keys = s.aes_keys.clone();
    drop(s);

    let mut keys = aes_keys.lock().await;

    if !keys.contains_key(to) {
        let pk = peer_keys.lock().await;
        let peer_key = match pk.get(to) {
            Some(k) => k.clone(),
            None => {
                eprintln!("No public key for {}", to);
                return;
            }
        };
        drop(pk);

        let mut rng = rand::thread_rng();
        let mut aes_key = vec![0u8; 32];
        let mut nonce_seed = vec![0u8; 12];
        rng.fill_bytes(&mut aes_key);
        rng.fill_bytes(&mut nonce_seed);

        let mut payload = aes_key.clone();
        payload.extend_from_slice(&nonce_seed);

        let encryptor = Encryptor::new(&peer_key);
        let encrypted = match encryptor.encrypt(&mut rng, &payload) {
            Ok(e) => e,
            Err(_) => {
                eprintln!("Failed to encrypt key for {}", to);
                return;
            }
        };

        let encoded = general_purpose::STANDARD.encode(&encrypted);

        let msg = WsMessage::KeyExchange {
            to: to.to_string(),
            from: my_token.clone(),
            payload: encoded,
        };

        keys.insert(to.to_string(), (aes_key, nonce_seed, 0));

        if let Ok(json) = serde_json::to_string(&msg) {
            let _ = write.send(Message::text(json)).await;
        }
    }

    if let Some((aes_key, nonce_seed, counter)) = keys.get_mut(to) {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));

        let mut nonce_bytes = nonce_seed.clone();
        let counter_bytes = counter.to_le_bytes();
        nonce_bytes.extend_from_slice(&counter_bytes[0..4]);

        let nonce = Nonce::from_slice(&nonce_bytes[0..12]);

        match cipher.encrypt(nonce, text.as_bytes()) {
            Ok(ciphertext) => {
                let encoded = general_purpose::STANDARD.encode(&ciphertext);

                let msg = WsMessage::ChatMessage {
                    to: to.to_string(),
                    from: my_token,
                    n: *counter,
                    data: encoded,
                };

                *counter += 1;

                if let Ok(json) = serde_json::to_string(&msg) {
                    let _ = write.send(Message::text(json)).await;
                }
            }
            Err(_) => {
                eprintln!("Failed to encrypt message");
            }
        }
    }
}