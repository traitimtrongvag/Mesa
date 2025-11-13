use warp::Filter;
use std::sync::{Arc, Mutex};
use futures::{SinkExt, StreamExt};
use warp::ws::{Message, WebSocket};
use std::collections::HashMap;
use tokio::sync::mpsc::UnboundedSender;
use rand::{Rng, distributions::Alphanumeric};
use rand::rngs::StdRng;
use rand::SeedableRng;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};

type Clients = Arc<Mutex<HashMap<String, ClientInfo>>>;

#[derive(Clone)]
struct ClientInfo {
    tx: UnboundedSender<Message>,
    rsa_private: RsaPrivateKey,
    rsa_public: RsaPublicKey,
    client_public: Option<RsaPublicKey>,
    aes_key: Option<[u8; 32]>,
}

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

pub async fn run_server(port: u16) {
    let clients: Clients = Arc::new(Mutex::new(HashMap::new()));
    let clients_filter = warp::any().map(move || clients.clone());

    let ws_route = warp::path("ws")
        .and(warp::ws())
        .and(clients_filter)
        .map(|ws: warp::ws::Ws, clients: Clients| {
            let clients = clients.clone();
            ws.on_upgrade(move |socket| async move {
                client_connected(socket, clients).await;
            })
        });

    println!("E2EE WebSocket server on port {} (path /ws)", port);
    println!("Protocol: RSA-2048 key exchange + AES-256-GCM encryption");
    
    warp::serve(ws_route).run(([0, 0, 0, 0], port)).await;
}

fn generate_token(len: usize, rng: &mut StdRng) -> String {
    rng.sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

async fn client_connected(ws: WebSocket, clients: Clients) {
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();

    let mut rng = StdRng::from_entropy();
    let token_len = rng.gen_range(10..=12);
    let token = generate_token(token_len, &mut rng);

    // RSA key pair
    let priv_key = match RsaPrivateKey::new(&mut rng, 2048) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("RSA key generation error: {:?}", e);
            return;
        }
    };
    let pub_key = RsaPublicKey::from(&priv_key);

    println!("Client [{}] connected", token);

    // Send server public key
    let pub_key_der = rsa::pkcs8::EncodePublicKey::to_public_key_der(&pub_key).unwrap();
    let pub_key_b64 = general_purpose::STANDARD.encode(pub_key_der.as_bytes());
    let key_exchange = KeyExchange { public_key: pub_key_b64 };
    let _ = tx.send(Message::text(format!("[KeyExchange]:{}", serde_json::to_string(&key_exchange).unwrap())));
    let _ = tx.send(Message::text(format!("[Token]:{}", token)));

    // Store client info
    let client_info = ClientInfo {
        tx: tx.clone(),
        rsa_private: priv_key.clone(),
        rsa_public: pub_key,
        client_public: None,
        aes_key: None,
    };
    clients.lock().unwrap().insert(token.clone(), client_info);

    // Task gửi tin nhắn
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_tx.send(msg).await.is_err() { break; }
        }
    });

    while let Some(result) = ws_rx.next().await {
        match result {
            Ok(msg) => {
                if msg.is_text() {
                    let text = msg.to_str().unwrap_or("").to_string();

                    // Nhận client public key
                    if text.starts_with("[ClientPublicKey]:") {
                        if let Some(key_data) = text.strip_prefix("[ClientPublicKey]:") {
                            if let Ok(key_exchange) = serde_json::from_str::<KeyExchange>(key_data) {
                                if let Ok(key_bytes) = general_purpose::STANDARD.decode(&key_exchange.public_key) {
                                    if let Ok(client_pub) = rsa::pkcs8::DecodePublicKey::from_public_key_der(&key_bytes) {
                                        let mut clients_map = clients.lock().unwrap();
                                        if let Some(client) = clients_map.get_mut(&token) {
                                            client.client_public = Some(client_pub);
                                            println!("Client [{}] public key received", token);
                                        }
                                    }
                                }
                            }
                        }
                        continue;
                    }

                    // Nhận AES key
                    if text.starts_with("[AESKey]:") {
                        if let Some(key_data) = text.strip_prefix("[AESKey]:") {
                            if let Ok(aes_msg) = serde_json::from_str::<AESKeyMessage>(key_data) {
                                if let Ok(encrypted_bytes) = general_purpose::STANDARD.decode(&aes_msg.encrypted_aes_key) {
                                    let mut clients_map = clients.lock().unwrap();
                                    if let Some(client) = clients_map.get_mut(&token) {
                                        if let Ok(decrypted) = client.rsa_private.decrypt(Pkcs1v15Encrypt, &encrypted_bytes) {
                                            if decrypted.len() == 32 {
                                                let mut aes_key = [0u8; 32];
                                                aes_key.copy_from_slice(&decrypted);
                                                client.aes_key = Some(aes_key);
                                                println!("Client [{}] AES-256 key established", token);
                                                let _ = client.tx.send(Message::text("[AESReady]:OK".to_string()));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        continue;
                    }

                    // Tin nhắn mã hóa
                    if text.starts_with("[Encrypted]:") {
                        if let Some(encrypted_data) = text.strip_prefix("[Encrypted]:") {
                            if let Ok(encrypted_msg) = serde_json::from_str::<EncryptedMessage>(encrypted_data) {
                                let clients_map = clients.lock().unwrap();
                                if let Some(sender_client) = clients_map.get(&token) {
                                    if let Some(aes_key) = sender_client.aes_key {
                                        let encrypted_bytes = general_purpose::STANDARD.decode(&encrypted_msg.encrypted_data).unwrap();
                                        let nonce_bytes = general_purpose::STANDARD.decode(&encrypted_msg.nonce).unwrap();
                                        let cipher = Aes256Gcm::new(&aes_key.into());
                                        let nonce = Nonce::from_slice(&nonce_bytes);
                                        if let Ok(decrypted) = cipher.decrypt(nonce, encrypted_bytes.as_ref()) {
                                            let decrypted_text = String::from_utf8_lossy(&decrypted).to_string();
                                            println!("Message from [{}]: {}", token, decrypted_text);

                                            // Broadcast cho mọi client khác
                                            for (tok, recipient) in clients_map.iter() {
                                                if *tok == token { continue; }
                                                if let Some(recipient_aes_key) = recipient.aes_key {
                                                    let recipient_cipher = Aes256Gcm::new(&recipient_aes_key.into());
                                                    let mut recipient_rng = StdRng::from_entropy();
                                                    let nonce_bytes: [u8; 12] = recipient_rng.gen();
                                                    let nonce = Nonce::from_slice(&nonce_bytes);
                                                    if let Ok(encrypted) = recipient_cipher.encrypt(nonce, decrypted_text.as_bytes()) {
                                                        let msg = EncryptedMessage {
                                                            encrypted_data: general_purpose::STANDARD.encode(&encrypted),
                                                            nonce: general_purpose::STANDARD.encode(&nonce_bytes),
                                                        };
                                                        let _ = recipient.tx.send(Message::text(
                                                            format!("[Encrypted]:{}", serde_json::to_string(&msg).unwrap())
                                                        ));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                } else if msg.is_close() { break; }
            }
            Err(e) => { eprintln!("WebSocket error [{}]: {:?}", token, e); break; }
        }
    }

    clients.lock().unwrap().remove(&token);
    println!("Client [{}] disconnected", token);
    let _ = send_task.await;
}

#[tokio::main]
async fn main() {
    run_server(8080).await;
}