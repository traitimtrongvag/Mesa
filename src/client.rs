use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose, Engine as _};
use futures::{SinkExt, StreamExt};
use rand::RngCore;
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt};
use tokio::sync::Mutex;
use tokio_tungstenite::connect_async;
use tungstenite::Message;

use message::protocol::WsMessage;

type AesSessionKey = (Vec<u8>, Vec<u8>, u64);
type PeerPublicKeys = Arc<Mutex<HashMap<String, RsaPublicKey>>>;
type AesKeys = Arc<Mutex<HashMap<String, AesSessionKey>>>;

struct Session {
    token: String,
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
    peer_keys: PeerPublicKeys,
    aes_keys: AesKeys,
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
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .expect("Failed to generate RSA key");
    let public_key = RsaPublicKey::from(&private_key);

    let session = Arc::new(Mutex::new(Session {
        token: String::new(),
        private_key,
        public_key,
        peer_keys: Arc::new(Mutex::new(HashMap::new())),
        aes_keys: Arc::new(Mutex::new(HashMap::new())),
    }));

    let (write, mut read) = ws_stream.split();
    let write_clone = Arc::new(Mutex::new(write));
    let session_clone = session.clone();
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

    while let Ok(Some(line)) = lines.next_line().await {
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

async fn handle_message(
    text: &str,
    session: &Arc<Mutex<Session>>,
    write: &Arc<
        Mutex<
            futures::stream::SplitSink<
                tokio_tungstenite::WebSocketStream<
                    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
                >,
                Message,
            >,
        >,
    >,
) {
    let ws_msg: WsMessage = match WsMessage::from_json(text) {
        Ok(m) => m,
        Err(_) => return,
    };

    match ws_msg {
        WsMessage::Token { token } => {
            handle_token_received(token, session, write).await;
        }
        WsMessage::ClientList { clients } => {
            println!("Online: {:?}", clients);
        }
        WsMessage::PublicKey { token, key } => {
            handle_peer_public_key(token, key, session).await;
        }
        WsMessage::KeyExchange { from, payload, .. } => {
            handle_key_exchange(from, payload, session).await;
        }
        WsMessage::ChatMessage { from, n, data, .. } => {
            handle_encrypted_message(from, n, data, session).await;
        }
    }
}

async fn handle_token_received(
    token: String,
    session: &Arc<Mutex<Session>>,
    write: &Arc<
        Mutex<
            futures::stream::SplitSink<
                tokio_tungstenite::WebSocketStream<
                    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
                >,
                Message,
            >,
        >,
    >,
) {
    let mut s = session.lock().await;
    s.token = token.clone();
    println!("Your token: {}", token);

    if let Ok(public_key_pem) = s.public_key.to_public_key_pem(LineEnding::LF) {
        let pubkey_msg = WsMessage::new_public_key(token, public_key_pem);
        if let Ok(json) = pubkey_msg.to_json() {
            let mut w = write.lock().await;
            let _ = w.send(Message::text(json)).await;
        }
    }
}

async fn handle_peer_public_key(token: String, key: String, session: &Arc<Mutex<Session>>) {
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
            Err(e) => eprintln!("Failed to parse public key from {}: {:?}", token, e),
        }
    }
}

async fn handle_key_exchange(from: String, payload: String, session: &Arc<Mutex<Session>>) {
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

    let decrypted = match private_key.decrypt(Pkcs1v15Encrypt, &encrypted) {
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

async fn handle_encrypted_message(
    from: String,
    n: u64,
    data: String,
    session: &Arc<Mutex<Session>>,
) {
    let s = session.lock().await;
    let aes_keys = s.aes_keys.clone();
    drop(s);

    let mut keys = aes_keys.lock().await;
    if let Some((aes_key, nonce_seed, counter)) = keys.get_mut(&from) {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(aes_key));
        let mut nonce_bytes = nonce_seed.clone();
        nonce_bytes.extend_from_slice(&n.to_le_bytes()[0..4]);
        let nonce = Nonce::from_slice(&nonce_bytes[0..12]);

        let ciphertext = match general_purpose::STANDARD.decode(&data) {
            Ok(c) => c,
            Err(_) => {
                eprintln!("Failed to decode message from {}", from);
                return;
            }
        };

        match cipher.decrypt(nonce, ciphertext.as_ref()) {
            Ok(plaintext) => match String::from_utf8(plaintext) {
                Ok(message) => {
                    println!("{}: {}", from, message);
                    *counter = n + 1;
                }
                Err(_) => eprintln!("Failed to decode UTF-8 from {}", from),
            },
            Err(_) => eprintln!("Failed to decrypt message from {}", from),
        }
    } else {
        eprintln!("No AES key for {}", from);
    }
}

async fn send_encrypted_message(
    write: &mut futures::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
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
        if let Err(e) = establish_session_key(to, &my_token, &peer_keys, &mut keys, write).await {
            eprintln!("Failed to establish session: {}", e);
            return;
        }
    }

    if let Some((aes_key, nonce_seed, counter)) = keys.get_mut(to) {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(aes_key));
        let mut nonce_bytes = nonce_seed.clone();
        nonce_bytes.extend_from_slice(&counter.to_le_bytes()[0..4]);
        let nonce = Nonce::from_slice(&nonce_bytes[0..12]);

        match cipher.encrypt(nonce, text.as_bytes()) {
            Ok(ciphertext) => {
                let encoded = general_purpose::STANDARD.encode(&ciphertext);
                let msg = WsMessage::new_chat_message(
                    to.to_string(),
                    my_token,
                    *counter,
                    encoded,
                );
                *counter += 1;
                if let Ok(json) = msg.to_json() {
                    let _ = write.send(Message::text(json)).await;
                }
            }
            Err(_) => eprintln!("Failed to encrypt message"),
        }
    }
}

async fn establish_session_key(
    to: &str,
    my_token: &str,
    peer_keys: &PeerPublicKeys,
    keys: &mut tokio::sync::MutexGuard<'_, HashMap<String, AesSessionKey>>,
    write: &mut futures::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
) -> Result<(), String> {
    let pk = peer_keys.lock().await;
    let peer_key = pk
        .get(to)
        .ok_or_else(|| format!("No public key for {}", to))?
        .clone();
    drop(pk);

    let mut rng = rand::thread_rng();
    let mut aes_key = vec![0u8; 32];
    let mut nonce_seed = vec![0u8; 12];
    rng.fill_bytes(&mut aes_key);
    rng.fill_bytes(&mut nonce_seed);

    let mut payload = aes_key.clone();
    payload.extend_from_slice(&nonce_seed);

    let encrypted = peer_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, &payload)
        .map_err(|_| format!("Failed to encrypt key for {}", to))?;

    let encoded = general_purpose::STANDARD.encode(&encrypted);
    let msg = WsMessage::new_key_exchange(to.to_string(), my_token.to_string(), encoded);

    keys.insert(to.to_string(), (aes_key, nonce_seed, 0));

    if let Ok(json) = msg.to_json() {
        let _ = write.send(Message::text(json)).await;
    }

    Ok(())
}
