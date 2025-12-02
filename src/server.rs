
use warp::Filter;
use std::sync::Arc;
use tokio::sync::RwLock;
use futures::{SinkExt, StreamExt};
use warp::ws::{Message, WebSocket};
use std::collections::HashMap;
use tokio::sync::mpsc::UnboundedSender;
use rand::{Rng, distributions::Alphanumeric};
use serde::{Deserialize, Serialize};

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

struct ClientInfo {
    tx: UnboundedSender<Message>,
    public_key: Option<String>,
}

type Clients = Arc<RwLock<HashMap<String, ClientInfo>>>;

pub async fn run_server(port: u16) {
    let clients: Clients = Arc::new(RwLock::new(HashMap::new()));
    let clients_filter = warp::any().map(move || clients.clone());

    let ws_route = warp::path("ws")
        .and(warp::ws())
        .and(clients_filter)
        .map(|ws: warp::ws::Ws, clients: Clients| {
            ws.on_upgrade(move |socket| async move {
                client_connected(socket, clients).await;
            })
        });

    println!("Server running on port {}", port);
    warp::serve(ws_route).run(([0, 0, 0, 0], port)).await;
}

fn generate_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect()
}

async fn client_connected(ws: WebSocket, clients: Clients) {
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();

    let token = generate_token();
    println!("Client {} connected", token);

    let token_msg = WsMessage::Token {
        token: token.clone(),
    };

    if let Ok(json) = serde_json::to_string(&token_msg) {
        let _ = tx.send(Message::text(json));
    }

    clients.write().await.insert(token.clone(), ClientInfo {
        tx: tx.clone(),
        public_key: None,
    });

    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    while let Some(result) = ws_rx.next().await {
        match result {
            Ok(msg) => {
                if msg.is_text() {
                    let text = msg.to_str().unwrap_or("");
                    handle_client_message(text, &token, &clients).await;
                } else if msg.is_close() {
                    break;
                }
            }
            Err(e) => {
                eprintln!("WebSocket error {}: {:?}", token, e);
                break;
            }
        }
    }

    clients.write().await.remove(&token);
    broadcast_client_list(&clients).await;
    println!("Client {} disconnected", token);
    let _ = send_task.await;
}

async fn handle_client_message(text: &str, sender_token: &str, clients: &Clients) {
    let ws_msg = match serde_json::from_str::<WsMessage>(text) {
        Ok(m) => m,
        Err(_) => {
            // If not JSON, treat as broadcast message
            let clients_map = clients.read().await;
            let broadcast = format!("[{}]: {}", sender_token, text);
            for (tok, client_info) in clients_map.iter() {
                if tok != sender_token {
                    let _ = client_info.tx.send(Message::text(broadcast.clone()));
                }
            }
            return;
        }
    };

    match ws_msg {
        WsMessage::PublicKey { key, .. } => {
            {
                let mut clients_map = clients.write().await;
                if let Some(client) = clients_map.get_mut(sender_token) {
                    client.public_key = Some(key.clone());
                }
            }

            let msg = WsMessage::PublicKey {
                token: sender_token.to_string(),
                key: key.clone(),
            };

            if let Ok(json) = serde_json::to_string(&msg) {
                let clients_map = clients.read().await;
                for (tok, client_info) in clients_map.iter() {
                    if tok != sender_token {
                        let _ = client_info.tx.send(Message::text(json.clone()));
                    }
                }
            }

            broadcast_client_list(clients).await;
        }
        WsMessage::KeyExchange { to, from, payload } => {
            let clients_map = clients.read().await;
            if let Some(recipient) = clients_map.get(&to) {
                let msg = WsMessage::KeyExchange {
                    to: to.clone(),
                    from: from.clone(),
                    payload,
                };
                if let Ok(json) = serde_json::to_string(&msg) {
                    let _ = recipient.tx.send(Message::text(json));
                }
            }
        }
        WsMessage::ChatMessage { to, from, n, data } => {
            let clients_map = clients.read().await;
            if let Some(recipient) = clients_map.get(&to) {
                let msg = WsMessage::ChatMessage {
                    to: to.clone(),
                    from: from.clone(),
                    n,
                    data,
                };
                if let Ok(json) = serde_json::to_string(&msg) {
                    let _ = recipient.tx.send(Message::text(json));
                }
            }
        }
        _ => {}
    }
}

async fn broadcast_client_list(clients: &Clients) {
    let clients_map = clients.read().await;
    let tokens: Vec<String> = clients_map.keys().cloned().collect();

    let msg = WsMessage::ClientList {
        clients: tokens,
    };

    if let Ok(json) = serde_json::to_string(&msg) {
        for (_, client) in clients_map.iter() {
            let _ = client.tx.send(Message::text(json.clone()));
        }
    }
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8081".to_string())
        .parse()
        .unwrap_or(8081);
    
    run_server(port).await;
}