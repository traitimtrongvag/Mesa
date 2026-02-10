use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc::UnboundedSender, RwLock};
use warp::ws::{Message, WebSocket};
use warp::Filter;

use message::protocol::WsMessage;
use message::token::generate_token;

struct ClientInfo {
    tx: UnboundedSender<Message>,
    public_key: Option<String>,
}

type Clients = Arc<RwLock<HashMap<String, ClientInfo>>>;

pub async fn run_server(port: u16) {
    let clients: Clients = Arc::new(RwLock::new(HashMap::new()));
    let clients_filter = warp::any().map(move || clients.clone());

    let ws_route = warp::path("ws").and(warp::ws()).and(clients_filter).map(
        |ws: warp::ws::Ws, clients: Clients| {
            ws.on_upgrade(move |socket| async move {
                client_connected(socket, clients).await;
            })
        },
    );

    println!("Server running on port {}", port);
    warp::serve(ws_route).run(([0, 0, 0, 0], port)).await;
}

async fn client_connected(ws: WebSocket, clients: Clients) {
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();

    let token = generate_token();
    println!("Client {} connected", token);

    let token_msg = WsMessage::new_token(token.clone());

    if let Ok(json) = token_msg.to_json() {
        let _ = tx.send(Message::text(json));
    }

    clients.write().await.insert(
        token.clone(),
        ClientInfo {
            tx: tx.clone(),
            public_key: None,
        },
    );

    let token_for_task = token.clone();
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
                    if let Ok(text) = msg.to_str() {
                        handle_client_message(text, &token, &clients).await;
                    }
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
    println!("Client {} disconnected", token_for_task);
    let _ = send_task.await;
}

async fn handle_client_message(text: &str, sender_token: &str, clients: &Clients) {
    let ws_msg = match WsMessage::from_json(text) {
        Ok(m) => m,
        Err(_) => {
            broadcast_plain_message(text, sender_token, clients).await;
            return;
        }
    };

    match ws_msg {
        WsMessage::PublicKey { key, .. } => {
            handle_public_key_message(sender_token, key, clients).await;
        }
        WsMessage::KeyExchange { to, from, payload } => {
            relay_key_exchange(to, from, payload, clients).await;
        }
        WsMessage::ChatMessage { to, from, n, data } => {
            relay_chat_message(to, from, n, data, clients).await;
        }
        _ => {}
    }
}

async fn broadcast_plain_message(text: &str, sender_token: &str, clients: &Clients) {
    let clients_map = clients.read().await;
    let broadcast = format!("[{}]: {}", sender_token, text);
    for (tok, client_info) in clients_map.iter() {
        if tok != sender_token {
            let _ = client_info.tx.send(Message::text(broadcast.clone()));
        }
    }
}

async fn handle_public_key_message(sender_token: &str, key: String, clients: &Clients) {
    {
        let mut clients_map = clients.write().await;
        if let Some(client) = clients_map.get_mut(sender_token) {
            client.public_key = Some(key.clone());
        }
    }

    let msg = WsMessage::new_public_key(sender_token.to_string(), key);

    if let Ok(json) = msg.to_json() {
        let clients_map = clients.read().await;
        for (tok, client_info) in clients_map.iter() {
            if tok != sender_token {
                let _ = client_info.tx.send(Message::text(json.clone()));
            }
        }
    }

    broadcast_client_list(clients).await;
}

async fn relay_key_exchange(to: String, from: String, payload: String, clients: &Clients) {
    let clients_map = clients.read().await;
    if let Some(recipient) = clients_map.get(&to) {
        let msg = WsMessage::new_key_exchange(to, from, payload);
        if let Ok(json) = msg.to_json() {
            let _ = recipient.tx.send(Message::text(json));
        }
    }
}

async fn relay_chat_message(to: String, from: String, n: u64, data: String, clients: &Clients) {
    let clients_map = clients.read().await;
    if let Some(recipient) = clients_map.get(&to) {
        let msg = WsMessage::new_chat_message(to, from, n, data);
        if let Ok(json) = msg.to_json() {
            let _ = recipient.tx.send(Message::text(json));
        }
    }
}

async fn broadcast_client_list(clients: &Clients) {
    let clients_map = clients.read().await;
    let tokens: Vec<String> = clients_map.keys().cloned().collect();

    let msg = WsMessage::new_client_list(tokens);

    if let Ok(json) = msg.to_json() {
        for client in clients_map.values() {
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
