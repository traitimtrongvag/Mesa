use warp::Filter;
use std::sync::{Arc, Mutex};
use futures::{SinkExt, StreamExt};
use warp::ws::{Message, WebSocket};
use std::collections::HashMap;
use tokio::sync::mpsc::UnboundedSender;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

type Clients = Arc<Mutex<HashMap<String, UnboundedSender<Message>>>>;

pub async fn run_server(port: u16) {
    let clients: Clients = Arc::new(Mutex::new(HashMap::new()));
    let clients_filter = warp::any().map(move || clients.clone());

    let ws_route = warp::path("ws")
        .and(warp::ws())
        .and(clients_filter)
        .map(|ws: warp::ws::Ws, clients| {
            ws.on_upgrade(move |socket| client_connected(socket, clients))
        });

    println!("WebSocket server on port {} (path /ws)", port);
    warp::serve(ws_route).run(([0,0,0,0], port)).await;
}

fn generate_token(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

async fn client_connected(ws: WebSocket, clients: Clients) {
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();

    let token = generate_token(6);
    println!("New client connected with token [{}]", token);

    clients.lock().unwrap().insert(token.clone(), tx);

    // task gửi message từ server -> client
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // nhận message từ client
    while let Some(result) = ws_rx.next().await {
        match result {
            Ok(msg) => {
                if msg.is_text() || msg.is_binary() {
                    let text = msg.to_str().unwrap_or("").to_string();
                    let broadcast_msg = format!("[{}]: {}", token, text);

                    // broadcast tới tất cả client khác
                    let clients_map = clients.lock().unwrap().clone();
                    for (tok, client_tx) in clients_map.iter() {
                        if *tok == token { continue; } // skip origin
                        let _ = client_tx.send(Message::text(broadcast_msg.clone()));
                    }
                } else if msg.is_close() {
                    break;
                }
            }
            Err(e) => {
                eprintln!("ws recv error: {:?}", e);
                break;
            }
        }
    }

    clients.lock().unwrap().remove(&token);
    println!("Client [{}] disconnected", token);

    let _ = send_task.await;
}