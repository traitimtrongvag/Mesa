
use warp::Filter;
use std::sync::{Arc, Mutex};
use futures::{SinkExt, StreamExt};
use warp::ws::{Message, WebSocket};
use std::collections::HashMap;
use tokio::sync::mpsc::UnboundedSender;
use rand::{Rng, distributions::Alphanumeric};

type Clients = Arc<Mutex<HashMap<String, UnboundedSender<Message>>>>;

pub async fn run_server(port: u16) {
    let clients: Clients = Arc::new(Mutex::new(HashMap::new()));
    let clients_filter = warp::any().map(move || clients.clone());

    let ws_route = warp::path("ws")
        .and(warp::ws())
        .and(clients_filter)
        .map(|ws: warp::ws::Ws, clients: Clients| {
            ws.on_upgrade(move |socket| async move {
                client_connected(socket, clients).await;
            })
        });

    println!("Simple WebSocket server on port {} (path /ws)", port);
    
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
    println!("Client [{}] connected", token);

    // Gửi token cho client
    let _ = tx.send(Message::text(format!("[Token]:{}", token)));

    // Lưu client
    clients.lock().unwrap().insert(token.clone(), tx.clone());

    // Task gửi tin nhắn
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_tx.send(msg).await.is_err() { break; }
        }
    });

    // Nhận tin nhắn từ client
    while let Some(result) = ws_rx.next().await {
        match result {
            Ok(msg) => {
                if msg.is_text() {
                    let text = msg.to_str().unwrap_or("").to_string();
                    println!("Message from [{}]: {}", token, text);

                    // Broadcast cho tất cả client khác
                    let clients_map = clients.lock().unwrap();
                    for (tok, recipient_tx) in clients_map.iter() {
                        if *tok != token {
                            let broadcast_msg = format!("[{}]: {}", token, text);
                            let _ = recipient_tx.send(Message::text(broadcast_msg));
                        }
                    }
                } else if msg.is_close() { 
                    break; 
                }
            }
            Err(e) => { 
                eprintln!("WebSocket error [{}]: {:?}", token, e); 
                break; 
            }
        }
    }

    clients.lock().unwrap().remove(&token);
    println!("Client [{}] disconnected", token);
    let _ = send_task.await;
}

#[tokio::main]
async fn main() {
    run_server(8081).await;
}
