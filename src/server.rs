use warp::Filter;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc::UnboundedSender};
use futures::{SinkExt, StreamExt};
use warp::ws::{Message, WebSocket};

type Clients = Arc<Mutex<Vec<UnboundedSender<Message>>>>;

pub async fn run_server() {
    let clients: Clients = Arc::new(Mutex::new(Vec::new()));
    let clients_filter = warp::any().map(move || clients.clone());

    // ws at "/" and "/ws" (so websocat without path works)
    let ws_root = warp::path::end()
        .and(warp::ws())
        .and(clients_filter.clone())
        .map(|ws: warp::ws::Ws, clients| {
            ws.on_upgrade(move |socket| handle_ws(socket, clients))
        });

    let ws_ws = warp::path("ws")
        .and(warp::ws())
        .and(clients_filter.clone())
        .map(|ws: warp::ws::Ws, clients| {
            ws.on_upgrade(move |socket| handle_ws(socket, clients))
        });

    let routes = ws_root.or(ws_ws).with(warp::log("message_ws"));

    // read PORT env var (Render sets $PORT)
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);

    println!("WebSocket server listening on 0.0.0.0:{} (paths: / and /ws)", port);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}

async fn handle_ws(ws: WebSocket, clients: Clients) {
    let (mut ws_tx, mut ws_rx) = ws.split();

    // channel to send messages to this client task
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();

    // add to clients list
    clients.lock().await.push(tx);

    // spawn a task that forwards messages from rx -> websocket sink
    let write_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // read loop: incoming messages from this ws connection
    while let Some(result) = ws_rx.next().await {
        match result {
            Ok(msg) => {
                if msg.is_text() {
                    let txt = msg.to_str().unwrap_or("").to_string();
                    // broadcast to all clients
                    let mut guard = clients.lock().await;
                    // retain only open clients; send text
                    guard.retain(|client_tx| {
                        client_tx.send(Message::text(txt.clone())).is_ok()
                    });
                } else if msg.is_close() {
                    break;
                }
            }
            Err(e) => {
                eprintln!("ws receive error: {:?}", e);
                break;
            }
        }
    }

    // connection closing: remove dead senders (we did retention above, but ensure cleanup)
    {
        let mut guard = clients.lock().await;
        // best-effort: remove any closed channels (retain those that can still send)
        guard.retain(|client_tx| client_tx.send(Message::text("")).is_ok());
    }

    // drop rx to stop write_task
    drop(rx);
    let _ = write_task.await;
}