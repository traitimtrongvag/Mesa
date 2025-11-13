use tokio_tungstenite::connect_async;
use tokio::io::{self, AsyncBufReadExt};
use futures::{SinkExt, StreamExt};
use tungstenite::Message;

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

    let (mut write, mut read) = ws_stream.split();
    let token = tokio::sync::Mutex::new(String::new());

    // Task nhận message từ server
    let token_clone = token.clone();
    tokio::spawn(async move {
        while let Some(msg) = read.next().await {
            match msg {
                Ok(m) => {
                    if let Ok(txt) = m.to_text() {
                        if txt.starts_with("[Token]:") {
                            // Lưu token của chính client
                            let mut t = token_clone.lock().await;
                            *t = txt[8..].to_string();
                        } else {
                            // In message từ server
                            println!("\n{}", txt);
                            let t = token_clone.lock().await;
                            print!("[{} (you)]: ", t);
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                        }
                    }
                }
                Err(e) => {
                    eprintln!("read error: {:?}", e);
                    break;
                }
            }
        }
    });

    // Task gửi message từ stdin
    let stdin = io::BufReader::new(io::stdin());
    let mut lines = stdin.lines();

    // In prompt lúc đầu (chưa có token thì tạm để trống)
    print!("[... (you)]: ");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    while let Ok(Some(line)) = lines.next_line().await {
        if write.send(Message::text(line)).await.is_err() {
            println!("connection closed");
            break;
        }
        let t = token.lock().await;
        print!("[{} (you)]: ", t);
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
}