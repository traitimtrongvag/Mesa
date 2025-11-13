use tokio_tungstenite::connect_async;
use tokio::io::{self, AsyncBufReadExt};
use futures::{SinkExt, StreamExt};
use tungstenite::Message;

pub async fn run_client() {
    // lấy URL từ env hoặc default localhost
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

    // task: đọc message từ server
    tokio::spawn(async move {
        while let Some(msg) = read.next().await {
            match msg {
                Ok(m) => {
                    if let Ok(txt) = m.to_text() {
                        // in thẳng token và nội dung, không kèm [remote]
                        println!("\n{}", txt);
                        print!("> ");
                        let _ = std::io::Write::flush(&mut std::io::stdout());
                    }
                }
                Err(e) => {
                    eprintln!("read error: {:?}", e);
                    break;
                }
            }
        }
    });

    // stdin loop: gửi message
    let stdin = io::BufReader::new(io::stdin());
    let mut lines = stdin.lines();

    print!("> ");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    while let Ok(Some(line)) = lines.next_line().await {
        if write.send(Message::text(line)).await.is_err() {
            println!("connection closed");
            break;
        }
        print!("> ");
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
}