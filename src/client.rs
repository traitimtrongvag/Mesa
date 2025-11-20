use tokio_tungstenite::connect_async;
use tokio::io::{self, AsyncBufReadExt};
use futures::{SinkExt, StreamExt};
use tungstenite::Message;
use std::sync::Arc;
use tokio::sync::Mutex;

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
    
    println!("Connected to server");

    let (mut write, mut read) = ws_stream.split();
    let token = Arc::new(Mutex::new(String::new()));
    let token_clone = token.clone();

    // Task nhận message từ server
    tokio::spawn(async move {
        while let Some(msg) = read.next().await {
            match msg {
                Ok(m) => {
                    if let Ok(txt) = m.to_text() {
                        if txt.starts_with("[Token]:") {
                            let tok = txt[8..].to_string();
                            *token_clone.lock().await = tok.clone();
                            println!("Your token: {}", tok);
                            print!("[{} (you)]: ", tok);
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                        } else {
                            println!("\n{}", txt);
                            let tok = token_clone.lock().await;
                            print!("[{} (you)]: ", tok);
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                        }
                    }
                }
                Err(e) => { 
                    eprintln!("Read error: {:?}", e); 
                    break; 
                }
            }
        }
    });

    // Gửi message từ stdin
    let stdin = io::BufReader::new(io::stdin());
    let mut lines = stdin.lines();

    loop {
        if let Ok(Some(line)) = lines.next_line().await {
            if write.send(Message::text(line)).await.is_err() {
                println!("Connection closed");
                break;
            }
            
            let tok = token.lock().await;
            print!("[{} (you)]: ", tok);
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }
    }
}
