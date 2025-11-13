mod server;
mod client;

use std::env;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // `cargo run -- client` sẽ chạy client (kết nối tới ws://localhost)
    if args.len() > 1 && args[1] == "client" {
        client::run_client().await;
    } else {
        // default: run server (sử dụng PORT từ env hoặc 8080)
        server::run_server().await;
    }
}