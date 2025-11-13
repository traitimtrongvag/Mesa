mod server;

#[tokio::main]
async fn main() {
    // Lấy port từ biến môi trường (Render)
    let port: u16 = std::env::var("PORT")
        .unwrap_or("8080".to_string())
        .parse()
        .unwrap_or(8080);

    server::run_server(port).await;
}