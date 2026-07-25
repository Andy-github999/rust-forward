use clap::Parser;
use futures_util::stream::StreamExt;
use futures_util::SinkExt;
use log::{error, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use rust_forward::*;

#[derive(Parser, Debug)]
#[command(name = "forward", about = "WSS → TCP forward server for OpenWrt")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:2097")]
    listen: String,
    #[arg(long)]
    password: Option<String>,
    #[arg(long, default_value = "10")]
    connect_timeout: u64,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let args = Args::parse();
    let password = resolve_password(args.password.as_deref());

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    info!("Rust WS Forwarder starting on {}", args.listen);

    let listener = TcpListener::bind(&args.listen).await.unwrap();
    loop {
        let (stream, addr) = listener.accept().await.unwrap();
        let pwd = password.clone();
        let timeout = args.connect_timeout;
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, addr, &pwd, timeout).await {
                error!("[{}] {}", addr, e);
            }
        });
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    password: &str,
    connect_timeout: u64,
) -> anyhow::Result<()> {
    info!("[{}] WS connected", addr);
    let ws = tokio_tungstenite::accept_async(stream).await?;
    let (ws_w, mut ws_r) = ws.split();
    let ws_w: WsWriterServer = Arc::new(Mutex::new(ws_w));
    let streams: Arc<Mutex<HashMap<u16, tokio::io::WriteHalf<tokio::net::TcpStream>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    while let Some(msg) = ws_r.next().await {
        match msg? {
            Message::Text(text) => {
                let t = text.trim().to_string();
                let parts: Vec<&str> = t.splitn(4, ' ').collect();
                if parts.len() == 4 && parts[0] == "CONNECT" {
                    let sid = parts[1].parse::<u16>().unwrap_or(0);
                    let target = parts[2].to_string();
                    let recv_pwd = parts[3].to_string();
                    if recv_pwd != password {
                        let _ = ws_w.lock().await
                            .send(Message::Text(format!("502 {} Auth Failed", sid).into()))
                            .await;
                        continue;
                    }
                    info!("[{}] CONNECT sid={} target={}", addr, sid, target);
                    let stm = streams.clone();
                    let w = ws_w.clone();
                    tokio::spawn(async move {
                        let connect_result = tokio::time::timeout(
                            std::time::Duration::from_secs(connect_timeout),
                            connect_tcp_v4(&target, connect_timeout),
                        )
                        .await;

                        let target_stream = match connect_result {
                            Ok(Ok(s)) => s,
                            Ok(Err(e)) => {
                                let _ = w.lock().await
                                    .send(Message::Text(format!("502 {} {}", sid, e).into()))
                                    .await;
                                return;
                            }
                            Err(_) => {
                                let _ = w.lock().await
                                    .send(Message::Text(format!("502 {} Timeout", sid).into()))
                                    .await;
                                return;
                            }
                        };

                        let (mut target_r, target_w) = tokio::io::split(target_stream);
                        stm.lock().await.insert(sid, target_w);

                        let _ = w.lock().await
                            .send(Message::Text(format!("200 {} Connected", sid).into()))
                            .await;

                        let mut buf = vec![0u8; 65536];
                        loop {
                            match target_r.read(&mut buf).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    let mut frame = Vec::with_capacity(2 + n);
                                    frame.extend_from_slice(&sid.to_be_bytes());
                                    frame.extend_from_slice(&buf[..n]);
                                    if w.lock().await
                                        .send(Message::Binary(frame.into()))
                                        .await
                                        .is_err()
                                    { break; }
                                }
                                Err(_) => break,
                            }
                        }

                        stm.lock().await.remove(&sid);
                        let _ = w.lock().await
                            .send(Message::Text(format!("CLOSE {}", sid).into()))
                            .await;
                    });
                } else if parts.len() >= 2 && parts[0] == "CLOSE" {
                    let sid = parts[1].parse::<u16>().unwrap_or(0);
                    if let Some(mut s) = streams.lock().await.remove(&sid) {
                        let _ = s.shutdown().await;
                    }
                }
            }
            Message::Binary(data) => {
                if data.len() < 2 { continue; }
                let sid = u16::from_be_bytes([data[0], data[1]]);
                let payload = &data[2..];
                let mut stm = streams.lock().await;
                if let Some(s) = stm.get_mut(&sid) {
                    if let Err(e) = s.write_all(payload).await {
                        warn!("sid={} write: {}", sid, e);
                        stm.remove(&sid);
                    }
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    let mut stm = streams.lock().await;
    for (_, mut s) in stm.drain() {
        let _ = s.shutdown().await;
    }
    Ok(())
}