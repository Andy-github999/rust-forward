use clap::Parser;
use futures_util::stream::StreamExt;
use futures_util::SinkExt;
use log::{error, info};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use rust_forward::*;

#[derive(Parser, Debug)]
#[command(name = "bridge", about = "SOCKS5 → WSS bridge for PC")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:1080")]
    listen: String,
    #[arg(long)]
    password: Option<String>,
    /// WebSocket server URL (env: RUST_FORWARD_WS_URL)
    #[arg(long)]
    ws_url: Option<String>,
    #[arg(long, default_value_t = false)]
    insecure: bool,
    #[arg(long, default_value = "65536")]
    buf_size: usize,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let args = Args::parse();
    let password = resolve_password(args.password.as_deref());
    let ws_url = resolve_ws_url(args.ws_url.as_deref());

    if ws_url.is_empty() {
        error!("--ws-url is required for bridge mode (or set RUST_FORWARD_WS_URL)");
        std::process::exit(1);
    }

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutting down...");
        std::process::exit(0);
    });

    info!("SOCKS5→WS bridge (multiplex) listening on {}", args.listen);
    info!("WS server: {}", ws_url);

    let shared_writer: SharedWriter = Arc::new(tokio::sync::RwLock::new(None));
    let streams: Arc<Mutex<HashMap<u16, StreamState>>> = Arc::new(Mutex::new(HashMap::new()));
    let next_id = Arc::new(AtomicU16::new(1));

    // 后台 WSS session（自动重连）
    {
        let sw = shared_writer.clone();
        let st = streams.clone();
        let url = ws_url.clone();
        tokio::spawn(async move {
            loop {
                info!("Connecting WSS...");
                match connect_wss(&url, args.insecure).await {
                    Ok((ws, _)) => {
                        let (writer, mut reader) = ws.split();
                        let writer = Arc::new(Mutex::new(writer));
                        *sw.write().await = Some(writer.clone());
                        st.lock().await.clear();
                        info!("WSS connected, session running");

                        // 保活 ping
                        let ka_writer = writer.clone();
                        tokio::spawn(async move {
                            loop {
                                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                                let mut w = ka_writer.lock().await;
                                if w.send(Message::Ping(vec![].into())).await.is_err() { break; }
                            }
                        });

                        while let Some(msg) = reader.next().await {
                            match msg {
                                Ok(Message::Text(text)) => {
                                    let t = text.trim().to_string();
                                    let parts: Vec<&str> = t.splitn(3, ' ').collect();
                                    if parts.len() >= 2 {
                                        let sid = parts[1].parse::<u16>().unwrap_or(0);
                                        if parts[0] == "200" {
                                            let mut stm = st.lock().await;
                                            if let Some(state) = stm.remove(&sid) {
                                                let _ = state.ready.send(Ok(()));
                                                let (tx, _) = tokio::sync::oneshot::channel();
                                                stm.entry(sid).or_insert(StreamState { ready: tx, data_tx: state.data_tx });
                                            }
                                        } else if parts[0] == "502" {
                                            let mut stm = st.lock().await;
                                            if let Some(state) = stm.remove(&sid) {
                                                let _ = state.ready.send(Err(anyhow::anyhow!(t)));
                                            }
                                        } else if parts[0] == "CLOSE" {
                                            st.lock().await.remove(&sid);
                                        }
                                    }
                                }
                                Ok(Message::Binary(data)) => {
                                    if data.len() < 2 { continue; }
                                    let sid = u16::from_be_bytes([data[0], data[1]]);
                                    let payload = data[2..].to_vec();

                                    // 取出 Sender（快速，不阻塞其他 stream 的消息处理）
                                    let data_tx = st.lock().await.get(&sid).map(|s| s.data_tx.clone());

                                    if let Some(tx) = data_tx {
                                        // 带 backpressure 的发送——慢 TCP 不会丢 stream
                                        if tx.send(payload).await.is_err() {
                                            st.lock().await.remove(&sid);
                                            let mut w = writer.lock().await;
                                            let _ = w.send(Message::Text(format!("CLOSE {}", sid).into())).await;
                                        }
                                    }
                                }
                                Ok(Message::Close(_)) => {
                                    *sw.write().await = None;
                                    st.lock().await.clear();
                                    break;
                                }
                                Err(e) => {
                                    log::warn!("WSS read error: {}", e);
                                    *sw.write().await = None;
                                    st.lock().await.clear();
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => { log::warn!("WSS connect failed: {}", e); }
                }

                *sw.write().await = None;
                st.lock().await.clear();
                info!("Reconnecting in 3s...");
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        });
    }

    let listener = TcpListener::bind(&args.listen).await.unwrap();
    loop {
        let (stream, addr) = listener.accept().await.unwrap();
        let sw = shared_writer.clone();
        let st = streams.clone();
        let sid = next_id.fetch_add(1, Ordering::Relaxed);
        let pwd = password.clone();

        let st_c = st.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_socks5(stream, addr, sw, st, sid, &pwd, args.buf_size).await {
                error!("[{}] sid={} {}", addr, sid, e);
            }
            st_c.lock().await.remove(&sid);
        });
    }
}