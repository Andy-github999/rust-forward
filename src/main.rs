use anyhow::Result;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use log::{error, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;

fn resolve_password(cli: Option<&str>) -> String {
    if let Some(p) = cli {
        return p.to_string();
    }
    if let Some(p) = option_env!("RUST_FORWARD_PASSWORD") {
        return p.to_string();
    }
    "123456".to_string()
}

fn resolve_ws_url(cli: Option<&str>) -> String {
    if let Some(url) = cli {
        return url.to_string();
    }
    if let Some(url) = option_env!("RUST_FORWARD_WS_URL") {
        return url.to_string();
    }
    // socks5-ws 模式下才需要，ws-server 不会调用
    String::new()
}

#[derive(Parser, Debug)]
#[command(name = "rust-forward", about = "TCP CONNECT proxy via WebSocket")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:2097")]
    listen: String,
    #[arg(long)]
    password: Option<String>,
    #[arg(long, default_value = "ws-server")]
    mode: String,
    /// WebSocket server URL (socks5-ws mode only, env: RUST_FORWARD_WS_URL)
    #[arg(long)]
    ws_url: Option<String>,
    #[arg(long, default_value = "10")]
    connect_timeout: u64,
    #[arg(long, default_value_t = false)]
    insecure: bool,
    #[arg(long, default_value = "65536")]
    buf_size: usize,
}

type WsWriter = Arc<Mutex<futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Message,
>>>;

/// Server 端 WS writer 类型
type WsWriterServer = Arc<Mutex<futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    Message,
>>>;

/// 每个流的状态
struct StreamState {
    /// 连接结果: Ok(()) = 200, Err(String) = 502
    ready: tokio::sync::oneshot::Sender<Result<()>>,
    /// 数据缓冲
    data_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let args = Args::parse();
    let password = resolve_password(args.password.as_deref());
    let ws_url = resolve_ws_url(args.ws_url.as_deref());

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Ctrl+C 优雅关闭
    let mode = args.mode.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutting down...");
        if mode == "socks5-ws" {
            // 桥接端：让 ws_session 的 reader 错误退出，自动清理
            std::process::exit(0);
        }
        std::process::exit(0);
    });

    match args.mode.as_str() {
        "ws-server" => run_ws_server(args, password).await,
        "socks5-ws" => run_socks5_bridge(args, password, ws_url).await,
        _ => {
            error!("Unknown mode: {}. Use ws-server or socks5-ws", args.mode);
            std::process::exit(1);
        }
    }
}

// ====================== WS Server (OpenWrt) ======================

async fn run_ws_server(args: Args, password: String) {
    info!("Rust WS Multiplexer starting on {}", args.listen);
    let listener = TcpListener::bind(&args.listen).await.unwrap();

    loop {
        let (stream, addr) = listener.accept().await.unwrap();
        let pwd = password.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_ws(stream, addr, &pwd).await {
                error!("[{}] {}", addr, e);
            }
        });
    }
}

async fn serve_ws(
    stream: tokio::net::TcpStream,
    addr: SocketAddr,
    password: &str,
) -> Result<()> {
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
                    let buf_size = 65536;
                    tokio::spawn(async move {
                        let connect_result = tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            connect_tcp_v4(&target, 10),
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

                        // split 成读写两半
                        let (mut target_r, target_w) = tokio::io::split(target_stream);
                        stm.lock().await.insert(sid, target_w);

                        // 通知客户端连接成功
                        let _ = w.lock().await
                            .send(Message::Text(format!("200 {} Connected", sid).into()))
                            .await;

                        // 读循环：target_r → WS
                        let mut buf = vec![0u8; buf_size];
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
                                    {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }

                        // 流结束，清理
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
                if data.len() < 2 {
                    continue;
                }
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

// ====================== SOCKS5 → WS Bridge (PC) with auto-reconnect ======================

type SharedWriter = Arc<tokio::sync::RwLock<Option<WsWriter>>>;

async fn connect_wss(url: &str, insecure: bool) -> Result<(tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, tokio_tungstenite::tungstenite::handshake::client::Response)> {
    let connector = if insecure {
        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoopVerifier))
            .with_no_client_auth();
        Some(tokio_tungstenite::Connector::Rustls(Arc::new(tls_config)))
    } else {
        None
    };
    tokio_tungstenite::connect_async_tls_with_config(url, None, true, connector)
        .await
        .map_err(|e| anyhow::anyhow!("WSS connect failed: {}", e))
}

async fn ws_session(
    ws_url: String,
    _password: String,
    shared_writer: SharedWriter,
    streams: Arc<Mutex<HashMap<u16, StreamState>>>,
    insecure: bool,
) {
    loop {
        info!("Connecting WSS...");
        match connect_wss(&ws_url, insecure).await {
            Ok((ws, _)) => {
                let (writer, mut reader) = ws.split();
                let writer = Arc::new(Mutex::new(writer));
                *shared_writer.write().await = Some(writer.clone());
                streams.lock().await.clear();
                info!("WSS connected, session running");

                // 保活 ping：每 30 秒发 ping 防止 CF 空闲断连
                let ka_writer = writer.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                        let mut w = ka_writer.lock().await;
                        if w.send(Message::Ping(vec![].into())).await.is_err() {
                            break;
                        }
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
                                    let mut st = streams.lock().await;
                                    if let Some(state) = st.remove(&sid) {
                                        let _ = state.ready.send(Ok(()));
                                        let (tx, _) = tokio::sync::oneshot::channel();
                                        st.entry(sid).or_insert(StreamState { ready: tx, data_tx: state.data_tx });
                                    }
                                } else if parts[0] == "502" {
                                    let mut st = streams.lock().await;
                                    if let Some(state) = st.remove(&sid) {
                                        let _ = state.ready.send(Err(anyhow::anyhow!(t)));
                                    }
                                }
                            }
                        }
                        Ok(Message::Binary(data)) => {
                            if data.len() < 2 { continue; }
                            let sid = u16::from_be_bytes([data[0], data[1]]);
                            let payload = data[2..].to_vec();
                            if let Some(state) = streams.lock().await.get(&sid) {
                                let _ = state.data_tx.send(payload);
                            }
                        }
                        Ok(Message::Close(_)) => {
                            *shared_writer.write().await = None;
                            streams.lock().await.clear();
                            break;
                        }
                        Err(e) => {
                            warn!("WSS read error: {}", e);
                            *shared_writer.write().await = None;
                            streams.lock().await.clear();
                            break;
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => { warn!("WSS connect failed: {}", e); }
        }

        *shared_writer.write().await = None;
        streams.lock().await.clear();
        info!("Reconnecting in 3s...");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

async fn run_socks5_bridge(args: Args, password: String, ws_url: String) {
    info!("SOCKS5→WS bridge (multiplex) listening on {}", args.listen);
    info!("WS server: {}", ws_url);

    let shared_writer: SharedWriter = Arc::new(tokio::sync::RwLock::new(None));
    let streams: Arc<Mutex<HashMap<u16, StreamState>>> = Arc::new(Mutex::new(HashMap::new()));
    let next_id = Arc::new(AtomicU16::new(1));

    {
        let sw = shared_writer.clone();
        let st = streams.clone();
        let url = ws_url.clone();
        let pwd = password.clone();
        tokio::spawn(async move { ws_session(url, pwd, sw, st, args.insecure).await; });
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

async fn handle_socks5(
    mut tcp: tokio::net::TcpStream,
    addr: SocketAddr,
    shared_writer: SharedWriter,
    streams: Arc<Mutex<HashMap<u16, StreamState>>>,
    sid: u16,
    password: &str,
    buf_size: usize,
) -> Result<()> {
    let mut buf = [0u8; 300];
    let n = tcp.read(&mut buf).await?;
    if n < 3 || buf[0] != 0x05 { return Ok(()); }
    tcp.write_all(&[0x05, 0x00]).await?;
    let n = tcp.read(&mut buf).await?;
    if n < 7 || buf[0] != 0x05 || buf[1] != 0x01 { return Ok(()); }

    let target = match buf[3] {
        0x01 => { let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]); let port = u16::from_be_bytes([buf[8], buf[9]]); format!("{}:{}", ip, port) }
        0x03 => { let len = buf[4] as usize; let domain = String::from_utf8_lossy(&buf[5..5+len]); let port = u16::from_be_bytes([buf[5+len], buf[5+len+1]]); format!("{}:{}", domain, port) }
        0x04 => { let mut octets = [0u8; 16]; octets.copy_from_slice(&buf[4..20]); let ip = std::net::Ipv6Addr::from(octets); let port = u16::from_be_bytes([buf[20], buf[21]]); format!("[{}]:{}", ip, port) }
        _ => return Ok(()),
    };
    info!("[{}] sid={} target={}", addr, sid, target);

    let ws_writer = match shared_writer.read().await.as_ref() {
        Some(w) => w.clone(),
        None => { warn!("[{}] WSS not connected", addr); return Ok(()); }
    };

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<()>>();
    let (data_tx, mut data_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    streams.lock().await.insert(sid, StreamState { ready: ready_tx, data_tx });

    {
        let mut w = ws_writer.lock().await;
        w.send(Message::Text(format!("CONNECT {} {} {}", sid, target, password).into())).await?;
    }

    match ready_rx.await {
        Ok(Ok(())) => { tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]).await?; info!("[{}] sid={} tunneling", addr, sid); }
        Ok(Err(e)) => { warn!("[{}] sid={} server error: {}", addr, sid, e); return Ok(()); }
        Err(_) => { warn!("[{}] sid={} channel closed", addr, sid); return Ok(()); }
    }

    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    let w = ws_writer.clone();
    let tcp_to_ws = tokio::spawn(async move {
        let mut buf = vec![0u8; buf_size];
        loop {
            match tcp_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let mut ww = w.lock().await;
                    let mut frame = Vec::with_capacity(2 + n);
                    frame.extend_from_slice(&sid.to_be_bytes());
                    frame.extend_from_slice(&buf[..n]);
                    if ww.send(Message::Binary(frame.into())).await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
    });
    let ws_to_tcp = tokio::spawn(async move { while let Some(d) = data_rx.recv().await { if tcp_w.write_all(&d).await.is_err() { break; } } });
    let _ = tokio::join!(tcp_to_ws, ws_to_tcp);

    let mut w = ws_writer.lock().await;
    let _ = w.send(Message::Text(format!("CLOSE {}", sid).into())).await;
    Ok(())
}

/// 解析目标并强制 IPv4 连接（避免 IPv6 在 PassWall2 环境下卡死）
async fn connect_tcp_v4(target: &str, timeout_secs: u64) -> Result<tokio::net::TcpStream> {
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok(tokio::net::TcpStream::connect(addr).await?);
    }

    let addrs = tokio::net::lookup_host(target).await?;
    let v4_addrs: Vec<_> = addrs.filter(|a| a.is_ipv4()).collect();

    if v4_addrs.is_empty() {
        return Ok(tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            tokio::net::TcpStream::connect(target),
        )
        .await??);
    }

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        async {
            let mut last_err = anyhow::anyhow!("No address available");
            for addr in &v4_addrs {
                match tokio::net::TcpStream::connect(addr).await {
                    Ok(s) => return Ok(s),
                    Err(e) => { last_err = e.into(); continue; }
                }
            }
            Err(last_err)
        },
    )
    .await
    .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

    Ok(result)
}

#[derive(Debug)]
struct NoopVerifier;
impl rustls::client::danger::ServerCertVerifier for NoopVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
}