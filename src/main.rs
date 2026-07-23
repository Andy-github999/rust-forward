use anyhow::{Context, Result};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use log::{error, info, warn};
use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

#[derive(Parser, Debug)]
#[command(name = "rust-forward", about = "TCP CONNECT proxy via WebSocket")]
struct Args {
    /// Listen address
    #[arg(long, default_value = "0.0.0.0:2097")]
    listen: String,

    /// Auth password (client must send CONNECT <target> <password>)
    #[arg(long, default_value = "123456")]
    password: String,

    /// Mode: ws-server (listen for WS connections), socks5-ws (bridge SOCKS5→WS)
    #[arg(long, default_value = "ws-server")]
    mode: String,

    /// WebSocket server URL (for socks5-ws mode only)
    #[arg(long, default_value = "wss://site5tunnel.candysmithw3yr4o.eu.org")]
    ws_url: String,

    /// Connect timeout in seconds for outbound TCP
    #[arg(long, default_value = "10")]
    connect_timeout: u64,

    /// Skip TLS certificate verification (socks5-ws mode only)
    #[arg(long, default_value_t = false)]
    insecure: bool,

    /// Buffer size for tunnel data (bytes)
    #[arg(long, default_value = "65536")]
    buf_size: usize,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let args = Args::parse();

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    match args.mode.as_str() {
        "ws-server" => run_ws_server(args).await,
        "socks5-ws" => run_socks5_bridge(args).await,
        _ => {
            error!("Unknown mode: {}. Use ws-server or socks5-ws", args.mode);
            std::process::exit(1);
        }
    }
}

// ==================== WS Server (OpenWrt side) ====================

async fn run_ws_server(args: Args) {
    info!("Rust WS Forwarder starting on {}", args.listen);
    let password = args.password;
    let connect_timeout = args.connect_timeout;
    let buf_size = args.buf_size;
    info!("Auth: enabled, connect timeout: {}s", connect_timeout);

    let listener = TcpListener::bind(&args.listen)
        .await
        .expect("Failed to bind address");
    info!("Listening on {} (WebSocket)", args.listen);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let pwd = password.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_ws(stream, addr, &pwd, connect_timeout, buf_size).await {
                        error!("[{}] Error: {:#}", addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept: {}", e);
            }
        }
    }
}

async fn handle_ws(
    stream: tokio::net::TcpStream,
    addr: SocketAddr,
    password: &str,
    connect_timeout: u64,
    buf_size: usize,
) -> Result<()> {
    info!("[{}] New WS connection, upgrading...", addr);
    let ws_stream = match tokio_tungstenite::accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            warn!("[{}] WS handshake failed: {}", addr, e);
            return Ok(());
        }
    };
    info!("[{}] WebSocket upgraded", addr);

    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    // 挑战-应答防重放: 发送随机 challenge
    let challenge = rand::random::<[u8; 16]>();
    let challenge_hex = hex_encode(&challenge);
    info!("[{}] Sending challenge: {}", addr, challenge_hex);
    ws_sender.send(Message::Text(format!("CHALLENGE {}", challenge_hex).into())).await?;

    // 等待 CONNECT <target> <sha256(password+challenge)>
    let target = loop {
        match ws_receiver.next().await {
            Some(Ok(Message::Text(text))) => {
                let t = text.trim().to_string();
                let parts: Vec<&str> = t.splitn(3, ' ').collect();
                if parts.len() == 3 && parts[0] == "CONNECT" {
                    let target = parts[1].trim().to_string();
                    let resp = parts[2].trim().to_string();
                    let expected = hash_challenge(password, &challenge_hex);
                    if resp == expected {
                        info!("[{}] CONNECT target: {} (auth OK)", addr, target);
                        break target;
                    } else {
                        warn!("[{}] Auth failed: wrong response", addr);
                        let _ = ws_sender.send(Message::Text("403 Auth Failed".to_string().into())).await;
                        return Ok(());
                    }
                } else if parts.len() >= 2 && parts[0] == "CONNECT" {
                    warn!("[{}] Auth failed: missing password", addr);
                    let _ = ws_sender.send(Message::Text("403 Auth Failed".to_string().into())).await;
                    return Ok(());
                } else {
                    warn!("[{}] Unexpected text: {}", addr, t);
                    let _ = ws_sender.send(Message::Text("400 Bad Request".to_string().into())).await;
                    return Ok(());
                }
            }
            Some(Ok(Message::Ping(p))) => { let _ = ws_sender.send(Message::Pong(p)).await; continue; }
            Some(Ok(_)) => {
                let _ = ws_sender.send(Message::Text("400 Expected text".to_string().into())).await;
                return Ok(());
            }
            Some(Err(e)) => {
                warn!("[{}] WS recv error: {}", addr, e);
                return Ok(());
            }
            None => {
                warn!("[{}] WS closed before CHALLENGE", addr);
                return Ok(());
            }
        }
    };

    let mut target_stream = match connect_tcp_v4(&target, connect_timeout).await {
        Ok(s) => s,
        Err(e) => {
            warn!("[{}] Failed to connect {}: {}", addr, target, e);
            let _ = ws_sender.send(Message::Text(format!("502 Bad Gateway: {}", e).into())).await;
            return Ok(());
        }
    };
    info!("[{}] Connected to {}", addr, target);

    ws_sender.send(Message::Text("200 Connected".to_string().into())).await?;
    info!("[{}] Tunneling: {} <-> {}", addr, addr, target);

    let mut buf = vec![0u8; buf_size];
    loop {
        tokio::select! {
            msg = ws_receiver.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        if let Err(e) = target_stream.write_all(&data).await {
                            warn!("[{}] Write to target error: {}", addr, e);
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(Message::Ping(p))) => { let _ = ws_sender.send(Message::Pong(p)).await; }
                    _ => {}
                }
            }
            n = target_stream.read(&mut buf) => {
                match n {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = ws_sender.send(Message::Binary(buf[..n].to_vec().into())).await {
                            warn!("[{}] Write to WS error: {}", addr, e);
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("[{}] Read from target error: {}", addr, e);
                        break;
                    }
                }
            }
        }
    }

    info!("[{}] Tunnel closed", addr);
    Ok(())
}

/// 解析目标并强制 IPv4 连接
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

// ==================== SOCKS5 → WS Bridge (PC side) ====================

async fn run_socks5_bridge(args: Args) {
    info!("SOCKS5→WS bridge listening on {}", args.listen);
    info!("WS server: {}", args.ws_url);
    info!("Password: {}, insecure TLS: {}", args.password, args.insecure);

    let listener = TcpListener::bind(&args.listen)
        .await
        .expect("Failed to bind address");

    loop {
        let (stream, addr) = listener.accept().await.unwrap();
        let ws_url = args.ws_url.clone();
        let password = args.password.clone();
        let insecure = args.insecure;
        let connect_timeout = args.connect_timeout;
        let buf_size = args.buf_size;
        tokio::spawn(async move {
            if let Err(e) = handle_socks5(stream, addr, &ws_url, &password, insecure, connect_timeout, buf_size).await {
                error!("[{}] {}", addr, e);
            }
        });
    }
}

async fn handle_socks5(
    mut stream: tokio::net::TcpStream,
    addr: SocketAddr,
    ws_url: &str,
    password: &str,
    insecure: bool,
    _connect_timeout: u64,
    buf_size: usize,
) -> Result<()> {
    let mut buf = [0u8; 300];
    let n = stream.read(&mut buf).await?;
    if n < 3 || buf[0] != 0x05 {
        return Ok(());
    }
    stream.write_all(&[0x05, 0x00]).await?;

    let n = stream.read(&mut buf).await?;
    if n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
        warn!("[{}] Unsupported cmd {}", addr, buf[1]);
        let _ = stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0]).await;
        return Ok(());
    }

    let target = match buf[3] {
        0x01 => {
            let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            format!("{}:{}", ip, port)
        }
        0x03 => {
            let len = buf[4] as usize;
            let domain = String::from_utf8_lossy(&buf[5..5+len]);
            let port = u16::from_be_bytes([buf[5+len], buf[5+len+1]]);
            format!("{}:{}", domain, port)
        }
        0x04 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            format!("[{}]:{}", ip, port)
        }
        _ => {
            let _ = stream.write_all(&[0x05, 0x08, 0x00, 0x01, 0,0,0,0, 0,0]).await;
            return Ok(());
        }
    };

    info!("[{}] SOCKS5 → target={}", addr, target);
    stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]).await?;

    // WSS 连接（disable_nagle 减少延迟）
    info!("[{}] Connecting WSS...", addr);
    let ws_stream = if insecure {
        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoopVerifier))
            .with_no_client_auth();
        let connector = tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(tls_config));
        tokio_tungstenite::connect_async_tls_with_config(ws_url, None, true, Some(connector))
            .await
            .map_err(|e| { warn!("[{}] WS connect failed: {:?}", addr, e); e })
            .context("WS connect failed")?
    } else {
        tokio_tungstenite::connect_async_tls_with_config(ws_url, None, true, None)
            .await
            .map_err(|e| { warn!("[{}] WS connect failed: {:?}", addr, e); e })
            .context("WS connect failed")?
    };
    let (mut ws_writer, mut ws_reader) = ws_stream.0.split();
    info!("[{}] WSS connected", addr);

    // 等待 CHALLENGE
    let challenge = match ws_reader.next().await {
        Some(Ok(Message::Text(text))) => {
            let t = text.trim().to_string();
            let parts: Vec<&str> = t.splitn(2, ' ').collect();
            if parts.len() == 2 && parts[0] == "CHALLENGE" {
                let c = parts[1].trim().to_string();
                info!("[{}] Got challenge: {}", addr, c);
                c
            } else {
                warn!("[{}] Expected CHALLENGE, got: {}", addr, t);
                return Ok(());
            }
        }
        Some(Ok(_)) => { warn!("[{}] Expected text CHALLENGE", addr); return Ok(()); }
        Some(Err(e)) => { warn!("[{}] WS error: {}", addr, e); return Ok(()); }
        None => { warn!("[{}] WS closed before CHALLENGE", addr); return Ok(()); }
    };

    // 计算响应: sha256(password + challenge_hex)
    let resp = hash_challenge(password, &challenge);
    let auth = format!("CONNECT {} {}", target, resp);
    ws_writer.send(Message::Text(auth.into())).await?;

    // 等 200 Connected
    match ws_reader.next().await {
        Some(Ok(Message::Text(resp))) => {
            let resp = resp.to_string();
            if resp == "200 Connected" {
                info!("[{}] Auth OK, tunneling...", addr);
            } else {
                warn!("[{}] Auth failed: {}", addr, resp);
                return Ok(());
            }
        }
        Some(Ok(msg)) => { warn!("[{}] Unexpected: {:?}", addr, msg); return Ok(()); }
        Some(Err(e)) => { warn!("[{}] WS error: {}", addr, e); return Ok(()); }
        None => { warn!("[{}] WS closed", addr); return Ok(()); }
    }

    let (mut tcp_r, mut tcp_w) = stream.split();

    let tcp_to_ws = async {
        let mut buf = vec![0u8; buf_size];
        loop {
            match tcp_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => { if ws_writer.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() { break; } }
                Err(_) => break,
            }
        }
    };

    let ws_to_tcp = async {
        while let Some(msg) = ws_reader.next().await {
            match msg {
                Ok(Message::Binary(data)) => { if tcp_w.write_all(&data).await.is_err() { break; } }
                Ok(Message::Close(_)) | Err(_) => break,
                _ => {}
            }
        }
    };

    tokio::select! {
        _ = tcp_to_ws => {}
        _ = ws_to_tcp => {}
    }

    info!("[{}] Tunnel closed", addr);
    Ok(())
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

/// hex 编码
fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

/// SHA256(password + challenge_hex) → hex string
fn hash_challenge(password: &str, challenge_hex: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(challenge_hex.as_bytes());
    let result = hasher.finalize();
    hex_encode(&result)
}