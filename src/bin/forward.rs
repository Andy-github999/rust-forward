use anyhow::Result;
use clap::Parser;
use log::{error, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{RwLock, Mutex};
use rust_forward::*;
use bytes::Bytes;

type SessionId = u64;

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

struct Session {
    target: Arc<tokio::sync::Mutex<tokio::net::TcpStream>>,
    last_active: AtomicU64,
}

struct AppState {
    password: String,
    connect_timeout: u64,
    max_sessions: usize,
    idle_timeout: Duration,
    sessions: RwLock<HashMap<SessionId, Session>>,
    next_id: AtomicU64,
    nonces: Mutex<Vec<([u8; 16], Instant)>>,
}

fn get_query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        if kv.next()? == key {
            return kv.next().map(|v| v.to_string());
        }
    }
    None
}

#[derive(Parser, Debug)]
#[command(name = "forward", about = "H2 TCP forward for OpenWrt")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:2086")]
    listen: String,
    #[arg(long)]
    password: Option<String>,
    #[arg(long, default_value = "10")]
    connect_timeout: u64,
    #[arg(long, default_value = "1024")]
    max_sessions: usize,
    #[arg(long, default_value = "300")]
    idle_timeout: u64,
}
#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis().init();
    let args = Args::parse();
    let password = resolve_password(args.password.as_deref());
    let connect_timeout = args.connect_timeout;

    let _ = rustls::crypto::ring::default_provider().install_default();

    // Generate self-signed cert for H2
    info!("Generating self-signed TLS certificate...");
    let cert_rcgen = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()])?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert_rcgen.cert.der().to_vec());
    let key_raw = cert_rcgen.key_pair.serialize_der();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_raw),
    );

    let mut server_cfg = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into()
    )
    .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("tls: {:?}", e))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| anyhow::anyhow!("cert: {:?}", e))?;
    server_cfg.alpn_protocols = vec![b"h2".to_vec()];
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let la: SocketAddr = args.listen.parse().expect("bind addr");
    let lis = tokio::net::TcpListener::bind(la).await.unwrap();
    let max_sessions = args.max_sessions;
    let idle_timeout = Duration::from_secs(args.idle_timeout);

    let state = Arc::new(AppState {
        password,
        connect_timeout,
        max_sessions,
        idle_timeout,
        sessions: RwLock::new(HashMap::new()),
        next_id: AtomicU64::new(1),
        nonces: Mutex::new(Vec::new()),
    });

    // Session idle cleanup
    {
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(st.idle_timeout / 2).await;
                let mut sessions = st.sessions.write().await;
                let before = sessions.len();
                let deadline = now_ms() - st.idle_timeout.as_millis() as u64;
                sessions.retain(|_, s| s.last_active.load(Ordering::Relaxed) >= deadline);
                if sessions.len() != before {
                    info!("session cleanup: {} -> {}", before, sessions.len());
                }
            }
        });
    }

    loop {
        match lis.accept().await {
            Ok((tcp, peer)) => {
                let tls = tls_acceptor.clone();
                let st = state.clone();
                tokio::spawn(async move {
                    let tls_stream = match tls.accept(tcp).await {
                        Ok(s) => s,
                        Err(e) => { warn!("[{}] TLS: {}", peer, e); return; }
                    };
                    if let Err(e) = serve_h2(tokio_rustls::TlsStream::Server(tls_stream), st).await {
                        warn!("[{}] H2: {}", peer, e);
                    }
                });
            }
            Err(e) => error!("accept: {}", e),
        }
    }
}

async fn serve_h2(
    tls_stream: tokio_rustls::TlsStream<tokio::net::TcpStream>,
    state: Arc<AppState>,
) -> Result<()> {
    let mut h2 = h2::server::Builder::new()
        .handshake(tls_stream)
        .await?;
    info!("H2 connection established");

    while let Some(result) = h2.accept().await {
        let (req, respond) = result?;
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(req, respond, &st).await {
                warn!("stream: {}", e);
            }
        });
    }
    Ok(())
}

async fn handle_stream(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    state: &AppState,
) -> Result<()> {
    let (head, mut body) = request.into_parts();
    let path = head.uri.path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_default();
    let method = head.method.as_str().to_string();
    info!(">>> {} {}", method, path);

    // ===== POST /connect =====
    if path.starts_with("/connect") {
        let target = head.uri.query()
            .and_then(|q| get_query_param(q, "target"))
            .unwrap_or_default();
        if target.is_empty() { return send_err(respond, 400, "no target").await; }

        // HMAC verification
        if !state.password.is_empty() {
            let time = head.headers.get("x-time").and_then(|v| v.to_str().ok()).unwrap_or("");
            let nonce_h = head.headers.get("x-nonce").and_then(|v| v.to_str().ok()).unwrap_or("");
            let sign = head.headers.get("x-sign").and_then(|v| v.to_str().ok()).unwrap_or("");
            if !hmac_verify(state.password.as_bytes(), time, nonce_h, sign, "/connect", "") {
                return send_err(respond, 502, "bad auth").await;
            }
            // Replay protection
            if let Some(nonce_bytes) = hex::decode(nonce_h).ok().filter(|v| v.len() == 16) {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&nonce_bytes);
                let mut nonces = state.nonces.lock().await;
                // lazy cleanup: remove expired entries
                if nonces.len() > 10_000 {
                    nonces.retain(|(_, t)| t.elapsed() < std::time::Duration::from_secs(30));
                }
                // check for duplicate
                if nonces.iter().any(|(n, _)| *n == arr) {
                    return send_err(respond, 502, "replay").await;
                }
                nonces.push((arr, Instant::now()));
            }
        }

        // Read ClientHello from body
        let mut helo = Vec::new();
        if let Some(Ok(chunk)) = body.data().await {
            helo.extend_from_slice(&chunk);
            let _ = body.flow_control().release_capacity(chunk.len());
        }
        info!("[/connect] ClientHello {} bytes", helo.len());

        // Connect to target
        let mut target_stream = match tokio::time::timeout(
            Duration::from_secs(state.connect_timeout),
            connect_tcp_v4(&target, state.connect_timeout),
        ).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => { return send_err(respond, 502, &format!("connect: {}", e)).await; }
            Err(_) => { return send_err(respond, 504, "timeout").await; }
        };

        // Write ClientHello
        if !helo.is_empty() { target_stream.write_all(&helo).await?; }

        // Read ServerHello from target
        let mut tbuf = [0u8; 65536];
        let mut resp_data = Vec::new();
        match tokio::time::timeout(Duration::from_secs(10), target_stream.read(&mut tbuf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {}
            Ok(Ok(n)) => resp_data.extend_from_slice(&tbuf[..n]),
        }
        for _ in 0..20 {
            match tokio::time::timeout(Duration::from_millis(200), target_stream.read(&mut tbuf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => resp_data.extend_from_slice(&tbuf[..n]),
            }
        }
        info!("read {} bytes from target", resp_data.len());
        if resp_data.is_empty() { return send_err(respond, 504, "no response").await; }

        // Check session limit
        {
            let sessions = state.sessions.read().await;
            if sessions.len() >= state.max_sessions {
                info!("session limit reached ({})", state.max_sessions);
                return send_err(respond, 503, "too many sessions").await;
            }
        }

        // Store session
        let sid = state.next_id.fetch_add(1, Ordering::Relaxed);
        let tgt = Arc::new(tokio::sync::Mutex::new(target_stream));
        state.sessions.write().await.insert(sid, Session {
            target: tgt,
            last_active: AtomicU64::new(now_ms()),
        });
        // Return 200 + ServerHello + SID
        let resp = http::Response::builder()
            .status(200)
            .header("x-session-id", sid.to_string())
            .body(())
            .unwrap();
        let mut send_stream = respond.send_response(resp, false)?;
        send_stream.send_data(Bytes::from(resp_data), true)?;
        info!("[/connect] done (session {})", sid);
        return Ok(());
    }
    // ===== POST /data =====
    if path.starts_with("/data") {
        let sid: u64 = head.uri.query()
            .and_then(|q| get_query_param(q, "id"))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        info!("[/data] sid={}", sid);

        // HMAC verification
        if !state.password.is_empty() {
            let time = head.headers.get("x-time").and_then(|v| v.to_str().ok()).unwrap_or("");
            let nonce_h = head.headers.get("x-nonce").and_then(|v| v.to_str().ok()).unwrap_or("");
            let sign = head.headers.get("x-sign").and_then(|v| v.to_str().ok()).unwrap_or("");
            let sid_str = sid.to_string();
            if !hmac_verify(state.password.as_bytes(), time, nonce_h, sign, "/data", &sid_str) {
                return send_err(respond, 502, "bad auth").await;
            }
            // Replay protection (same as /connect)
            if let Some(nonce_bytes) = hex::decode(nonce_h).ok().filter(|v| v.len() == 16) {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&nonce_bytes);
                let mut nonces = state.nonces.lock().await;
                if nonces.len() > 10_000 {
                    nonces.retain(|(_, t)| t.elapsed() < std::time::Duration::from_secs(30));
                }
                if nonces.iter().any(|(n, _)| *n == arr) {
                    return send_err(respond, 502, "replay").await;
                }
                nonces.push((arr, Instant::now()));
            }
        }

        let session = { state.sessions.read().await.get(&sid).map(|s| s.target.clone()) };
        match session {
            Some(tm) => {
                let mut req_data = Vec::new();
                while let Some(Ok(chunk)) = body.data().await {
                    req_data.extend_from_slice(&chunk);
                    let _ = body.flow_control().release_capacity(chunk.len());
                }
                info!("[/data] read {} bytes", req_data.len());

                let mut t = tm.lock().await;
                if !req_data.is_empty() { t.write_all(&req_data).await?; }

                let mut buf = [0u8; 65536];
                let mut resp = Vec::new();
                match tokio::time::timeout(Duration::from_millis(500), t.read(&mut buf)).await {
                    Ok(Ok(0)) => info!("[/data] target EOF"),
                    Err(_) => info!("[/data] target timeout"),
                    Ok(Ok(n)) => {
                        resp.extend_from_slice(&buf[..n]);
                        for _ in 0..20 {
                            match tokio::time::timeout(Duration::from_millis(100), t.read(&mut buf)).await {
                                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                                Ok(Ok(n)) => resp.extend_from_slice(&buf[..n]),
                            }
                        }
                    }
                    _ => {}
                }
                drop(t);
                // Update session last_active (read lock, atomic store)
                if let Some(s) = state.sessions.read().await.get(&sid) {
                    s.last_active.store(now_ms(), Ordering::Relaxed);
                }
                info!("[/data] return {} bytes", resp.len());

                let resp_http = http::Response::builder()
                    .status(200)
                    .header("content-length", resp.len().to_string())
                    .body(())
                    .unwrap();
                let mut send_stream = respond.send_response(resp_http, false)?;
                send_stream.send_data(Bytes::from(resp), true)?;
            }
            None => {
                warn!("[/data] session {} not found", sid);
                return send_err(respond, 404, "session not found").await;
            }
        }
        return Ok(());
    }

    warn!("unknown path: {}", path);
    send_err(respond, 404, "unknown").await
}

async fn send_err(
    mut respond: h2::server::SendResponse<Bytes>,
    status: u16,
    msg: &str,
) -> Result<()> {
    let resp = http::Response::builder()
        .status(status)
        .body(())
        .unwrap();
    let mut send = respond.send_response(resp, false)?;
    send.send_data(Bytes::from(msg.to_string()), true)?;
    Ok(())
}
