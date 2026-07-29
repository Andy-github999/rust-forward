use anyhow::Result;
use clap::Parser;
use std::fs;
use tracing::{error, info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio::sync::Notify;
use rust_forward::*;
use bytes::Bytes;
use dashmap::DashMap;

type SessionId = u64;

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

struct Session {
    conn_id: u64,
    target: Arc<tokio::sync::Mutex<tokio::net::TcpStream>>,
    last_active: AtomicU64,
}

/// Maximum concurrent TCP connections (AtomicUsize guard, no kernel wait).
const MAX_CONN: usize = 64;

/// Drop guard that decrements the connection counter.
struct ConnGuard(Arc<AtomicUsize>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Extract host part from "host:port" string.
fn target_host(target: &str) -> &str {
    target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target)
}

/// Verify HMAC headers + replay protection for a request, in a single call.
#[derive(Debug)]
enum AuthError {
    BadAuth,
    Replay,
}

fn verify_hmac_request(
    conn: &ConnState,
    password: &str,
    headers: &http::HeaderMap,
    path: &str,
    session_id: &str,
) -> std::result::Result<(), AuthError> {
    if password.is_empty() {
        return Ok(());
    }
    let time = headers.get("x-time").and_then(|v| v.to_str().ok()).unwrap_or("");
    let nonce_h = headers.get("x-nonce").and_then(|v| v.to_str().ok()).unwrap_or("");
    let sign = headers.get("x-sign").and_then(|v| v.to_str().ok()).unwrap_or("");
    if !hmac_verify(password.as_bytes(), time, nonce_h, sign, path, session_id) {
        return Err(AuthError::BadAuth);
    }
    // Replay protection via nonce dedup
    if let Some(nonce_bytes) = hex::decode(nonce_h).ok().filter(|v| v.len() == 16) {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&nonce_bytes);
        let mut nonces = conn.nonces.lock().unwrap();
        if nonces.len() > conn.max_nonces {
            nonces.retain(|(_, t)| t.elapsed() < Duration::from_secs(30));
        }
        if nonces.iter().any(|(n, _)| *n == arr) {
            return Err(AuthError::Replay);
        }
        nonces.push((arr, Instant::now()));
    }
    Ok(())
}

struct AppState {
    password: String,
    connect_timeout: u64,
    max_sessions: usize,
    idle_timeout: Duration,
    socks5_proxy: String,
    sessions: DashMap<SessionId, Arc<Session>>,
    next_id: AtomicU64,
    next_conn_id: AtomicU64,
    unreachable: DashMap<String, Instant>,
}

/// Per-H2-connection state: nonces for replay protection only.
struct ConnState {
    nonces: StdMutex<Vec<([u8; 16], Instant)>>,
    max_nonces: usize,
}

#[derive(Parser, Debug)]
#[command(name = "forward", about = "H2 TCP forward for OpenWrt")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:2086")]
    listen: String,
    #[arg(long)]
    password: Option<String>,
    /// Path to TLS certificate file (PEM). If omitted, generates self-signed.
    #[arg(long)]
    cert: Option<String>,
    /// Path to TLS private key file (PEM). Required if --cert is set.
    #[arg(long)]
    key: Option<String>,
    #[arg(long, default_value = "10")]
    connect_timeout: u64,
    #[arg(long, default_value = "1024")]
    max_sessions: usize,
    #[arg(long, default_value = "60")]
    idle_timeout: u64,
    /// SOCKS5 proxy address (e.g., 192.168.2.1:1070). Empty = direct connect.
    #[arg(long, default_value = "")]
    socks5_proxy: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let default_level = if cfg!(debug_assertions) { "info" } else { "error" };
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level))
        )
        .init();
    let args = Args::parse();
    let password = resolve_password(args.password.as_deref());
    let connect_timeout = args.connect_timeout;

    let _ = rustls::crypto::ring::default_provider().install_default();

    // Load TLS certificate (from file or self-signed)
    let (cert_der, key_der) = if let (Some(cert_path), Some(key_path)) = (&args.cert, &args.key) {
        info!("Loading TLS cert from {} and key from {}", cert_path, key_path);
        let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(fs::File::open(cert_path)?))
            .collect::<Result<Vec<_>, _>>()?;
        let key_raw = rustls_pemfile::private_key(&mut std::io::BufReader::new(fs::File::open(key_path)?))?
            .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path))?;
        let key_der = match key_raw {
            rustls::pki_types::PrivateKeyDer::Pkcs8(k) => {
                rustls::pki_types::PrivateKeyDer::Pkcs8(k)
            }
            other => anyhow::bail!("unsupported key format: {:?}", other.secret_der()),
        };
        (certs.into_iter().next().ok_or_else(|| anyhow::anyhow!("no cert found"))?, key_der)
    } else {
        info!("Generating self-signed TLS certificate...");
        let cert_rcgen = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()])?;
        let der = rustls::pki_types::CertificateDer::from(cert_rcgen.cert.der().to_vec());
        let key_raw = cert_rcgen.key_pair.serialize_der();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_raw),
        );
        (der, key)
    };

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

    let socks5_proxy = args.socks5_proxy;
    let state = Arc::new(AppState {
        password,
        connect_timeout,
        max_sessions,
        idle_timeout,
        socks5_proxy,
        sessions: DashMap::new(),
        next_id: AtomicU64::new(1),
        next_conn_id: AtomicU64::new(1),
        unreachable: DashMap::new(),
    });

    // Global session idle cleanup (one task for entire process)
    {
        let state_clone = state.clone();
        let idle_timeout = state.idle_timeout;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(idle_timeout / 2).await;
                let before = state_clone.sessions.len();
                let deadline = now_ms() - idle_timeout.as_millis() as u64;
                state_clone.sessions.retain(|_, s| s.last_active.load(Ordering::Relaxed) >= deadline);
                if state_clone.sessions.len() != before {
                    info!("session cleanup: {} -> {}", before, state_clone.sessions.len());
                }
                // Expire old unreachable entries (checked on lookup too, this is just GC)
                state_clone.unreachable.retain(|_, ts| ts.elapsed() < Duration::from_secs(60));
            }
        });
    }

    let conn_limit = Arc::new(AtomicUsize::new(0));

    loop {
        match lis.accept().await {
            Ok((tcp, peer)) => {
                let prev = conn_limit.fetch_add(1, Ordering::AcqRel);
                if prev >= MAX_CONN {
                    conn_limit.fetch_sub(1, Ordering::AcqRel);
                    warn!("[{}] connection limit reached ({}), dropping", peer, MAX_CONN);
                    drop(tcp);
                    continue;
                }
                let guard = ConnGuard(conn_limit.clone());
                let tls = tls_acceptor.clone();
                let st = state.clone();
                tokio::spawn(async move {
                    let _guard = guard;
                    let tls_stream = match tls.accept(tcp).await {
                        Ok(s) => s,
                        Err(e) => { warn!("[{}] TLS: {}", peer, e); return; }
                    };
                    // Log the ALPN negotiated between Edge and forward
                    let alpn = tls_stream.get_ref().1.alpn_protocol().map(|v| String::from_utf8_lossy(v).to_string());
                    info!("[{}] TLS established, ALPN: {:?}, Edge→forward protocol: {}", peer, alpn, alpn.as_deref().unwrap_or("unknown"));
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
    let conn_id = state.next_conn_id.fetch_add(1, Ordering::Relaxed);
    let mut h2 = h2::server::Builder::new()
        .max_concurrent_streams(256)
        .initial_window_size(4_194_304)
        .initial_connection_window_size(33_554_432)
        .handshake(tls_stream)
        .await?;
    info!("conn {}: H2 connection established", conn_id);

    let conn = Arc::new(ConnState {
        nonces: StdMutex::new(Vec::new()),
        max_nonces: 10_000,
    });

    // H2 keepalive: send PING every 20s to prevent Cloudflare Edge from timing out.
    // If PING fails (connection truly dead), signal shutdown to free the fd.
    let ping_handle = h2.ping_pong();
    let shutdown = Arc::new(Notify::new());
    if let Some(mut ping_pong) = ping_handle {
        let sig = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(20)).await;
                match tokio::time::timeout(Duration::from_secs(10), ping_pong.ping(h2::Ping::opaque())).await {
                    Ok(Ok(_)) => {}
                    _ => {
                        info!("conn: H2 keepalive PING failed or timed out");
                        sig.notify_one();
                        break;
                    }
                }
            }
        });
    }

    // Safety counter: consecutive stream errors without a successful accept.
    // In h2 0.4, connection-level errors return None (not Some(Err)),
    // but this guard prevents infinite spinning if behavior differs.
    let mut stream_errs: u32 = 0;

    loop {
        tokio::select! {
            result = h2.accept() => {
                match result {
                    Some(Ok((req, respond))) => {
                        stream_errs = 0;
                        let st = state.clone();
                        let cn = conn.clone();
                        let cid = conn_id;
                        tokio::spawn(async move {
                            if let Err(e) = handle_stream(req, respond, &st, &cn, cid).await {
                                warn!("stream: {}", e);
                            }
                        });
                    }
                    Some(Err(e)) => {
                        stream_errs += 1;
                        warn!("conn {}: H2 error (consecutive={}): {}", conn_id, stream_errs, e);
                        if stream_errs > 50 {
                            // Too many consecutive errors without a single success.
                            // h2 0.4 should return None for connection-level errors,
                            // but this guard prevents spinning if it doesn't.
                            warn!("conn {}: too many consecutive H2 errors, dropping connection", conn_id);
                            break;
                        }
                    }
                    None => break,
                }
            }
            _ = shutdown.notified() => {
                info!("conn {}: graceful shutdown...", conn_id);
                h2.graceful_shutdown();
                // Wait for existing streams to complete (max 5s)
                loop {
                    tokio::select! {
                        result = h2.accept() => {
                            match result {
                                Some(Ok((req, respond))) => {
                                    let st = state.clone();
                                    let cn = conn.clone();
                                    let cid = conn_id;
                                    tokio::spawn(async move {
                                        if let Err(e) = handle_stream(req, respond, &st, &cn, cid).await {
                                            warn!("stream: {}", e);
                                        }
                                    });
                                }
                                Some(Err(e)) => {
                                    warn!("conn {}: stream error during shutdown: {}", conn_id, e);
                                }
                                None => {
                                    info!("conn {}: shutdown complete", conn_id);
                                    break;
                                }
                            }
                        }
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {
                            info!("conn {}: shutdown timeout, forcing close", conn_id);
                            break;
                        }
                    }
                }
                break;
            }
        }
    }

    // Clean up sessions owned by this connection (prevents fd leaks on unclean
    // disconnects, e.g., bridge killed, Chrome closed, network drop).
    // Always runs — it's idempotent and harmless even on graceful shutdown.
    let before = state.sessions.len();
    state.sessions.retain(|_, s| s.conn_id != conn_id);
    let removed = before - state.sessions.len();
    if removed > 0 {
        info!("conn {}: cleaned {} sessions (target fds released)", conn_id, removed);
    }

    Ok(())
}

async fn handle_stream(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    state: &AppState,
    conn: &ConnState,
    conn_id: u64,
) -> Result<()> {
    let (head, mut body) = request.into_parts();
    let path = head.uri.path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("");
    let method = head.method.as_str();
    // Log all request headers to see CF/cloudflared additions
    let mut header_summary = String::new();
    for (k, v) in head.headers.iter() {
        if let Ok(val) = v.to_str() {
            header_summary.push(' ');
            header_summary.push_str(k.as_str());
            header_summary.push('=');
            header_summary.push_str(val);
        }
    }
    info!(">>> {} {}{}", method, path, header_summary);

    // ===== POST /tunnel/connect =====
    if path.starts_with("/tunnel/connect") {
        let target = head.headers.get("x-target")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if target.is_empty() { return send_err(respond, 400, "no target").await; }

        // HMAC verification + replay protection (typed error)
        if let Err(e) = verify_hmac_request(conn, &state.password, &head.headers, "/tunnel/connect", "") {
            let msg = match e { AuthError::BadAuth => "bad auth", AuthError::Replay => "replay" };
            return send_err(respond, 502, msg).await;
        }

        // Skip immediately if target is in unreachable cache (recently failed)
        let host = target_host(&target).to_string();
        if let Some(entry) = state.unreachable.get(&host) {
            if entry.elapsed() < Duration::from_secs(60) {
                info!("[/connect] [{}] cached unreachable, skip", target);
                return send_err(respond, 503, "target unreachable").await;
            }
            drop(entry);
            state.unreachable.remove(&host);
        }

        // Read ClientHello from body (loop over all H2 DATA frames)
        let mut helo = Vec::new();
        while let Some(Ok(chunk)) = body.data().await {
            helo.extend_from_slice(&chunk);
            let _ = body.flow_control().release_capacity(chunk.len());
        }
        info!("[/connect] [{}] ClientHello {} bytes", target, helo.len());

        // Connect to target (via SOCKS5 proxy or direct)
        let mut target_stream = if !state.socks5_proxy.is_empty() {
            info!("[/connect] [{}] via SOCKS5 {}", target, state.socks5_proxy);
            match connect_via_socks5(&state.socks5_proxy, &target, state.connect_timeout).await {
                Ok(s) => s,
                Err(e) => {
                    state.unreachable.insert(host.clone(), Instant::now());
                    return send_err(respond, 502, &format!("socks5: {}", e)).await;
                }
            }
        } else {
            // Connect directly to target — pass the original hostname so
            // connect_tcp_v4 can resolve DNS and try all resolved IPv4
            // addresses (CDN multi-IP fallback).
            match tokio::time::timeout(
                Duration::from_secs(state.connect_timeout),
                connect_tcp_v4(&target, state.connect_timeout),
            ).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    state.unreachable.insert(host.clone(), Instant::now());
                    return send_err(respond, 502, &format!("connect: {}", e)).await;
                }
                Err(_) => {
                    state.unreachable.insert(host.clone(), Instant::now());
                    return send_err(respond, 504, "timeout").await;
                }
            }
        };

        // Write ClientHello
        if !helo.is_empty() { target_stream.write_all(&helo).await?; }

        // Read ServerHello from target (idle-batched: 10s first byte, 50ms idle between chunks)
        let resp_data = read_until_idle(
            &mut target_stream,
            Duration::from_secs(10),
            Duration::from_millis(50),
        ).await;
        info!("[/connect] [{}] read {} bytes from target", target, resp_data.len());
        if resp_data.is_empty() { return send_err(respond, 504, "no response").await; }

        // Check session limit
        if state.sessions.len() >= state.max_sessions {
            info!("session limit reached ({})", state.max_sessions);
            return send_err(respond, 503, "too many sessions").await;
        }

        // Store session
        let sid = state.next_id.fetch_add(1, Ordering::Relaxed);
        let tgt = Arc::new(Mutex::new(target_stream));
        state.sessions.insert(sid, Arc::new(Session {
            conn_id,
            target: tgt,
            last_active: AtomicU64::new(now_ms()),
        }));
        // Return 200 + ServerHello + SID
        let resp = http::Response::builder()
            .status(200)
            .header("x-session-id", sid.to_string())
            .body(())
            .unwrap();
        let mut send_stream = match respond.send_response(resp, false) {
            Ok(s) => s,
            Err(e) => {
                state.sessions.remove(&sid);
                return Err(e.into());
            }
        };
        if let Err(e) = send_stream.send_data(Bytes::from(resp_data), true) {
            state.sessions.remove(&sid);
            return Err(e.into());
        }
        info!("[/connect] [{}] done (session {})", target, sid);
        return Ok(());
    }
    // ===== POST /tunnel/data =====
    if path.starts_with("/tunnel/data") {
        let sid: u64 = head.headers.get("x-session-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        // HMAC verification + replay protection (typed error)
        let sid_str = sid.to_string();
        if let Err(e) = verify_hmac_request(conn, &state.password, &head.headers, "/tunnel/data", &sid_str) {
            let msg = match e { AuthError::BadAuth => "bad auth", AuthError::Replay => "replay" };
            return send_err(respond, 502, msg).await;
        }

        let session = state.sessions.get(&sid).map(|r| r.clone());
        match session {
            Some(s) => {
                let tm = s.target.clone();
                let mut req_data = Vec::new();
                while let Some(Ok(chunk)) = body.data().await {
                    req_data.extend_from_slice(&chunk);
                    let _ = body.flow_control().release_capacity(chunk.len());
                }

                let mut t = tm.lock().await;
                if !req_data.is_empty() { t.write_all(&req_data).await?; }

                // Read target response (idle-batched: 5s first byte, 100ms idle between chunks)
                let resp = read_until_idle(
                    &mut t,
                    Duration::from_secs(5),
                    Duration::from_millis(100),
                ).await;
                if resp.is_empty() && !req_data.is_empty() {
                    // We sent data but got nothing back — target TCP connection is dead.
                    // Close the session to reclaim the fd and prevent bridge from
                    // looping forever on empty responses.
                    info!("[/data] [sid={}] target closed while data pending, removing session", sid);
                    state.sessions.remove(&sid);
                    drop(t);
                    return send_err(respond, 502, "target closed").await;
                }
                if resp.is_empty() {
                    info!("[/data] [sid={}] target no response", sid);
                }
                drop(t);
                // Update session last_active via Arc (no second read lock)
                s.last_active.store(now_ms(), Ordering::Relaxed);
                info!("[/data] [sid={}] return {} bytes", sid, resp.len());

                let resp_http = http::Response::builder()
                    .status(200)
                    .header("content-length", resp.len().to_string())
                    .body(())
                    .unwrap();
                let mut send_stream = respond.send_response(resp_http, false)?;
                send_stream.send_data(Bytes::from(resp), true)?;
            }
            None => {
                warn!("[/data] [sid={}] session not found", sid);
                return send_err(respond, 410, "session gone").await;
            }
        }
        return Ok(());
    }
    // ===== POST /tunnel/close =====
    if path.starts_with("/tunnel/close") {
        let sid: u64 = head.headers.get("x-session-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        let sid_str = sid.to_string();
        if let Err(e) = verify_hmac_request(conn, &state.password, &head.headers, "/tunnel/close", &sid_str) {
            let msg = match e { AuthError::BadAuth => "bad auth", AuthError::Replay => "replay" };
            return send_err(respond, 502, msg).await;
        }

        if state.sessions.remove(&sid).is_some() {
            info!("[/close] session {} closed, target fd released", sid);
        } else {
            warn!("[/close] session {} not found", sid);
        }
        let resp = http::Response::builder()
            .status(200)
            .body(())
            .unwrap();
        let mut send_stream = respond.send_response(resp, false)?;
        send_stream.send_data(Bytes::from("ok"), true)?;
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
