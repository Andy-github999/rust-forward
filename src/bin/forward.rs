use anyhow::Result;
use clap::Parser;
use log::{error, info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use rust_forward::*;
use bytes::Bytes;
use dashmap::DashMap;

type SessionId = u64;

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

struct Session {
    target: Arc<tokio::sync::Mutex<tokio::net::TcpStream>>,
    last_active: AtomicU64,
}

/// Look up a host:port in the DashMap DNS cache; insert on miss.
async fn resolve_dns(cache: &DashMap<String, SocketAddr>, target: &str) -> Result<SocketAddr> {
    let (host, port) = if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok(addr);
    } else {
        let (h, p) = target.rsplit_once(':').ok_or_else(|| anyhow::anyhow!("invalid target: {}", target))?;
        (h.to_string(), p.parse::<u16>()?)
    };
    if let Some(addr) = cache.get(&host) {
        return Ok(*addr);
    }
    let addrs = tokio::net::lookup_host((host.as_str(), port)).await?;
    let v4 = addrs.filter(|a| a.is_ipv4()).next()
        .ok_or_else(|| anyhow::anyhow!("no IPv4 for {}", target))?;
    cache.insert(host, v4);
    Ok(v4)
}

/// Remove a host from the DNS cache on connection failure.
fn dns_remove(cache: &DashMap<String, SocketAddr>, target: &str) {
    if let Some((h, _)) = target.rsplit_once(':') {
        cache.remove(h);
    }
}



struct AppState {
    password: String,
    connect_timeout: u64,
    max_sessions: usize,
    idle_timeout: Duration,
    socks5_proxy: String,
}

/// Per-H2-connection state: domain-isolated, no locks between connections.
struct ConnState {
    sessions: DashMap<SessionId, Arc<Session>>,
    next_id: AtomicU64,
    nonces: StdMutex<Vec<([u8; 16], Instant)>>,
    dns_cache: DashMap<String, SocketAddr>,
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
    /// SOCKS5 proxy address (e.g., 192.168.2.1:1070). Empty = direct connect.
    #[arg(long, default_value = "")]
    socks5_proxy: String,
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

    let socks5_proxy = args.socks5_proxy;
    let state = Arc::new(AppState {
        password,
        connect_timeout,
        max_sessions,
        idle_timeout,
        socks5_proxy,
    });

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
        .max_concurrent_streams(256)
        .initial_window_size(4_194_304)
        .initial_connection_window_size(33_554_432)
        .handshake(tls_stream)
        .await?;
    info!("H2 connection established");

    let conn = Arc::new(ConnState {
        sessions: DashMap::new(),
        next_id: AtomicU64::new(1),
        nonces: StdMutex::new(Vec::new()),
        dns_cache: DashMap::new(),
    });

    // Per-connection session idle cleanup
    {
        let conn = conn.clone();
        let idle_timeout = state.idle_timeout;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(idle_timeout / 2).await;
                let before = conn.sessions.len();
                let deadline = now_ms() - idle_timeout.as_millis() as u64;
                conn.sessions.retain(|_, s| s.last_active.load(Ordering::Relaxed) >= deadline);
                if conn.sessions.len() != before {
                    info!("session cleanup: {} -> {}", before, conn.sessions.len());
                }
            }
        });
    }

    while let Some(result) = h2.accept().await {
        let (req, respond) = result?;
        let st = state.clone();
        let cn = conn.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(req, respond, &st, &cn).await {
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
    conn: &ConnState,
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

        // HMAC verification
        if !state.password.is_empty() {
            let time = head.headers.get("x-time").and_then(|v| v.to_str().ok()).unwrap_or("");
            let nonce_h = head.headers.get("x-nonce").and_then(|v| v.to_str().ok()).unwrap_or("");
            let sign = head.headers.get("x-sign").and_then(|v| v.to_str().ok()).unwrap_or("");
            if !hmac_verify(state.password.as_bytes(), time, nonce_h, sign, "/tunnel/connect", "") {
                return send_err(respond, 502, "bad auth").await;
            }
            // Replay protection
            if let Some(nonce_bytes) = hex::decode(nonce_h).ok().filter(|v| v.len() == 16) {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&nonce_bytes);
                let is_replay = {
                    let mut nonces = conn.nonces.lock().unwrap();
                    // lazy cleanup: remove expired entries
                    if nonces.len() > 10_000 {
                        nonces.retain(|(_, t)| t.elapsed() < std::time::Duration::from_secs(30));
                    }
                    // check for duplicate
                    if nonces.iter().any(|(n, _)| *n == arr) {
                        true
                    } else {
                        nonces.push((arr, Instant::now()));
                        false
                    }
                }; // StdMutexGuard dropped here
                if is_replay {
                    return send_err(respond, 502, "replay").await;
                }
            }
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
                Err(e) => return send_err(respond, 502, &format!("socks5: {}", e)).await,
            }
        } else {
            // Resolve target via DashMap DNS cache (lock-free per-shard)
            let target_addr = match resolve_dns(&conn.dns_cache, &target).await {
                Ok(addr) => addr,
                Err(e) => { return send_err(respond, 502, &format!("dns: {}", e)).await; }
            };
            info!("[/connect] [{}] resolved to {}", target, target_addr);
            let ip_target = format!("{}:{}", target_addr.ip(), target_addr.port());
            match tokio::time::timeout(
                Duration::from_secs(state.connect_timeout),
                connect_tcp_v4(&ip_target, state.connect_timeout),
            ).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    dns_remove(&conn.dns_cache, &target);
                    return send_err(respond, 502, &format!("connect: {}", e)).await;
                }
                Err(_) => {
                    dns_remove(&conn.dns_cache, &target);
                    return send_err(respond, 504, "timeout").await;
                }
            }
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
        info!("[/connect] [{}] read {} bytes from target", target, resp_data.len());
        if resp_data.is_empty() { return send_err(respond, 504, "no response").await; }

        // Check session limit
        if conn.sessions.len() >= state.max_sessions {
            info!("session limit reached ({})", state.max_sessions);
            return send_err(respond, 503, "too many sessions").await;
        }

        // Store session
        let sid = conn.next_id.fetch_add(1, Ordering::Relaxed);
        let tgt = Arc::new(Mutex::new(target_stream));
        conn.sessions.insert(sid, Arc::new(Session {
            target: tgt,
            last_active: AtomicU64::new(now_ms()),
        }));
        // Return 200 + ServerHello + SID
        let resp = http::Response::builder()
            .status(200)
            .header("x-session-id", sid.to_string())
            .body(())
            .unwrap();
        let mut send_stream = respond.send_response(resp, false)?;
        send_stream.send_data(Bytes::from(resp_data), true)?;
        info!("[/connect] [{}] done (session {})", target, sid);
        return Ok(());
    }
    // ===== POST /tunnel/data =====
    if path.starts_with("/tunnel/data") {
        let sid: u64 = head.headers.get("x-session-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        // HMAC verification
        if !state.password.is_empty() {
            let time = head.headers.get("x-time").and_then(|v| v.to_str().ok()).unwrap_or("");
            let nonce_h = head.headers.get("x-nonce").and_then(|v| v.to_str().ok()).unwrap_or("");
            let sign = head.headers.get("x-sign").and_then(|v| v.to_str().ok()).unwrap_or("");
            let sid_str = sid.to_string();
            if !hmac_verify(state.password.as_bytes(), time, nonce_h, sign, "/tunnel/data", &sid_str) {
                return send_err(respond, 502, "bad auth").await;
            }
            // Replay protection (same as /connect)
            if let Some(nonce_bytes) = hex::decode(nonce_h).ok().filter(|v| v.len() == 16) {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&nonce_bytes);
                let is_replay = {
                    let mut nonces = conn.nonces.lock().unwrap();
                    if nonces.len() > 10_000 {
                        nonces.retain(|(_, t)| t.elapsed() < std::time::Duration::from_secs(30));
                    }
                    if nonces.iter().any(|(n, _)| *n == arr) {
                        true
                    } else {
                        nonces.push((arr, Instant::now()));
                        false
                    }
                }; // StdMutexGuard dropped here
                if is_replay {
                    return send_err(respond, 502, "replay").await;
                }
            }
        }

        let session = conn.sessions.get(&sid).map(|r| r.clone());
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

                let mut buf = [0u8; 65536];
                let mut resp = Vec::new();
                match tokio::time::timeout(Duration::from_secs(5), t.read(&mut buf)).await {
                    Ok(Ok(0)) => info!("[/data] [sid={}] target EOF", sid),
                    Err(_) => info!("[/data] [sid={}] target timeout", sid),
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
