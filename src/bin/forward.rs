use anyhow::Result;
use clap::Parser;
use std::fs;
use tracing::{error, info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
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

const DNS_TTL: Duration = Duration::from_secs(300);

struct DnsEntry {
    addr: SocketAddr,
    inserted: Instant,
}

/// Look up a host:port in the DashMap DNS cache; insert on miss.
async fn resolve_dns(cache: &DashMap<String, DnsEntry>, target: &str) -> Result<SocketAddr> {
    let (host, port) = if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok(addr);
    } else {
        let (h, p) = target.rsplit_once(':').ok_or_else(|| anyhow::anyhow!("invalid target: {}", target))?;
        (h.to_string(), p.parse::<u16>()?)
    };
    if let Some(entry) = cache.get(&host) {
        if entry.inserted.elapsed() < DNS_TTL {
            return Ok(entry.addr);
        }
        // Expired — fall through to re-resolve
        drop(entry);
        cache.remove(&host);
    }
    let addrs = tokio::net::lookup_host((host.as_str(), port)).await?;
    let v4 = addrs.filter(|a| a.is_ipv4()).next()
        .ok_or_else(|| anyhow::anyhow!("no IPv4 for {}", target))?;
    cache.insert(host, DnsEntry { addr: v4, inserted: Instant::now() });
    Ok(v4)
}

/// Remove a host from the DNS cache on connection failure.
fn dns_remove(cache: &DashMap<String, DnsEntry>, target: &str) {
    if let Some((h, _)) = target.rsplit_once(':') {
        cache.remove(h);
    }
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
    dns_cache: DashMap<String, DnsEntry>,
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
    #[arg(long, default_value = "300")]
    idle_timeout: u64,
    /// SOCKS5 proxy address (e.g., 192.168.2.1:1070). Empty = direct connect.
    #[arg(long, default_value = "")]
    socks5_proxy: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
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
        dns_cache: DashMap::new(),
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
    let mut h2 = h2::server::Builder::new()
        .max_concurrent_streams(256)
        .initial_window_size(4_194_304)
        .initial_connection_window_size(33_554_432)
        .handshake(tls_stream)
        .await?;
    info!("H2 connection established");

    let conn = Arc::new(ConnState {
        nonces: StdMutex::new(Vec::new()),
        max_nonces: 10_000,
    });

    // Global session idle cleanup
    {
        let sessions = state.sessions.clone();
        let idle_timeout = state.idle_timeout;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(idle_timeout / 2).await;
                let before = sessions.len();
                let deadline = now_ms() - idle_timeout.as_millis() as u64;
                sessions.retain(|_, s| s.last_active.load(Ordering::Relaxed) >= deadline);
                if sessions.len() != before {
                    info!("session cleanup: {} -> {}", before, sessions.len());
                }
            }
        });
    }

    // H2 keepalive: send PING every 20s to prevent Cloudflare Edge from timing out
    let ping_handle = h2.ping_pong();
    if let Some(mut ping_pong) = ping_handle {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(20)).await;
                if ping_pong.ping(h2::Ping::opaque()).await.is_err() {
                    info!("H2 keepalive PING failed, connection may be dead");
                    break;
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

        // HMAC verification + replay protection (typed error)
        if let Err(e) = verify_hmac_request(conn, &state.password, &head.headers, "/tunnel/connect", "") {
            let msg = match e { AuthError::BadAuth => "bad auth", AuthError::Replay => "replay" };
            return send_err(respond, 502, msg).await;
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
            let target_addr = match resolve_dns(&state.dns_cache, &target).await {
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
                    dns_remove(&state.dns_cache, &target);
                    return send_err(respond, 502, &format!("connect: {}", e)).await;
                }
                Err(_) => {
                    dns_remove(&state.dns_cache, &target);
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
