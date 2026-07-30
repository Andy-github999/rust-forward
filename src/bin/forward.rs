use clap::Parser;
use log::{error, info, warn};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use rust_forward::*;
use bytes::Bytes;

type SessionId = u64;

const MAX_PENDING: usize = 2048;

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

struct Session {
    conn_id: u64,
    target: tokio::sync::Mutex<tokio::net::tcp::OwnedWriteHalf>,
    last_active: AtomicU64,
    next_seq: AtomicU64,
    pending: tokio::sync::Mutex<BTreeMap<u64, Vec<u8>>>,
}

struct AppState {
    password: String,
    connect_timeout: u64,
    socks5_proxy: String,
    sessions: RwLock<HashMap<SessionId, Arc<Session>>>,
    next_id: AtomicU64,
    next_conn_id: AtomicU64,
}

#[derive(Parser, Debug)]
#[command(name = "forward", about = "H2 TLS forward server for OpenWrt")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:2086")]
    listen: String,
    #[arg(long)]
    password: Option<String>,
    #[arg(long, default_value = "10")]
    connect_timeout: u64,
    /// Path to TLS certificate file (PEM). If omitted, generates self-signed.
    #[arg(long)]
    cert: Option<String>,
    /// Path to TLS private key file (PEM). Required if --cert is set.
    #[arg(long)]
    key: Option<String>,
    /// SOCKS5 proxy address (e.g., 127.0.0.1:1070). Empty = direct connect.
    #[arg(long, default_value = "")]
    socks5_proxy: String,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let args = Args::parse();
    let password = resolve_password(args.password.as_deref());

    let state = Arc::new(AppState {
        password: password.clone(),
        connect_timeout: args.connect_timeout,
        socks5_proxy: args.socks5_proxy,
        sessions: RwLock::new(HashMap::new()),
        next_id: AtomicU64::new(1),
        next_conn_id: AtomicU64::new(1),
    });

    // Load TLS cert
    let (h2_cert_der, h2_key_der) = if let (Some(cert_path), Some(key_path)) = (&args.cert, &args.key) {
        info!("Loading TLS cert from {} and key from {}", cert_path, key_path);
        let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(
            fs::File::open(cert_path).expect("cert file"),
        ))
        .collect::<Result<Vec<_>, _>>().expect("read certs");
        let key_raw = rustls_pemfile::private_key(&mut std::io::BufReader::new(
            fs::File::open(key_path).expect("key file"),
        ))
        .expect("read key")
        .expect("no private key");
        let key_der = match key_raw {
            rustls::pki_types::PrivateKeyDer::Pkcs8(k) => {
                rustls::pki_types::PrivateKeyDer::Pkcs8(k)
            }
            other => panic!("unsupported key format: {:?}", other.secret_der()),
        };
        (certs.into_iter().next().expect("no cert found"), key_der)
    } else {
        info!("Generating self-signed TLS certificate for H2 server...");
        let cert_rcgen = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let der = rustls::pki_types::CertificateDer::from(cert_rcgen.cert.der().to_vec());
        let key_raw = cert_rcgen.signing_key.serialize_der();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_raw),
        );
        (der, key)
    };

    let mut server_cfg = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into()
    )
    .with_safe_default_protocol_versions()
        .expect("tls versions")
        .with_no_client_auth()
        .with_single_cert(vec![h2_cert_der], h2_key_der)
        .expect("h2 cert");
    server_cfg.alpn_protocols = vec![b"h2".to_vec()];
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let addr: SocketAddr = args.listen.parse().expect("invalid listen address");
    assert!(addr.is_ipv4(), "only IPv4 supported");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    info!("H2 TLS server listening on {} (ALPN=h2)", addr);

    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                let tls = tls_acceptor.clone();
                let st = state.clone();
                tokio::spawn(async move {
                    let tls_stream = match tls.accept(tcp).await {
                        Ok(s) => s,
                        Err(e) => { warn!("[{}] TLS reject: {}", peer, e); return; }
                    };
                    let alpn = tls_stream.get_ref().1.alpn_protocol()
                        .map(|v| String::from_utf8_lossy(v).to_string());
                    info!("[{}] TLS, ALPN: {:?}", peer, alpn);
                    if let Err(e) = serve_h2(tokio_rustls::TlsStream::Server(tls_stream), &st).await {
                        warn!("[{}] H2: {}", peer, e);
                    }
                });
            }
            Err(e) => error!("accept: {}", e),
        }
    }
}

// ──────────────────────────────────────────────
// H2 server
// ──────────────────────────────────────────────

async fn serve_h2(
    tls_stream: tokio_rustls::TlsStream<tokio::net::TcpStream>,
    state: &Arc<AppState>,
) -> anyhow::Result<()> {
    let conn_id = state.next_conn_id.fetch_add(1, Ordering::Relaxed);
    let mut h2 = h2::server::Builder::new()
        .max_concurrent_streams(256)
        .initial_window_size(4_194_304)
        .initial_connection_window_size(33_554_432)
        .handshake(tls_stream)
        .await?;
    info!("conn {}: H2 connection established", conn_id);

    loop {
        match h2.accept().await {
            Some(Ok((req, respond))) => {
                let st = Arc::clone(state);
                let cid = conn_id;
                tokio::spawn(async move {
                    if let Err(e) = handle_h2_stream(req, respond, &st, cid).await {
                        warn!("h2 stream: {}", e);
                    }
                });
            }
            Some(Err(e)) => {
                warn!("conn {}: H2 error: {}", conn_id, e);
            }
            None => break,
        }
    }

    Ok(())
}

async fn handle_h2_stream(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    state: &Arc<AppState>,
    conn_id: u64,
) -> anyhow::Result<()> {
    let (head, mut body) = request.into_parts();
    let path = head.uri.path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("");
    let method = head.method.as_str();
    info!("H2 >>> {} {}", method, path);


    // ===== POST /tunnel/connect =====
    if path.starts_with("/tunnel/connect") {
        let target = head.headers.get("x-target")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        // Read body bytes (for both old JSON format and new raw format)
        let mut body_bytes = Vec::new();
        while let Some(Ok(chunk)) = body.data().await {
            body_bytes.extend_from_slice(&chunk);
            let _ = body.flow_control().release_capacity(chunk.len());
        }

        if target.is_empty() {
            return send_h2_err(respond, 400, "no target").await;
        }
        let auth = head.headers.get("x-auth")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !state.password.is_empty() && auth != state.password {
            return send_h2_err(respond, 403, "bad auth").await;
        }

        // Connect to target (via SOCKS5 or direct)
        let mut target_stream = if !state.socks5_proxy.is_empty() {
            match connect_via_socks5(&state.socks5_proxy, &target, state.connect_timeout).await {
                Ok(s) => s,
                Err(e) => return send_h2_err(respond, 502, &format!("socks5: {}", e)).await,
            }
        } else {
            match connect_tcp_v4(&target, state.connect_timeout).await {
                Ok(s) => s,
                Err(e) => return send_h2_err(respond, 502, &format!("connect: {}", e)).await,
            }
        };

        // Write initial data to target
        if !body_bytes.is_empty() {
            target_stream.write_all(&body_bytes).await?;
        }

        // Read ServerHello (full stream, idle-batched)
        let resp_data = read_until_idle(
            &mut target_stream,
            Duration::from_secs(10),
            Duration::from_millis(50),
        ).await;
        info!("[/connect] [{}] read {} bytes from target", target, resp_data.len());

        if resp_data.is_empty() {
            return send_h2_err(respond, 504, "no response").await;
        }

        // Store session: keep response stream open, pipe target→Chrome data
        let sid = state.next_id.fetch_add(1, Ordering::Relaxed);
        let (mut target_r, target_w) = target_stream.into_split();
        let session = Arc::new(Session {
            conn_id,
            target: tokio::sync::Mutex::new(target_w),
            last_active: AtomicU64::new(now_ms()),
            pending: tokio::sync::Mutex::new(BTreeMap::new()),
            next_seq: AtomicU64::new(0),
        });
        state.sessions.write().await.insert(sid, session);

        // Return 200 + ServerHello with open body (no END_STREAM)
        let resp = http::Response::builder()
            .status(200)
            .header("x-session-id", sid.to_string())
            .body(())
            .unwrap();
        let mut send_stream = respond.send_response(resp, false)?;

        // Send ServerHello (not end of stream)
        // If we closed here, forward could no longer push target→Chrome data
        if !resp_data.is_empty() {
            send_stream.send_data(Bytes::from(resp_data), false)?;
        }

        // Pipe target→Chrome data through the open response body
        // This is the ONLY path for target→Chrome streaming
        info!("[/connect] [{}] session {}, piping target→client", target, sid);
        let mut buf = vec![0u8; 65536];
        loop {
            match tokio::time::timeout(
                Duration::from_secs(state.connect_timeout),
                target_r.read(&mut buf),
            ).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    if send_stream.send_data(Bytes::copy_from_slice(&buf[..n]), false).is_err() {
                        break;
                    }
                    // Update last active
                    if let Some(s) = state.sessions.read().await.get(&sid) {
                        s.last_active.store(now_ms(), Ordering::Relaxed);
                    }
                }
                _ => break,
            }
        }
        // Target connection closed, end the response stream
        let _ = send_stream.send_data(Bytes::new(), true);
        // Clean up session
        state.sessions.write().await.remove(&sid);
        info!("[/connect] [{}] session {} closed", target, sid);
        return Ok(());
    }

    // ===== POST /tunnel/data =====
    if path.starts_with("/tunnel/data") {
        let sid: SessionId = head.headers.get("x-session-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        // Parse seq from query string
        let seq: u64 = head.uri.query()
            .and_then(|q| {
                q.split('&')
                    .find(|p| p.starts_with("seq="))
                    .and_then(|s| s.get(4..).and_then(|v| v.parse().ok()))
            })
            .unwrap_or(0);

        // Read body
        let mut req_data = Vec::new();
        while let Some(Ok(chunk)) = body.data().await {
            req_data.extend_from_slice(&chunk);
            let _ = body.flow_control().release_capacity(chunk.len());
        }

        let session = state.sessions.read().await.get(&sid).cloned();
        match session {
            Some(s) => {
                if !req_data.is_empty() {
                    let mut pend = s.pending.lock().await;
                    let expected = s.next_seq.load(Ordering::Relaxed);
                    if seq == expected {
                        // In-order, write directly
                        let mut t = s.target.lock().await;
                        let _ = t.write_all(&req_data).await;
                        drop(t);
                        s.next_seq.store(expected + 1, Ordering::Relaxed);
                        let mut seq_now = expected + 1;
                        // Flush pending
                        while let Some(data) = pend.remove(&seq_now) {
                            let mut t = s.target.lock().await;
                            let _ = t.write_all(&data).await;
                            drop(t);
                            seq_now += 1;
                        }
                        s.next_seq.store(seq_now, Ordering::Relaxed);
                    } else if seq > expected {
                        // Out-of-order, buffer (with cap)
                        if pend.len() < MAX_PENDING {
                            pend.insert(seq, req_data);
                            info!("[/data] [sid={}] buffered seq={}, expect={}, pending={}", sid, seq, expected, pend.len());
                        } else {
                            warn!("[/data] [sid={}] pending overflow (>{}) at seq={}, dropping connection", sid, MAX_PENDING, seq);
                            return Ok(());
                        }
                    } else {
                        warn!("[/data] [sid={}] stale seq={} < expect={}", sid, seq, expected);
                    }
                    drop(pend);
                    s.last_active.store(now_ms(), Ordering::Relaxed);
                }
                let resp_http = http::Response::builder()
                    .status(200)
                    .body(())
                    .unwrap();
                let mut send_stream = respond.send_response(resp_http, false)?;
                send_stream.send_data(Bytes::from("ok"), true)?;
            }
            None => {
                warn!("[/data] [sid={}] session not found", sid);
                return send_h2_err(respond, 404, "session not found").await;
            }
        }
        return Ok(());
    }

    // ===== POST /tunnel/close =====
    if path.starts_with("/tunnel/close") {
        let sid: SessionId = head.headers.get("x-session-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        if state.sessions.write().await.remove(&sid).is_some() {
            info!("[/close] session {} closed", sid);
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

    warn!("unknown h2 path: {}", path);
    send_h2_err(respond, 404, "unknown path").await
}

async fn send_h2_err(
    mut respond: h2::server::SendResponse<Bytes>,
    status: u16,
    msg: &str,
) -> anyhow::Result<()> {
    let resp = http::Response::builder()
        .status(status)
        .body(())
        .unwrap();
    let mut send = respond.send_response(resp, false)?;
    send.send_data(Bytes::from(msg.to_string()), true)?;
    Ok(())
}

// ──────────────────────────────────────────────
