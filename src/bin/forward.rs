use clap::Parser;
use log::{error, info, warn};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    target: tokio::sync::Mutex<tokio::net::tcp::OwnedWriteHalf>,
    last_active: AtomicU64,
    next_seq: AtomicU64,
    pending: tokio::sync::Mutex<BTreeMap<u64, Bytes>>,
    /// Set by /tunnel/close. The /connect relay loop checks it between reads so
    /// it can stop at once instead of waiting for the target to time out.
    closed: AtomicBool,
    /// Wakes the relay loop when `closed` flips. `notify_one` stores a permit,
    /// so the signal is not lost if the loop is mid-`select!` when it lands.
    closed_notify: tokio::sync::Notify,
    up_bytes: AtomicU64,
    down_bytes: AtomicU64,
    created_ms: u64,
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
                // Set TCP_NODELAY on the accepted socket before TLS handshake.
                // Proxy traffic is latency-sensitive; disable Nagle.
                // Use raw fd to avoid into_std/from_std round-trip.
                #[cfg(target_os = "linux")]
                {
                    use std::os::fd::AsRawFd;
                    let fd = tcp.as_raw_fd();
                    let on: libc::c_int = 1;
                    unsafe {
                        libc::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY,
                            &on as *const _ as *const libc::c_void,
                            std::mem::size_of::<libc::c_int>() as libc::socklen_t);
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    // On Windows: TcpStream::set_nodelay requires mutable access,
                    // but configure happens inside forward (always Linux).
                }
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
    _conn_id: u64,
) -> anyhow::Result<()> {
    let (head, mut body) = request.into_parts();
    let path = head.uri.path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("");
    let method = head.method.as_str();
    // Wall-clock independent timing: report how long *this side* spent from
    // "request head received" to "response head sent". The bridge subtracts it
    // from its own resp= figure to get the pure round trip. Doing it in-band
    // avoids trusting either host's clock (the router has no RTC, and the two
    // logs were measured to be ~6.9s apart).
    let t_handler = std::time::Instant::now();
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
        //
        // idle_timeout used to be 50ms, which was pure added latency: the
        // target writes the ServerHello burst in one go, so the 50ms was
        // always a sleep on the *last* chunk. 15ms still absorbs multi-segment
        // bursts (read_until_idle drains the socket buffer via try_read first),
        // and anything later just rides the normal relay loop instead.
        let t_hello = now_ms();
        let resp_data = read_until_idle(
            &mut target_stream,
            Duration::from_secs(10),
            Duration::from_millis(15),
        ).await;
        info!("[/connect] [{}] read {} bytes from target ({}ms)",
            target, resp_data.len(), now_ms().saturating_sub(t_hello));

        if resp_data.is_empty() {
            return send_h2_err(respond, 504, "no response").await;
        }

        // Store session: keep response stream open, pipe target→Chrome data
        let sid = state.next_id.fetch_add(1, Ordering::Relaxed);
        let (mut target_r, target_w) = target_stream.into_split();
        let hello_len = resp_data.len();
        let session = Arc::new(Session {
            target: tokio::sync::Mutex::new(target_w),
            last_active: AtomicU64::new(now_ms()),
            pending: tokio::sync::Mutex::new(BTreeMap::new()),
            next_seq: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            closed_notify: tokio::sync::Notify::new(),
            up_bytes: AtomicU64::new(0),
            down_bytes: AtomicU64::new(hello_len as u64),
            created_ms: now_ms(),
        });
        state.sessions.write().await.insert(sid, session.clone());

        // Return 200 + ServerHello with open body (no END_STREAM)
        let resp = http::Response::builder()
            .status(200)
            .header("x-session-id", sid.to_string())
            .header("x-fwd-ms", t_handler.elapsed().as_millis().to_string())
            .body(())
            .unwrap();
        let mut send_stream = respond.send_response(resp, false)?;
        let stream_id = send_stream.stream_id();

        // Send ServerHello (not end of stream)
        // If we closed here, forward could no longer push target→Chrome data
        if !resp_data.is_empty() {
            send_stream.send_data(resp_data.freeze(), false)?;
        }
        info!("[/connect] [{}] sid={} stream={:?} -> 200 + {}B ServerHello sent (send_capacity={}B)",
            target, sid, stream_id, hello_len, send_stream.capacity());

        // Pipe target→Chrome data through the open response body.
        // This is the ONLY path for target→Chrome streaming.
        info!("[/connect] [{}] session {}, piping target→client", target, sid);
        // Reusable buffer: read_buf appends into BytesMut (zero-copy), then
        // split_to().freeze() yields the chunk without an extra copy.
        // BytesMut::remaining_mut() is effectively unbounded: chunk_mut grows
        // the buffer by 64 bytes when capacity == len, so read_buf never
        // returns Ok(0) because the buffer is full. Top up with a full-size
        // reserve instead so reads stay large after split_to exhausts it.
        let mut buf = bytes::BytesMut::with_capacity(65536);
        let reason = loop {
            // Belt and braces: /tunnel/close may land between select! iterations.
            if session.closed.load(Ordering::Relaxed) {
                break "client closed";
            }
            // split_to() advances the buffer start and consumes that much
            // capacity; restore the full 64KiB window once it is exhausted.
            if buf.capacity() == buf.len() {
                buf.reserve(65536);
            }
            tokio::select! {
                biased;
                // /tunnel/close flips `closed` and stores a notify permit, so
                // the wakeup cannot be lost if it lands between iterations.
                _ = session.closed_notify.notified() => break "client closed",
                r = tokio::time::timeout(Duration::from_secs(30), target_r.read_buf(&mut buf)) => {
                    match r {
                        Ok(Ok(0)) => break "target eof",
                        Ok(Ok(n)) => {
                            if !send_chunk(&mut send_stream, &mut buf, n, &session).await {
                                break "client send failed";
                            }
                            session.last_active.store(now_ms(), Ordering::Relaxed);
                        }
                        Ok(Err(e)) => {
                            warn!("[/connect] [{}] sid={} target read error: {}", target, sid, e);
                            break "target read error";
                        }
                        Err(_) => {
                            // Timeout: the session may still be alive via
                            // /tunnel/data writes, so only give up once both
                            // directions have been idle past the threshold.
                            let last = session.last_active.load(Ordering::Relaxed);
                            if last < now_ms().saturating_sub(60_000) {
                                info!("[/connect] [{}] session {} idle >60s, closing", target, sid);
                                break "idle timeout";
                            }
                        }
                    }
                }
            }
        };
        // Target connection closed, end the response stream
        let _ = send_stream.send_data(Bytes::new(), true);
        // Clean up session
        state.sessions.write().await.remove(&sid);
        let up = session.up_bytes.load(Ordering::Relaxed);
        let down = session.down_bytes.load(Ordering::Relaxed);
        let dur = now_ms().saturating_sub(session.created_ms);
        info!("[/connect] [{}] session {} closed: reason={} up={}B down={}B dur={}ms",
            target, sid, reason, up, down, dur);
        // If the client vanished, half-close the target so it releases the
        // socket instead of holding it until its own idle timeout.
        if reason == "client closed" || reason == "client send failed" {
            if let Ok(mut t) = tokio::time::timeout(Duration::from_secs(2), session.target.lock()).await {
                let _ = tokio::time::timeout(Duration::from_secs(1), t.shutdown()).await;
            }
        }
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

        // Read body: collect zero-copy Bytes chunks (do NOT merge into Vec).
        // In-order path writes each chunk directly via write_all_buf (no copy);
        // out-of-order path merges only when buffering for reordering.
        //
        // Wrapped in `kick`: the H2 body stream drops a wakeup now and then
        // (same class of bug as the H3 receive path on the bridge), which
        // shows up as a /data whose payload is already buffered but whose
        // handler sits idle until some unrelated frame re-polls it.
        let mut req_chunks: Vec<bytes::Bytes> = Vec::new();
        let mut req_len = 0usize;
        loop {
            match kick(body.data(), Duration::from_millis(20)).await {
                Some(Ok(chunk)) => {
                    req_len += chunk.len();
                    let released = chunk.len();
                    req_chunks.push(chunk);
                    let _ = body.flow_control().release_capacity(released);
                }
                _ => break,
            }
        }

        let session = state.sessions.read().await.get(&sid).cloned();
        match session {
            Some(s) if !s.closed.load(Ordering::Relaxed) => {
                if req_len > 0 {
                    // Step 1: buffer the payload under a *short* lock.
                    //
                    // The old code held `pending` for the whole target write.
                    // One slow write therefore serialised every concurrent
                    // /data behind it, and out-of-order frames could not even
                    // be buffered while that happened — a single stalled
                    // target turned into a tunnel-wide stall.
                    let merged = if req_chunks.len() == 1 {
                        req_chunks.pop().unwrap()
                    } else {
                        let mut m = bytes::BytesMut::with_capacity(req_len);
                        for c in &req_chunks {
                            m.extend_from_slice(c);
                        }
                        m.freeze()
                    };
                    let expected = s.next_seq.load(Ordering::Relaxed);
                    if seq < expected {
                        warn!("[/data] [sid={}] stale seq={} < expect={}", sid, seq, expected);
                    } else {
                        let mut pend = s.pending.lock().await;
                        if pend.len() >= MAX_PENDING && !pend.contains_key(&seq) {
                            drop(pend);
                            warn!("[/data] [sid={}] pending overflow (>{}) at seq={}, dropping connection",
                                sid, MAX_PENDING, seq);
                            return send_h2_err(respond, 503, "pending overflow").await;
                        }
                        if seq > expected {
                            info!("[/data] [sid={}] buffered seq={}, expect={}, pending={}",
                                sid, seq, expected, pend.len() + 1);
                        }
                        pend.insert(seq, merged);
                    }

                    // Step 2: drain in seq order. Whoever wins the target lock
                    // is the writer for this round; concurrent /data calls just
                    // return once their bytes are buffered and will be flushed
                    // by the current writer (or by themselves on the next call).
                    let mut t = s.target.lock().await;
                    let mut werr = None;
                    loop {
                        let expected = s.next_seq.load(Ordering::Relaxed);
                        let next = {
                            let mut pend = s.pending.lock().await;
                            pend.remove(&expected)
                        };
                        let Some(mut chunk) = next else { break };
                        // Swallowing this used to drop the payload silently
                        // while still advancing next_seq: the client thought
                        // the bytes had landed and the target saw a hole in
                        // its stream (a dead TLS handshake with no error).
                        if let Err(e) = t.write_all_buf(&mut chunk).await {
                            werr = Some(e);
                            break;
                        }
                        s.next_seq.store(expected + 1, Ordering::Relaxed);
                    }
                    drop(t);
                    if let Some(e) = werr {
                        warn!("[/data] [sid={}] target write failed at seq={}: {}", sid, seq, e);
                        return send_h2_err(respond, 502, "target write failed").await;
                    }
                    s.up_bytes.fetch_add(req_len as u64, Ordering::Relaxed);
                    s.last_active.store(now_ms(), Ordering::Relaxed);
                }
                let resp_http = http::Response::builder()
                    .status(200)
                    .body(())
                    .unwrap();
                let mut send_stream = respond.send_response(resp_http, false)?;
                send_stream.send_data(Bytes::from("ok"), true)?;
            }
            Some(_) => {
                // Session already torn down (client closed); the in-flight
                // /data is stale by definition. Ack it instead of 404 so the
                // bridge does not abort a healthy SOCKS5 connection over a
                // race it cannot avoid.
                warn!("[/data] [sid={}] seq={} arrived after close, dropped", sid, seq);
                let resp_http = http::Response::builder()
                    .status(200)
                    .body(())
                    .unwrap();
                let mut send_stream = respond.send_response(resp_http, false)?;
                send_stream.send_data(Bytes::from("gone"), true)?;
            }
            None => {
                warn!("[/data] [sid={}] session not found (never created or already reaped), seq={}", sid, seq);
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

        // Take the session out of the map, then actively tear it down:
        //   1. flag it closed and wake the /connect relay loop (it stops at
        //      once instead of waiting for the target to time out);
        //   2. half-close the target so the upstream peer sees FIN and releases
        //      the socket, instead of holding it for its own idle timeout.
        // This is what makes the client's "I'm done" propagate immediately.
        let session = state.sessions.write().await.remove(&sid);
        match session {
            Some(s) => {
                s.closed.store(true, Ordering::Relaxed);
                // notify_one (not notify_waiters) so the permit is stored even
                // if the relay loop is between select! iterations right now.
                s.closed_notify.notify_one();
                // Bounded, not a plain `lock().await`: a /data write stuck on a
                // dead target holds this lock, and waiting forever here would
                // leak this task plus its H2 stream. Those leaks pile up until
                // the connection runs out of stream slots, which shows up as
                // "the tunnel cannot connect at all".
                if let Ok(mut t) = tokio::time::timeout(Duration::from_secs(2), s.target.lock()).await {
                    let _ = tokio::time::timeout(Duration::from_secs(1), t.shutdown()).await;
                }
                info!("[/close] sid={} closed by client: up={}B down={}B dur={}ms",
                    sid,
                    s.up_bytes.load(Ordering::Relaxed),
                    s.down_bytes.load(Ordering::Relaxed),
                    now_ms().saturating_sub(s.created_ms));
            }
            None => {
                warn!("[/close] sid={} already gone (double close)", sid);
            }
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

/// Send `n` bytes from the front of `buf` on `send_stream`, honouring H2 flow
/// control.
///
/// The previous inline version leaked its waker: when `poll_capacity` returned
/// `Ready(Some(Ok(cap)))` with `cap < n` it answered `Pending` **without**
/// arranging to be woken again. The task then only made progress when the outer
/// 30-second timeout fired, so any ServerHello larger than the granted capacity
/// stalled for a full 30s. Wrapping each `poll_capacity` in its own `poll_fn`
/// re-registers the waker on every call, and the loop below keeps going until
/// the requested bytes have actually been handed to the stream.
async fn send_chunk(
    send_stream: &mut h2::SendStream<Bytes>,
    buf: &mut bytes::BytesMut,
    n: usize,
    session: &Session,
) -> bool {
    let mut sent = 0usize;
    send_stream.reserve_capacity(n);
    while sent < n {
        let remaining = n - sent;
        match tokio::time::timeout(
            Duration::from_secs(30),
            kick(
                std::future::poll_fn(|cx| send_stream.poll_capacity(cx)),
                Duration::from_millis(20),
            ),
        ).await {
            Ok(Some(Ok(cap))) if cap > 0 => {
                let take = cap.min(remaining);
                let piece = buf.split_to(take).freeze();
                if send_stream.send_data(piece, false).is_err() {
                    return false;
                }
                sent += take;
                session.down_bytes.fetch_add(take as u64, Ordering::Relaxed);
                if sent < n {
                    send_stream.reserve_capacity(n - sent);
                }
            }
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(e))) => {
                warn!("send capacity error: {}", e);
                return false;
            }
            Ok(None) => return false,
            Err(_) => {
                warn!("send capacity timeout (need={} sent={})", n, sent);
                return false;
            }
        }
    }
    true
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
