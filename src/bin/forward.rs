use clap::Parser;
use log::{error, info};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use rust_forward::*;

// Session 管理: 由 POST /connect 创建，POST /data 使用
type SessionId = u64;
struct Session {
    target_w: tokio::net::tcp::OwnedWriteHalf,
}

struct AppState {
    password: String,
    connect_timeout: u64,
    sessions: RwLock<HashMap<SessionId, Session>>,
    next_id: AtomicU64,
}

#[derive(Parser, Debug)]
#[command(name = "forward", about = "H3 → TCP forward server for OpenWrt")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:2087")]
    listen: String,
    #[arg(long)]
    password: Option<String>,
    #[arg(long, default_value = "10")]
    connect_timeout: u64,
    #[arg(long, default_value = "0.0.0.0:2086")]
    tcp_listen: String,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let args = Args::parse();
    let password = resolve_password(args.password.as_deref());

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Generate self-signed TLS cert for QUIC
    let cert = rcgen::generate_simple_self_signed(vec!["forward.local".into()]).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(
        cert.signing_key.serialize_der(),
    ).unwrap();

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    tls_config.max_early_data_size = u32::MAX;
    tls_config.alpn_protocols = vec![ALPN.to_vec()];

    let addr: SocketAddr = args.listen.parse().expect("invalid listen address");
    assert!(addr.is_ipv4(), "only IPv4 supported");
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).unwrap(),
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(60)).unwrap(),
    ));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    server_config.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::server(server_config, addr).unwrap();
    info!("H3 forward listening on {} (QUIC)", addr);

    // TCP listener for cloudflared HTTP/1.1 connections
    let tcp_addr: SocketAddr = args.tcp_listen.parse().expect("invalid tcp listen address");
    assert!(tcp_addr.is_ipv4(), "only IPv4 supported");
    let state = Arc::new(AppState {
        password: password.clone(),
        connect_timeout: args.connect_timeout,
        sessions: RwLock::new(HashMap::new()),
        next_id: AtomicU64::new(1),
    });

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(tcp_addr).await.unwrap();
        info!("TCP forward listening on {} (HTTP/1.1)", tcp_addr);
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let state = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_connection(stream, &state).await {
                            error!("TCP handler [{}]: {}", peer, e);
                        }
                    });
                }
                Err(e) => {
                    error!("TCP accept: {}", e);
                }
            }
        }
    });

    while let Some(new_conn) = endpoint.accept().await {
        let pwd = password.clone();
        let timeout = args.connect_timeout;
        tokio::spawn(async move {
            match new_conn.await {
                Ok(conn) => {
                    info!("new QUIC connection from {}", conn.remote_address());
                    let mut h3_conn = h3::server::Connection::new(
                        h3_quinn::Connection::new(conn),
                    )
                    .await
                    .unwrap();
                    loop {
                        match h3_conn.accept().await {
                            Ok(Some(resolver)) => {
                                let pwd = pwd.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = handle_h3_stream(resolver, &pwd, timeout).await {
                                        error!("handle stream: {}", e);
                                    }
                                });
                            }
                            Ok(None) => break,
                            Err(err) => {
                                error!("accept error: {}", err);
                                break;
                            }
                        }
                    }
                }
                Err(err) => {
                    error!("accept connection: {}", err);
                }
            }
        });
    }

    endpoint.wait_idle().await;
}

async fn handle_h3_stream<C>(
    resolver: h3::server::RequestResolver<C, bytes::Bytes>,
    password: &str,
    connect_timeout: u64,
) -> anyhow::Result<()>
where
    C: h3::quic::Connection<bytes::Bytes>,
{
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (req, mut stream) = resolver.resolve_request().await?;

    let target = req
        .headers()
        .get("x-target")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let auth = req
        .headers()
        .get("x-auth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if target.is_empty() {
        let resp = http::Response::builder()
            .status(http::StatusCode::BAD_REQUEST)
            .body(())
            .unwrap();
        stream.send_response(resp).await?;
        stream.finish().await?;
        return Ok(());
    }

    if !password.is_empty() && auth != password {
        let resp = http::Response::builder()
            .status(http::StatusCode::BAD_GATEWAY)
            .body(())
            .unwrap();
        stream.send_response(resp).await?;
        stream.finish().await?;
        return Ok(());
    }

    info!("H3 CONNECT target={}", target);

    let target_stream = match tokio::time::timeout(
        std::time::Duration::from_secs(connect_timeout),
        connect_tcp_v4(&target, connect_timeout),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(_e)) => {
            let resp = http::Response::builder()
                .status(http::StatusCode::BAD_GATEWAY)
                .body(())
                .unwrap();
            stream.send_response(resp).await?;
            stream.finish().await?;
            return Ok(());
        }
        Err(_) => {
            let resp = http::Response::builder()
                .status(http::StatusCode::GATEWAY_TIMEOUT)
                .body(())
                .unwrap();
            stream.send_response(resp).await?;
            stream.finish().await?;
            return Ok(());
        }
    };

    // Send 200 OK
    let resp = http::Response::builder()
        .status(http::StatusCode::OK)
        .body(())
        .unwrap();
    stream.send_response(resp).await?;

    let (mut target_r, mut target_w) = tokio::io::split(target_stream);

    // Bidirectional proxy: TCP <-> H3 stream
    let mut buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            r = target_r.read(&mut buf) => {
                match r {
                    Ok(0) => break,
                    Ok(n) => {
                        if stream.send_data(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            d = stream.recv_data() => {
                match d {
                    Ok(Some(mut chunk)) => {
                        if target_w.write_all_buf(&mut chunk).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }
    }

    let _ = stream.finish().await;
    Ok(())
}

/// 读取 HTTP 请求行和 headers + body，返回 (method, path, body)
async fn read_http_request(
    stream: &mut tokio::net::TcpStream,
) -> anyhow::Result<(String, String, Vec<u8>)> {
    // Read request line
    let mut request_line = String::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        if byte[0] == b'\n' { break; }
        if byte[0] != b'\r' { request_line.push(byte[0] as char); }
    }
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(anyhow::anyhow!("bad request line"));
    }
    let method = parts[0].to_string();
    let path = parts[1].to_string();

    // Read headers
    let mut header_buf = Vec::new();
    loop {
        stream.read_exact(&mut byte).await?;
        header_buf.push(byte[0]);
        let len = header_buf.len();
        if len >= 4 && header_buf[len - 4..] == [b'\r', b'\n', b'\r', b'\n'] {
            break;
        }
    }
    let headers_str = String::from_utf8_lossy(&header_buf[..header_buf.len() - 4]);

    // Parse body
    let is_chunked = headers_str
        .lines()
        .any(|l| l.to_lowercase().contains("transfer-encoding:") && l.to_lowercase().contains("chunked"));
    let mut body = Vec::new();
    if is_chunked {
        let mut line = String::new();
        loop {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await?;
            if byte[0] == b'\n' { break; }
            if byte[0] != b'\r' { line.push(byte[0] as char); }
        }
        let chunk_size = usize::from_str_radix(line.trim(), 16).unwrap_or(0);
        if chunk_size > 0 {
            body.resize(chunk_size, 0);
            stream.read_exact(&mut body).await?;
            let mut crlf = [0u8; 2];
            stream.read_exact(&mut crlf).await?;
        }
    } else {
        let content_length = headers_str
            .lines()
            .find(|l| l.to_lowercase().starts_with("content-length:"))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        if content_length > 0 {
            body.resize(content_length, 0);
            stream.read_exact(&mut body).await?;
        }
    }

    Ok((method, path, body))
}

/// 写 HTTP 响应
async fn write_http_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    body: &[u8],
) -> anyhow::Result<()> {
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\n\r\n",
        status,
        match status {
            200 => "OK",
            400 => "Bad Request",
            502 => "Bad Gateway",
            504 => "Gateway Timeout",
            _ => "Unknown",
        },
        body.len()
    );
    stream.write_all(resp.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    Ok(())
}

async fn handle_tcp_connection(
    mut stream: tokio::net::TcpStream,
    state: &AppState,
) -> anyhow::Result<()> {
    let (method, path, body) = read_http_request(&mut stream).await?;

    if method != "POST" {
        write_http_response(&mut stream, 400, b"need POST").await?;
        return Ok(());
    }

    let body_str = String::from_utf8_lossy(&body);

    if path == "/connect" {
        // ===== POST /connect: 建立 session =====
        let target = extract_json_str(&body_str, "target").unwrap_or_default();
        let auth = extract_json_str(&body_str, "password").unwrap_or_default();

        if target.is_empty() {
            write_http_response(&mut stream, 400, b"no target").await?;
            return Ok(());
        }
        if !state.password.is_empty() && auth != state.password {
            write_http_response(&mut stream, 502, b"bad auth").await?;
            return Ok(());
        }

        // 解码 data_hex
        let data_hex = extract_json_str(&body_str, "data_hex").unwrap_or_default();
        let mut initial_data = Vec::new();
        if !data_hex.is_empty() && data_hex.len() % 2 == 0 {
            for i in (0..data_hex.len()).step_by(2) {
                if let Ok(b) = u8::from_str_radix(&data_hex[i..i+2], 16) {
                    initial_data.push(b);
                }
            }
        }

        info!("TCP CONNECT target={} initial={}bytes", target, initial_data.len());

        let target_stream = match tokio::time::timeout(
            std::time::Duration::from_secs(state.connect_timeout),
            connect_tcp_v4(&target, state.connect_timeout),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(_)) => {
                write_http_response(&mut stream, 502, b"target connect failed").await?;
                return Ok(());
            }
            Err(_) => {
                write_http_response(&mut stream, 504, b"target timeout").await?;
                return Ok(());
            }
        };

        let (mut target_r, target_w) = target_stream.into_split();
        let sid = state.next_id.fetch_add(1, Ordering::SeqCst);

        // 存 session
        {
            let mut sessions = state.sessions.write().await;
            sessions.insert(sid, Session { target_w });
        }

        // 写初始数据到 target
        if !initial_data.is_empty() {
            // 需要从 session 借 target_w 写，但 pipe 时 target_r 在手
            // 我们直接用 target_r 的配对的 target_w... 不对，split 了
            // 重新写: 从 session 取出 target_w 写一次
            let mut sessions = state.sessions.write().await;
            if let Some(s) = sessions.get_mut(&sid) {
                let _ = s.target_w.write_all(&initial_data).await;
            }
            drop(sessions);
            info!("sent {} bytes initial data to target", initial_data.len());
        }

        // 回 200，body 为空，X-Session-Id 头传 session ID
        let resp = format!(
            "HTTP/1.1 200 OK\r\nX-Session-Id: {}\r\n\r\n",
            sid
        );
        stream.write_all(resp.as_bytes()).await?;

        info!("session {}: pipe target→client", sid);

        // pipe: target_r → stream response body（保持连接打开）
        let mut buf = [0u8; 65536];
        loop {
            match target_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        // 清理 session
        let mut sessions = state.sessions.write().await;
        sessions.remove(&sid);
        info!("session {} closed", sid);

    } else if path.starts_with("/data") {
        // ===== POST /data: 发数据到已建 session =====
        let sid_str = if let Some(pos) = path.find("?id=") {
            path[pos + 4..].to_string()
        } else {
            extract_json_str(&body_str, "id").unwrap_or_default()
        };

        let sid: SessionId = match sid_str.parse() {
            Ok(id) => id,
            Err(_) => {
                write_http_response(&mut stream, 400, b"bad session id").await?;
                return Ok(());
            }
        };

        let data_hex = extract_json_str(&body_str, "data_hex").unwrap_or_default();
        let mut data = Vec::new();
        if !data_hex.is_empty() && data_hex.len() % 2 == 0 {
            for i in (0..data_hex.len()).step_by(2) {
                if let Ok(b) = u8::from_str_radix(&data_hex[i..i+2], 16) {
                    data.push(b);
                }
            }
        }

        let mut sessions = state.sessions.write().await;
        if let Some(session) = sessions.get_mut(&sid) {
            if session.target_w.write_all(&data).await.is_err() {
                drop(sessions);
                write_http_response(&mut stream, 502, b"target write failed").await?;
                sessions = state.sessions.write().await;
                sessions.remove(&sid);
                return Ok(());
            }
            drop(sessions);
            info!("session {}: piped {} bytes to target", sid, data.len());
            write_http_response(&mut stream, 200, b"ok").await?;
        } else {
            drop(sessions);
            write_http_response(&mut stream, 404, b"session not found").await?;
        }

    } else {
        write_http_response(&mut stream, 404, b"not found").await?;
    }

    Ok(())
}

/// Extract a string value from a simple JSON object like {"key":"value"}
fn extract_json_str(s: &str, key: &str) -> Option<String> {
    let search = format!("\"{}\":\"", key);
    let start = s.find(&search)?;
    let value_start = start + search.len();
    let remaining = &s[value_start..];
    let end = remaining.find('"')?;
    Some(remaining[..end].to_string())
}
