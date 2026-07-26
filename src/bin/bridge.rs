use clap::Parser;
use tracing::{error, info, warn};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use rust_forward::*;
use bytes::Bytes;

#[derive(Parser, Debug)]
#[command(name = "bridge", about = "SOCKS5 → H2 bridge for PC")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:1080")]
    listen: String,
    #[arg(long)]
    connect: Option<String>,
    #[arg(long, default_value = "forward.local")]
    server_name: String,
    #[arg(long)]
    password: Option<String>,
    #[arg(long, default_value_t = false)]
    insecure: bool,
    #[arg(long, default_value = "65536")]
    buf_size: usize,
    #[arg(long)]
    cf_ip: Option<String>,
    /// Max time (seconds) to wait for a single /connect or /data H2 round-trip.
    #[arg(long, default_value = "30")]
    request_timeout: u64,
}

fn resolve_connect(cli: Option<&str>) -> String {
    cli.map(|s| s.to_string()).or_else(|| std::env::var("RUST_FORWARD_CONNECT").ok()).unwrap_or_default()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .init();
    let args = Args::parse();
    let password = resolve_password(args.password.as_deref());
    let connect_str = resolve_connect(args.connect.as_deref());
    let (ch, cp) = connect_str.rsplit_once(':').unwrap_or((&connect_str, "443"));
    let port = cp.parse::<u16>().expect("port");
    let ca = if let Some(ip) = &args.cf_ip {
        let addr = format!("{}:{}", ip, port);
        info!("using CF preferred IP: {} (original host: {})", addr, ch);
        addr
    } else {
        format!("{}:{}", ch, port)
    };
    let (tx, rx) = watch::channel(None::<h2::client::SendRequest<Bytes>>);
    let tx_reconnect = tx.clone();
    let s2 = args.server_name.clone();
    let s3 = args.insecure;
    let s4 = ca.clone();
    // Initial connect — synchronously wait before accepting any SOCKS5 connection
    info!("Initial H2 connect to {}...", ca);
    let (init_h2, mut init_conn) = loop {
        match connect_h2(&ca, &s2, s3).await {
            Ok((h2, conn)) => { info!("Initial H2 connected"); break (h2, conn); }
            Err(e) => { error!("Initial H2 connect failed: {} (retry in 5s)", e); }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    };
    let init_ping_pong = init_conn.ping_pong().expect("ping_pong");
    tx.send(Some(init_h2)).ok();
    // Background: poll connection health via H2 PING/PONG.
    // Two-phase approach:
    //   1. Wait 30s OR connection drop.
    //   2. If 30s elapsed, send PING (connection stays polled). Healthy → continue; else reconnect.
    tokio::spawn(async move {
        let mut conn = init_conn;
        let mut ping_pong = init_ping_pong;
        loop {
            // Phase 1: wait 30s or connection drops
            let should_check = {
                tokio::select! {
                    _ = &mut conn => {
                        info!("H2 connection dropped, reconnecting...");
                        false
                    }
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {
                        true
                    }
                }
            };
            if should_check {
                // Phase 2: send PING while still polling connection
                tokio::select! {
                    _ = &mut conn => {
                        info!("H2 connection dropped during PING");
                    }
                    result = ping_pong.ping(h2::Ping::opaque()) => {
                        match result {
                            Ok(_) => {
                                info!("H2 health check OK");
                                continue; // Healthy → skip reconnect
                            }
                            Err(e) => warn!("H2 PING failed: {}", e),
                        }
                    }
                }
            }
            // Reconnect (connection dropped OR health check failed)
            loop {
                match connect_h2(&s4, &s2, s3).await {
                    Ok((h2, mut new_conn)) => {
                        tx_reconnect.send(Some(h2)).ok();
                        ping_pong = new_conn.ping_pong().expect("ping_pong");
                        conn = new_conn;
                        break;
                    }
                    Err(e) => {
                        error!("H2 reconnect failed: {} (retry in 5s)", e);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        }
    });
    let la: SocketAddr = args.listen.parse().expect("addr");
    assert!(la.is_ipv4(), "IPv4 only");
    let lis = tokio::net::TcpListener::bind(la).await.unwrap();
    info!("bridge on {} -> {}", la, ca);
    loop {
        match lis.accept().await {
            Ok((tcp, addr)) => {
                let rx = rx.clone();
                let sn = args.server_name.clone();
                let pw = password.clone();
                let req_to = Duration::from_secs(args.request_timeout);
                tokio::spawn(async move {
                    if let Err(e) = handle(tcp, addr, rx, &sn, &pw, req_to).await {
                        warn!("[{}] {}", addr, e);
                    }
                });
            }
            Err(e) => { error!("accept: {}", e); }
        }
    }
}

async fn handle(
    mut tcp: tokio::net::TcpStream, addr: SocketAddr,
    mut rx: watch::Receiver<Option<h2::client::SendRequest<Bytes>>>,
    server_name: &str, password: &str,
    req_to: Duration,
) -> anyhow::Result<()> {
    let start = Instant::now();
    let mut buf = [0u8; 300];
    let n = tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut buf)).await??;
    if n < 3 || buf[0] != 0x05 { return Ok(()); }
    tcp.write_all(&[0x05, 0x00]).await?;
    let n = tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut buf)).await??;
    if n < 7 || buf[0] != 0x05 || buf[1] != 0x01 { return Ok(()); }
    let target = match buf[3] {
        0x01 => format!("{}:{}", std::net::Ipv4Addr::new(buf[4],buf[5],buf[6],buf[7]), u16::from_be_bytes([buf[8],buf[9]])),
        0x03 => { let l = buf[4] as usize; format!("{}:{}", String::from_utf8_lossy(&buf[5..5+l]), u16::from_be_bytes([buf[5+l],buf[5+l+1]])) }
        _ => return Ok(()),
    };
    info!("[{}] CONNECT from {}", target, addr);
    let mut h2c = match rx.borrow_and_update().clone() {
        Some(c) => c, None => { warn!("[{}] H2 down", target); return Ok(()); }
    };
    tcp.write_all(&[0x05,0x00,0x00,0x01,0,0,0,0,0,0]).await?;

    // Read ClientHello directly into Vec (zero-copy from stack)
    let mut fd = vec![0u8; 8192];
    tokio::select! {
        r = tcp.read(&mut fd) => { match r {
            Ok(n) if n > 0 => fd.truncate(n),
            _ => fd.clear(),
        }}
        _ = tokio::time::sleep(Duration::from_millis(200)) => { fd.clear(); }
    }
    info!("[{}] ClientHello {} bytes", target, fd.len());

    // POST /connect with ClientHello body + HMAC auth
    let (time, nonce, sign) = hmac_sign(password.as_bytes(), "/tunnel/connect", "");
    let req = http::Request::builder().method("POST")
        .uri(format!("https://{}/tunnel/connect", server_name))
        .header("x-target", &target)
        .header("x-time", &time)
        .header("x-nonce", &nonce)
        .header("x-sign", &sign)
        .header("content-length", fd.len().to_string())
        .body(()).unwrap();
    let (resp_fut, mut send) = h2c.send_request(req, false)?;
    send.send_data(Bytes::from(fd.clone()), true)?;

    let resp = 'connect: loop {
        match tokio::time::timeout(req_to, resp_fut).await {
            Ok(Ok(r)) => break 'connect r,
            Ok(Err(e)) => {
                warn!("[{}] /connect H2 err: {} (retry once)", target, e);
                // Get fresh H2 client and retry
                let mut h2c2 = match rx.borrow_and_update().clone() {
                    Some(c) => c, None => { return Ok(()); }
                };
                let (t2, n2, s2) = hmac_sign(password.as_bytes(), "/tunnel/connect", "");
                let req2 = http::Request::builder().method("POST")
                    .uri(format!("https://{}/tunnel/connect", server_name))
                    .header("x-target", &target)
                    .header("x-time", &t2)
                    .header("x-nonce", &n2)
                    .header("x-sign", &s2)
                    .header("content-length", fd.len().to_string())
                    .body(()).unwrap();
                let (rf2, mut sd2) = match h2c2.send_request(req2, false) {
                    Ok(pair) => pair,
                    Err(e2) => { warn!("[{}] /connect retry send failed: {}", target, e2); return Ok(()); }
                };
                sd2.send_data(Bytes::from(fd), true)?;
                match tokio::time::timeout(req_to, rf2).await {
                    Ok(Ok(r)) => break 'connect r,
                    Ok(Err(e2)) => { warn!("[{}] /connect retry err: {}", target, e2); return Ok(()); }
                    Err(_) => { warn!("[{}] /connect retry timeout", target); return Ok(()); }
                }
            }
            Err(_) => { return Err(anyhow::anyhow!("/connect timeout")); }
        }
    };
    let status = resp.status();
    if status != 200 {
        let (_, mut eb) = resp.into_parts();
        let mut et = String::new();
        while let Some(Ok(c)) = eb.data().await { et.push_str(&String::from_utf8_lossy(&c)); }
        warn!("[{}] /connect {}: {}", target, status, et);
        return Ok(());
    }
    // Read ServerHello from response body, extract session id
    let sid = resp.headers().get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("0")
        .to_string();
    let (_, mut recv_body) = resp.into_parts();
    let mut total = 0usize;
    loop {
        match tokio::time::timeout(req_to, recv_body.data()).await {
            Ok(Some(Ok(chunk))) => {
                let n = chunk.len();
                if total == 0 && n > 0 {
                    info!("[{}] /connect body first bytes: {:02x?}", target, &chunk[..n.min(32)]);
                }
                total += n;
                if tcp.write_all(&chunk).await.is_err() { return Ok(()); }
                let _ = recv_body.flow_control().release_capacity(n);
            }
            Ok(Some(Err(_))) | Ok(None) => break,
            Err(_) => { warn!("[{}] /connect body timeout after {} bytes", target, total); break; }
        }
    }
    info!("[{}] /connect body total: {} bytes (sid={})", target, total, sid);

    let (mut tr, mut tw) = tcp.into_split();

    // /data loop
    let mut data = Vec::with_capacity(65536 + 8192);
    let mut more = [0u8; 8192];
    loop {
        data.resize(65536, 0);
        let n = match tr.read(&mut data).await { Ok(0) => break, Ok(n) => n, Err(_) => break };
        data.truncate(n);
        loop { match tr.try_read(&mut more) { Ok(0)|Err(_) => break, Ok(n) => data.extend_from_slice(&more[..n]), } }
        info!("[{}] /data {} bytes", target, data.len());
        let (time, nonce, sign) = hmac_sign(password.as_bytes(), "/tunnel/data", &sid);
        let req = http::Request::builder().method("POST")
            .uri(format!("https://{}/tunnel/data", server_name))
            .header("x-session-id", &sid)
            .header("x-time", &time)
            .header("x-nonce", &nonce)
            .header("x-sign", &sign)
            .header("content-length", data.len().to_string())
            .body(()).unwrap();
        let data_bytes = Bytes::from(std::mem::take(&mut data));
        match h2c.send_request(req, false) {
            Ok((rf, mut st)) => {
                st.send_data(data_bytes.clone(), true)?;
                match tokio::time::timeout(req_to, rf).await {
                    Ok(Ok(r)) => {
                        let status = r.status();
                        if status != 200 {
                            let (_, mut eb) = r.into_parts();
                            let mut et = String::new();
                            while let Some(Ok(c)) = eb.data().await { et.push_str(&String::from_utf8_lossy(&c)); }
                            warn!("[{}] /data status {}: {}", target, status, et);
                            break;
                        }
                        let (_, mut bd) = r.into_parts();
                        loop {
                            match tokio::time::timeout(req_to, bd.data()).await {
                                Ok(Some(Ok(c))) => {
                                    if tw.write_all(&c).await.is_err() { break; }
                                    let _ = bd.flow_control().release_capacity(c.len());
                                }
                                Ok(Some(Err(_))) | Ok(None) => break,
                                Err(_) => { warn!("[{}] /data body timeout", target); break; }
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("[{}] /data response err (retry once): {}", target, e);
                        let mut h2c2 = match rx.borrow_and_update().clone() {
                            Some(c) => c, None => break,
                        };
                        let (t2, n2, s2) = hmac_sign(password.as_bytes(), "/tunnel/data", &sid);
                        let req2 = http::Request::builder().method("POST")
                            .uri(format!("https://{}/tunnel/data", server_name))
                            .header("x-session-id", &sid)
                            .header("x-time", &t2)
                            .header("x-nonce", &n2)
                            .header("x-sign", &s2)
                            .header("content-length", data_bytes.len().to_string())
                            .body(()).unwrap();
                        match h2c2.send_request(req2, false) {
                            Ok((rf2, mut sd2)) => {
                                sd2.send_data(data_bytes, true)?;
                                match tokio::time::timeout(req_to, rf2).await {
                                    Ok(Ok(r2)) => {
                                        let status2 = r2.status();
                                        if status2 != 200 {
                                            let (_, mut eb) = r2.into_parts();
                                            let mut et = String::new();
                                            while let Some(Ok(c)) = eb.data().await { et.push_str(&String::from_utf8_lossy(&c)); }
                                            warn!("[{}] /data retry status {}: {}", target, status2, et);
                                            break;
                                        }
                                        let (_, mut bd) = r2.into_parts();
                                        loop {
                                            match tokio::time::timeout(req_to, bd.data()).await {
                                                Ok(Some(Ok(c))) => {
                                                    if tw.write_all(&c).await.is_err() { break; }
                                                    let _ = bd.flow_control().release_capacity(c.len());
                                                }
                                                Ok(Some(Err(_))) | Ok(None) => break,
                                                Err(_) => { warn!("[{}] /data retry body timeout", target); break; }
                                            }
                                        }
                                    }
                                    Ok(Err(e2)) => { warn!("[{}] /data retry err: {}", target, e2); break; }
                                    Err(_) => { warn!("[{}] /data retry timeout", target); break; }
                                }
                            }
                            Err(e2) => { warn!("[{}] /data retry send failed: {}", target, e2); break; }
                        }
                    }
                    Err(_) => { warn!("[{}] /data response timeout", target); break; }
                }
            }
            Err(e) => { warn!("[{}] /data send: {}", target, e); break; }
        }
    }
    let elapsed = start.elapsed();
    info!("[{}] DONE: {:.1}s", target, elapsed.as_secs_f64());
    Ok(())
}
type H2Conn = h2::client::Connection<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, Bytes>;

async fn connect_h2(addr: &str, server_name: &str, _insecure: bool) -> anyhow::Result<(h2::client::SendRequest<Bytes>, H2Conn)> {
    use std::sync::Arc;
    use tokio::net::TcpStream;
    use tokio_rustls::{TlsConnector, rustls::ClientConfig};
    use rustls::pki_types::ServerName;

    let tcp = TcpStream::connect(addr).await?;
    let mut cfg = ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into()
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(NoopVerifier))
    .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let cfg = Arc::new(cfg);
    let cn = server_name.to_string();
    let sn = ServerName::try_from(cn.clone())
        .map_err(|e| anyhow::anyhow!("server name: {:?}", e))?;
    let tls = TlsConnector::from(cfg).connect(sn, tcp).await?;
    let (h2, conn) = h2::client::Builder::new()
        .max_concurrent_streams(256)
        .initial_window_size(4_194_304)
        .initial_connection_window_size(33_554_432)
        .handshake(tls).await?;
    info!("H2 connected to {}", addr);
    Ok((h2, conn))
}
