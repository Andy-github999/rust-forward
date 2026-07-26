use clap::Parser;
use log::{error, info, warn};
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
}

fn resolve_connect(cli: Option<&str>) -> String {
    cli.map(|s| s.to_string()).or_else(|| std::env::var("RUST_FORWARD_CONNECT").ok()).unwrap_or_default()
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis().init();
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
    tokio::spawn(async move {
        loop {
            match connect_h2(&s4, &s2, s3).await {
                Ok(c) => { tx_reconnect.send(Some(c)).ok(); }
                Err(e) => { error!("H2 connect: {}", e); }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
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
                tokio::spawn(async move {
                    if let Err(e) = handle(tcp, addr, rx, &sn, &pw).await {
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
    send.send_data(Bytes::from(fd), true)?;

    let resp = resp_fut.await?;
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
    while let Some(Ok(chunk)) = recv_body.data().await {
        let n = chunk.len();
        if total == 0 && n > 0 {
            info!("[{}] /connect body first bytes: {:02x?}", target, &chunk[..n.min(32)]);
        }
        total += n;
        if tcp.write_all(&chunk).await.is_err() { return Ok(()); }
        let _ = recv_body.flow_control().release_capacity(n);
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
        match h2c.send_request(req, false) {
            Ok((rf, mut st)) => {
                st.send_data(Bytes::from(std::mem::take(&mut data)), true)?;
                match rf.await {
                    Ok(r) => {
                        let (_, mut bd) = r.into_parts();
                        while let Some(Ok(c)) = bd.data().await {
                            if tw.write_all(&c).await.is_err() { break; }
                            let _ = bd.flow_control().release_capacity(c.len());
                        }
                    }
                    Err(e) => { warn!("[{}] /data err: {}", target, e); break; }
                }
            }
            Err(e) => { warn!("[{}] /data send: {}", target, e); break; }
        }
    }
    let elapsed = start.elapsed();
    info!("[{}] DONE: {:.1}s", target, elapsed.as_secs_f64());
    Ok(())
}
async fn connect_h2(addr: &str, server_name: &str, _insecure: bool) -> Result<h2::client::SendRequest<Bytes>, anyhow::Error> {
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
    tokio::spawn(async move { let _ = conn.await; });
    info!("H2 connected to {}", addr);
    Ok(h2)
}
