use bytes::Bytes;
use clap::Parser;
use log::{error, info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::RwLock;
use rust_forward::*;

type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>;
type SharedH3Client = Arc<RwLock<Option<H3SendRequest>>>;

#[derive(Parser, Debug)]
#[command(name = "bridge", about = "SOCKS5 → H3 bridge for PC")]
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
    #[arg(long, default_value = "1048576")]
    buf_size: usize,
}

fn resolve_connect(cli: Option<&str>) -> String {
    cli.map(|s| s.to_string())
        .or_else(|| std::env::var("RUST_FORWARD_CONNECT").ok())
        .unwrap_or_default()
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let args = Args::parse();
    let password = resolve_password(args.password.as_deref());
    let connect_str = resolve_connect(args.connect.as_deref());
    if connect_str.is_empty() {
        eprintln!("error: --connect or RUST_FORWARD_CONNECT is required");
        std::process::exit(1);
    }

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Parse connect address and resolve to IPv4
    let (connect_host, connect_port) = connect_str
        .rsplit_once(':')
        .unwrap_or((&connect_str, "2087"));
    let connect_port: u16 = connect_port.parse().expect("invalid port");
    let connect_addr = tokio::net::lookup_host((connect_host, connect_port))
        .await
        .expect("failed to resolve connect address")
        .filter(|a| a.is_ipv4())
        .next()
        .unwrap_or_else(|| panic!("no IPv4 address found for {}", connect_str));

    // Create QUIC client endpoint (IPv4 only)
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse::<SocketAddr>().unwrap())
        .expect("failed to create QUIC endpoint");

    let shared: SharedH3Client = Arc::new(RwLock::new(None));

    // Background H3 connection manager
    {
        let shared = shared.clone();
        let server_name = args.server_name.clone();
        let insecure = args.insecure;
        tokio::spawn(async move {
            loop {
                let tls_config = if insecure {
                    let mut cfg = rustls::ClientConfig::builder()
                        .dangerous()
                        .with_custom_certificate_verifier(Arc::new(NoopVerifier))
                        .with_no_client_auth();
                    cfg.alpn_protocols = vec![ALPN.to_vec()];
                    cfg
                } else {
                    let roots = rustls::RootCertStore::empty();
                    let mut cfg = rustls::ClientConfig::builder()
                        .with_root_certificates(roots)
                        .with_no_client_auth();
                    cfg.alpn_protocols = vec![ALPN.to_vec()];
                    cfg
                };

                let mut client_config = quinn::ClientConfig::new(Arc::new(
                    quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).unwrap(),
                ));
                let mut transport = quinn::TransportConfig::default();
                transport.max_idle_timeout(Some(
                    quinn::IdleTimeout::try_from(std::time::Duration::from_secs(60)).unwrap(),
                ));
                transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
                client_config.transport_config(Arc::new(transport));
                endpoint.set_default_client_config(client_config);

                info!(
                    "Connecting H3 to {} (server_name={})...",
                    connect_addr, server_name
                );

                let conn = match endpoint.connect(connect_addr, &server_name) {
                    Ok(connecting) => match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        connecting,
                    )
                    .await
                    {
                        Ok(Ok(c)) => c,
                        Ok(Err(e)) => {
                            warn!("QUIC handshake failed: {}", e);
                            *shared.write().await = None;
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            continue;
                        }
                        Err(_) => {
                            warn!("QUIC handshake timed out after 10s");
                            *shared.write().await = None;
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            continue;
                        }
                    },
                    Err(e) => {
                        warn!("QUIC connect failed: {}", e);
                        *shared.write().await = None;
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        continue;
                    }
                };


                let quinn_conn = h3_quinn::Connection::new(conn);
                match h3::client::new(quinn_conn).await {
                    Ok((mut driver, send_request)) => {
                        info!("H3 connected");
                        *shared.write().await = Some(send_request);

                        // Drive connection until closed
                        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
                        info!("H3 connection closed");
                    }
                    Err(e) => {
                        warn!("H3 handshake failed: {}", e);
                    }
                }

                *shared.write().await = None;
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });
    }

    // SOCKS5 listener
    let listen_addr: SocketAddr = args.listen.parse().expect("invalid listen address");
    assert!(listen_addr.is_ipv4(), "only IPv4 supported");
    let listener = tokio::net::TcpListener::bind(listen_addr).await.unwrap();

    info!("SOCKS5→H3 bridge listening on {}", listen_addr);
    info!("H3 forward target: {}:{}", connect_host, connect_port);

    loop {
        let (tcp, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("accept: {}", e);
                continue;
            }
        };
        let shared = shared.clone();
        let pwd = password.clone();
        let buf_size = args.buf_size;
        let sn = args.server_name.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_socks5(tcp, addr, &shared, &pwd, &sn, buf_size).await {
                warn!("[{}] {}", addr, e);
            }
        });
    }
}

async fn handle_socks5(
    mut tcp: tokio::net::TcpStream,
    addr: SocketAddr,
    shared: &SharedH3Client,
    password: &str,
    server_name: &str,
    buf_size: usize,
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    // SOCKS5 handshake
    let mut buf = [0u8; 300];
    let n = tcp.read(&mut buf).await?;
    if n < 3 || buf[0] != 0x05 { return Ok(()); }
    tcp.write_all(&[0x05, 0x00]).await?;
    let n = tcp.read(&mut buf).await?;
    if n < 7 || buf[0] != 0x05 || buf[1] != 0x01 { return Ok(()); }

    let target = match buf[3] {
        0x01 => {
            let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            format!("{}:{}", ip, port)
        }
        0x03 => {
            let len = buf[4] as usize;
            let domain = String::from_utf8_lossy(&buf[5..5 + len]);
            let port = u16::from_be_bytes([buf[5 + len], buf[5 + len + 1]]);
            format!("{}:{}", domain, port)
        }
        0x04 => {
            log::warn!("[{}] IPv6 target rejected", addr);
            let _ = tcp.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            return Ok(());
        }
        _ => return Ok(()),
    };

    log::info!("[{}] target={}", addr, target);

    let mut send_request = match shared.read().await.as_ref() {
        Some(sr) => sr.clone(),
        None => {
            log::warn!("[{}] H3 not connected", addr);
            return Ok(());
        }
    };

    // SOCKS5 OK (optimistic), read client first data
    tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    let mut first_data = Vec::new();
    let mut tmp = [0u8; 4096];
    tokio::select! {
        r = tcp.read(&mut tmp) => {
            if let Ok(n) = r { if n > 0 { first_data = tmp[..n].to_vec(); } }
        }
        _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
    }

    // ===== Stream 1: POST /tunnel/connect (headers + raw body) =====
    let body_bytes = Bytes::from(first_data);
    let cl = body_bytes.len();

    let req = http::Request::builder()
        .method("POST")
        .uri(format!("https://{}/tunnel/connect", server_name))
        .header("x-target", &target)
        .header("x-auth", password)
        .header("content-length", cl.to_string().as_str())
        .body(())
        .unwrap();
    let mut stream1 = send_request.send_request(req).await?;
    stream1.send_data(body_bytes).await?;
    stream1.finish().await?;
    let resp = stream1.recv_response().await?;

    if resp.status() != http::StatusCode::OK {
        log::warn!("[{}] server rejected: {}", addr, resp.status());
        return Ok(());
    }

    // 从响应头取 session ID
    let session_id = resp
        .headers()
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    log::info!("[{}] session {} established", addr, session_id);

    // 拆 SOCKS5 TCP
    let (mut tcp_r, tcp_w) = tcp.into_split();
    let tcp_w = Arc::new(tokio::sync::Mutex::new(tcp_w));

    // 后台任务: stream1.recv_data() → tcp_w (target→client)
    let bg_w = tcp_w.clone();
    tokio::spawn(async move {
        while let Ok(Some(mut chunk)) = stream1.recv_data().await {
            if bg_w.lock().await.write_all_buf(&mut chunk).await.is_err() {
                break;
            }
        }
        let _ = stream1.finish().await;
    });

    // 主循环: 读客户端数据 → 并发 POST /tunnel/data (seq)
    let err_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut seq = 0u64;
    loop {
        if err_flag.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        let mut data = Vec::with_capacity(buf_size);
        data.resize(buf_size, 0);
        let n = match tcp_r.read(&mut data).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        // try_read more data
        let mut total = n;
        let mut more = [0u8; 65536];
        loop {
            match tcp_r.try_read(&mut more) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if total + n <= buf_size {
                        data[total..total+n].copy_from_slice(&more[..n]);
                        total += n;
                    } else { break; }
                }
            }
        }
        data.truncate(total);

        let seq_no = seq;
        seq += 1;
        let data_bytes = Bytes::copy_from_slice(&data);
        let sid = session_id.clone();
        let sn = server_name.to_string();
        let mut h3c = send_request.clone();
        let flag = err_flag.clone();

        tokio::spawn(async move {
            let req_data = http::Request::builder()
                .method("POST")
                .uri(format!("https://{}/tunnel/data?sid={}&seq={}", sn, sid, seq_no))
                .header("x-session-id", &sid)
                .header("content-length", data_bytes.len().to_string().as_str())
                .body(())
                .unwrap();
            match h3c.send_request(req_data).await {
                Ok(mut s) => {
                    let _ = s.send_data(data_bytes).await;
                    let _ = s.finish().await;
                    if let Ok(rp) = s.recv_response().await {
                        if rp.status() != http::StatusCode::OK {
                            warn!("[/data] seq={} status={}", seq_no, rp.status());
                            flag.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
                Err(e) => {
                    warn!("[/data] seq={} err: {}", seq_no, e);
                    flag.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        });
    }

    Ok(())
}
