use bytes::Bytes;
use clap::Parser;
use hickory_resolver::lookup::Lookup;
use log::{error, info, warn};
use rustls::client::{EchConfig, EchGreaseConfig, EchMode};
use rustls::crypto::aws_lc_rs::hpke;
use rustls::crypto::hpke::Hpke;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
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
    #[arg(long, default_value = "1048576")]
    buf_size: usize,
    /// Enable Encrypted Client Hello (ECH). Automatically fetches the ECH
    /// config from the target domain via DNS-over-HTTPS (DoH). Falls back to
    /// GREASE if the DoH query fails. Use --ech-config for a manual file.
    #[arg(long, default_value_t = false)]
    ech: bool,
    /// Path to ECH config list file (binary). Overrides DoH auto-fetch.
    #[arg(long)]
    ech_config: Option<String>,
    /// DoH endpoints (https URL) used to fetch ECH config. Defaults to
    /// small/neutral international resolvers reachable from CN networks
    /// (Cloudflare/Google/Quad9 DoH are SNI-blocked). Comma-separated;
    /// the first reachable one wins. Customize via --doh url1,url2.
    #[arg(long, value_delimiter = ',')]
    doh: Option<Vec<String>>,
    /// Per-query timeout for each DoH endpoint (seconds).
    #[arg(long, default_value_t = 4)]
    doh_timeout: u64,
}

fn resolve_connect(cli: Option<&str>) -> String {
    cli.map(|s| s.to_string())
        .or_else(|| std::env::var("RUST_FORWARD_CONNECT").ok())
        .unwrap_or_default()
}

/// Parse a DoH endpoint URL into (host, port, path).
fn parse_doh_endpoint(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("https://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/dns-query".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (authority.to_string(), 443),
    };
    Some((host, port, path))
}

/// Global DoH priority queue; head = current fastest endpoint.
/// Race winner is promoted to head; queries only hit the head,
/// avoiding conflicting responses across DoH upstreams.
static DOH_PRIORITY: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

fn doh_priority(defaults: &[String]) -> MutexGuard<'static, Vec<String>> {
    DOH_PRIORITY
        .get_or_init(|| Mutex::new(defaults.to_vec()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Result of a single DoH endpoint query.
enum DoHAnswer {
    /// Endpoint responded with a valid ECH config.
    Ech(EchMode),
    /// Authoritative negative response (NXDOMAIN / NOERROR empty / no ech=).
    /// A definitive answer, not an endpoint failure.
    NoEch,
    /// Endpoint failed (connect/timeout/TLS); triggers a race.
    Failed,
}

/// Extract ECH config from an HTTPS lookup.
fn extract_ech_from_lookup(lookup: &Lookup) -> DoHAnswer {
    use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
    use hickory_resolver::proto::rr::RData;
    use rustls::pki_types::EchConfigListBytes;

    for record in lookup.answers() {
        let rdata = &record.data;
        if let RData::HTTPS(svcb) = rdata {
            for (key, value) in &svcb.svc_params {
                if let SvcParamKey::EchConfigList = key {
                    if let SvcParamValue::EchConfigList(ref ech_inner) = value {
                        let raw = EchConfigListBytes::from(ech_inner.0.clone());
                        if let Ok(config) = EchConfig::new(raw, hpke::ALL_SUPPORTED_SUITES) {
                            info!("DoH: ECH config found and accepted");
                            return DoHAnswer::Ech(EchMode::from(config));
                        } else {
                            warn!("DoH: ECH config rejected by rustls");
                        }
                    }
                }
            }
        }
    }
    warn!("DoH: no valid ECH config found in HTTPS records");
    DoHAnswer::NoEch
}

/// Query a single DoH endpoint for ECH config.
/// Returns Ech (with config) / NoEch (definitive negative) / Failed.
async fn query_one_endpoint(url: &str, qname: &str, timeout: Duration) -> DoHAnswer {
    use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    use hickory_resolver::proto::rr::RecordType;
    use hickory_resolver::Resolver;

    let Some((host, ep_port, path)) = parse_doh_endpoint(url) else {
        warn!("DoH: skipping invalid endpoint {}", url);
        return DoHAnswer::Failed;
    };
    let ips = match tokio::net::lookup_host((host.as_str(), ep_port)).await {
        Ok(ips) => ips,
        Err(e) => {
            warn!("DoH: failed to resolve endpoint {}: {}", host, e);
            return DoHAnswer::Failed;
        }
    };
    let mut name_servers: Vec<NameServerConfig> = Vec::new();
    for ip in ips.filter(|a| a.is_ipv4()).map(|a| a.ip()) {
        name_servers.push(NameServerConfig::https(
            ip,
            Arc::from(host.as_str()),
            Some(Arc::from(path.as_str())),
        ));
    }
    if name_servers.is_empty() {
        warn!("DoH: endpoint {} has no IPv4", host);
        return DoHAnswer::Failed;
    }

    let config = ResolverConfig::from_parts(None, vec![], name_servers);
    let mut opts = ResolverOpts::default();
    opts.timeout = timeout;
    opts.attempts = 1; // fail fast, race covers retries across endpoints
    let resolver = match Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            warn!("DoH: failed to build resolver for {}: {}", host, e);
            return DoHAnswer::Failed;
        }
    };

    match resolver.lookup(qname.to_string(), RecordType::HTTPS).await {
        Ok(lookup) => extract_ech_from_lookup(&lookup),
        Err(e) => {
            if e.is_no_records_found() {
                // Authoritative negative: no HTTPS record, not a failure.
                warn!("DoH: {} authoritative negative response", host);
                DoHAnswer::NoEch
            } else {
                warn!("DoH: {} lookup failed: {}", host, e);
                DoHAnswer::Failed
            }
        }
    }
}

/// Fetch ECH config for the target domain via DNS-over-HTTPS.
///
/// Priority-queue strategy (race, promote winner to head):
/// 1. Fast path: query only the head endpoint (single upstream, no
///    conflicting responses across DoH servers).
/// 2. On head failure: race all endpoints (Happy Eyeballs); first success
///    becomes the new head.
async fn fetch_ech_config_doh(
    hostname: &str,
    port: u16,
    defaults: &[String],
    timeout: Duration,
) -> Option<EchMode> {
    // RFC 9460 §9.1: non-standard port uses _port._https.hostname
    let qname = if port == 443 {
        hostname.to_string()
    } else {
        format!("_{}._https.{}", port, hostname)
    };

    // Snapshot the queue (head = fastest). Block scope releases the
    // MutexGuard before any await, avoiding holding the lock across awaits.
    let endpoints: Vec<String> = {
        let queue = doh_priority(defaults);
        queue.clone()
    };
    if endpoints.is_empty() {
        warn!("DoH: no endpoints configured");
        return None;
    }

    info!(
        "Fetching ECH config via DoH for {}:{} | priority: {}",
        hostname,
        port,
        endpoints.join(" > ")
    );
    info!("DoH query: {} HTTPS", qname);

    // Fast path: query only the head (single upstream).
    match query_one_endpoint(&endpoints[0], &qname, timeout).await {
        DoHAnswer::Ech(m) => {
            info!("DoH: served by priority head {}", endpoints[0]);
            return Some(m);
        }
        DoHAnswer::NoEch => {
            // Authoritative negative: definitive, no endpoint switch.
            warn!(
                "DoH: priority head {} authoritative negative response",
                endpoints[0]
            );
            return None;
        }
        DoHAnswer::Failed => {
            warn!(
                "DoH: priority head {} failed, racing all endpoints",
                endpoints[0]
            );
        }
    }

    // Slow path: race all endpoints; first success (Ech/NoEch) promoted.
    // Only head failure reaches here; negatives never race.
    use tokio::task::JoinSet;
    let mut set = JoinSet::new();
    for url in &endpoints {
        let url = url.clone();
        let qname = qname.clone();
        set.spawn(async move {
            let answer = query_one_endpoint(&url, &qname, timeout).await;
            (url, answer)
        });
    }
    let mut reachable_noech: Option<String> = None;
    while let Some(res) = set.join_next().await {
        let Ok((url, answer)) = res else { continue };
        match answer {
            DoHAnswer::Ech(m) => {
                info!("DoH: race winner {} promoted to priority head", url);
                let mut q = doh_priority(defaults);
                q.retain(|u| *u != url);
                q.insert(0, url);
                return Some(m);
            }
            DoHAnswer::NoEch => {
                // Reachable but no ECH; remember first, keep racing for Ech.
                info!("DoH: race endpoint {} reachable, no ECH config", url);
                if reachable_noech.is_none() {
                    reachable_noech = Some(url);
                }
            }
            DoHAnswer::Failed => {}
        }
    }
    // No ECH anywhere; promote a reachable endpoint so the next fast path confirms.
    if let Some(url) = reachable_noech {
        info!("DoH: no ECH anywhere; promoting reachable {} to priority head", url);
        let mut q = doh_priority(defaults);
        q.retain(|u| *u != url);
        q.insert(0, url);
    }
    warn!("DoH: all endpoints failed or no ECH config");
    None
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

    // Compute ECH mode (after address parsing so connect_host/connect_port are available)
    let ech_mode: Option<EchMode> = if let Some(ref cfg_path) = args.ech_config {
        // Manual file override
        info!("Loading ECH config from {}", cfg_path);
        let bytes = std::fs::read(cfg_path)
            .expect("failed to read ECH config file");
        let config_list = rustls::pki_types::EchConfigListBytes::from(bytes);
        let config = EchConfig::new(config_list, hpke::ALL_SUPPORTED_SUITES)
            .expect("invalid ECH config");
        info!("ECH enabled (config file)");
        Some(EchMode::from(config))
    } else if args.ech {
        // Auto-fetch via DoH: try multiple endpoints, first reachable wins.
        let endpoints: Vec<String> = match args.doh {
            Some(ref e) => e.clone(),
            None => vec![
                // DoH multiple endpoint（Happy Eyeballs）
                // self define endpoint --doh https://host:port/path(comma-separated)
                "https://odvr.nic.cz/dns-query".to_string(),
                "https://dns.hetzner.com/dns-query".to_string(),
                "https://dns.digitale-gesellschaft.ch/dns-query".to_string(),
                "https://dns.aa.net.uk/dns-query".to_string(),
            ],
        };
        let timeout = Duration::from_secs(args.doh_timeout);
        match fetch_ech_config_doh(connect_host, connect_port, &endpoints, timeout).await {
            Some(mode) => {
                info!("ECH enabled (DoH auto-fetch)");
                Some(mode)
            }
            None => {
                warn!("ECH DoH fetch failed, falling back to GREASE");
                let (pub_key, _) = hpke::DH_KEM_X25519_HKDF_SHA256_AES_128
                    .generate_key_pair()
                    .expect("HPKE key generation for GREASE");
                let grease = EchGreaseConfig::new(
                    hpke::DH_KEM_X25519_HKDF_SHA256_AES_128,
                    pub_key,
                );
                Some(EchMode::from(grease))
            }
        }
    } else {
        None
    };

    // Create QUIC client endpoint (IPv4 only)
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse::<SocketAddr>().unwrap())
        .expect("failed to create QUIC endpoint");

    let shared: SharedH3Client = Arc::new(RwLock::new(None));

    // Background H3 connection manager
    {
        let shared = shared.clone();
        let server_name = args.server_name.clone();
        let ech_mode = ech_mode.clone();
        tokio::spawn(async move {
            loop {
                let tls_config = if let Some(ref mode) = ech_mode {
                    let provider = Arc::new(
                        rustls::crypto::aws_lc_rs::default_provider(),
                    );
                    let mut roots = rustls::RootCertStore::empty();
                    roots.extend(
                        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                    );
                    let mut cfg = rustls::ClientConfig::builder_with_provider(
                        provider,
                    )
                    .with_ech(mode.clone())
                    .expect("ECH not supported by provider")
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                    cfg.alpn_protocols = vec![ALPN.to_vec()];
                    cfg
                } else {
                    let mut roots = rustls::RootCertStore::empty();
                    roots.extend(
                        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                    );
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

    // Read session ID from response headers
    let session_id = resp
        .headers()
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    log::info!("[{}] session {} established", addr, session_id);

    // Split SOCKS5 TCP
    let (mut tcp_r, tcp_w) = tcp.into_split();
    let tcp_w = Arc::new(tokio::sync::Mutex::new(tcp_w));

    // Background: stream1.recv_data() -> tcp_w (target->client)
    let bg_w = tcp_w.clone();
    tokio::spawn(async move {
        while let Ok(Some(mut chunk)) = stream1.recv_data().await {
            if bg_w.lock().await.write_all_buf(&mut chunk).await.is_err() {
                break;
            }
        }
        let _ = stream1.finish().await;
    });

    // Main loop: read client data, concurrent POST /tunnel/data (seq)
    let err_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut seq = 0u64;
    let sem = Arc::new(tokio::sync::Semaphore::new(16));
    // BytesMut + read_buf avoids per-iteration zeroing and the try_read copy.
    // split() advances the buffer start and consumes that much capacity, so
    // reserve() below re-arms the buffer for the next chunk (may reallocate).
    // Keep capacity available before read_buf: len==capacity makes it return
    // Ok(0), which the loop would otherwise treat as EOF.
    let mut data_buf = bytes::BytesMut::with_capacity(buf_size);
    loop {
        if err_flag.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        // Clear consumed region but keep capacity (no realloc)
        data_buf.clear();
        if data_buf.capacity() < buf_size {
            data_buf.reserve(buf_size - data_buf.capacity());
        }
        match tcp_r.read_buf(&mut data_buf).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        };
        // try_read more data (incremental, no manual copy)
        loop {
            match tcp_r.try_read_buf(&mut data_buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        let data_bytes = data_buf.split().freeze();
        let seq_no = seq;
        seq += 1;
        let sid = session_id.clone();
        let sn = server_name.to_string();
        let mut h3c = send_request.clone();
        let flag = err_flag.clone();

        // Wait for semaphore permit, but check err_flag during wait
        let permit = loop {
            if err_flag.load(std::sync::atomic::Ordering::Relaxed) {
                break None;
            }
            match sem.clone().try_acquire_owned() {
                Ok(p) => break Some(p),
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        };
        let Some(permit) = permit else { break; };
        tokio::spawn(async move {
            let _permit = permit; // held until task exits
            if flag.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
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
