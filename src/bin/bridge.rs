use bytes::{Buf, Bytes};
use clap::Parser;
use hickory_resolver::lookup::Lookup;
use log::{error, info, warn};
use rustls::client::{EchConfig, EchGreaseConfig, EchMode};
use rustls::crypto::aws_lc_rs::hpke;
use rustls::crypto::hpke::Hpke;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};
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

                // Congestion control.
                //
                // Measured on this link (211ms min_rtt, 0% loss, mtu 1452):
                //   BBR 256KB  -> cwnd grows to 712KB but only ~23 pkt/s
                //                 egress; path latency 30-45s. BBR's pacing
                //                 is fed by ACK-driven bandwidth estimation,
                //                 and this workload is bursty (request/response
                //                 with long idle gaps). The estimator never
                //                 converges upward, so pacing throttles itself
                //                 and window utilisation sits at ~0.3%.
                //   CUBIC      -> the right family for bursty request/response.
                //
                // The initial window matters far more than the algorithm here.
                // A browser opens 40-70 SOCKS5 connections at once, each
                // shipping a ~2KB TLS ClientHello: 130KB of uplink in one
                // burst. With quinn's default 14.7KB (10*MTU) start, that
                // burst needs ~9 RTTs before slow start catches up, which is
                // exactly the 1.6s -> 18.4s path latency we measured as
                // concurrency rose from 19 to 65. Size the window to cover the
                // whole burst instead.
                let cc = std::env::var("RF_CC").unwrap_or_else(|_| "cubic".to_string());
                if cc.eq_ignore_ascii_case("bbr") {
                    let mut bbr = quinn::congestion::BbrConfig::default();
                    bbr.initial_window(256 * 1024);
                    transport.congestion_controller_factory(Arc::new(bbr));
                    info!("congestion control: bbr (initial_window=256KB)");
                } else {
                    let iw: u64 = std::env::var("RF_INITIAL_WINDOW")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(256 * 1024);
                    let mut cubic = quinn::congestion::CubicConfig::default();
                    cubic.initial_window(iw);
                    transport.congestion_controller_factory(Arc::new(cubic));
                    info!("congestion control: cubic (initial_window={}KB)", iw / 1024);
                }

                // Allow the peer to open plenty of streams back to us (downlink).
                transport.max_concurrent_bidi_streams(1024u32.into());
                transport.max_concurrent_uni_streams(1024u32.into());
                // Buffer ServerHello bursts without stalling on flow control.
                transport.stream_receive_window((1u32 << 20).into());
                transport.receive_window((16u32 << 20).into());

                // MTU. RF_MTU pins the datagram size and disables DPLPMTUD.
                //
                // Why this knob exists: in every slow capture the collapse
                // starts at the exact moment `mtu` reaches 1452 in the
                // telemetry. Before that (1200-1389) `sent` climbs normally;
                // after it, egress drops to 2-7 packets per 2s while cwnd
                // stays untouched and `lost` stays 0 — the signature of
                // downlink packets being black-holed rather than congested.
                // PMTUD only proves that one padded probe of size N got
                // through; a path that fragments or rate-limits sustained
                // full-size datagrams still passes that probe. Pinning a
                // conservative MTU trades a few percent of goodput for not
                // stalling for 20-30s at a time.
                let mtu: u16 = std::env::var("RF_MTU")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                if mtu > 0 {
                    transport.initial_mtu(mtu);
                    transport.min_mtu(mtu);
                    transport.mtu_discovery_config(None);
                    info!("mtu pinned to {} (DPLPMTUD disabled)", mtu);
                }

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


                // QUIC telemetry. Without it, a slow tunnel is indistinguishable
                // between "cwnd collapsed after loss", "the path RTT is not what
                // we think", and "CF edge is queueing our streams". The bridge
                // cannot see inside the edge, but it can see its own window,
                // loss count and packet rate, which is enough to tell those apart.
                {
                    let c = conn.clone();
                    tokio::spawn(async move {
                        let mut iv = tokio::time::interval(Duration::from_secs(2));
                        let mut prev_sent = 0u64;
                        let mut prev_lost = 0u64;
                        let mut prev_rx = 0u64;
                        loop {
                            iv.tick().await;
                            if c.close_reason().is_some() {
                                break;
                            }
                            let st = c.stats();
                            let p = &st.path;
                            let sent = p.sent_packets;
                            let lost = p.lost_packets;
                            // Downlink visibility. `sent`/`lost` only describe
                            // our egress; when requests stall the question is
                            // always "are the responses reaching us at all?".
                            // udp_rx answers it: flat rx while forward has
                            // already answered means the loss is on their side.
                            let rx = st.udp_rx.bytes;
                            info!(
                                "[quic] rtt={}ms min_rtt={}ms cwnd={}KB mtu={} sent={}(+{}) lost={}(+{}) rx={}(+{}) cong={} holes={}",
                                p.rtt.as_millis(),
                                p.min_rtt.as_millis(),
                                p.cwnd / 1024,
                                p.current_mtu,
                                sent,
                                sent.saturating_sub(prev_sent),
                                lost,
                                lost.saturating_sub(prev_lost),
                                rx,
                                rx.saturating_sub(prev_rx),
                                p.congestion_events,
                                p.black_holes_detected,
                            );
                            prev_rx = rx;
                            prev_sent = sent;
                            prev_lost = lost;
                        }
                    });
                }

                let quinn_conn = h3_quinn::Connection::new(conn);
                match h3::client::new(quinn_conn).await {
                    Ok((mut driver, send_request)) => {
                        info!("H3 connected");
                        *shared.write().await = Some(send_request);

                        // Drive the connection until closed.
                        //
                        // h3 0.0.8's SendStream::send_data only enqueues into
                        // the shared state; the bytes reach QUIC when the
                        // driver is polled. The wakeup raised from a *cloned*
                        // SendRequest is not reliable once many requests are
                        // in flight: requests then sit in the buffer until an
                        // unrelated event (ACK, keep-alive, the next request)
                        // happens to poll the driver.
                        //
                        // Symptom that led here: cwnd pinned at 256KB with
                        // lost=0 and only ~8 pkt/s egress, while forward saw
                        // connections trickle in one every 1-9s and then ten
                        // at once. A pure-waker-driven driver cannot produce
                        // that pattern; a starved one does.
                        //
                        // A short tick bounds the stall. 2ms costs ~500
                        // no-op polls/s on one connection, which is nothing
                        // next to the seconds it saves.
                        let mut tick = tokio::time::interval(Duration::from_millis(2));
                        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                        let _ = std::future::poll_fn(|cx| loop {
                            match driver.poll_close(cx) {
                                std::task::Poll::Ready(_) => {
                                    return std::task::Poll::Ready(());
                                }
                                std::task::Poll::Pending => {}
                            }
                            match tick.poll_tick(cx) {
                                std::task::Poll::Ready(_) => continue,
                                std::task::Poll::Pending => {
                                    return std::task::Poll::Pending;
                                }
                            }
                        })
                        .await;
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

/// Live SOCKS5 sessions. Logged on every `/connect` so the bridge log shows
/// whether a latency spike correlates with concurrency (it does: 4 concurrent
/// -> path ~3.1s, 19 concurrent -> path ~31s).
static ACTIVE_SESSIONS: AtomicU64 = AtomicU64::new(0);

/// RAII guard so the counter can never leak on early return or panic.
struct ActiveGuard;

impl ActiveGuard {
    fn new() -> Self {
        ACTIVE_SESSIONS.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        ACTIVE_SESSIONS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Optional cap on concurrent `/tunnel/connect` calls.
///
/// 0 (default) = unlimited. Note that a *lower* cap can raise throughput:
/// by Little's Law, 8 concurrent x 600ms ~= 13 req/s while 19 concurrent x
/// 31s ~= 0.6 req/s. Queueing on the tunnel is what destroys latency here,
/// so bounding it at the bridge is strictly better than letting Chrome pile
/// on retries. Set RF_MAX_CONNECT=8 to experiment.
fn connect_sem() -> Option<&'static tokio::sync::Semaphore> {
    static SEM: OnceLock<Option<tokio::sync::Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| {
        let n: usize = std::env::var("RF_MAX_CONNECT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if n == 0 {
            info!("connect concurrency: unlimited (RF_MAX_CONNECT=0)");
            None
        } else {
            info!("connect concurrency: limited to {}", n);
            Some(tokio::sync::Semaphore::new(n))
        }
    })
    .as_ref()
}

/// Explicitly tear a session down on the forward side.
///
/// Without this the forward-side relay only notices the client is gone when
/// its 30s read timeout fires, so sessions linger for ~35s (observed max
/// 167s). Each lingering session keeps an H2 stream and a target socket open,
/// and Chrome reacts by opening yet more connections — the feedback loop that
/// turned a slow first request into a dead tunnel.
async fn close_session(send_request: &mut H3SendRequest, server_name: &str, session_id: &str) {
    if session_id.is_empty() {
        return;
    }
    let req = match http::Request::builder()
        .method("POST")
        .uri(format!("https://{}/tunnel/close", server_name))
        .header("x-session-id", session_id)
        .header("content-length", "0")
        .body(())
    {
        Ok(r) => r,
        Err(e) => {
            warn!("[/close] session {} bad request: {}", session_id, e);
            return;
        }
    };
    // The whole exchange is bounded: if the H3 connection is already gone we
    // must not block teardown waiting for a stream that will never open.
    let fut = async {
        let mut s = send_request.send_request(req).await.ok()?;
        let _ = s.finish().await;
        kick(s.recv_response(), Duration::from_millis(20)).await.ok()
    };
    match tokio::time::timeout(Duration::from_secs(3), fut).await {
        Ok(Some(rp)) => info!("[/close] session {} -> {}", session_id, rp.status()),
        Ok(None) => warn!("[/close] session {} failed (h3 error)", session_id),
        Err(_) => warn!("[/close] session {} timed out after 3s", session_id),
    }
}

/// Record the first uplink failure reason. Later errors are usually cascade
/// effects (every in-flight /data fails once the connection is gone) and would
/// just bury the root cause.
fn mark_err(slot: &Mutex<Option<String>>, msg: String) {
    let mut g = slot.lock().unwrap_or_else(|e| e.into_inner());
    if g.is_none() {
        *g = Some(msg);
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

    let _active = ActiveGuard::new();
    let _permit = match connect_sem() {
        Some(sem) => match sem.acquire().await {
            Ok(p) => Some(p),
            Err(_) => return Ok(()),
        },
        None => None,
    };

    // ===== SOCKS5 greeting =====
    // read_exact, not read(): a single read() may return a partial greeting,
    // or the greeting and the CONNECT request coalesced into one segment.
    // The old code then hit `n < 3` (or mis-parsed buf[1] from the request
    // header) and silently dropped the connection — the "SOCKS5 首包被吞"
    // symptom.
    let mut head = [0u8; 2];
    tcp.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Ok(());
    }
    let nmethods = head[1] as usize;
    if nmethods == 0 {
        return Ok(());
    }
    let mut methods = vec![0u8; nmethods];
    tcp.read_exact(&mut methods).await?;
    // We only offer "no auth"; the tunnel itself authenticates via x-auth.
    tcp.write_all(&[0x05, 0x00]).await?;

    // ===== SOCKS5 request =====
    let mut req4 = [0u8; 4];
    tcp.read_exact(&mut req4).await?;
    if req4[0] != 0x05 {
        return Ok(());
    }
    if req4[1] != 0x01 {
        // Only CONNECT is supported (0x02 BIND / 0x03 UDP ASSOCIATE rejected).
        let _ = tcp
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return Ok(());
    }

    let target = match req4[3] {
        0x01 => {
            let mut a = [0u8; 6];
            tcp.read_exact(&mut a).await?;
            let ip = std::net::Ipv4Addr::new(a[0], a[1], a[2], a[3]);
            let port = u16::from_be_bytes([a[4], a[5]]);
            format!("{}:{}", ip, port)
        }
        0x03 => {
            let mut l = [0u8; 1];
            tcp.read_exact(&mut l).await?;
            let len = l[0] as usize;
            if len == 0 {
                return Ok(());
            }
            let mut d = vec![0u8; len + 2];
            tcp.read_exact(&mut d).await?;
            let domain = String::from_utf8_lossy(&d[..len]);
            let port = u16::from_be_bytes([d[len], d[len + 1]]);
            format!("{}:{}", domain, port)
        }
        0x04 => {
            warn!("[{}] IPv6 target rejected", addr);
            let _ = tcp
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Ok(());
        }
        _ => return Ok(()),
    };

    info!("[{}] target={}", addr, target);

    let mut send_request = match shared.read().await.as_ref() {
        Some(sr) => sr.clone(),
        None => {
            warn!("[{}] H3 not connected", addr);
            // Reply "general failure" instead of dropping the socket, so the
            // client fails fast and retries rather than hanging.
            let _ = tcp
                .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Ok(());
        }
    };

    // SOCKS5 OK (optimistic: we answer before the tunnel round-trip completes,
    // otherwise every connection stalls for a full RTT before the client
    // starts speaking).
    tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    // Fold the client's first bytes into the /connect body to save a full
    // tunnel round-trip per connection.
    //
    // The old code always burned 50ms here. Try a non-blocking read first: on
    // loopback the TLS ClientHello is normally already queued by the time the
    // SOCKS5 reply is written.
    let mut first_data = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut got = false;
    if let Ok(n) = tcp.try_read(&mut tmp) {
        if n > 0 {
            first_data = tmp[..n].to_vec();
            got = true;
        }
    }
    if !got {
        tokio::select! {
            r = tcp.read(&mut tmp) => {
                if let Ok(n) = r {
                    if n > 0 {
                        first_data = tmp[..n].to_vec();
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }

    // ===== Stream 1: POST /tunnel/connect =====
    // The response body stays open for the whole session and carries
    // target -> client bytes.
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

    // Four-phase timing. Without it, a 30s `/connect` is indistinguishable
    // between "QUIC path is congested", "forward is waiting on the target",
    // and "our own send/finish is slow".
    let t_open = Instant::now();
    let mut stream1 = send_request.send_request(req).await?;
    let t_sent = Instant::now();
    stream1.send_data(body_bytes).await?;
    let t_body = Instant::now();
    stream1.finish().await?;
    let t_fin = Instant::now();
    // Kick: h3 0.0.8's per-stream receive path can drop the wakeup for a
    // response whose bytes are already in quinn's buffer. Measured: a burst of
    // 12 connections delivered all ~34KB into udp_rx within one 2s sample, yet
    // 7 of the 12 recv_response() calls stayed Pending for another 20-30s and
    // then completed at once. Re-polling bounds that stall to one period.
    let resp = kick(stream1.recv_response(), Duration::from_millis(20)).await?;
    let t_resp = Instant::now();

    if resp.status() != http::StatusCode::OK {
        warn!("[{}] server rejected: {}", addr, resp.status());
        return Ok(());
    }

    let session_id = resp
        .headers()
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // forward reports how long it spent inside its own handler. Subtracting it
    // from the total isolates the tunnel round-trip without needing clock sync
    // between the two machines (they drift ~6.9s apart on this setup).
    let fwd_ms: u128 = resp
        .headers()
        .get("x-fwd-ms")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let total_ms = t_resp.duration_since(t_open).as_millis();
    let path_ms = total_ms.saturating_sub(fwd_ms);

    info!(
        "[{}] session {} established: open={}ms send={}ms fin={}ms resp={}ms total={}ms \
         (fwd={}ms path={}ms, up-first={}B, active={})",
        addr,
        session_id,
        t_sent.duration_since(t_open).as_millis(),
        t_body.duration_since(t_sent).as_millis(),
        t_fin.duration_since(t_body).as_millis(),
        t_resp.duration_since(t_fin).as_millis(),
        total_ms,
        fwd_ms,
        path_ms,
        cl,
        ACTIVE_SESSIONS.load(Ordering::Relaxed)
    );

    let (mut tcp_r, tcp_w) = tcp.into_split();
    let tcp_w = Arc::new(tokio::sync::Mutex::new(tcp_w));
    let addr_log = addr;

    // Downlink: stream1.recv_data() -> client.
    let bg_w = tcp_w.clone();
    let mut bg = tokio::spawn(async move {
        let mut down_bytes = 0u64;
        let mut first = true;
        // Same wakeup-loss guard as recv_response above: the body stream is the
        // one that carries the actual page bytes, so a lost wakeup here shows
        // up as a page that loads half way and then freezes.
        loop {
            let next = match kick(stream1.recv_data(), Duration::from_millis(20)).await {
                Ok(Some(chunk)) => chunk,
                _ => break,
            };
            let mut chunk = next;
            let n = chunk.remaining();
            if n == 0 {
                continue;
            }
            if first {
                first = false;
                info!("[{}] first DOWN frame {}B", addr_log, n);
            }
            down_bytes += n as u64;
            if bg_w.lock().await.write_all_buf(&mut chunk).await.is_err() {
                warn!(
                    "[{}] client write failed after {}B down",
                    addr_log, down_bytes
                );
                break;
            }
        }
        let _ = stream1.finish().await;
        down_bytes
    });

    // Uplink: each client block becomes its own /tunnel/data H2 stream,
    // tagged with a monotonic seq. forward reorders by seq, so concurrent
    // streams cannot corrupt the byte stream.
    let err_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let err_reason: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let up_bytes = Arc::new(AtomicU64::new(0));

    // Bounded at 8 by default. More concurrent /data streams means more H2
    // streams queued behind the same tunnel; by Little's Law that *lowers*
    // throughput (8 x 600ms ~= 13 req/s vs 19 x 31s ~= 0.6 req/s).
    let conc: usize = std::env::var("RF_DATA_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v: &usize| *v > 0)
        .unwrap_or(8);
    let sem = Arc::new(tokio::sync::Semaphore::new(conc));
    let mut tasks: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

    let mut seq = 0u64;
    let mut first_up = true;
    // BytesMut + read_buf avoids per-iteration zeroing and the try_read copy.
    // split() advances the buffer start and consumes that much capacity, so
    // reserve() below re-arms the buffer for the next chunk (may reallocate).
    // Keep capacity available before read_buf: len==capacity makes it return
    // Ok(0), which the loop would otherwise treat as EOF.
    let mut data_buf = bytes::BytesMut::with_capacity(buf_size);
    loop {
        if err_flag.load(Ordering::Relaxed) {
            break;
        }
        // Reap finished /data tasks so the set cannot grow without bound.
        while tasks.try_join_next().is_some() {}

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

        if first_up {
            first_up = false;
            info!("[{}] first UP frame {}B", addr_log, data_buf.len());
        }

        let data_bytes = data_buf.split().freeze();
        let seq_no = seq;
        seq += 1;
        let sid = session_id.clone();
        let sn = server_name.to_string();
        let mut h3c = send_request.clone();
        let flag = err_flag.clone();
        let reason_slot = err_reason.clone();
        let up = up_bytes.clone();
        let nbytes = data_bytes.len() as u64;

        // Wait for a permit, but bail out as soon as the session is known bad.
        let permit = loop {
            if err_flag.load(Ordering::Relaxed) {
                break None;
            }
            match sem.clone().try_acquire_owned() {
                Ok(p) => break Some(p),
                Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        };
        let Some(permit) = permit else { break; };

        // JoinSet, not tokio::spawn: on teardown we must be able to abort
        // in-flight /data tasks. Detached tasks outlived the session and kept
        // posting to a dead sid, producing the "session not found" storm.
        tasks.spawn(async move {
            let _permit = permit; // held until task exits
            if flag.load(Ordering::Relaxed) {
                return;
            }
            let req_data = http::Request::builder()
                .method("POST")
                .uri(format!(
                    "https://{}/tunnel/data?sid={}&seq={}",
                    sn, sid, seq_no
                ))
                .header("x-session-id", &sid)
                .header("content-length", data_bytes.len().to_string().as_str())
                .body(())
                .unwrap();
            match h3c.send_request(req_data).await {
                Ok(mut s) => {
                    let _ = s.send_data(data_bytes).await;
                    let _ = s.finish().await;
                    match kick(s.recv_response(), Duration::from_millis(20)).await {
                        Ok(rp) if rp.status() == http::StatusCode::OK => {
                            up.fetch_add(nbytes, Ordering::Relaxed);
                        }
                        Ok(rp) => {
                            let msg = format!("/data seq={} status={}", seq_no, rp.status());
                            warn!("[{}] {}", sn, msg);
                            mark_err(&reason_slot, msg);
                            flag.store(true, Ordering::Relaxed);
                        }
                        Err(e) => {
                            let msg = format!("/data seq={} resp err: {}", seq_no, e);
                            warn!("[{}] {}", sn, msg);
                            mark_err(&reason_slot, msg);
                            flag.store(true, Ordering::Relaxed);
                        }
                    }
                }
                Err(e) => {
                    let msg = format!("/data seq={} err: {}", seq_no, e);
                    warn!("[{}] {}", sn, msg);
                    mark_err(&reason_slot, msg);
                    flag.store(true, Ordering::Relaxed);
                }
            }
        });
    }

    // ===== Teardown =====
    // Explicit /tunnel/close. Without it forward only notices the client is
    // gone via its 30s idle timeout, keeping an H2 stream and a target socket
    // alive the whole time (observed sessions lasting up to 167s), and Chrome
    // reacts by opening yet more connections.
    close_session(&mut send_request, server_name, &session_id).await;

    // Let the downlink drain its final frames; if forward is wedged, stop
    // waiting and abort rather than leak the task.
    let down_bytes = match tokio::time::timeout(Duration::from_secs(2), &mut bg).await {
        Ok(Ok(n)) => n,
        Ok(Err(_)) => 0,
        Err(_) => {
            warn!("[{}] downlink did not finish in 2s, aborting", addr_log);
            bg.abort();
            0
        }
    };

    // Close the client socket so the browser sees a clean FIN instead of
    // hanging on a half-open connection.
    if let Ok(mut w) = tokio::time::timeout(Duration::from_secs(1), tcp_w.lock()).await {
        let _ = w.shutdown().await;
    }

    // Abort any /data task still in flight; they belong to a dead session.
    tasks.shutdown().await;

    let reason = err_reason
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_else(|| "client eof".to_string());
    info!(
        "[{}] session {} end: reason={} up={}B down={}B",
        addr_log,
        session_id,
        reason,
        up_bytes.load(Ordering::Relaxed),
        down_bytes
    );

    Ok(())
}
