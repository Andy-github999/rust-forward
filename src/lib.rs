use anyhow::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

pub async fn connect_tcp_v4(target: &str, timeout_secs: u64) -> Result<TcpStream> {
    let (host, port) = if let Ok(addr) = target.parse::<SocketAddr>() {
        (addr.ip().to_string(), addr.port())
    } else {
        let (h, p) = target.rsplit_once(':').ok_or_else(|| anyhow::anyhow!("invalid target: {}", target))?;
        (h.to_string(), p.parse()?)
    };
    let addrs = tokio::net::lookup_host((host.as_str(), port)).await?;
    let v4_addrs: Vec<_> = addrs.filter(|a| a.is_ipv4()).collect();
    if v4_addrs.is_empty() {
        return Err(anyhow::anyhow!("no IPv4 address for {}", target));
    }
    // Try each resolved IPv4 address with per-address timeout.
    // CDNs often return multiple IPs (e.g. DuckDuckGo); if the first one
    // is rate-limited or temporarily blocked, fall through to the next.
    let per_addr = Duration::from_secs((timeout_secs as f64 / v4_addrs.len() as f64).ceil() as u64);
    let mut last_err = None;
    for addr in &v4_addrs {
        match tokio::time::timeout(per_addr, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                // TCP keepalive via socket2 (15s interval)
                let stream = match stream.into_std() {
                    Ok(std) => {
                        use socket2::{SockRef, TcpKeepalive};
                        let s2 = SockRef::from(&std);
                        let _ = s2.set_keepalive(true);
                        let _ = s2.set_tcp_keepalive(&TcpKeepalive::new().with_time(Duration::from_secs(15)));
                        tokio::net::TcpStream::from_std(std)?
                    }
                    Err(e) => return Err(anyhow::anyhow!("into_std: {}", e)),
                };
                return Ok(stream);
            }
            Ok(Err(e)) => last_err = Some(e),
            Err(_) => last_err = Some(std::io::Error::new(std::io::ErrorKind::TimedOut, "per-address timeout").into()),
        }
    }
    Err(anyhow::anyhow!("connect_tcp_v4: all {} addresses failed: {}", v4_addrs.len(), last_err.as_ref().unwrap()))
}

/// Connect to a target through a SOCKS5 proxy.
/// Returns a raw TcpStream (SOCKS5 CONNECT handshake already completed).
pub async fn connect_via_socks5(
    proxy: &str,
    target: &str,
    timeout_secs: u64,
) -> Result<TcpStream> {
    let stream = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        tokio_socks::tcp::socks5::Socks5Stream::connect(proxy, target),
    ).await??;
    // SOCKS5 handshake done → extract inner TcpStream (all further data is application)
    let inner = stream.into_inner();

    // TCP keepalive via socket2 (15s interval)
    match inner.into_std() {
        Ok(std) => {
            use socket2::{SockRef, TcpKeepalive};
            let s2 = SockRef::from(&std);
            let _ = s2.set_keepalive(true);
            let _ = s2.set_tcp_keepalive(&TcpKeepalive::new().with_time(Duration::from_secs(15)));
            Ok(TcpStream::from_std(std)?)
        }
        Err(e) => Err(anyhow::anyhow!("into_std: {}", e)),
    }
}

/// Read from a TCP stream with idle timeout batching.
/// - Waits up to `first_timeout` for the first byte.
/// - After receiving data, waits up to `idle_timeout` between chunks.
/// - Returns all data received (may be empty, never an error).
pub async fn read_until_idle(
    stream: &mut TcpStream,
    first_timeout: Duration,
    idle_timeout: Duration,
) -> Vec<u8> {
    let mut buf = vec![0u8; 65536];
    let mut total = 0usize;
    let mut timeout = first_timeout;
    loop {
        if total >= buf.len() {
            buf.resize(buf.len() + 32768, 0);
        }
        match tokio::time::timeout(timeout, stream.read(&mut buf[total..])).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(n)) => {
                total += n;
                timeout = idle_timeout;
            }
            _ => break,
        }
    }
    buf.truncate(total);
    buf
}

#[derive(Debug)]
pub struct NoopVerifier;

impl rustls::client::danger::ServerCertVerifier for NoopVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _m: &[u8], _c: &rustls::pki_types::CertificateDer<'_>, _d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _m: &[u8], _c: &rustls::pki_types::CertificateDer<'_>, _d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

pub fn resolve_password(cli: Option<&str>) -> String {
    cli.map(|s| s.to_string()).or_else(|| std::env::var("RUST_FORWARD_PASSWORD").ok()).unwrap_or_default()
}

// ===== HMAC authentication =====

use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Generate HMAC-SHA256 signature headers
pub fn hmac_sign(secret: &[u8], path: &str, session_id: &str) -> (String, String, String) {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let nonce: [u8; 16] = rand::thread_rng().gen();

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC: invalid key length");
    mac.update(&time.to_be_bytes());
    mac.update(&nonce);
    mac.update(path.as_bytes());
    mac.update(session_id.as_bytes());
    let sign = mac.finalize().into_bytes();

    (time.to_string(), hex::encode(nonce), hex::encode(sign))
}

/// Verify HMAC signature, returns true if valid
pub fn hmac_verify(
    secret: &[u8],
    time_str: &str,
    nonce_str: &str,
    sign_str: &str,
    path: &str,
    session_id: &str,
) -> bool {
    let time: u128 = match time_str.parse() { Ok(t) => t, _ => return false };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    // ±30s window
    if time.abs_diff(now) > 30_000 { return false; }

    let nonce = match hex::decode(nonce_str) { Ok(v) if v.len() == 16 => v, _ => return false };
    let sign = match hex::decode(sign_str) { Ok(s) => s, _ => return false };

    let mut mac = match HmacSha256::new_from_slice(secret) { Ok(m) => m, _ => return false };
    mac.update(&time.to_be_bytes());
    mac.update(&nonce);
    mac.update(path.as_bytes());
    mac.update(session_id.as_bytes());
    mac.verify_slice(&sign).is_ok()
}
