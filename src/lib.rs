use anyhow::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// H3 ALPN protocol ID
pub static ALPN: &[u8] = b"h3";

pub fn resolve_password(cli: Option<&str>) -> String {
    cli.map(|s| s.to_string())
        .or_else(|| std::env::var("RUST_FORWARD_PASSWORD").ok())
        .unwrap_or_default()
}

/// Resolve target (IP:port or host:port), force IPv4 connection.
pub async fn connect_tcp_v4(target: &str, timeout_secs: u64) -> Result<TcpStream> {
    let (host, port) = if let Ok(addr) = target.parse::<SocketAddr>() {
        (addr.ip().to_string(), addr.port())
    } else {
        let (h, p) = target.rsplit_once(':').ok_or_else(|| anyhow::anyhow!("invalid target: {}", target))?;
        (h.to_string(), p.parse()?)
    };
    let addrs = tokio::net::lookup_host((host.as_str(), port)).await?;
    let v4 = addrs.filter(|a| a.is_ipv4()).next().ok_or_else(|| anyhow::anyhow!("no IPv4 address for {}", target))?;
    let stream = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        TcpStream::connect(v4),
    ).await??;

    // TCP keepalive via socket2 (15s interval)
    let stream = match stream.into_std() {
        Ok(std) => {
            use socket2::{SockRef, TcpKeepalive};
            let s2 = SockRef::from(&std);
            let _ = s2.set_keepalive(true);
            let _ = s2.set_tcp_keepalive(&TcpKeepalive::new().with_time(Duration::from_secs(15)));
            TcpStream::from_std(std)?
        }
        Err(e) => return Err(anyhow::anyhow!("into_std: {}", e)),
    };
    Ok(stream)
}

/// Connect to a target through a SOCKS5 proxy.
pub async fn connect_via_socks5(
    proxy: &str,
    target: &str,
    timeout_secs: u64,
) -> Result<TcpStream> {
    let stream = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        tokio_socks::tcp::socks5::Socks5Stream::connect(proxy, target),
    ).await??;
    let inner = stream.into_inner();
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



/// Extract host part from "host:port" string.
pub fn target_host(target: &str) -> &str {
    target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target)
}