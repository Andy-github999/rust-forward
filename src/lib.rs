use anyhow::Result;
use bytes::BytesMut;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// H3 ALPN protocol ID
pub static ALPN: &[u8] = b"h3";

// ── TCP socket tuning ────────────────────────

/// Apply low-latency TCP options suited for proxy forwarding.
///
/// - `TCP_NODELAY`: disable Nagle (send immediately, don't wait to coalesce)
/// - `TCP_QUICKACK` (Linux): disable delayed ACK (acknowledge immediately)
/// - `TCP_THIN_LINEAR_TIMEOUTS` (Linux): optimise retransmission for thin streams
#[cfg(target_os = "linux")]
pub fn configure_tcp_socket(stream: &std::net::TcpStream) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use socket2::SockRef;
    let s = SockRef::from(stream);
    s.set_tcp_nodelay(true)?;

    // TCP_QUICKACK: disable delayed ACK (immediate acknowledges)
    let fd = stream.as_raw_fd();
    let on: libc::c_int = 1;
    // SAFETY: fd is a valid TCP socket, setting standard socket options.
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_QUICKACK,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    // TCP_THIN_LINEAR_TIMEOUTS: optimise retransmission for thin (low-throughput)
    // streams — best-effort, not all kernels support it.
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_THIN_LINEAR_TIMEOUTS,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    Ok(())
}

/// Non-Linux version (Windows, macOS) — only set TCP_NODELAY.
#[cfg(not(target_os = "linux"))]
pub fn configure_tcp_socket(stream: &std::net::TcpStream) -> std::io::Result<()> {
    use socket2::SockRef;
    let s = SockRef::from(stream);
    s.set_tcp_nodelay(true)?;
    Ok(())
}

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

    // TCP keepalive via socket2 (15s interval) + low-latency tuning
    let stream = match stream.into_std() {
        Ok(std) => {
            configure_tcp_socket(&std)?;
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
            configure_tcp_socket(&std)?;
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
///
/// The `try_read` fast path matters: the caller uses this to grab a TLS
/// ServerHello, which the target normally writes in one burst. Without it we
/// pay a full `idle_timeout` sleep on the *last* chunk of every call, and that
/// delay lands squarely on the `/connect` critical path.
pub async fn read_until_idle(
    stream: &mut TcpStream,
    first_timeout: Duration,
    idle_timeout: Duration,
) -> BytesMut {
    let mut buf = BytesMut::with_capacity(65536);
    let mut timeout = first_timeout;
    loop {
        if buf.len() == buf.capacity() {
            buf.reserve(32768);
        }
        // Drain whatever is already queued before paying for a timer.
        match stream.try_read_buf(&mut buf) {
            Ok(0) => break,          // EOF
            Ok(_) => {
                timeout = idle_timeout;
                continue;
            }
            Err(_) => {}             // WouldBlock: fall through to the timed read
        }
        match tokio::time::timeout(timeout, stream.read_buf(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(_)) => {
                timeout = idle_timeout;
            }
            _ => break,
        }
    }
    buf
}

// ── Wakeup-loss guard ────────────────────────

/// Re-poll a future on a fixed cadence until it resolves.
///
/// Some layers in this stack drop a wakeup when data lands on a stream whose
/// task is parked. The evidence is unambiguous: a 12-connection burst showed
/// `udp_rx` jump by the whole 34KB of responses inside a single 2s sample,
/// while `recv_response()` stayed `Pending` for another 20-30s and then
/// resolved all at once. The bytes were already sitting in quinn's stream
/// buffer; nothing had re-polled the future to notice.
///
/// Re-polling is safe: every `poll` re-registers the same waker, and a future
/// that has nothing to do just returns `Pending` again. The cost is one cheap
/// poll per `period` per waiting stream, which is nothing next to the seconds
/// it saves.
pub struct Kick<F> {
    inner: std::pin::Pin<Box<F>>,
    interval: tokio::time::Interval,
}

impl<F: std::future::Future> std::future::Future for Kick<F> {
    type Output = F::Output;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<F::Output> {
        let this = self.get_mut();
        loop {
            if let std::task::Poll::Ready(v) = this.inner.as_mut().poll(cx) {
                return std::task::Poll::Ready(v);
            }
            match this.interval.poll_tick(cx) {
                std::task::Poll::Ready(_) => continue,
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

/// Wrap `fut` so a lost wakeup cannot stall it for longer than `period`.
pub fn kick<F: std::future::Future>(fut: F, period: Duration) -> Kick<F> {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    Kick {
        inner: Box::pin(fut),
        interval,
    }
}




/// Extract host part from "host:port" string.
pub fn target_host(target: &str) -> &str {
    target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target)
}
