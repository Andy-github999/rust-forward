use anyhow::Result;
use futures_util::SinkExt;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;

pub type WsWriter = Arc<Mutex<futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Message,
>>>;

pub type WsWriterServer = Arc<Mutex<futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    Message,
>>>;

pub type SharedWriter = Arc<tokio::sync::RwLock<Option<WsWriter>>>;

/// 每个流的状态
pub struct StreamState {
    pub ready: tokio::sync::oneshot::Sender<Result<()>>,
    pub data_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

pub fn resolve_password(cli: Option<&str>) -> String {
    if let Some(p) = cli {
        return p.to_string();
    }
    if let Some(p) = option_env!("RUST_FORWARD_PASSWORD") {
        return p.to_string();
    }
    "123456".to_string()
}

pub fn resolve_ws_url(cli: Option<&str>) -> String {
    if let Some(url) = cli {
        return url.to_string();
    }
    if let Some(url) = option_env!("RUST_FORWARD_WS_URL") {
        return url.to_string();
    }
    String::new()
}

/// 解析目标并强制 IPv4 连接（避免 IPv6 在 PassWall2 环境下卡死）
pub async fn connect_tcp_v4(target: &str, timeout_secs: u64) -> Result<tokio::net::TcpStream> {
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok(tokio::net::TcpStream::connect(addr).await?);
    }

    let addrs = tokio::net::lookup_host(target).await?;
    let v4_addrs: Vec<_> = addrs.filter(|a| a.is_ipv4()).collect();

    if v4_addrs.is_empty() {
        return Ok(tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            tokio::net::TcpStream::connect(target),
        )
        .await??);
    }

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        async {
            let mut last_err = anyhow::anyhow!("No address available");
            for addr in &v4_addrs {
                match tokio::net::TcpStream::connect(addr).await {
                    Ok(s) => return Ok(s),
                    Err(e) => { last_err = e.into(); continue; }
                }
            }
            Err(last_err)
        },
    )
    .await
    .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

    Ok(result)
}

pub async fn connect_wss(url: &str, insecure: bool) -> Result<(tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, tokio_tungstenite::tungstenite::handshake::client::Response)> {
    let connector = if insecure {
        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoopVerifier))
            .with_no_client_auth();
        Some(tokio_tungstenite::Connector::Rustls(Arc::new(tls_config)))
    } else {
        None
    };
    tokio_tungstenite::connect_async_tls_with_config(url, None, true, connector)
        .await
        .map_err(|e| anyhow::anyhow!("WSS connect failed: {}", e))
}

pub async fn handle_socks5(
    mut tcp: tokio::net::TcpStream,
    addr: SocketAddr,
    shared_writer: SharedWriter,
    streams: Arc<Mutex<HashMap<u16, StreamState>>>,
    sid: u16,
    password: &str,
    buf_size: usize,
) -> Result<()> {
    let mut buf = [0u8; 300];
    let n = tcp.read(&mut buf).await?;
    if n < 3 || buf[0] != 0x05 { return Ok(()); }
    tcp.write_all(&[0x05, 0x00]).await?;
    let n = tcp.read(&mut buf).await?;
    if n < 7 || buf[0] != 0x05 || buf[1] != 0x01 { return Ok(()); }

    let target = match buf[3] {
        0x01 => { let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]); let port = u16::from_be_bytes([buf[8], buf[9]]); format!("{}:{}", ip, port) }
        0x03 => { let len = buf[4] as usize; let domain = String::from_utf8_lossy(&buf[5..5+len]); let port = u16::from_be_bytes([buf[5+len], buf[5+len+1]]); format!("{}:{}", domain, port) }
        0x04 => { let mut octets = [0u8; 16]; octets.copy_from_slice(&buf[4..20]); let ip = std::net::Ipv6Addr::from(octets); let port = u16::from_be_bytes([buf[20], buf[21]]); format!("[{}]:{}", ip, port) }
        _ => return Ok(()),
    };
    log::info!("[{}] sid={} target={}", addr, sid, target);

    let ws_writer = match shared_writer.read().await.as_ref() {
        Some(w) => w.clone(),
        None => { log::warn!("[{}] WSS not connected", addr); return Ok(()); }
    };

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<()>>();
    const CHANNEL_CAP: usize = 256;
    let (data_tx, mut data_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(CHANNEL_CAP);
    streams.lock().await.insert(sid, StreamState { ready: ready_tx, data_tx });

    {
        let mut w = ws_writer.lock().await;
        w.send(Message::Text(format!("CONNECT {} {} {}", sid, target, password).into())).await?;
    }

    match ready_rx.await {
        Ok(Ok(())) => { tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]).await?; log::info!("[{}] sid={} tunneling", addr, sid); }
        Ok(Err(e)) => { log::warn!("[{}] sid={} server error: {}", addr, sid, e); return Ok(()); }
        Err(_) => { log::warn!("[{}] sid={} channel closed", addr, sid); return Ok(()); }
    }

    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    let w = ws_writer.clone();
    let tcp_to_ws = tokio::spawn(async move {
        let mut buf = vec![0u8; buf_size];
        loop {
            match tcp_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let mut ww = w.lock().await;
                    let mut frame = Vec::with_capacity(2 + n);
                    frame.extend_from_slice(&sid.to_be_bytes());
                    frame.extend_from_slice(&buf[..n]);
                    if ww.send(Message::Binary(frame.into())).await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
    });
    let ws_to_tcp = tokio::spawn(async move { while let Some(d) = data_rx.recv().await { if tcp_w.write_all(&d).await.is_err() { break; } } });
    let _ = tokio::join!(tcp_to_ws, ws_to_tcp);

    let mut w = ws_writer.lock().await;
    let _ = w.send(Message::Text(format!("CLOSE {}", sid).into())).await;
    Ok(())
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
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
}