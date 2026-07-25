use anyhow::Result;
use std::net::SocketAddr;

/// H3 ALPN protocol ID
pub static ALPN: &[u8] = b"h3";

pub fn resolve_password(cli: Option<&str>) -> String {
    cli.map(|s| s.to_string())
        .or_else(|| std::env::var("RUST_FORWARD_PASSWORD").ok())
        .unwrap_or_default()
}

/// 解析目标（IP:port 或 host:port），强制 IPv4 连接
pub async fn connect_tcp_v4(target: &str, timeout_secs: u64) -> Result<tokio::net::TcpStream> {
    let (host, port) = if let Ok(addr) = target.parse::<SocketAddr>() {
        (addr.ip().to_string(), addr.port())
    } else {
        let (h, p) = target.rsplit_once(':').ok_or_else(|| anyhow::anyhow!("invalid target: {}", target))?;
        (h.to_string(), p.parse()?)
    };
    let addrs = tokio::net::lookup_host((host.as_str(), port)).await?;
    let v4 = addrs.filter(|a| a.is_ipv4()).next().ok_or_else(|| anyhow::anyhow!("no IPv4 address for {}", target))?;
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        tokio::net::TcpStream::connect(v4),
    )
    .await??;
    Ok(stream)
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

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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