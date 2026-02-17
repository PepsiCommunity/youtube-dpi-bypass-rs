use crate::cert_cache::CertCache;
use crate::spoof_map::SpoofMap;
use anyhow::{anyhow, Context, Result};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x509_parser::prelude::*;

pub async fn handle_connection(
    stream: TcpStream,
    spoof_map: SpoofMap,
    cert_cache: Arc<CertCache>,
    auth_token: Option<String>,
    verbose: bool,
) -> Result<()> {
    let (stream, host, port) = parse_connect_request(stream, auth_token).await?;
    let domain = normalize_domain(&host);

    if let Some(spoof_domain) = spoof_map.get_spoof(&domain) {
        println!("🔌 {} → {} (SNI spoof)", domain, spoof_domain);
        handle_mitm_tunnel(
            stream,
            &domain,
            &host,
            port,
            spoof_domain,
            cert_cache,
            verbose,
        )
        .await
    } else {
        handle_normal_proxy(stream, &host, port).await
    }
}

async fn parse_connect_request(
    stream: TcpStream,
    expected_auth: Option<String>,
) -> Result<(TcpStream, String, u16)> {
    let mut reader = BufReader::new(stream);
    let mut first_line = String::new();

    reader
        .read_line(&mut first_line)
        .await
        .context("Failed to read CONNECT request")?;

    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "CONNECT" {
        return Err(anyhow!("Invalid CONNECT request: {}", first_line));
    }

    let target = parts[1];
    let (host, port) = if let Some((h, p)) = target.split_once(':') {
        (h.to_string(), p.parse::<u16>().unwrap_or(443))
    } else {
        (target.to_string(), 443)
    };

    // Read headers until empty line
    let mut proxy_auth: Option<String> = None;
    let mut line = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }

        // Check for Proxy-Authorization header
        if line.to_lowercase().starts_with("proxy-authorization:") {
            if let Some(auth_value) = line.split(':').nth(1) {
                proxy_auth = Some(auth_value.trim().to_string());
            }
        }
    }

    // Validate authentication if required
    if let Some(expected) = expected_auth {
        match proxy_auth {
            Some(provided) if provided == expected => {
                // Authentication successful
            }
            _ => {
                // Authentication failed
                let mut stream = reader.into_inner();
                stream
                    .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n")
                    .await
                    .ok();
                return Err(anyhow!("Proxy authentication required"));
            }
        }
    }

    let stream = reader.into_inner();
    Ok((stream, host, port))
}

/// Normal proxy mode - direct TCP tunnel
async fn handle_normal_proxy(mut client: TcpStream, host: &str, port: u16) -> Result<()> {
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("Failed to send 200 response")?;

    let target_addr = format!("{}:{}", host, port);
    let mut server = TcpStream::connect(&target_addr)
        .await
        .context(format!("Failed to connect to {}", target_addr))?;

    let (mut client_read, mut client_write) = client.split();
    let (mut server_read, mut server_write) = server.split();

    let client_to_server = tokio::io::copy(&mut client_read, &mut server_write);
    let server_to_client = tokio::io::copy(&mut server_read, &mut client_write);

    tokio::select! {
        _ = client_to_server => {},
        _ = server_to_client => {},
    }

    Ok(())
}

/// MITM tunnel mode - SNI spoofing
async fn handle_mitm_tunnel(
    mut client_stream: TcpStream,
    domain: &str,
    host: &str,
    port: u16,
    spoof_domain: &str,
    cert_cache: Arc<CertCache>,
    verbose: bool,
) -> Result<()> {
    client_stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("Failed to send 200 response")?;

    let (mut certs, key) = cert_cache
        .get_cert(domain)
        .await
        .context("Failed to get certificate")?;

    // Add CA to chain
    let ca_cert = cert_cache.get_ca_cert()?;
    certs.extend(ca_cert);

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to create TLS server config")?;

    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let client_tls = acceptor
        .accept(client_stream)
        .await
        .context("Failed to establish TLS with client")?;

    let target_addr = format!("{}:{}", host, port);
    let server_stream = TcpStream::connect(&target_addr)
        .await
        .context(format!("❌ Dial to {} failed", target_addr))?;

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(client_config));

    // KEY MOMENT: use spoofed domain for SNI
    let server_name =
        ServerName::try_from(spoof_domain.to_string()).context("Invalid spoof domain")?;

    let server_tls = match connector.connect(server_name.clone(), server_stream).await {
        Ok(tls) => tls,
        Err(e) => {
            if verbose {
                // Try to get certificate details without verification
                if let Ok(sans) = get_certificate_sans(host, port, spoof_domain).await {
                    eprintln!(
                        "❌ Handshake with {} failed (SNI: {})\n   Certificate SANs: {}",
                        host, spoof_domain, sans
                    );
                } else {
                    eprintln!(
                        "❌ Handshake with {} failed (SNI: {})\n   Error: {}",
                        host, spoof_domain, e
                    );
                }
            }
            return Err(anyhow!(
                "❌ Handshake with {} failed (SNI: {})",
                host,
                spoof_domain
            ));
        }
    };

    // Bidirectional copy
    let (mut client_read, mut client_write) = tokio::io::split(client_tls);
    let (mut server_read, mut server_write) = tokio::io::split(server_tls);

    let client_to_server = async { tokio::io::copy(&mut client_read, &mut server_write).await };
    let server_to_client = async { tokio::io::copy(&mut server_read, &mut client_write).await };

    tokio::select! {
        result = client_to_server => {
            if let Err(e) = result {
                let err_str = e.to_string();
                if !err_str.contains("close_notify") && !err_str.contains("UnexpectedEof") {
                    eprintln!("❌ Client to server error: {}", e);
                }
            }
        }
        result = server_to_client => {
            if let Err(e) = result {
                let err_str = e.to_string();
                if !err_str.contains("close_notify") && !err_str.contains("UnexpectedEof") {
                    eprintln!("❌ Server to client error: {}", e);
                }
            }
        }
    }

    Ok(())
}

fn normalize_domain(host: &str) -> String {
    host.split(':').next().unwrap_or(host).to_lowercase()
}

/// Attempts to retrieve certificate SANs by connecting without verification
async fn get_certificate_sans(host: &str, port: u16, spoof_domain: &str) -> Result<String> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName as RustlsServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    // Custom verifier that accepts any certificate but captures it
    #[derive(Debug)]
    struct CertCapture {
        captured_cert: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    }

    impl ServerCertVerifier for CertCapture {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &RustlsServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            // Capture the certificate
            if let Ok(mut cert) = self.captured_cert.lock() {
                *cert = Some(end_entity.to_vec());
            }
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::ED25519,
            ]
        }
    }

    let captured_cert = Arc::new(std::sync::Mutex::new(None));
    let verifier = Arc::new(CertCapture {
        captured_cert: captured_cert.clone(),
    });

    let client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(client_config));

    let target_addr = format!("{}:{}", host, port);
    let server_stream = TcpStream::connect(&target_addr).await?;

    let server_name = ServerName::try_from(spoof_domain.to_string())?;

    // Try to connect - we don't care if it succeeds, we just want the cert
    let _ = connector.connect(server_name, server_stream).await;

    // Extract SANs from captured certificate
    if let Ok(cert_guard) = captured_cert.lock() {
        if let Some(cert_der) = cert_guard.as_ref() {
            return extract_sans_from_der(cert_der);
        }
    }

    Err(anyhow!("Failed to capture certificate"))
}

/// Extracts Subject Alternative Names from a DER-encoded certificate
fn extract_sans_from_der(cert_der: &[u8]) -> Result<String> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| anyhow!("Failed to parse certificate: {}", e))?;

    let mut sans = Vec::new();

    // Get SANs from extensions
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            match name {
                GeneralName::DNSName(dns) => sans.push(format!("DNS:{}", dns)),
                GeneralName::IPAddress(ip) => {
                    let ip_str = if ip.len() == 4 {
                        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
                    } else {
                        format!("{:?}", ip)
                    };
                    sans.push(format!("IP:{}", ip_str));
                }
                _ => {}
            }
        }
    }

    if sans.is_empty() {
        // Fallback to Common Name if no SANs
        if let Some(cn) = cert.subject().iter_common_name().next() {
            if let Ok(cn_str) = cn.as_str() {
                sans.push(format!("CN:{}", cn_str));
            }
        }
    }

    if sans.is_empty() {
        Ok("(none)".to_string())
    } else {
        Ok(sans.join(", "))
    }
}
