use crate::cert_cache::CertCache;
use crate::spoof_map::SpoofMap;
use anyhow::{anyhow, Context, Result};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub async fn handle_connection(
    stream: TcpStream,
    spoof_map: SpoofMap,
    cert_cache: Arc<CertCache>,
) -> Result<()> {
    let (stream, host, port) = parse_connect_request(stream).await?;
    let domain = normalize_domain(&host);

    if let Some(spoof_domain) = spoof_map.get_spoof(&domain) {
        println!("🔌 {} → {} (SNI spoof)", domain, spoof_domain);
        handle_mitm_tunnel(stream, &domain, &host, port, spoof_domain, cert_cache).await
    } else {
        handle_normal_proxy(stream, &host, port).await
    }
}

async fn parse_connect_request(stream: TcpStream) -> Result<(TcpStream, String, u16)> {
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
    let mut line = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
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

    let server_tls = connector
        .connect(server_name, server_stream)
        .await
        .context(format!(
            "❌ Handshake with {} failed (SNI: {})",
            host, spoof_domain
        ))?;

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
