mod ca;
mod cert_cache;
mod proxy;
mod spoof_map;

use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    println!("============================================================");
    println!("✅ MitM Proxy with SNI spoofing (spoof.list)");
    println!("============================================================");

    let spoof_map = spoof_map::SpoofMap::load("spoof.list")?;
    println!("📥 Loaded {} mappings", spoof_map.len());

    let ca = ca::CA::load_or_create("mitm-ca.crt", "mitm-ca.key")?;
    println!("✅ CA certificate ready");

    let cert_cache = Arc::new(cert_cache::CertCache::new(ca));

    let addr = "127.0.0.1:8080";
    let listener = TcpListener::bind(addr).await?;

    println!("============================================================");
    println!("Proxy: {}", addr);
    println!("CA cert: mitm-ca.crt");
    println!("Spoof map: spoof.list");
    println!();
    println!("⚠️  УСТАНОВИ mitm-ca.crt В ДОВЕРЕННЫЕ КОРНЕВЫЕ ЦЕНТРЫ");
    println!("============================================================");

    loop {
        let (stream, _) = listener.accept().await?;
        let spoof_map = spoof_map.clone();
        let cert_cache = cert_cache.clone();

        tokio::spawn(async move {
            if let Err(e) = proxy::handle_connection(stream, spoof_map, cert_cache).await {
                eprintln!("❌ Connection error: {}", e);
            }
        });
    }
}
