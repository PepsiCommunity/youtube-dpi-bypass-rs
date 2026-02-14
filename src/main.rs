mod ca;
mod cert_cache;
mod proxy;
mod spoof_map;

use anyhow::Result;
use base64::{engine::general_purpose, Engine};
use std::env;
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

    let args: Vec<String> = env::args().collect();
    let addr = if args.len() > 1 {
        args[1].as_str()
    } else {
        "127.0.0.1:8080"
    };

    // Parse username:password from args[2] if provided
    let auth_token = if args.len() > 2 {
        let credentials = &args[2];
        let encoded = general_purpose::STANDARD.encode(credentials.as_bytes());
        Some(format!("Basic {}", encoded))
    } else {
        None
    };

    let listener = TcpListener::bind(addr).await?;

    println!("============================================================");
    println!("🌐 Proxy: {}", addr);
    println!("🔐 Auth: {}", if auth_token.is_some() { "Enabled" } else { "Disabled" });
    println!("📜 CA cert: mitm-ca.crt");
    println!("📋 Spoof map: spoof.list");
    println!();
    println!("💡 Usage: {} [address:port] [username:password]", args.get(0).unwrap_or(&String::from("youtube-dpi-bypass-rs")));
    println!("   Default: 127.0.0.1:8080 (no auth)");
    println!();
    println!("⚠️  УСТАНОВИ mitm-ca.crt В ДОВЕРЕННЫЕ КОРНЕВЫЕ ЦЕНТРЫ");
    println!("============================================================");

    loop {
        let (stream, _) = listener.accept().await?;
        let spoof_map = spoof_map.clone();
        let cert_cache = cert_cache.clone();
        let auth_token = auth_token.clone();

        tokio::spawn(async move {
            if let Err(e) = proxy::handle_connection(stream, spoof_map, cert_cache, auth_token).await {
                eprintln!("❌ Connection error: {}", e);
            }
        });
    }
}
