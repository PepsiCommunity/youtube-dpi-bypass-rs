mod ca;
mod cert_cache;
mod proxy;
mod spoof_map;

use anyhow::Result;
use base64::{engine::general_purpose, Engine};
use clap::Parser;
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "MitM Proxy with SNI spoofing", long_about = None)]
struct Args {
    /// Proxy listen address
    #[arg(default_value = "127.0.0.1:8080")]
    address: String,

    /// Authentication credentials (username:password)
    #[arg(short, long)]
    auth: Option<String>,

    /// Enable verbose output (show certificate SANs on errors)
    #[arg(short, long)]
    verbose: bool,
}

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

    let args = Args::parse();

    // Parse authentication credentials if provided
    let auth_token = args.auth.as_ref().map(|credentials| {
        let encoded = general_purpose::STANDARD.encode(credentials.as_bytes());
        format!("Basic {}", encoded)
    });

    let listener = TcpListener::bind(&args.address).await?;

    println!("============================================================");
    println!("🌐 Proxy: {}", args.address);
    println!(
        "🔐 Auth: {}",
        if auth_token.is_some() {
            "Enabled"
        } else {
            "Disabled"
        }
    );
    println!(
        "📊 Verbose: {}",
        if args.verbose { "Enabled" } else { "Disabled" }
    );
    println!("📜 CA cert: mitm-ca.crt");
    println!("📋 Spoof map: spoof.list");
    println!();
    println!("💡 Usage: youtube-dpi-bypass-rs [OPTIONS] [ADDRESS]");
    println!("   --auth <user:pass>  Enable proxy authentication");
    println!("   --verbose           Show certificate SANs on errors");
    println!();
    println!("⚠️  УСТАНОВИ mitm-ca.crt В ДОВЕРЕННЫЕ КОРНЕВЫЕ ЦЕНТРЫ");
    println!("============================================================");

    loop {
        let (stream, _) = listener.accept().await?;
        let spoof_map = spoof_map.clone();
        let cert_cache = cert_cache.clone();
        let auth_token = auth_token.clone();
        let verbose = args.verbose;

        tokio::spawn(async move {
            if let Err(e) =
                proxy::handle_connection(stream, spoof_map, cert_cache, auth_token, verbose).await
            {
                eprintln!("❌ Connection error: {}", e);
            }
        });
    }
}
