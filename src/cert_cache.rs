use crate::ca::CA;
use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;

pub struct CertCache {
    ca: Arc<CA>,
    cache: Arc<Mutex<HashMap<String, Arc<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>>>>,
}

impl CertCache {
    pub fn new(ca: CA) -> Self {
        CertCache {
            ca: Arc::new(ca),
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn get_cert(
        &self,
        domain: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        {
            let cache = self.cache.lock().await;
            if let Some(cert) = cache.get(domain) {
                return Ok((cert.0.clone(), cert.1.clone_key()));
            }
        }

        // Double-check locking pattern
        let cert = Arc::new(self.generate_cert(domain)?);

        {
            let mut cache = self.cache.lock().await;
            if let Some(cached) = cache.get(domain) {
                return Ok((cached.0.clone(), cached.1.clone_key()));
            }
            cache.insert(domain.to_string(), cert.clone());
        }

        Ok((cert.0.clone(), cert.1.clone_key()))
    }

    fn generate_cert(
        &self,
        domain: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let mut params = CertificateParams::default();

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, domain);
        params.distinguished_name = dn;

        params.subject_alt_names = vec![rcgen::SanType::DnsName(
            domain.try_into().context("Invalid domain name")?,
        )];

        let now = OffsetDateTime::now_utc();
        let serial = (now.unix_timestamp_nanos() / 1000) as u64;
        params.serial_number = Some(serial.into());

        params.not_before = now;
        params.not_after = now + Duration::days(365);

        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];

        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

        let key_pair = KeyPair::generate()?;
        let key_pem = key_pair.serialize_pem();

        // Sign with CA
        let cert_pem = params
            .signed_by(&key_pair, &self.ca.cert, &self.ca.key_pair)
            .context("Failed to generate certificate")?
            .pem();

        let cert_der = self.parse_cert_pem(&cert_pem)?;
        let key_der = self.parse_key_pem(&key_pem)?;

        Ok((cert_der, key_der))
    }

    fn parse_cert_pem(&self, pem: &str) -> Result<Vec<CertificateDer<'static>>> {
        let mut cursor = std::io::Cursor::new(pem.as_bytes());
        let certs = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse certificate PEM")?;
        Ok(certs)
    }

    fn parse_key_pem(&self, pem: &str) -> Result<PrivateKeyDer<'static>> {
        let mut cursor = std::io::Cursor::new(pem.as_bytes());
        let key = rustls_pemfile::private_key(&mut cursor)
            .context("Failed to parse private key PEM")?
            .context("No private key found")?;
        Ok(key)
    }

    pub fn get_ca_cert(&self) -> Result<Vec<CertificateDer<'static>>> {
        self.parse_cert_pem(&self.ca.cert_pem)
    }
}
