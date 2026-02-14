use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use std::fs;
use std::path::Path;
use time::{Duration, OffsetDateTime};

pub struct CA {
    pub key_pair: KeyPair,
    pub cert: rcgen::Certificate,
    pub cert_pem: String,
    pub key_pem: String,
}

impl CA {
    pub fn load_or_create(cert_path: &str, key_path: &str) -> Result<Self> {
        if Path::new(cert_path).exists() && Path::new(key_path).exists() {
            Self::load(cert_path, key_path)
        } else {
            let ca = Self::generate()?;
            ca.save(cert_path, key_path)?;
            println!("✅ Created new CA certificate");
            Ok(ca)
        }
    }

    fn load(cert_path: &str, key_path: &str) -> Result<Self> {
        let cert_pem = fs::read_to_string(cert_path).context("Failed to read CA certificate")?;
        let key_pem = fs::read_to_string(key_path).context("Failed to read CA private key")?;

        let key_pair = KeyPair::from_pem(&key_pem).context("Failed to parse CA private key")?;
        let params = CertificateParams::from_ca_cert_pem(&cert_pem)?;

        // Recreate Certificate object from params (needed for signing new certs)
        let cert = params
            .self_signed(&key_pair)
            .context("Failed to recreate CA certificate")?;

        Ok(CA {
            key_pair,
            cert,
            cert_pem,
            key_pem,
        })
    }

    fn generate() -> Result<Self> {
        let mut params = CertificateParams::default();

        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, "SNI Spoof Proxy");
        dn.push(DnType::CommonName, "SNI Spoof CA");
        params.distinguished_name = dn;

        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let now = OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + Duration::days(3650); // 10 years

        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];

        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];

        let key_pair = KeyPair::generate()?;
        let key_pem = key_pair.serialize_pem();

        let cert = params
            .self_signed(&key_pair)
            .context("Failed to generate CA certificate")?;
        let cert_pem = cert.pem();

        Ok(CA {
            key_pair,
            cert,
            cert_pem,
            key_pem,
        })
    }

    fn save(&self, cert_path: &str, key_path: &str) -> Result<()> {
        fs::write(cert_path, &self.cert_pem).context("Failed to write CA certificate")?;
        fs::write(key_path, &self.key_pem).context("Failed to write CA private key")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(key_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(key_path, perms)?;
        }

        Ok(())
    }
}
