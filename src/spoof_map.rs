use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone)]
pub struct SpoofMap {
    map: Arc<HashMap<String, String>>,
}

impl SpoofMap {
    pub fn load(path: &str) -> Result<Self> {
        if !Path::new(path).exists() {
            Self::create_default_file(path)?;
            println!("✅ Created default spoof.list");
        }

        let content = fs::read_to_string(path).context("Failed to read spoof.list")?;
        let mut map = HashMap::new();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((origin, spoof)) = line.split_once("->") {
                let origin = origin.trim().to_lowercase();
                let spoof = spoof.trim().to_string();

                if !origin.is_empty() && !spoof.is_empty() {
                    println!("📥 {} → {}", origin, spoof);
                    map.insert(origin, spoof);
                } else {
                    eprintln!("⚠️  Line {}: invalid format (empty domain)", line_num + 1);
                }
            } else {
                eprintln!("⚠️  Line {}: invalid format (missing '->')", line_num + 1);
            }
        }

        if map.is_empty() {
            eprintln!("⚠️  No mappings found, using defaults");
            map = Self::default_mappings();
        }

        Ok(SpoofMap { map: Arc::new(map) })
    }

    fn create_default_file(path: &str) -> Result<()> {
        let content = r#"# SNI Spoof Mapping Configuration
# Format: origin_domain -> spoof_domain
#
# YouTube domains
youtube.com -> www.google.com
ytimg.com -> edgestatic.com
ggpht.com -> www.google.com

# Video CDN
googlevideo.com -> a.gvt1.com
c.youtube.com -> a.gvt1.com
"#;

        fs::write(path, content).context("Failed to create default spoof.list")?;
        Ok(())
    }

    fn default_mappings() -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("youtube.com".to_string(), "www.google.com".to_string());
        map.insert("ytimg.com".to_string(), "edgestatic.com".to_string());
        map.insert("ggpht.com".to_string(), "www.google.com".to_string());
        map.insert("googlevideo.com".to_string(), "a.gvt1.com".to_string());
        map.insert("c.youtube.com".to_string(), "a.gvt1.com".to_string());
        map
    }

    /// Returns spoof domain for given domain (supports suffix matching)
    pub fn get_spoof(&self, domain: &str) -> Option<&str> {
        let domain = domain.to_lowercase();

        // Direct match
        if let Some(spoof) = self.map.get(&domain) {
            return Some(spoof.as_str());
        }

        // Suffix matching: www.youtube.com matches youtube.com
        for (origin, spoof) in self.map.iter() {
            if domain.ends_with(origin) {
                if domain.len() == origin.len() {
                    return Some(spoof.as_str());
                }
                if domain.as_bytes().get(domain.len() - origin.len() - 1) == Some(&b'.') {
                    return Some(spoof.as_str());
                }
            }
        }

        None
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suffix_matching() {
        let mut map = HashMap::new();
        map.insert("youtube.com".to_string(), "www.google.com".to_string());

        let spoof_map = SpoofMap { map: Arc::new(map) };

        assert_eq!(spoof_map.get_spoof("youtube.com"), Some("www.google.com"));
        assert_eq!(
            spoof_map.get_spoof("www.youtube.com"),
            Some("www.google.com")
        );
        assert_eq!(spoof_map.get_spoof("m.youtube.com"), Some("www.google.com"));

        assert_eq!(spoof_map.get_spoof("notyoutube.com"), None);
        assert_eq!(spoof_map.get_spoof("youtube.org"), None);
    }
}
