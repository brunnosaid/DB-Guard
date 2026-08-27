use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use url::{Host, Url};

#[derive(Debug)]
pub struct DomainLoadResult {
    pub domains: Vec<String>,
    pub total_lines: usize,
    pub accepted_entries: usize,
    pub duplicates_removed: usize,
    pub invalid_entries: usize,
}

pub fn load_domains(path: &Path) -> Result<DomainLoadResult> {
    let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut unique = BTreeSet::new();
    let mut total_lines = 0usize;
    let mut accepted_entries = 0usize;
    let mut invalid_entries = 0usize;

    for (index, line) in reader.lines().enumerate() {
        total_lines += 1;
        let raw = line.with_context(|| format!("failed reading line {}", index + 1))?;
        let trimmed = raw.trim().trim_start_matches('\u{feff}');

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        match normalize_domain(trimmed) {
            Some(domain) => {
                accepted_entries += 1;
                unique.insert(domain);
            }
            None => {
                invalid_entries += 1;
                eprintln!("[WARN] Ignoring invalid entry at line {}: {}", index + 1, trimmed);
            }
        }
    }

    let duplicates_removed = accepted_entries.saturating_sub(unique.len());

    Ok(DomainLoadResult {
        domains: unique.into_iter().collect(),
        total_lines,
        accepted_entries,
        duplicates_removed,
        invalid_entries,
    })
}

fn normalize_domain(input: &str) -> Option<String> {
    let mut candidate = input
        .trim()
        .trim_start_matches('\u{feff}')
        .trim_matches(|c| matches!(c, '<' | '>' | '"' | '\''))
        .trim()
        .to_string();

    if candidate.is_empty() {
        return None;
    }

    // Accept raw mailbox entries. Everything through the final '@' is local
    // part and must not be sent to Spamhaus DBL.
    // Example: bounce-abc@envios.suantc.com -> envios.suantc.com
    if let Some((_, domain_part)) = candidate.rsplit_once('@') {
        candidate = domain_part.trim().to_string();
    }

    // Accept URLs in dirty input lists and retain the complete hostname,
    // including subdomains.
    if candidate.contains("://") {
        let parsed = Url::parse(&candidate).ok()?;
        candidate = parsed.host_str()?.to_string();
    } else {
        // Strip path/query/fragment if a hostname was copied together with one.
        candidate = candidate
            .trim_start_matches("//")
            .split(['/', '?', '#'])
            .next()?
            .to_string();

        // Strip a conventional :port suffix without trying to accept IPv6.
        if let Some((host, port)) = candidate.rsplit_once(':') {
            if !host.contains(':') && port.parse::<u16>().is_ok() {
                candidate = host.to_string();
            }
        }
    }

    let domain = candidate
        .trim()
        .trim_matches(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '\'' | ',' | ';'))
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if domain.is_empty() {
        return None;
    }

    match Host::parse(&domain).ok()? {
        Host::Domain(value) => Some(value),
        Host::Ipv4(_) | Host::Ipv6(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_domain;

    #[test]
    fn normalizes_plain_domains() {
        assert_eq!(normalize_domain("Example.COM."), Some("example.com".into()));
        assert_eq!(normalize_domain("envios.suantc.com"), Some("envios.suantc.com".into()));
    }

    #[test]
    fn extracts_domain_from_email_address() {
        assert_eq!(
            normalize_domain("bounce-776092e70d5348f5e3bd65fbe069bed3@envios.suantc.com"),
            Some("envios.suantc.com".into())
        );
        assert_eq!(
            normalize_domain("<user@MAIL.Example.COM>"),
            Some("mail.example.com".into())
        );
    }

    #[test]
    fn extracts_hostname_from_urls_and_ports() {
        assert_eq!(
            normalize_domain("https://Sub.Example.com/path?q=1"),
            Some("sub.example.com".into())
        );
        assert_eq!(
            normalize_domain("mail.example.com:443/path"),
            Some("mail.example.com".into())
        );
    }

    #[test]
    fn rejects_ips() {
        assert_eq!(normalize_domain("1.2.3.4"), None);
    }
}
