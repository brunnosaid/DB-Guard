#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DblCategory {
    Spam,
    Phishing,
    Malware,
    BotnetC2,
    AbusedLegitSpam,
    AbusedRedirector,
    AbusedLegitPhishing,
    AbusedLegitMalware,
    AbusedLegitBotnetC2,
    IpQueryProhibited,
    DnsblNameError,
    PublicResolverError,
    QueryLimitExceeded,
    Unknown(String),
}

impl DblCategory {
    pub fn label(&self) -> &str {
        match self {
            Self::Spam => "Spam domain",
            Self::Phishing => "Phishing domain",
            Self::Malware => "Malware domain",
            Self::BotnetC2 => "Botnet C&C domain",
            Self::AbusedLegitSpam => "Abused legitimate domain - Spam",
            Self::AbusedRedirector => "Abused/spammed redirector domain",
            Self::AbusedLegitPhishing => "Abused legitimate domain - Phishing",
            Self::AbusedLegitMalware => "Abused legitimate domain - Malware",
            Self::AbusedLegitBotnetC2 => "Abused legitimate domain - Botnet C&C",
            Self::IpQueryProhibited => "IP query prohibited",
            Self::DnsblNameError => "DNSBL name error",
            Self::PublicResolverError => "Query via public/open resolver",
            Self::QueryLimitExceeded => "Query limit exceeded",
            Self::Unknown(_) => "Unknown Spamhaus response",
        }
    }

    pub fn is_listing(&self) -> bool {
        matches!(
            self,
            Self::Spam
                | Self::Phishing
                | Self::Malware
                | Self::BotnetC2
                | Self::AbusedLegitSpam
                | Self::AbusedRedirector
                | Self::AbusedLegitPhishing
                | Self::AbusedLegitMalware
                | Self::AbusedLegitBotnetC2
        )
    }

    pub fn is_error(&self) -> bool {
        matches!(
            self,
            Self::IpQueryProhibited
                | Self::DnsblNameError
                | Self::PublicResolverError
                | Self::QueryLimitExceeded
        )
    }
}

pub fn classify_return_code(ip: &str) -> DblCategory {
    match ip {
        "127.0.1.2" => DblCategory::Spam,
        "127.0.1.4" => DblCategory::Phishing,
        "127.0.1.5" => DblCategory::Malware,
        "127.0.1.6" => DblCategory::BotnetC2,
        "127.0.1.102" => DblCategory::AbusedLegitSpam,
        "127.0.1.103" => DblCategory::AbusedRedirector,
        "127.0.1.104" => DblCategory::AbusedLegitPhishing,
        "127.0.1.105" => DblCategory::AbusedLegitMalware,
        "127.0.1.106" => DblCategory::AbusedLegitBotnetC2,
        "127.0.1.255" => DblCategory::IpQueryProhibited,
        "127.255.255.252" => DblCategory::DnsblNameError,
        "127.255.255.254" => DblCategory::PublicResolverError,
        "127.255.255.255" => DblCategory::QueryLimitExceeded,
        other => DblCategory::Unknown(other.to_string()),
    }
}

pub fn query_name(domain: &str, dqs_key: Option<&str>) -> String {
    match dqs_key {
        Some(key) if !key.trim().is_empty() => {
            format!("{}.{}.dbl.dq.spamhaus.net.", domain, key.trim())
        }
        _ => format!("{}.dbl.spamhaus.org.", domain),
    }
}
