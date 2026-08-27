use hickory_resolver::{proto::rr::{RData, RecordType}, TokioResolver};
use std::net::Ipv4Addr;

use crate::spamhaus::{classify_return_code, query_name, DblCategory};

#[derive(Debug, Clone)]
pub enum CheckStatus {
    Listed,
    NotListed,
    Error,
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub domain: String,
    pub status: CheckStatus,
    pub categories: Vec<DblCategory>,
    pub return_codes: Vec<String>,
    pub query: String,
    pub detail: String,
}

impl CheckResult {
    pub fn is_listed(&self) -> bool {
        matches!(self.status, CheckStatus::Listed)
    }

    pub fn is_not_listed(&self) -> bool {
        matches!(self.status, CheckStatus::NotListed)
    }

    pub fn status_label(&self) -> &'static str {
        match self.status {
            CheckStatus::Listed => "LISTED",
            CheckStatus::NotListed => "NOT LISTED",
            CheckStatus::Error => "ERROR",
        }
    }

    pub fn category_text(&self) -> String {
        if self.categories.is_empty() {
            return "-".to_string();
        }

        self.categories
            .iter()
            .map(DblCategory::label)
            .collect::<Vec<_>>()
            .join("; ")
    }
}

pub async fn check_domain(
    resolver: &TokioResolver,
    domain: &str,
    dqs_key: Option<&str>,
) -> CheckResult {
    let query = query_name(domain, dqs_key);

    // Query DBL explicitly for A records. Spamhaus DBL reputation responses
    // are encoded as IPv4 loopback addresses such as 127.0.1.2.
    match resolver.lookup(query.as_str(), RecordType::A).await {
        Ok(lookup) => {
            let mut ips: Vec<Ipv4Addr> = lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::A(a) => Some(a.0),
                    _ => None,
                })
                .collect();

            ips.sort();
            ips.dedup();

            // A successful DNS response with no usable A records is NOT
            // equivalent to NXDOMAIN and must never be called clean.
            if ips.is_empty() {
                return CheckResult {
                    domain: domain.to_string(),
                    status: CheckStatus::Error,
                    categories: Vec::new(),
                    return_codes: Vec::new(),
                    query,
                    detail: "DNS query succeeded but returned no IPv4 DBL response. This is not NXDOMAIN and cannot be classified as NOT LISTED.".to_string(),
                };
            }

            let return_codes: Vec<String> = ips.iter().map(ToString::to_string).collect();
            let categories: Vec<DblCategory> = return_codes
                .iter()
                .map(|ip| classify_return_code(ip))
                .collect();

            let has_error = categories.iter().any(DblCategory::is_error);
            let has_listing = categories.iter().any(DblCategory::is_listing);

            let status = if has_error {
                CheckStatus::Error
            } else if has_listing {
                CheckStatus::Listed
            } else {
                CheckStatus::Error
            };

            let detail = if has_error {
                format!(
                    "Spamhaus returned an operational/error code: {}. Do not interpret this as reputation data.",
                    return_codes.join(", ")
                )
            } else if has_listing {
                format!(
                    "Spamhaus DBL returned listing code(s): {}.",
                    return_codes.join(", ")
                )
            } else {
                format!(
                    "Unexpected Spamhaus response code(s): {}. Review before using the result.",
                    return_codes.join(", ")
                )
            };

            CheckResult {
                domain: domain.to_string(),
                status,
                categories,
                return_codes,
                query,
                detail,
            }
        }
        // Only an authoritative NXDOMAIN means the queried domain has no DBL
        // listing. Other DNS failures must not become false negatives.
        Err(error) if error.is_nx_domain() => CheckResult {
            domain: domain.to_string(),
            status: CheckStatus::NotListed,
            categories: Vec::new(),
            return_codes: Vec::new(),
            query,
            detail: "NXDOMAIN returned by the DBL zone: domain is not listed.".to_string(),
        },
        Err(error) => CheckResult {
            domain: domain.to_string(),
            status: CheckStatus::Error,
            categories: Vec::new(),
            return_codes: Vec::new(),
            query,
            detail: format!("DNS lookup failed or returned a non-NXDOMAIN condition: {error}"),
        },
    }
}
