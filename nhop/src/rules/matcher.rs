use std::net::IpAddr;

use ipnet::IpNet;
use nhop_ipc::{ErrKind, Host, Port, RuleKind, RuleValue};

/// Rejection of a rule value that cannot be read as its kind.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct InvalidRule {
    message: String,
}

impl InvalidRule {
    fn new(kind: RuleKind, value: &RuleValue, expected: &str) -> Self {
        let kind = kind_name(kind);
        let RuleValue(value) = value;
        Self {
            message: format!("invalid {kind} value {value:?}: expected {expected}"),
        }
    }

    /// Returns the wire category this rejection is reported as.
    pub fn err_kind(&self) -> ErrKind {
        ErrKind::InvalidArgs
    }

    /// Returns the explanation shown to the operator.
    pub fn message(&self) -> &str {
        &self.message
    }
}

fn kind_name(kind: RuleKind) -> &'static str {
    match kind {
        RuleKind::Suffix => "suffix",
        RuleKind::Cidr => "cidr",
        RuleKind::Port => "port",
        RuleKind::Keyword => "keyword",
    }
}

/// Destination host lowercased and stripped of a trailing dot, with its IP literal read once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedHost {
    host: String,
    address: Option<IpAddr>,
}

impl NormalizedHost {
    /// Prepares a destination host for matching.
    pub fn new(host: &Host) -> Self {
        let Host(host) = host;
        let host = host.strip_suffix('.').unwrap_or(host);
        let host = host.to_lowercase();
        let address = host.parse::<IpAddr>().ok();
        Self { host, address }
    }

    /// Returns the normalized host.
    pub fn as_str(&self) -> &str {
        &self.host
    }

    /// Returns the address the host was written as, absent when it is a name.
    pub fn address(&self) -> Option<IpAddr> {
        self.address
    }
}

/// Hostname suffix matched exactly or on a dot boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suffix(String);

impl Suffix {
    fn parse(value: &RuleValue) -> Result<Self, InvalidRule> {
        let RuleValue(suffix) = value;
        let suffix = suffix.strip_suffix('.').unwrap_or(suffix);
        let suffix = suffix.to_lowercase();
        if suffix.is_empty()
            || suffix.contains(char::is_whitespace)
            || suffix.starts_with('.')
            || suffix.contains('*')
        {
            return Err(InvalidRule::new(
                RuleKind::Suffix,
                value,
                "a hostname such as example.com",
            ));
        }
        Ok(Self(suffix))
    }

    fn matches(&self, host: &NormalizedHost) -> bool {
        let Self(suffix) = self;
        let host = host.as_str();
        if host == suffix {
            return true;
        }
        let Some(head) = host.strip_suffix(suffix) else {
            return false;
        };
        head.ends_with('.')
    }
}

/// Substring matched against the host and never against the port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keyword(String);

impl Keyword {
    fn parse(value: &RuleValue) -> Result<Self, InvalidRule> {
        let RuleValue(keyword) = value;
        let keyword = keyword.to_lowercase();
        if keyword.is_empty() || keyword.contains(char::is_whitespace) {
            return Err(InvalidRule::new(
                RuleKind::Keyword,
                value,
                "a non-empty substring of a hostname",
            ));
        }
        Ok(Self(keyword))
    }

    fn matches(&self, host: &NormalizedHost) -> bool {
        let Self(keyword) = self;
        host.as_str().contains(keyword.as_str())
    }
}

/// Right-hand side of a rule, ready to match destinations against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Matcher {
    /// Matches a hostname exactly or on a dot boundary.
    Suffix(Suffix),
    /// Matches hosts that read as an IP literal inside the network.
    Cidr(IpNet),
    /// Matches an exact destination port.
    Port(Port),
    /// Matches a substring of the host.
    Keyword(Keyword),
}

impl Matcher {
    /// Reads a rule value according to its kind.
    pub fn parse(kind: RuleKind, value: &RuleValue) -> Result<Self, InvalidRule> {
        match kind {
            RuleKind::Suffix => Ok(Self::Suffix(Suffix::parse(value)?)),
            RuleKind::Cidr => Ok(Self::Cidr(parse_network(value)?)),
            RuleKind::Port => Ok(Self::Port(parse_port(value)?)),
            RuleKind::Keyword => Ok(Self::Keyword(Keyword::parse(value)?)),
        }
    }

    /// Returns what this matcher matches on.
    pub fn kind(&self) -> RuleKind {
        match self {
            Self::Suffix(_) => RuleKind::Suffix,
            Self::Cidr(_) => RuleKind::Cidr,
            Self::Port(_) => RuleKind::Port,
            Self::Keyword(_) => RuleKind::Keyword,
        }
    }

    /// Returns whether a destination matches.
    pub fn matches(&self, host: &NormalizedHost, port: Port) -> bool {
        match self {
            Self::Suffix(suffix) => suffix.matches(host),
            Self::Cidr(network) => {
                let NormalizedHost { host: _, address } = host;
                let Some(address) = address else {
                    return false;
                };
                network.contains(address)
            }
            Self::Port(expected) => {
                let Port(expected) = expected;
                let Port(port) = port;
                *expected == port
            }
            Self::Keyword(keyword) => keyword.matches(host),
        }
    }
}

fn parse_network(value: &RuleValue) -> Result<IpNet, InvalidRule> {
    let RuleValue(network) = value;
    let Ok(network) = network.parse::<IpNet>() else {
        return Err(InvalidRule::new(
            RuleKind::Cidr,
            value,
            "a network such as 192.0.2.0/24",
        ));
    };
    Ok(network)
}

fn parse_port(value: &RuleValue) -> Result<Port, InvalidRule> {
    let RuleValue(port) = value;
    let Ok(port) = port.parse::<u16>() else {
        return Err(InvalidRule::new(
            RuleKind::Port,
            value,
            "a single port between 0 and 65535, ranges are not supported",
        ));
    };
    Ok(Port(port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(host: &str) -> NormalizedHost {
        NormalizedHost::new(&Host(host.to_owned()))
    }

    fn matcher(kind: RuleKind, value: &str) -> Matcher {
        Matcher::parse(kind, &RuleValue(value.to_owned())).unwrap()
    }

    fn rejection(kind: RuleKind, value: &str) -> InvalidRule {
        Matcher::parse(kind, &RuleValue(value.to_owned())).unwrap_err()
    }

    #[test]
    fn suffix_matches_the_domain_itself() {
        let rule = matcher(RuleKind::Suffix, "example.com");
        assert!(rule.matches(&host("example.com"), Port(443)));
    }

    #[test]
    fn suffix_matches_a_subdomain() {
        let rule = matcher(RuleKind::Suffix, "example.com");
        assert!(rule.matches(&host("api.internal.example.com"), Port(443)));
    }

    #[test]
    fn suffix_ignores_a_shared_tail() {
        let rule = matcher(RuleKind::Suffix, "example.com");
        assert!(!rule.matches(&host("notexample.com"), Port(443)));
        assert!(!rule.matches(&host("example.com.evil.test"), Port(443)));
        assert!(!rule.matches(&host("com"), Port(443)));
    }

    #[test]
    fn suffix_ignores_case_on_both_sides() {
        let rule = matcher(RuleKind::Suffix, "Example.COM");
        assert!(rule.matches(&host("API.Example.Com"), Port(443)));
    }

    #[test]
    fn suffix_strips_the_trailing_dot() {
        let rule = matcher(RuleKind::Suffix, "example.com.");
        assert!(rule.matches(&host("example.com"), Port(443)));
        assert!(rule.matches(&host("api.example.com."), Port(443)));
    }

    #[test]
    fn cidr_matches_an_address_in_range() {
        let rule = matcher(RuleKind::Cidr, "192.0.2.0/24");
        assert!(rule.matches(&host("192.0.2.17"), Port(80)));
    }

    #[test]
    fn cidr_ignores_an_address_out_of_range() {
        let rule = matcher(RuleKind::Cidr, "192.0.2.0/24");
        assert!(!rule.matches(&host("198.51.100.17"), Port(80)));
    }

    #[test]
    fn cidr_never_matches_a_hostname() {
        let rule = matcher(RuleKind::Cidr, "0.0.0.0/0");
        assert!(!rule.matches(&host("example.com"), Port(80)));
        assert!(!rule.matches(&host("192.0.2.17.example.com"), Port(80)));
    }

    #[test]
    fn cidr_ignores_the_other_address_family() {
        let rule = matcher(RuleKind::Cidr, "192.0.2.0/24");
        assert!(!rule.matches(&host("2001:db8::1"), Port(80)));

        let rule = matcher(RuleKind::Cidr, "2001:db8::/32");
        assert!(rule.matches(&host("2001:DB8::1"), Port(80)));
        assert!(!rule.matches(&host("192.0.2.17"), Port(80)));
    }

    #[test]
    fn port_matches_exact_equality_only() {
        let rule = matcher(RuleKind::Port, "8443");
        assert!(rule.matches(&host("example.com"), Port(8443)));
        assert!(!rule.matches(&host("example.com"), Port(8444)));
        assert!(!rule.matches(&host("example.com"), Port(443)));
    }

    #[test]
    fn keyword_matches_a_substring_ignoring_case() {
        let rule = matcher(RuleKind::Keyword, "Internal");
        assert!(rule.matches(&host("api.INTERNAL.example.com"), Port(443)));
        assert!(!rule.matches(&host("api.example.com"), Port(443)));
    }

    #[test]
    fn keyword_never_matches_the_port() {
        let rule = matcher(RuleKind::Keyword, "8443");
        assert!(!rule.matches(&host("example.com"), Port(8443)));
    }

    #[test]
    fn kind_survives_parsing() {
        let kinds = [
            (RuleKind::Suffix, "example.com"),
            (RuleKind::Cidr, "192.0.2.0/24"),
            (RuleKind::Port, "443"),
            (RuleKind::Keyword, "internal"),
        ];
        for (kind, value) in kinds {
            assert_eq!(matcher(kind, value).kind(), kind);
        }
    }

    #[test]
    fn suffix_rejects_an_empty_value() {
        let failure = rejection(RuleKind::Suffix, ".");
        assert_eq!(failure.err_kind(), ErrKind::InvalidArgs);
        assert!(failure.message().contains("suffix"), "{failure}");
        assert!(
            rejection(RuleKind::Suffix, "  ")
                .message()
                .contains("suffix")
        );
    }

    #[test]
    fn suffix_rejects_spellings_that_would_match_nothing() {
        let failure = rejection(RuleKind::Suffix, ".example.com");
        assert_eq!(failure.err_kind(), ErrKind::InvalidArgs);
        assert!(failure.message().contains("suffix"), "{failure}");
        assert!(
            rejection(RuleKind::Suffix, "*.example.com")
                .message()
                .contains("suffix")
        );
    }

    #[test]
    fn cidr_rejects_a_value_without_a_prefix_length() {
        let failure = rejection(RuleKind::Cidr, "example.com");
        assert_eq!(failure.err_kind(), ErrKind::InvalidArgs);
        assert!(failure.message().contains("cidr"), "{failure}");
        assert!(
            rejection(RuleKind::Cidr, "192.0.2.0/33")
                .message()
                .contains("cidr")
        );
    }

    #[test]
    fn port_rejects_a_range_and_an_out_of_bounds_value() {
        let failure = rejection(RuleKind::Port, "80-90");
        assert_eq!(failure.err_kind(), ErrKind::InvalidArgs);
        assert!(
            failure.message().contains("ranges are not supported"),
            "{failure}"
        );
        assert!(
            rejection(RuleKind::Port, "70000")
                .message()
                .contains("port")
        );
    }

    #[test]
    fn keyword_rejects_an_empty_value() {
        let failure = rejection(RuleKind::Keyword, "");
        assert_eq!(failure.err_kind(), ErrKind::InvalidArgs);
        assert!(failure.message().contains("keyword"), "{failure}");
    }

    #[test]
    fn normalized_host_lowercases_and_strips_the_trailing_dot() {
        assert_eq!(host("API.Example.COM.").as_str(), "api.example.com");
    }
}
