use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::SystemTime;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::command::{Host, Port, RuleClass, RuleKind, RuleValue, UpstreamAddr};

/// Instant rendered on the wire as an RFC3339 UTC string with second precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp(pub SystemTime);

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Timestamp(at) = self;
        serializer.collect_str(&humantime::format_rfc3339_seconds(*at))
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let at = String::deserialize(deserializer)?;
        let at = humantime::parse_rfc3339(&at).map_err(D::Error::custom)?;
        Ok(Timestamp(at))
    }
}

/// Which side of the router serves a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    /// Dialled directly because no rule matched.
    Direct,
    /// Dialled directly because a `never` rule matched.
    Never,
    /// Sent through the upstream proxy.
    Upstream,
}

/// Verdict on whether the upstream is usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    /// The upstream answered the most recent dial or probe.
    Up,
    /// The upstream failed the most recent dial or probe.
    Down,
}

/// How the most recent init-script run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadOutcome {
    /// The script exited zero and its ruleset was swapped in.
    Ok,
    /// The script exited non-zero or one of its commands failed.
    Failed,
    /// The script outlived the load timeout and was killed.
    TimedOut,
}

/// One rule of the live ruleset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleView {
    /// Position in declaration order.
    pub index: u32,
    /// Routing class of the rule.
    pub class: RuleClass,
    /// What the rule matches on.
    pub kind: RuleKind,
    /// Value the kind is matched against.
    pub value: RuleValue,
}

/// Where a destination would be routed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionView {
    /// Side of the router that would serve the destination.
    pub decision: DecisionKind,
    /// Index of the matching rule, absent when no rule matched.
    pub rule_index: Option<u32>,
    /// Class of the matching rule, absent when no rule matched.
    pub class: Option<RuleClass>,
    /// Address the connection would be handed to.
    pub next_hop: String,
}

/// Result of the most recent init-script run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastLoadView {
    /// When the run finished.
    pub at: Timestamp,
    /// How the run ended.
    pub outcome: LoadOutcome,
    /// Command that failed, absent when the run succeeded or timed out.
    pub command: Option<String>,
}

/// Number of live rules per class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleCountsView {
    /// Rules that must traverse the upstream.
    pub require: u32,
    /// Rules that try the upstream and fall back to direct.
    pub prefer: u32,
    /// Rules that always dial directly.
    pub never: u32,
}

/// Proxy settings macOS reports for the configured network service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemProxyView {
    /// Configured HTTP proxy, absent when disabled.
    pub http: Option<String>,
    /// Configured HTTPS proxy, absent when disabled.
    pub https: Option<String>,
    /// Configured SOCKS proxy, absent when disabled.
    pub socks: Option<String>,
}

/// Snapshot of everything the daemon knows about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusView {
    /// Seconds since the daemon started.
    pub uptime_secs: u64,
    /// Address the HTTP front end is configured to bind.
    pub http_listen: SocketAddr,
    /// Whether the HTTP front end holds that address.
    pub http_bound: bool,
    /// Address the SOCKS5 front end is configured to bind.
    pub socks_listen: SocketAddr,
    /// Whether the SOCKS5 front end holds that address.
    pub socks_bound: bool,
    /// Address of the upstream proxy.
    pub upstream: UpstreamAddr,
    /// Current upstream verdict.
    pub health: HealthState,
    /// When the verdict last changed.
    pub health_changed_at: Timestamp,
    /// Init script the daemon remembers, absent until one is run.
    pub init_path: Option<PathBuf>,
    /// Result of the most recent run, absent until one finishes.
    pub last_load: Option<LastLoadView>,
    /// Number of live rules per class.
    pub rules: RuleCountsView,
    /// Proxy settings macOS reports for the configured network service.
    pub system_proxy: SystemProxyView,
}

/// One diagnostic check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckView {
    /// Stable identifier of the check.
    pub name: String,
    /// Whether the check passed.
    pub ok: bool,
    /// What the check observed, and the remedy when it failed.
    pub detail: String,
}

/// One routing decision, as published to subscribers and to the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventView {
    /// Destination host.
    pub host: Host,
    /// Destination port.
    pub port: Port,
    /// Side of the router that served the connection.
    pub decision: DecisionKind,
    /// Index of the matching rule, absent when no rule matched.
    pub rule_index: Option<u32>,
    /// Class of the matching rule, absent when no rule matched.
    pub class: Option<RuleClass>,
    /// Upstream verdict at the time of the decision.
    pub upstream: HealthState,
    /// How long the connection lasted.
    pub duration_ms: u64,
    /// Why the connection ended badly, absent when it did not.
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    #[test]
    fn timestamp_renders_rfc3339_seconds() {
        let at = Timestamp(UNIX_EPOCH + Duration::from_secs(1_770_000_000));
        assert_eq!(
            serde_json::to_string(&at).unwrap(),
            r#""2026-02-02T02:40:00Z""#
        );
    }

    #[test]
    fn timestamp_round_trips() {
        let at = Timestamp(UNIX_EPOCH + Duration::from_secs(1_770_000_000));
        let wire = serde_json::to_string(&at).unwrap();
        assert_eq!(serde_json::from_str::<Timestamp>(&wire).unwrap(), at);
    }

    #[test]
    fn malformed_timestamp_is_rejected() {
        let failure = serde_json::from_str::<Timestamp>(r#""yesterday""#).unwrap_err();
        assert!(failure.to_string().contains("timestamp"), "{failure}");
    }

    #[test]
    fn absent_view_fields_render_as_null() {
        let decision = DecisionView {
            decision: DecisionKind::Direct,
            rule_index: None,
            class: None,
            next_hop: "example.com:443".to_owned(),
        };
        assert_eq!(
            serde_json::to_string(&decision).unwrap(),
            r#"{"decision":"direct","rule_index":null,"class":null,"next_hop":"example.com:443"}"#
        );
    }

    #[test]
    fn view_enums_use_contract_spellings() {
        assert_eq!(serde_json::to_string(&HealthState::Up).unwrap(), r#""up""#);
        assert_eq!(
            serde_json::to_string(&HealthState::Down).unwrap(),
            r#""down""#
        );
        assert_eq!(
            serde_json::to_string(&DecisionKind::Upstream).unwrap(),
            r#""upstream""#
        );
        assert_eq!(
            serde_json::to_string(&LoadOutcome::TimedOut).unwrap(),
            r#""timed_out""#
        );
    }
}
