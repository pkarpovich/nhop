use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::view::{CheckView, DecisionView, EventView, RuleView, StatusView};

/// Environment variable the daemon tags an init-script run with.
///
/// The script inherits it; the client sends it back as each command's `load`, making a run atomic.
pub const LOAD_ID_ENV: &str = "NHOP_LOAD_ID";

/// Identifier of a single init-script run, grouping the commands it stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LoadId(pub u64);

/// Rejection of a load identifier that is not a number.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid load id {0:?}")]
pub struct InvalidLoadId(String);

impl fmt::Display for LoadId {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(id) = self;
        write!(out, "{id}")
    }
}

impl FromStr for LoadId {
    type Err = InvalidLoadId;

    fn from_str(id: &str) -> Result<Self, Self::Err> {
        let Ok(parsed) = id.trim().parse::<u64>() else {
            return Err(InvalidLoadId(id.to_owned()));
        };
        Ok(Self(parsed))
    }
}

/// Hostname or IP literal a connection is destined for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Host(pub String);

/// TCP port a connection is destined for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Port(pub u16);

/// Right-hand side of a rule, interpreted according to its [`RuleKind`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RuleValue(pub String);

/// Address of the SOCKS5 upstream, in `socks5://host:port` form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UpstreamAddr(pub String);

/// How a connection matching a rule is routed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleClass {
    /// Must traverse the upstream and fails fast when the upstream is down.
    Require,
    /// Tries the upstream and falls back to a direct connection when it is down.
    Prefer,
    /// Always dials the destination directly.
    Never,
}

/// What part of a destination a rule matches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    /// Exact-or-dot-boundary hostname suffix, case-insensitive.
    Suffix,
    /// Network range matching hosts that parse as an IP literal.
    Cidr,
    /// Exact port equality.
    Port,
    /// Case-insensitive substring of the host.
    Keyword,
}

/// One request sent to the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    /// `add_rule` - appends a rule to the ruleset being built.
    AddRule {
        /// Routing class of the rule.
        class: RuleClass,
        /// What the rule matches on.
        kind: RuleKind,
        /// Value the kind is matched against.
        value: RuleValue,
        /// Init run this command belongs to, absent outside a load.
        load: Option<LoadId>,
    },
    /// `clear_rules` - empties the ruleset being built.
    ClearRules {
        /// Init run this command belongs to, absent outside a load.
        load: Option<LoadId>,
    },
    /// `set_upstream` - points the router at a SOCKS5 upstream.
    SetUpstream {
        /// Address of the upstream proxy.
        addr: UpstreamAddr,
        /// Init run this command belongs to, absent outside a load.
        load: Option<LoadId>,
    },
    /// `set_listen` - moves the HTTP and SOCKS5 front ends.
    SetListen {
        /// Address the HTTP front end binds to.
        http: SocketAddr,
        /// Address the SOCKS5 front end binds to.
        socks: SocketAddr,
        /// Init run this command belongs to, absent outside a load.
        load: Option<LoadId>,
    },
    /// `reload` - re-runs the init script, optionally from a different path.
    Reload {
        /// Script to run instead of the remembered one.
        path: Option<PathBuf>,
    },
    /// `on` - re-runs the remembered init script.
    On,
    /// `off` - clears the live ruleset while both front ends keep listening.
    Off,
    /// `status` - reports daemon state as a [`StatusView`].
    Status,
    /// `rules` - lists the live ruleset as [`RuleView`] values.
    Rules,
    /// `test` - reports the routing decision for a destination without dialling it.
    Test {
        /// Destination host.
        host: Host,
        /// Destination port.
        port: Port,
    },
    /// `doctor` - runs the diagnostic checks.
    Doctor,
    /// `subscribe` - switches the connection to a stream of decision events.
    Subscribe,
}

/// One reply written by the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "resp", content = "data", rename_all = "snake_case")]
pub enum Response {
    /// `ok` - the command succeeded and carries no payload.
    Ok,
    /// `rules` - the live ruleset in declaration order.
    Rules(Vec<RuleView>),
    /// `status` - the daemon state snapshot.
    Status(StatusView),
    /// `decision` - where a destination would be routed.
    Decision(DecisionView),
    /// `doctor` - the diagnostic check results in a fixed order.
    Doctor(Vec<CheckView>),
    /// `event` - one connection decision, emitted only on a subscribed connection.
    Event(EventView),
    /// `err` - the command failed.
    Err {
        /// Category the client maps onto an exit code.
        kind: ErrKind,
        /// Human-readable explanation.
        message: String,
    },
}

/// Category of a failed command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrKind {
    /// The addressed thing does not exist.
    NotFound,
    /// The upstream is down and a `require` rule demands it.
    UpstreamDown,
    /// The command arguments are malformed.
    InvalidArgs,
    /// An init run is in progress and this command does not belong to it.
    LoadInProgress,
    /// The daemon failed for a reason the client cannot act on.
    Internal,
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use crate::view::{
        DecisionKind, HealthState, LastLoadView, LoadOutcome, RuleCountsView, SystemProxyView,
        Timestamp,
    };

    use super::*;

    fn commands() -> Vec<Command> {
        vec![
            Command::AddRule {
                class: RuleClass::Require,
                kind: RuleKind::Suffix,
                value: RuleValue("example.com".to_owned()),
                load: Some(LoadId(7)),
            },
            Command::AddRule {
                class: RuleClass::Prefer,
                kind: RuleKind::Cidr,
                value: RuleValue("192.0.2.0/24".to_owned()),
                load: None,
            },
            Command::AddRule {
                class: RuleClass::Never,
                kind: RuleKind::Keyword,
                value: RuleValue("internal".to_owned()),
                load: None,
            },
            Command::AddRule {
                class: RuleClass::Prefer,
                kind: RuleKind::Port,
                value: RuleValue("443".to_owned()),
                load: None,
            },
            Command::ClearRules {
                load: Some(LoadId(1)),
            },
            Command::SetUpstream {
                addr: UpstreamAddr("socks5://192.0.2.10:1080".to_owned()),
                load: None,
            },
            Command::SetListen {
                http: "127.0.0.1:7890".parse().unwrap(),
                socks: "127.0.0.1:7891".parse().unwrap(),
                load: Some(LoadId(2)),
            },
            Command::Reload {
                path: Some(PathBuf::from("/tmp/init")),
            },
            Command::Reload { path: None },
            Command::On,
            Command::Off,
            Command::Status,
            Command::Rules,
            Command::Test {
                host: Host("example.com".to_owned()),
                port: Port(443),
            },
            Command::Doctor,
            Command::Subscribe,
        ]
    }

    fn status_view() -> StatusView {
        StatusView {
            uptime_secs: 42,
            http_listen: "127.0.0.1:7890".parse().unwrap(),
            http_bound: true,
            socks_listen: "127.0.0.1:7891".parse().unwrap(),
            socks_bound: true,
            upstream: UpstreamAddr("socks5://192.0.2.10:1080".to_owned()),
            health: HealthState::Down,
            health_changed_at: Timestamp(UNIX_EPOCH + Duration::from_secs(1_770_000_000)),
            init_path: Some(PathBuf::from("/home/operator/.config/nhop/init")),
            last_load: Some(LastLoadView {
                at: Timestamp(UNIX_EPOCH + Duration::from_secs(1_770_000_001)),
                outcome: LoadOutcome::TimedOut,
                command: Some("add_rule".to_owned()),
            }),
            rules: RuleCountsView {
                require: 3,
                prefer: 2,
                never: 1,
            },
            system_proxy: SystemProxyView {
                http: Some("127.0.0.1:7890".to_owned()),
                https: None,
                socks: Some("127.0.0.1:7891".to_owned()),
            },
        }
    }

    fn responses() -> Vec<Response> {
        vec![
            Response::Ok,
            Response::Rules(vec![RuleView {
                index: 0,
                class: RuleClass::Require,
                kind: RuleKind::Suffix,
                value: RuleValue("example.com".to_owned()),
            }]),
            Response::Status(status_view()),
            Response::Decision(DecisionView {
                decision: DecisionKind::Upstream,
                rule_index: Some(3),
                class: Some(RuleClass::Prefer),
                next_hop: "socks5://192.0.2.10:1080".to_owned(),
            }),
            Response::Doctor(vec![CheckView {
                name: "daemon_reachable".to_owned(),
                ok: true,
                detail: "socket answered".to_owned(),
            }]),
            Response::Event(EventView {
                host: Host("example.com".to_owned()),
                port: Port(443),
                decision: DecisionKind::Never,
                rule_index: None,
                class: None,
                upstream: HealthState::Up,
                connect_ms: Some(4),
                hop: Some(crate::EffectiveHop::Direct),
                duration_ms: 12,
                error: Some("reset by peer".to_owned()),
            }),
            Response::Err {
                kind: ErrKind::UpstreamDown,
                message: "upstream is down".to_owned(),
            },
        ]
    }

    #[test]
    fn every_command_round_trips() {
        for command in commands() {
            let wire = serde_json::to_string(&command).unwrap();
            let back: Command = serde_json::from_str(&wire).unwrap();
            assert_eq!(command, back, "{wire}");
        }
    }

    #[test]
    fn every_response_round_trips() {
        for response in responses() {
            let wire = serde_json::to_string(&response).unwrap();
            let back: Response = serde_json::from_str(&wire).unwrap();
            assert_eq!(response, back, "{wire}");
        }
    }

    #[test]
    fn command_tag_is_snake_case() {
        let wire = serde_json::to_string(&Command::ClearRules {
            load: Some(LoadId(9)),
        })
        .unwrap();
        assert_eq!(wire, r#"{"cmd":"clear_rules","load":9}"#);
    }

    #[test]
    fn response_tag_is_snake_case() {
        let wire = serde_json::to_string(&Response::Ok).unwrap();
        assert_eq!(wire, r#"{"resp":"ok"}"#);
    }

    #[test]
    fn err_kinds_round_trip() {
        let kinds = [
            ErrKind::NotFound,
            ErrKind::UpstreamDown,
            ErrKind::InvalidArgs,
            ErrKind::LoadInProgress,
            ErrKind::Internal,
        ];
        for kind in kinds {
            let wire = serde_json::to_string(&kind).unwrap();
            let back: ErrKind = serde_json::from_str(&wire).unwrap();
            assert_eq!(kind, back, "{wire}");
        }
        assert_eq!(
            serde_json::to_string(&ErrKind::LoadInProgress).unwrap(),
            r#""load_in_progress""#
        );
    }

    #[test]
    fn a_load_id_renders_and_reads_back_as_a_bare_number() {
        assert_eq!(LoadId(7).to_string(), "7");
        assert_eq!("7".parse::<LoadId>().unwrap(), LoadId(7));
        assert_eq!(" 7\n".parse::<LoadId>().unwrap(), LoadId(7));
    }

    #[test]
    fn a_load_id_that_is_not_a_number_is_rejected() {
        let failure = "seven".parse::<LoadId>().unwrap_err();
        assert!(failure.to_string().contains("seven"), "{failure}");
        assert!("-1".parse::<LoadId>().is_err());
        assert!("".parse::<LoadId>().is_err());
    }

    #[test]
    fn unknown_command_variant_is_rejected() {
        let failure = serde_json::from_str::<Command>(r#"{"cmd":"teleport"}"#).unwrap_err();
        assert!(failure.to_string().contains("unknown variant"), "{failure}");
    }

    #[test]
    fn unknown_response_variant_is_rejected() {
        let failure = serde_json::from_str::<Response>(r#"{"resp":"teleport"}"#).unwrap_err();
        assert!(failure.to_string().contains("unknown variant"), "{failure}");
    }

    #[test]
    fn missing_command_tag_is_rejected() {
        let failure = serde_json::from_str::<Command>(r#"{"load":1}"#).unwrap_err();
        assert!(failure.to_string().contains("cmd"), "{failure}");
    }
}
