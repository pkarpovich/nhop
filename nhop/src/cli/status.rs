use std::path::PathBuf;

use nhop_ipc::{LastLoadView, RuleCountsView, StatusView, Timestamp, UpstreamAddr};
use serde_json::Value;

use crate::cli::system_proxy::SystemProxy;
use crate::daemon::state::BindState;
use crate::proxy::Listen;
use crate::upstream::Health;

/// Everything `status` reports that the daemon knows without asking macOS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonStatus {
    /// Seconds since the daemon started.
    pub uptime_secs: u64,
    /// Addresses the front ends are configured to bind.
    pub listen: Listen,
    /// Whether the front ends hold those addresses.
    pub bound: BindState,
    /// Upstream as the init script wrote it, empty until one names it.
    pub upstream: UpstreamAddr,
    /// Verdict on the upstream and the instant it settled.
    pub health: Health,
    /// Init script the daemon remembers, absent until one is run.
    pub init_path: Option<PathBuf>,
    /// Result of the most recent run, absent until one finishes.
    pub last_load: Option<LastLoadView>,
    /// Number of live rules per class.
    pub rules: RuleCountsView,
}

/// Renders the status the IPC contract defines.
pub fn status_view(state: &DaemonStatus, proxy: &SystemProxy) -> StatusView {
    let DaemonStatus {
        uptime_secs,
        listen,
        bound,
        upstream,
        health,
        init_path,
        last_load,
        rules,
    } = state;
    let Listen { http, socks } = listen;
    let Health { state, changed_at } = health;
    StatusView {
        uptime_secs: *uptime_secs,
        http_listen: *http,
        http_bound: bound.is_bound(),
        socks_listen: *socks,
        socks_bound: bound.is_bound(),
        upstream: upstream.clone(),
        health: *state,
        health_changed_at: Timestamp(*changed_at),
        init_path: init_path.clone(),
        last_load: last_load.clone(),
        rules: *rules,
        system_proxy: proxy.view(),
    }
}

/// Renders the document `status --json` prints, without asking macOS anything.
pub fn status_json(state: &DaemonStatus, proxy: &SystemProxy) -> Value {
    let Ok(document) = serde_json::to_value(status_view(state, proxy)) else {
        return Value::Null;
    };
    document
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use nhop_ipc::{HealthState, LoadOutcome, SystemProxyView};

    use crate::cli::system_proxy::{ProxyEndpoint, parse};

    use super::*;

    const GOLDEN: &str = include_str!("../../tests/golden/status.json");

    fn settled() -> Timestamp {
        Timestamp(UNIX_EPOCH + Duration::from_secs(1_770_000_000))
    }

    fn loaded() -> DaemonStatus {
        let Timestamp(changed_at) = settled();
        DaemonStatus {
            uptime_secs: 3600,
            listen: Listen {
                http: "127.0.0.1:7890".parse().unwrap(),
                socks: "127.0.0.1:7891".parse().unwrap(),
            },
            bound: BindState::Bound,
            upstream: UpstreamAddr("socks5://192.0.2.10:1080".to_owned()),
            health: Health {
                state: HealthState::Up,
                changed_at,
            },
            init_path: Some(PathBuf::from("/Users/operator/.config/nhop/init")),
            last_load: Some(LastLoadView {
                at: settled(),
                outcome: LoadOutcome::Ok,
                command: None,
            }),
            rules: RuleCountsView {
                require: 2,
                prefer: 3,
                never: 1,
            },
        }
    }

    fn configured() -> SystemProxy {
        SystemProxy {
            http: parse("Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\n"),
            https: parse("Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\n"),
            socks: parse("Enabled: Yes\nServer: 127.0.0.1\nPort: 7891\n"),
        }
    }

    #[test]
    fn a_loaded_status_matches_the_checked_in_document() {
        let rendered =
            serde_json::to_string_pretty(&status_json(&loaded(), &configured())).unwrap();

        assert_eq!(format!("{rendered}\n"), GOLDEN);
    }

    #[test]
    fn the_view_carries_what_the_daemon_and_macos_each_know() {
        let view = status_view(&loaded(), &configured());

        let StatusView {
            uptime_secs,
            http_listen,
            http_bound,
            socks_listen,
            socks_bound,
            upstream,
            health,
            health_changed_at,
            init_path,
            last_load,
            rules,
            system_proxy,
        } = view;
        assert_eq!(uptime_secs, 3600);
        assert_eq!(http_listen, "127.0.0.1:7890".parse().unwrap());
        assert_eq!(socks_listen, "127.0.0.1:7891".parse().unwrap());
        assert!(http_bound);
        assert!(socks_bound);
        assert_eq!(
            upstream,
            UpstreamAddr("socks5://192.0.2.10:1080".to_owned())
        );
        assert_eq!(health, HealthState::Up);
        assert_eq!(health_changed_at, settled());
        assert_eq!(
            init_path,
            Some(PathBuf::from("/Users/operator/.config/nhop/init"))
        );
        assert_eq!(
            last_load,
            Some(LastLoadView {
                at: settled(),
                outcome: LoadOutcome::Ok,
                command: None,
            })
        );
        assert_eq!(
            rules,
            RuleCountsView {
                require: 2,
                prefer: 3,
                never: 1,
            }
        );
        assert_eq!(
            system_proxy,
            SystemProxyView {
                http: Some("127.0.0.1:7890".to_owned()),
                https: Some("127.0.0.1:7890".to_owned()),
                socks: Some("127.0.0.1:7891".to_owned()),
            }
        );
    }

    #[test]
    fn an_unbound_daemon_that_has_loaded_nothing_reports_it() {
        let mut state = loaded();
        state.bound = BindState::Unbound;
        state.init_path = None;
        state.last_load = None;
        state.upstream = UpstreamAddr(String::new());

        let view = status_view(&state, &SystemProxy::default());

        assert!(!view.http_bound);
        assert!(!view.socks_bound);
        assert_eq!(view.init_path, None);
        assert_eq!(view.last_load, None);
        assert_eq!(view.upstream, UpstreamAddr(String::new()));
        assert_eq!(
            view.system_proxy,
            SystemProxyView {
                http: None,
                https: None,
                socks: None,
            }
        );
    }

    #[test]
    fn the_json_document_carries_the_endpoint_macos_reported() {
        let document = status_json(&loaded(), &configured());

        let Some(proxy) = document.get("system_proxy") else {
            panic!("the document must carry the system proxy: {document}");
        };
        assert_eq!(
            proxy.get("socks").and_then(Value::as_str),
            Some("127.0.0.1:7891")
        );
        assert_eq!(
            ProxyEndpoint::new("127.0.0.1", 7891).to_string(),
            "127.0.0.1:7891"
        );
    }
}
