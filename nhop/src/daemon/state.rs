use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use arc_swap::ArcSwap;
use nhop_ipc::{
    Command, ErrKind, HealthState, LastLoadView, Response, RuleClass, RuleCountsView, RuleView,
    StatusView, SystemProxyView, Timestamp, UpstreamAddr,
};
use tokio::sync::{mpsc, oneshot};

use crate::rules::{RuleId, Ruleset};

/// Address the HTTP front end binds until the init script moves it.
pub const DEFAULT_HTTP_LISTEN: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7890);

/// Address the SOCKS5 front end binds until the init script moves it.
pub const DEFAULT_SOCKS_LISTEN: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7891);

const REQUEST_CAPACITY: usize = 64;

type Request = (Command, oneshot::Sender<Response>);

/// Whether a front end holds the address it is configured to bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindState {
    /// The front end holds the address.
    Bound,
    /// Nothing is listening on the address.
    Unbound,
}

impl BindState {
    fn is_bound(self) -> bool {
        match self {
            Self::Bound => true,
            Self::Unbound => false,
        }
    }
}

/// Ruleset serving traffic, published as one unit and read without locking.
///
/// A connection takes a single snapshot when it is accepted and routes by it for its whole life,
/// so a [`LiveRules::publish`] reaches only connections accepted afterwards.
#[derive(Debug, Clone)]
pub struct LiveRules(Arc<ArcSwap<Ruleset>>);

impl Default for LiveRules {
    fn default() -> Self {
        Self(Arc::new(ArcSwap::from_pointee(Ruleset::default())))
    }
}

impl LiveRules {
    /// Returns the ruleset serving traffic at this instant.
    pub fn snapshot(&self) -> Arc<Ruleset> {
        let Self(live) = self;
        live.load_full()
    }

    /// Swaps in a ruleset for connections accepted from now on.
    pub fn publish(&self, ruleset: Ruleset) {
        let Self(live) = self;
        live.store(Arc::new(ruleset));
    }
}

/// Client end of the task that owns every piece of mutable daemon state.
#[derive(Debug, Clone)]
pub struct StateHandle {
    requests: mpsc::Sender<Request>,
    rules: LiveRules,
}

impl StateHandle {
    /// Returns the publication a connection takes its ruleset snapshot from.
    pub fn rules(&self) -> &LiveRules {
        &self.rules
    }

    /// Sends one command to the state task and waits for its single reply.
    pub async fn call(&self, command: Command) -> Response {
        let (reply, answer) = oneshot::channel();
        let Ok(()) = self.requests.send((command, reply)).await else {
            return state_gone();
        };
        let Ok(response) = answer.await else {
            return state_gone();
        };
        response
    }
}

fn state_gone() -> Response {
    Response::Err {
        kind: ErrKind::Internal,
        message: "the daemon state task is gone".to_owned(),
    }
}

/// Starts the state task and returns the handle every command travels through.
pub fn spawn() -> StateHandle {
    let rules = LiveRules::default();
    let (requests, inbox) = mpsc::channel(REQUEST_CAPACITY);
    tokio::spawn(serve(DaemonState::new(rules.clone()), inbox));
    StateHandle { requests, rules }
}

async fn serve(state: DaemonState, mut inbox: mpsc::Receiver<Request>) {
    while let Some((command, reply)) = inbox.recv().await {
        let response = state.handle(command);
        let _ = reply.send(response);
    }
}

#[derive(Debug)]
struct DaemonState {
    started: Instant,
    rules: LiveRules,
    http_listen: SocketAddr,
    http_bind: BindState,
    socks_listen: SocketAddr,
    socks_bind: BindState,
    upstream: UpstreamAddr,
    health: HealthState,
    health_changed_at: SystemTime,
    init_path: Option<PathBuf>,
    last_load: Option<LastLoadView>,
}

impl DaemonState {
    fn new(rules: LiveRules) -> Self {
        Self {
            started: Instant::now(),
            rules,
            http_listen: DEFAULT_HTTP_LISTEN,
            http_bind: BindState::Unbound,
            socks_listen: DEFAULT_SOCKS_LISTEN,
            socks_bind: BindState::Unbound,
            upstream: UpstreamAddr(String::new()),
            health: HealthState::Down,
            health_changed_at: SystemTime::now(),
            init_path: None,
            last_load: None,
        }
    }

    fn handle(&self, command: Command) -> Response {
        match command {
            Command::Status => Response::Status(self.status()),
            Command::Rules => Response::Rules(self.rule_views()),
            Command::AddRule {
                class: _,
                kind: _,
                value: _,
                load: _,
            }
            | Command::ClearRules { load: _ }
            | Command::SetUpstream { addr: _, load: _ }
            | Command::SetListen {
                http: _,
                socks: _,
                load: _,
            }
            | Command::Reload { path: _ }
            | Command::On
            | Command::Off
            | Command::Test { host: _, port: _ }
            | Command::Doctor
            | Command::Subscribe => Response::Err {
                kind: ErrKind::Internal,
                message: "the daemon does not serve this command yet".to_owned(),
            },
        }
    }

    fn status(&self) -> StatusView {
        let rules = self.rules.snapshot();
        StatusView {
            uptime_secs: self.started.elapsed().as_secs(),
            http_listen: self.http_listen,
            http_bound: self.http_bind.is_bound(),
            socks_listen: self.socks_listen,
            socks_bound: self.socks_bind.is_bound(),
            upstream: self.upstream.clone(),
            health: self.health,
            health_changed_at: Timestamp(self.health_changed_at),
            init_path: self.init_path.clone(),
            last_load: self.last_load.clone(),
            rules: RuleCountsView {
                require: counted(rules.count(RuleClass::Require)),
                prefer: counted(rules.count(RuleClass::Prefer)),
                never: counted(rules.count(RuleClass::Never)),
            },
            system_proxy: SystemProxyView {
                http: None,
                https: None,
                socks: None,
            },
        }
    }

    fn rule_views(&self) -> Vec<RuleView> {
        let rules = self.rules.snapshot();
        let mut views = Vec::with_capacity(rules.rules().len());
        for rule in rules.rules() {
            let RuleId(index) = rule.id();
            views.push(RuleView {
                index: counted(index),
                class: rule.class(),
                kind: rule.kind(),
                value: rule.value().clone(),
            });
        }
        views
    }
}

fn counted(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use nhop_ipc::{DecisionKind, Host, Port, RuleKind, RuleValue};

    use crate::rules::Decision;

    use super::*;

    fn ruleset(rules: &[(RuleClass, RuleKind, &str)]) -> Ruleset {
        let mut ruleset = Ruleset::default();
        for (class, kind, value) in rules {
            ruleset
                .push(*class, *kind, RuleValue((*value).to_owned()))
                .unwrap();
        }
        ruleset
    }

    fn decide(ruleset: &Ruleset, host: &str) -> Decision {
        ruleset.decide(&Host(host.to_owned()), Port(443))
    }

    #[tokio::test]
    async fn status_describes_a_daemon_that_has_loaded_nothing() {
        let state = spawn();

        let Response::Status(status) = state.call(Command::Status).await else {
            panic!("status must answer with a status view");
        };
        let StatusView {
            uptime_secs: _,
            http_listen,
            http_bound,
            socks_listen,
            socks_bound,
            upstream,
            health,
            health_changed_at: _,
            init_path,
            last_load,
            rules,
            system_proxy,
        } = status;
        assert_eq!(http_listen, DEFAULT_HTTP_LISTEN);
        assert_eq!(socks_listen, DEFAULT_SOCKS_LISTEN);
        assert!(!http_bound);
        assert!(!socks_bound);
        assert_eq!(upstream, UpstreamAddr(String::new()));
        assert_eq!(health, HealthState::Down);
        assert_eq!(init_path, None);
        assert_eq!(last_load, None);
        assert_eq!(
            rules,
            RuleCountsView {
                require: 0,
                prefer: 0,
                never: 0,
            }
        );
        assert_eq!(
            system_proxy,
            SystemProxyView {
                http: None,
                https: None,
                socks: None,
            }
        );
    }

    #[tokio::test]
    async fn status_counts_the_live_rules_per_class() {
        let state = spawn();
        state.rules().publish(ruleset(&[
            (RuleClass::Require, RuleKind::Suffix, "example.com"),
            (RuleClass::Prefer, RuleKind::Port, "443"),
            (RuleClass::Prefer, RuleKind::Keyword, "cdn"),
            (RuleClass::Never, RuleKind::Cidr, "192.0.2.0/24"),
        ]));

        let Response::Status(status) = state.call(Command::Status).await else {
            panic!("status must answer with a status view");
        };
        assert_eq!(
            status.rules,
            RuleCountsView {
                require: 1,
                prefer: 2,
                never: 1,
            }
        );
    }

    #[tokio::test]
    async fn rules_lists_the_live_ruleset_in_declaration_order() {
        let state = spawn();
        state.rules().publish(ruleset(&[
            (RuleClass::Require, RuleKind::Suffix, "example.com"),
            (RuleClass::Never, RuleKind::Port, "22"),
        ]));

        let Response::Rules(rules) = state.call(Command::Rules).await else {
            panic!("rules must answer with rule views");
        };
        assert_eq!(
            rules,
            vec![
                RuleView {
                    index: 0,
                    class: RuleClass::Require,
                    kind: RuleKind::Suffix,
                    value: RuleValue("example.com".to_owned()),
                },
                RuleView {
                    index: 1,
                    class: RuleClass::Never,
                    kind: RuleKind::Port,
                    value: RuleValue("22".to_owned()),
                },
            ]
        );
    }

    #[tokio::test]
    async fn a_command_of_a_later_task_reports_an_internal_error() {
        let state = spawn();

        let Response::Err { kind, message } = state.call(Command::Doctor).await else {
            panic!("an unserved command must answer with an error");
        };
        assert_eq!(kind, ErrKind::Internal);
        assert!(message.contains("yet"), "{message}");
    }

    #[tokio::test]
    async fn a_swap_leaves_an_open_connection_on_its_own_snapshot() {
        let live = LiveRules::default();
        let (accepted, open) = oneshot::channel();
        let (resume, wait) = oneshot::channel();
        let connection = tokio::spawn({
            let live = live.clone();
            async move {
                let snapshot = live.snapshot();
                accepted.send(()).unwrap();
                wait.await.unwrap();
                decide(&snapshot, "example.com")
            }
        });

        open.await.unwrap();
        live.publish(ruleset(&[(
            RuleClass::Require,
            RuleKind::Suffix,
            "example.com",
        )]));
        resume.send(()).unwrap();

        assert_eq!(connection.await.unwrap(), Decision::Direct);
        assert_eq!(
            decide(&live.snapshot(), "example.com").kind(),
            DecisionKind::Upstream
        );
    }

    #[test]
    fn bind_state_renders_as_the_wire_boolean() {
        assert!(BindState::Bound.is_bound());
        assert!(!BindState::Unbound.is_bound());
    }
}
