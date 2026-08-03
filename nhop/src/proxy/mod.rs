pub mod http;
pub mod socks5;

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use nhop_ipc::{EventView, HealthState, Host, Port, UpstreamAddr};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::logging;
use crate::rules::{Decision, RuleId, Ruleset};
use crate::upstream::HealthHandle;

/// Addresses the two front ends listen on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listen {
    /// Address the HTTP front end binds.
    pub http: SocketAddr,
    /// Address the SOCKS5 front end binds.
    pub socks: SocketAddr,
}

/// Address published while no init script has named an upstream.
///
/// Port zero cannot be dialled, so a router without an upstream refuses `require` traffic at once
/// instead of waiting out a connect timeout.
pub const NO_UPSTREAM: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

const SOCKS5_SCHEME: &str = "socks5://";

/// Rejection of an upstream address that cannot be dialled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("upstream must be socks5://<ip>:<port>, got {0:?}")]
pub struct InvalidUpstream(String);

/// Upstream proxy, as the operator wrote it and as it is dialled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    written: UpstreamAddr,
    socket: SocketAddr,
}

impl Upstream {
    /// Reads the `socks5://<ip>:<port>` form an init script writes.
    ///
    /// The scheme is optional, and the host must be an IP literal because the upstream is dialled
    /// without a resolver.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidUpstream`] when the address is not an IP literal followed by a port.
    pub fn parse(written: UpstreamAddr) -> Result<Self, InvalidUpstream> {
        let UpstreamAddr(text) = &written;
        let text = text.trim();
        let text = match text.strip_prefix(SOCKS5_SCHEME) {
            Some(rest) => rest,
            None => text,
        };
        let Ok(socket) = text.parse::<SocketAddr>() else {
            return Err(InvalidUpstream(text.to_owned()));
        };
        Ok(Self { written, socket })
    }

    /// Returns the address as the operator wrote it.
    pub fn written(&self) -> &UpstreamAddr {
        &self.written
    }

    /// Returns the address the dialer connects to.
    pub fn socket(&self) -> SocketAddr {
        self.socket
    }
}

/// Sink a front end publishes one event per decision to.
#[derive(Debug, Clone, Default)]
pub enum EventTx {
    /// Nobody is listening, so events are dropped.
    #[default]
    Discarded,
    /// Events are queued, and dropped once the queue is full.
    Queued(mpsc::Sender<EventView>),
}

impl EventTx {
    /// Publishes one decision event without ever waiting for its reader.
    pub fn publish(&self, event: EventView) {
        match self {
            Self::Discarded => {}
            Self::Queued(queue) => {
                let _queued = queue.try_send(event);
            }
        }
    }
}

/// Refusal a `require` rule produces when the upstream it needs is down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamDown {
    addr: SocketAddr,
    rule: RuleId,
}

impl UpstreamDown {
    /// Names the upstream that is down and the rule that demanded it.
    pub fn new(addr: SocketAddr, rule: RuleId) -> Self {
        Self { addr, rule }
    }

    /// Returns the refusal a dial failure carries, absent when it failed for another reason.
    pub fn carried_by(failure: &io::Error) -> Option<&Self> {
        failure.get_ref()?.downcast_ref::<Self>()
    }
}

impl fmt::Display for UpstreamDown {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            addr,
            rule: RuleId(index),
        } = self;
        write!(out, "nhop: upstream {addr} is down (require rule {index})")
    }
}

impl std::error::Error for UpstreamDown {}

impl From<UpstreamDown> for io::Error {
    fn from(down: UpstreamDown) -> Self {
        Self::new(io::ErrorKind::HostUnreachable, down)
    }
}

/// Everything one accepted connection is routed by.
///
/// A front end builds this once, when it accepts, so a load that commits mid-connection cannot
/// move that connection to another next hop.
#[derive(Debug, Clone)]
pub struct ConnCtx {
    /// Ruleset the connection was accepted under.
    pub rules: Arc<Ruleset>,
    /// Verdict on the upstream.
    pub health: HealthHandle,
    /// Address of the SOCKS5 upstream.
    pub upstream: SocketAddr,
    /// Sink the decision is published to.
    pub events: EventTx,
}

/// One connection, from the decision that routed it to the line it leaves in the log.
///
/// The verdict is taken when the decision is made and the duration when the connection ends, so
/// the event reports what the routing actually saw.
#[derive(Debug)]
pub struct Routed {
    host: Host,
    port: Port,
    decision: Decision,
    upstream: HealthState,
    started: Instant,
}

impl Routed {
    /// Records the decision a connection was routed by.
    pub fn begun(ctx: &ConnCtx, host: &Host, port: Port, decision: Decision) -> Self {
        Self {
            host: host.clone(),
            port,
            decision,
            upstream: ctx.health.state(),
            started: Instant::now(),
        }
    }

    /// Emits the single event this connection produces, once it has ended.
    pub fn ended(self, failure: Option<&io::Error>) {
        let Self {
            host,
            port,
            decision,
            upstream,
            started,
        } = self;
        logging::decision(&EventView {
            host,
            port,
            decision: decision.kind(),
            rule_index: matched_index(decision),
            class: decision.class(),
            upstream,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            error: failure.map(io::Error::to_string),
        });
    }
}

fn matched_index(decision: Decision) -> Option<u32> {
    let RuleId(index) = decision.rule()?;
    Some(u32::try_from(index).unwrap_or(u32::MAX))
}

/// Opens the connection a [`Decision`] calls for.
pub trait NextHop: fmt::Debug + Send + Sync + 'static {
    /// Connects to the destination, through the upstream or directly.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] carrying [`UpstreamDown`] when a `require` rule needs an upstream
    /// that is down, and the underlying failure when the dial itself failed.
    ///
    /// [`io::Error`]: std::io::Error
    fn dial<'a>(
        &'a self,
        host: &'a Host,
        port: Port,
        decision: Decision,
    ) -> Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + 'a>>;
}

#[cfg(test)]
mod tests {
    use nhop_ipc::{HealthState, Host, Port};

    use super::*;

    fn upstream(written: &str) -> Result<Upstream, InvalidUpstream> {
        Upstream::parse(UpstreamAddr(written.to_owned()))
    }

    #[test]
    fn an_upstream_keeps_the_written_form_and_the_dialable_one() {
        let parsed = upstream("socks5://192.0.2.10:1080").unwrap();
        assert_eq!(
            parsed.written(),
            &UpstreamAddr("socks5://192.0.2.10:1080".to_owned())
        );
        assert_eq!(parsed.socket(), "192.0.2.10:1080".parse().unwrap());
    }

    #[test]
    fn an_upstream_without_a_scheme_is_accepted() {
        let parsed = upstream("192.0.2.10:1080").unwrap();
        assert_eq!(parsed.socket(), "192.0.2.10:1080".parse().unwrap());
    }

    #[test]
    fn an_upstream_that_is_not_an_address_is_rejected() {
        let failure = upstream("socks5://vm.example.com:1080").unwrap_err();
        assert!(failure.to_string().contains("vm.example.com"), "{failure}");
        assert!(upstream("").is_err());
        assert!(upstream("socks5://192.0.2.10").is_err());
    }

    #[test]
    fn the_refusal_names_the_upstream_and_the_rule() {
        let down = UpstreamDown::new("192.0.2.10:1080".parse().unwrap(), RuleId(3));
        assert_eq!(
            down.to_string(),
            "nhop: upstream 192.0.2.10:1080 is down (require rule 3)"
        );
    }

    #[test]
    fn a_dial_failure_carries_the_refusal_it_was_built_from() {
        let down = UpstreamDown::new("192.0.2.10:1080".parse().unwrap(), RuleId(1));
        let failure = io::Error::from(down.clone());
        assert_eq!(failure.kind(), io::ErrorKind::HostUnreachable);
        assert_eq!(UpstreamDown::carried_by(&failure), Some(&down));
    }

    #[test]
    fn an_ordinary_dial_failure_carries_no_refusal() {
        let failure = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert_eq!(UpstreamDown::carried_by(&failure), None);
    }

    #[test]
    fn a_discarded_event_reaches_nobody() {
        EventTx::default().publish(event());
    }

    #[tokio::test]
    async fn a_queued_event_reaches_its_reader_and_a_full_queue_drops() {
        let (queue, mut events) = mpsc::channel(1);
        let sink = EventTx::Queued(queue);

        sink.publish(event());
        sink.publish(event());

        assert_eq!(events.recv().await, Some(event()));
        assert!(events.try_recv().is_err());
    }

    fn event() -> EventView {
        EventView {
            host: Host("example.com".to_owned()),
            port: Port(443),
            decision: nhop_ipc::DecisionKind::Direct,
            rule_index: None,
            class: None,
            upstream: HealthState::Down,
            duration_ms: 1,
            error: None,
        }
    }
}
