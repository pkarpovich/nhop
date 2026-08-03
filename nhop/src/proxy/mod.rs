pub mod http;
pub mod socks5;

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
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

/// Number of events one subscriber may fall behind by before its events are dropped.
pub const SUBSCRIBER_CAPACITY: usize = 256;

/// One reader of the decision stream, and how many events it has missed.
#[derive(Debug)]
struct Subscriber {
    events: mpsc::Sender<EventView>,
    dropped: u64,
}

/// Whether a subscriber is still listening once an event has been offered to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivery {
    /// The subscriber is still there, whether it took the event or lost it.
    Kept,
    /// The subscriber is gone and is dropped from the fan-out.
    Gone,
}

impl Subscriber {
    fn offer(&mut self, event: &EventView) -> Delivery {
        let offered = match self.dropped {
            0 => event.clone(),
            dropped => reporting(event.clone(), dropped),
        };
        let Err(refused) = self.events.try_send(offered) else {
            self.dropped = 0;
            return Delivery::Kept;
        };
        match refused {
            mpsc::error::TrySendError::Full(_offered) => {
                self.dropped = self.dropped.saturating_add(1);
                Delivery::Kept
            }
            mpsc::error::TrySendError::Closed(_offered) => Delivery::Gone,
        }
    }
}

fn reporting(event: EventView, dropped: u64) -> EventView {
    let EventView {
        host,
        port,
        decision,
        rule_index,
        class,
        upstream,
        duration_ms,
        error,
    } = event;
    let error = match error {
        Some(error) => format!("dropped {dropped}: {error}"),
        None => format!("dropped {dropped}"),
    };
    EventView {
        host,
        port,
        decision,
        rule_index,
        class,
        upstream,
        duration_ms,
        error: Some(error),
    }
}

/// Fan-out a front end publishes one event per decision to.
///
/// Publishing never waits: a subscriber that reads too slowly loses events and is told how many on
/// the next one that reaches it, so one `nhop tail` can never hold up a connection.
#[derive(Debug, Clone, Default)]
pub struct EventTx(Arc<Mutex<Vec<Subscriber>>>);

impl EventTx {
    /// Adds a subscriber and returns the queue its events arrive on.
    ///
    /// Dropping the queue unsubscribes: the subscriber is removed at the next publish.
    pub fn subscribe(&self) -> mpsc::Receiver<EventView> {
        let (events, queue) = mpsc::channel(SUBSCRIBER_CAPACITY);
        let Self(subscribers) = self;
        subscribers
            .lock()
            .unwrap()
            .push(Subscriber { events, dropped: 0 });
        queue
    }

    /// Publishes one decision event without ever waiting for a reader.
    pub fn publish(&self, event: &EventView) {
        let Self(subscribers) = self;
        let mut subscribers = subscribers.lock().unwrap();
        subscribers.retain_mut(|subscriber| match subscriber.offer(event) {
            Delivery::Kept => true,
            Delivery::Gone => false,
        });
    }

    /// Returns how many subscribers the stream is fanned out to.
    pub fn subscribers(&self) -> usize {
        let Self(subscribers) = self;
        let subscribers = subscribers.lock().unwrap();
        subscribers.len()
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
    events: EventTx,
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
            events: ctx.events.clone(),
        }
    }

    /// Emits the single event this connection produces, once it has ended.
    ///
    /// The same event goes to the log and to every subscriber. The fan-out never waits for a
    /// reader: a subscriber that cannot keep up loses events instead. The log line is appended on
    /// this task, after the connection is over, so it delays nothing the client is waiting for.
    pub fn ended(self, failure: Option<&io::Error>) {
        let Self {
            host,
            port,
            decision,
            upstream,
            started,
            events,
        } = self;
        let event = EventView {
            host,
            port,
            decision: decision.kind(),
            rule_index: matched_index(decision),
            class: decision.class(),
            upstream,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            error: failure.map(io::Error::to_string),
        };
        logging::decision(&event);
        events.publish(&event);
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
    fn an_event_published_to_nobody_reaches_nobody() {
        EventTx::default().publish(&event());
    }

    #[tokio::test]
    async fn one_event_reaches_every_subscriber() {
        let events = EventTx::default();
        let mut first = events.subscribe();
        let mut second = events.subscribe();
        assert_eq!(events.subscribers(), 2);

        events.publish(&event());

        assert_eq!(first.recv().await, Some(event()));
        assert_eq!(second.recv().await, Some(event()));
    }

    #[tokio::test]
    async fn a_subscriber_that_hung_up_is_removed_at_the_next_publish() {
        let events = EventTx::default();
        let queue = events.subscribe();
        drop(queue);
        assert_eq!(events.subscribers(), 1);

        events.publish(&event());

        assert_eq!(events.subscribers(), 0);
    }

    #[tokio::test]
    async fn a_connection_never_waits_for_a_subscriber_that_stopped_reading() {
        let events = EventTx::default();
        let mut queue = events.subscribe();
        for _filled in 0..SUBSCRIBER_CAPACITY {
            events.publish(&event());
        }

        let ctx = ConnCtx {
            rules: Arc::new(Ruleset::default()),
            health: HealthHandle::default(),
            upstream: NO_UPSTREAM,
            events: events.clone(),
        };
        let host = Host("api.example.com".to_owned());
        let routed = Routed::begun(&ctx, &host, Port(443), Decision::Direct);
        routed.ended(None);

        assert_eq!(events.subscribers(), 1);
        assert_eq!(drained(&mut queue).len(), SUBSCRIBER_CAPACITY);
        events.publish(&event());
        let reported = queue.try_recv().unwrap();
        assert_eq!(reported.error, Some("dropped 1".to_owned()));

        events.publish(&event());
        assert_eq!(queue.try_recv().unwrap().error, None);
    }

    #[tokio::test]
    async fn a_drop_report_keeps_the_failure_the_event_it_rides_on_carried() {
        let events = EventTx::default();
        let mut queue = events.subscribe();
        for _filled in 0..SUBSCRIBER_CAPACITY + 2 {
            events.publish(&event());
        }
        drained(&mut queue);

        let mut failed = event();
        failed.error = Some("reset by peer".to_owned());
        events.publish(&failed);

        let reported = queue.try_recv().unwrap();
        assert_eq!(reported.error, Some("dropped 2: reset by peer".to_owned()));
    }

    fn drained(queue: &mut mpsc::Receiver<EventView>) -> Vec<EventView> {
        let mut drained = Vec::new();
        for _read in 0..SUBSCRIBER_CAPACITY {
            let Ok(event) = queue.try_recv() else {
                break;
            };
            drained.push(event);
        }
        drained
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
