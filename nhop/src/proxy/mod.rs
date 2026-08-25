//! The two front ends, and the contract both `serve` functions share.
//!
//! Each routes one connection with a [`ConnCtx`] and dials through a [`NextHop`], leaves exactly
//! one log line once a decision is reached, and answers the client before returning a failure -
//! a refused dial included.
pub mod http;
pub mod socks5;

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nhop_ipc::{EventView, HealthState, Host, Port, UpstreamAddr};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::logging;
use crate::rules::{Decision, NormalizedHost, RuleId, Ruleset};
use crate::upstream::HealthHandle;

/// Addresses the two front ends listen on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listen {
    pub http: SocketAddr,
    pub socks: SocketAddr,
}

/// Address published while no init script has named an upstream.
///
/// Port zero cannot be dialled, so `require` traffic is refused at once instead of waiting out a
/// connect timeout.
pub const NO_UPSTREAM: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

const SOCKS5_SCHEME: &str = "socks5://";

const LOCALHOST: &str = "localhost";

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
    /// Reads the `socks5://<ip>:<port>` form an init script writes, scheme optional.
    ///
    /// The host must be an IP literal: the upstream is dialled without a resolver.
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

    pub fn written(&self) -> &UpstreamAddr {
        &self.written
    }

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
    Kept,
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
        connect_ms,
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
        connect_ms,
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

    /// Publishes one decision event.
    pub fn publish(&self, event: &EventView) {
        let Self(subscribers) = self;
        let mut subscribers = subscribers.lock().unwrap();
        subscribers.retain_mut(|subscriber| match subscriber.offer(event) {
            Delivery::Kept => true,
            Delivery::Gone => false,
        });
    }

    pub fn subscribers(&self) -> usize {
        let Self(subscribers) = self;
        let subscribers = subscribers.lock().unwrap();
        subscribers.len()
    }
}

/// Answers whether a destination is the address the connection was accepted on.
///
/// [RFC 9110 §7.6.3] requires a proxy that detects a forwarding loop to answer with an error, and
/// its `Via` mechanism cannot serve a tunnelling front end: `CONNECT` relays opaque bytes and
/// SOCKS5 carries no headers at all, so a loop is visible only as an address. `listening` is the
/// accepted socket's local address, which under a wildcard bind is the concrete interface the
/// client reached rather than the wildcard the listener would report.
///
/// The port is compared first because it is two integers on every accepted connection; the host is
/// looked at only when the ports match, which is rare.
///
/// Names are not resolved, deliberately: a lookup per connection costs more than the case is
/// worth, so short forms such as `127.1` - which only `getaddrinfo` expands - are not caught.
///
/// [RFC 9110 §7.6.3]: https://httpwg.org/specs/rfc9110.html#field.via
fn dials_itself(destination: &Host, port: Port, listening: SocketAddr) -> bool {
    let Port(port) = port;
    if port != listening.port() {
        return false;
    }
    let listening = canonical(listening.ip());
    let destination = NormalizedHost::new(destination);
    let Some(address) = destination.address() else {
        return destination.as_str() == LOCALHOST && listening.is_loopback();
    };
    let address = canonical(address);
    address.is_unspecified() || address == listening
}

/// Whether the destination is the address this connection was accepted on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Loop {
    /// The destination is this front end itself, reached on that address.
    Own(SocketAddr),
    /// The destination is somewhere else, or the accepted socket could not name itself.
    Elsewhere,
}

/// Reads the address the client reached and answers whether the destination is that same address.
///
/// A socket that cannot name itself is treated as no loop: refusing traffic because a socket call
/// failed would be worse than the loop the check guards against.
fn own_address(client: &TcpStream, host: &Host, port: Port) -> Loop {
    let Ok(listening) = client.local_addr() else {
        return Loop::Elsewhere;
    };
    if dials_itself(host, port, listening) {
        return Loop::Own(listening);
    }
    Loop::Elsewhere
}

/// Folds an IPv4-mapped IPv6 address back to v4, so `::ffff:127.0.0.1` and `127.0.0.1` compare equal.
fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(address) => IpAddr::V4(address),
        IpAddr::V6(address) => match address.to_ipv4_mapped() {
            Some(address) => IpAddr::V4(address),
            None => IpAddr::V6(address),
        },
    }
}

/// Refusal a front end produces when it is asked to dial the address it accepted the connection on.
///
/// The address is the accepted socket's local address, so the text names the interface the client
/// actually reached rather than whatever the listener was bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialsItself {
    listening: SocketAddr,
}

impl DialsItself {
    pub fn new(listening: SocketAddr) -> Self {
        Self { listening }
    }
}

impl fmt::Display for DialsItself {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { listening } = self;
        write!(
            out,
            "nhop: refusing to dial my own listening address {listening}"
        )
    }
}

impl std::error::Error for DialsItself {}

impl From<DialsItself> for io::Error {
    fn from(refused: DialsItself) -> Self {
        Self::new(io::ErrorKind::PermissionDenied, refused)
    }
}

/// Refusal a `require` rule produces when the upstream it needs is down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamDown {
    addr: SocketAddr,
    rule: RuleId,
}

impl UpstreamDown {
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
    pub rules: Arc<Ruleset>,
    pub health: HealthHandle,
    pub upstream: SocketAddr,
    pub events: EventTx,
}

/// What the dial phase of one connection cost.
///
/// The two variants are what separates a slow dial from a long-lived connection in the log, which
/// [`EventView::duration_ms`] alone cannot say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connect {
    /// No dial was made, so there is no dial time: the decision refused before the network.
    Refused,
    /// A dial was made and took this long, whether or not it produced a connection.
    Attempted(Duration),
}

/// One connection, from the decision that routed it to the line it leaves in the log.
///
/// The verdict is taken at the decision and the duration at the end, so the event reports what
/// the routing saw.
#[derive(Debug)]
pub struct Routed {
    host: Host,
    port: Port,
    decision: Decision,
    upstream: HealthState,
    connect: Option<Duration>,
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
            connect: None,
            started: Instant::now(),
            events: ctx.events.clone(),
        }
    }

    /// Records what the dial phase cost, once the front end has been through it.
    pub fn dialled(&mut self, connect: Connect) {
        self.connect = match connect {
            Connect::Refused => None,
            Connect::Attempted(took) => Some(took),
        };
    }

    /// Emits the single event this connection produces, once it has ended.
    ///
    /// The log line is appended on this task, after the connection is over, so it delays nothing
    /// the client is waiting for.
    pub fn ended(self, failure: Option<&io::Error>) {
        let Self {
            host,
            port,
            decision,
            upstream,
            connect,
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
            connect_ms: connect.map(millis),
            duration_ms: millis(started.elapsed()),
            error: failure.map(io::Error::to_string),
        };
        logging::decision(&event);
        events.publish(&event);
    }
}

fn millis(took: Duration) -> u64 {
    u64::try_from(took.as_millis()).unwrap_or(u64::MAX)
}

fn matched_index(decision: Decision) -> Option<u32> {
    let RuleId(index) = decision.rule()?;
    Some(u32::try_from(index).unwrap_or(u32::MAX))
}

/// What one dial did, and the connection it produced if it produced one.
///
/// Only the dial site knows whether the network was touched: [`UpstreamHop`] answers a `require`
/// rule with the same [`UpstreamDown`] surface whether it refused before dialling or dialled and
/// failed, and timing cannot tell them apart either, since a refusal and an instant failure both
/// take about no time. So the distinction is carried out of the dial rather than inferred after it.
///
/// [`UpstreamHop`]: crate::upstream::UpstreamHop
#[derive(Debug)]
pub enum Dialled {
    /// Nothing was dialled: a `require` rule whose upstream is down is refused before the network.
    Refused(io::Error),
    /// A dial was made over the network, whether or not it produced a connection.
    Attempted(io::Result<TcpStream>),
}

impl Dialled {
    /// Splits the outcome into what the dial phase cost and the connection it produced.
    ///
    /// The elapsed time belongs to the caller, which is the only side that can measure the await;
    /// it is kept only when a dial was actually made.
    pub fn timed(self, took: Duration) -> (Connect, io::Result<TcpStream>) {
        match self {
            Self::Refused(failure) => (Connect::Refused, Err(failure)),
            Self::Attempted(next) => (Connect::Attempted(took), next),
        }
    }
}

/// Opens the connection a [`Decision`] calls for.
pub trait NextHop: fmt::Debug + Send + Sync + 'static {
    /// Connects to the destination, through the upstream or directly.
    ///
    /// A [`Dialled::Refused`] carries an [`io::Error`] holding [`UpstreamDown`] when a `require`
    /// rule needs an upstream that is down; a [`Dialled::Attempted`] carries the connection, or the
    /// underlying failure when the dial itself failed.
    ///
    /// [`io::Error`]: std::io::Error
    fn dial<'a>(
        &'a self,
        host: &'a Host,
        port: Port,
        decision: Decision,
    ) -> Pin<Box<dyn Future<Output = Dialled> + Send + 'a>>;
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

    fn loops(destination: &str, port: u16, listening: &str) -> bool {
        dials_itself(
            &Host(destination.to_owned()),
            Port(port),
            listening.parse().unwrap(),
        )
    }

    #[test]
    fn a_front_end_asked_for_its_own_address_sees_a_loop() {
        assert!(loops("127.0.0.1", 7890, "127.0.0.1:7890"));
        assert!(loops("localhost", 7890, "127.0.0.1:7890"));
    }

    #[test]
    fn an_ipv4_mapped_destination_is_the_address_it_maps_to() {
        assert!(loops("::ffff:127.0.0.1", 7890, "127.0.0.1:7890"));
        assert!(loops("::1", 7890, "[::1]:7890"));
        assert!(loops("127.0.0.1", 7890, "[::ffff:127.0.0.1]:7890"));
        assert!(loops("localhost", 7890, "[::ffff:127.0.0.1]:7890"));
        assert!(!loops("localhost", 7890, "[::ffff:192.168.1.5]:7890"));
    }

    #[test]
    fn an_unspecified_destination_lands_on_a_local_address_so_it_is_a_loop() {
        assert!(loops("0.0.0.0", 7890, "127.0.0.1:7890"));
        assert!(loops("::", 7890, "127.0.0.1:7890"));
        assert!(loops("0.0.0.0", 7890, "192.168.1.5:7890"));
    }

    #[test]
    fn a_name_written_as_the_host_would_write_it_still_matches() {
        assert!(loops("LocalHost", 7890, "127.0.0.1:7890"));
        assert!(loops("localhost.", 7890, "127.0.0.1:7890"));
        assert!(loops("LOCALHOST.", 7890, "127.0.0.1:7890"));
    }

    #[test]
    fn another_address_on_the_same_port_is_not_a_loop() {
        assert!(!loops("127.0.0.2", 7890, "127.0.0.1:7890"));
        assert!(!loops("192.0.2.10", 7890, "127.0.0.1:7890"));
    }

    #[test]
    fn a_front_end_off_the_loopback_refuses_its_own_address_and_not_the_name() {
        assert!(loops("192.168.1.5", 7890, "192.168.1.5:7890"));
        assert!(!loops("localhost", 7890, "192.168.1.5:7890"));
        assert!(!loops("127.0.0.1", 7890, "192.168.1.5:7890"));
    }

    #[test]
    fn the_same_host_on_another_port_is_not_a_loop() {
        assert!(!loops("127.0.0.1", 19998, "127.0.0.1:7890"));
        assert!(!loops("localhost", 19998, "127.0.0.1:7890"));
        assert!(!loops("127.0.0.1", 7891, "127.0.0.1:7890"));
    }

    #[test]
    fn a_short_form_is_not_caught_because_names_are_not_resolved() {
        assert!(!loops("127.1", 7890, "127.0.0.1:7890"));
        assert!(!loops("localhost.localdomain", 7890, "127.0.0.1:7890"));
    }

    #[test]
    fn the_loop_refusal_names_the_address_it_was_reached_on() {
        let refused = DialsItself::new("127.0.0.1:7890".parse().unwrap());
        assert_eq!(
            refused.to_string(),
            "nhop: refusing to dial my own listening address 127.0.0.1:7890"
        );
        let failure = io::Error::from(refused);
        assert_eq!(failure.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            failure.to_string(),
            "nhop: refusing to dial my own listening address 127.0.0.1:7890"
        );
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
            connect_ms: Some(0),
            duration_ms: 1,
            error: None,
        }
    }

    #[tokio::test]
    async fn a_dial_that_was_made_reports_its_time_and_a_refusal_reports_none() {
        let events = EventTx::default();
        let mut queue = events.subscribe();
        let ctx = ConnCtx {
            rules: Arc::new(Ruleset::default()),
            health: HealthHandle::default(),
            upstream: NO_UPSTREAM,
            events: events.clone(),
        };
        let host = Host("api.example.com".to_owned());

        let mut attempted = Routed::begun(&ctx, &host, Port(443), Decision::Direct);
        attempted.dialled(Connect::Attempted(Duration::from_millis(41)));
        attempted.ended(None);
        let mut refused = Routed::begun(&ctx, &host, Port(443), Decision::Direct);
        refused.dialled(Connect::Refused);
        refused.ended(None);

        assert_eq!(queue.try_recv().unwrap().connect_ms, Some(41));
        assert_eq!(queue.try_recv().unwrap().connect_ms, None);
    }
}
