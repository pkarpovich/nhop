mod health;

pub use health::{Health, HealthHandle};

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use nhop_ipc::{HealthState, Host, Port, RuleClass};
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_socks::tcp::Socks5Stream;

use crate::daemon::state::LiveUpstream;
use crate::proxy::{NO_UPSTREAM, NextHop, UpstreamDown};
use crate::rules::{Decision, RuleId};

/// How long a dial through the upstream may take before it counts as a failure.
pub const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// How long the patrol waits between probes, in either verdict state.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(5);

/// How long one probe may take before it counts as a failure.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// How long the patrol waits before the probe that has to confirm a contradicting one.
pub const PROBE_CONFIRM_DELAY: Duration = Duration::from_secs(1);

/// How long the patrol waits before looking again for an address worth probing.
///
/// The daemon binds the front ends - and so spawns the hop - before any init script runs, so the
/// snapshot is [`NO_UPSTREAM`] until the first load publishes the configured address. Sleeping a
/// whole interval on that snapshot would make cold start slower than it is today; a short tick
/// means the published address is probed as soon as it appears.
const NO_UPSTREAM_TICK: Duration = Duration::from_millis(250);

/// How long a relay socket may sit idle before the first keepalive probe goes out.
pub const KEEPALIVE_IDLE: Duration = Duration::from_secs(15);

/// How long the relay socket waits between keepalive probes once it has started sending them.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// How many unanswered keepalive probes end a relay socket.
pub const KEEPALIVE_RETRIES: u32 = 4;

/// Next hop that sends `require` and `prefer` traffic through the SOCKS5 upstream.
///
/// While the verdict is [`HealthState::Down`] nothing is dialled through the upstream: `prefer`
/// goes direct at once and `require` fails at once, so a powered-off upstream costs a decision
/// rather than a connect timeout per connection.
#[derive(Debug)]
pub struct UpstreamHop {
    upstream: LiveUpstream,
    health: HealthHandle,
    patrolling: JoinHandle<()>,
}

impl Drop for UpstreamHop {
    fn drop(&mut self) {
        let Self {
            upstream: _,
            health: _,
            patrolling,
        } = self;
        patrolling.abort();
    }
}

impl UpstreamHop {
    /// Starts dialling through the published upstream, patrolling it in both verdict states.
    ///
    /// The interval and the confirm delay are parameters so tests do not wait out
    /// [`PROBE_INTERVAL`] and [`PROBE_CONFIRM_DELAY`].
    pub fn start(
        upstream: LiveUpstream,
        health: HealthHandle,
        interval: Duration,
        confirm_delay: Duration,
    ) -> Self {
        let patrolling = tokio::spawn(patrol(
            upstream.clone(),
            health.clone(),
            interval,
            confirm_delay,
        ));
        Self {
            upstream,
            health,
            patrolling,
        }
    }

    /// Returns the verdict the dialer routes by.
    pub fn health(&self) -> &HealthHandle {
        &self.health
    }

    async fn routed(
        &self,
        host: &Host,
        port: Port,
        class: RuleClass,
        rule: RuleId,
    ) -> io::Result<TcpStream> {
        let upstream = self.upstream.snapshot();
        match class {
            RuleClass::Never => direct(host, port).await,
            RuleClass::Require => self.required(host, port, rule, upstream).await,
            RuleClass::Prefer => self.preferred(host, port, upstream).await,
        }
    }

    async fn required(
        &self,
        host: &Host,
        port: Port,
        rule: RuleId,
        upstream: SocketAddr,
    ) -> io::Result<TcpStream> {
        match self.health.state() {
            HealthState::Down => Err(UpstreamDown::new(upstream, rule).into()),
            HealthState::Up => match through(host, port, upstream).await {
                Ok(next) => Ok(next),
                Err(DialFailure::Destination(failure)) => Err(failure),
                Err(DialFailure::Upstream(_failure)) => {
                    self.health.set(HealthState::Down);
                    Err(UpstreamDown::new(upstream, rule).into())
                }
            },
        }
    }

    async fn preferred(
        &self,
        host: &Host,
        port: Port,
        upstream: SocketAddr,
    ) -> io::Result<TcpStream> {
        match self.health.state() {
            HealthState::Down => direct(host, port).await,
            HealthState::Up => match through(host, port, upstream).await {
                Ok(next) => Ok(next),
                Err(DialFailure::Destination(_failure)) => direct(host, port).await,
                Err(DialFailure::Upstream(_failure)) => {
                    self.health.set(HealthState::Down);
                    direct(host, port).await
                }
            },
        }
    }
}

/// Why one dial through the upstream did not produce a connection.
#[derive(Debug)]
enum DialFailure {
    /// The upstream itself could not carry the connection, so the verdict flips down.
    Upstream(io::Error),
    /// The upstream answered about the destination, which says nothing about its own health.
    Destination(io::Error),
}

impl NextHop for UpstreamHop {
    fn dial<'a>(
        &'a self,
        host: &'a Host,
        port: Port,
        decision: Decision,
    ) -> Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + 'a>> {
        Box::pin(async move {
            match decision {
                Decision::Direct => direct(host, port).await,
                Decision::Never { rule: _ } => direct(host, port).await,
                Decision::Upstream { class, rule } => self.routed(host, port, class, rule).await,
            }
        })
    }
}

/// Arms TCP keepalive on an outbound relay socket.
///
/// The two dial sites buy different things from it, and neither is the whole story.
///
/// A socket from [`direct`] crosses the home NAT, which drops the mapping for an idle established
/// connection far below RFC 5382 REQ-5's 2h4m minimum, so a tunnel nothing is written on simply
/// dies and the next read costs a client-visible hang. The probes keep the mapping alive. Idle and
/// interval are 15s because that is Go's dialer default, proven on this network for years, and it
/// sits well inside the band RFC 6202 §5.5 calls safe - Chrome's own 45s sits in the same band.
///
/// A socket from [`through`] terminates on the LAN at the upstream and so refreshes no NAT mapping
/// at all; the onward hop belongs to the upstream. What it buys there is bounded dead-peer
/// detection: a powered-off upstream surfaces within `KEEPALIVE_IDLE + KEEPALIVE_RETRIES *
/// KEEPALIVE_INTERVAL` instead of parking an fd until the kernel gives up.
///
/// The client half of a relay gets nothing, because loopback cannot die silently.
fn keep_alive(stream: &TcpStream) -> io::Result<()> {
    let socket = SockRef::from(stream);
    socket.set_keepalive(true)?;
    socket.set_tcp_keepalive(
        &TcpKeepalive::new()
            .with_time(KEEPALIVE_IDLE)
            .with_interval(KEEPALIVE_INTERVAL)
            .with_retries(KEEPALIVE_RETRIES),
    )
}

async fn direct(host: &Host, port: Port) -> io::Result<TcpStream> {
    let Host(host) = host;
    let Port(port) = port;
    let dialled = TcpStream::connect((host.as_str(), port)).await?;
    if let Err(failure) = keep_alive(&dialled) {
        tracing::warn!(keepalive_error = %failure, "a direct relay socket carries no tcp keepalive");
    }
    Ok(dialled)
}

async fn through(host: &Host, port: Port, upstream: SocketAddr) -> Result<TcpStream, DialFailure> {
    let Host(host) = host;
    let Port(port) = port;
    let dialling = Socks5Stream::connect(upstream, (host.as_str(), port));
    let Ok(dialled) = tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, dialling).await else {
        return Err(DialFailure::Upstream(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "the upstream {upstream} did not answer within {}s",
                UPSTREAM_CONNECT_TIMEOUT.as_secs()
            ),
        )));
    };
    let dialled = match dialled {
        Ok(dialled) => dialled,
        Err(failure) => return Err(failed_dial(failure)),
    };
    let dialled = dialled.into_inner();
    if let Err(failure) = keep_alive(&dialled) {
        tracing::warn!(keepalive_error = %failure, "an upstream relay socket carries no tcp keepalive");
    }
    Ok(dialled)
}

/// Splits a dial failure by whether the upstream answered at all.
///
/// Any SOCKS5 reply proves the upstream is alive, however it judged the destination, so a refusal
/// it sent belongs to the destination. Only a failure to obtain a well-formed reply means the
/// upstream itself is gone.
///
/// `UnknownAuthMethod` sits on the answered side despite its name: tokio-socks raises it both for
/// an auth method it cannot use and, on the reply path, for any status byte outside the 0x00..=0x08
/// the RFC assigns. Real proxies do emit those - 3proxy answers 0x09 to a CONNECT aimed at its own
/// listening address, which is exactly what the health probe asks for.
fn failed_dial(failure: tokio_socks::Error) -> DialFailure {
    match failure {
        tokio_socks::Error::GeneralSocksServerFailure
        | tokio_socks::Error::ConnectionNotAllowedByRuleset
        | tokio_socks::Error::NetworkUnreachable
        | tokio_socks::Error::HostUnreachable
        | tokio_socks::Error::ConnectionRefused
        | tokio_socks::Error::TtlExpired
        | tokio_socks::Error::AddressTypeNotSupported
        | tokio_socks::Error::CommandNotSupported
        | tokio_socks::Error::UnknownAuthMethod
        | tokio_socks::Error::InvalidTargetAddress(_) => {
            DialFailure::Destination(io::Error::other(failure))
        }
        tokio_socks::Error::Io(_)
        | tokio_socks::Error::ParseError(_)
        | tokio_socks::Error::ProxyServerUnreachable
        | tokio_socks::Error::InvalidResponseVersion
        | tokio_socks::Error::NoAcceptableAuthMethods
        | tokio_socks::Error::UnknownError
        | tokio_socks::Error::InvalidReservedByte
        | tokio_socks::Error::UnknownAddressType
        | tokio_socks::Error::InvalidAuthValues(_)
        | tokio_socks::Error::PasswordAuthFailure(_)
        | tokio_socks::Error::AuthorizationRequired
        | tokio_socks::Error::IdentdAuthFailure
        | tokio_socks::Error::InvalidUserIdAuthFailure => {
            DialFailure::Upstream(io::Error::other(failure))
        }
    }
}

/// One contradicting observation waiting for a second one to agree with it.
///
/// Both ends of the sequence are recorded. The `target` is what the sequence is trying to reach,
/// and anchoring on it rather than on "contradicts whatever the verdict is right now" is
/// load-bearing: a contradiction banked against [`HealthState::Up`], a dial failure flipping the
/// verdict down underneath it, and then a *successful* confirming probe would otherwise read as a
/// second contradiction and declare the upstream alive on one good probe. The `baseline` is the
/// verdict the sequence started from, so a verdict that moved by any other path - a real dial
/// failure, an operator command - retires the sequence instead of counting towards it.
#[derive(Debug, Clone, Copy)]
struct Pending {
    target: HealthState,
    baseline: HealthState,
}

/// Probes the upstream in both verdict states, moving the verdict only on two probes that agree.
///
/// The first probe goes out immediately, so a daemon that starts against a live upstream does not
/// hand the discovery to the first user dial, and a dead one is found by the patrol rather than by
/// a connection somebody is waiting on.
///
/// A single observation never moves the verdict: one 2s [`PROBE_TIMEOUT`] miss against a
/// momentarily loaded upstream must not hard-refuse `require` traffic, and one stray answer while
/// the upstream boots must not declare it alive. A verdict change therefore costs
/// `interval + confirm_delay` plus up to one [`PROBE_TIMEOUT`] per observation, which is the
/// difference between a peer that refuses fast and one that black-holes.
///
/// A real dial failure still flips down on one failure, in [`UpstreamHop`]: that path is evidence
/// a user already paid for, while a self-generated timeout is not.
async fn patrol(
    upstream: LiveUpstream,
    health: HealthHandle,
    interval: Duration,
    confirm_delay: Duration,
) {
    let mut pending = None;
    loop {
        let addr = upstream.snapshot();
        if addr == NO_UPSTREAM {
            tokio::time::sleep(NO_UPSTREAM_TICK.min(interval)).await;
            continue;
        }
        pending = advance(pending, probe(addr).await, &health);
        let waited = match pending {
            Some(_sequence) => confirm_delay,
            None => interval,
        };
        tokio::time::sleep(waited).await;
    }
}

/// Folds one observation into the pending sequence, moving the verdict when the sequence closes.
///
/// An observation agreeing with the live verdict discards whatever was pending, since the verdict
/// it contradicted is the one in force again.
fn advance(pending: Option<Pending>, seen: HealthState, health: &HealthHandle) -> Option<Pending> {
    let settled = health.state();
    match (settled, seen) {
        (HealthState::Up, HealthState::Up) | (HealthState::Down, HealthState::Down) => return None,
        (HealthState::Up, HealthState::Down) | (HealthState::Down, HealthState::Up) => {}
    }
    let confirms = match pending {
        None => false,
        Some(Pending { target, baseline }) => target == seen && baseline == settled,
    };
    if confirms {
        health.set(seen);
        return None;
    }
    Some(Pending {
        target: seen,
        baseline: settled,
    })
}

/// Asks the upstream to carry a connection to its own address, and reads the answer as a verdict.
///
/// A reply about the destination counts as serving, and the probe is the only transition up: an
/// upstream that refuses its own address - an `ssh -D` tunnel with nothing on that port, a ruleset
/// denying loopback destinations - would otherwise never leave [`HealthState::Down`].
async fn probe(upstream: SocketAddr) -> HealthState {
    let handshake = Socks5Stream::connect(upstream, upstream);
    let Ok(reached) = tokio::time::timeout(PROBE_TIMEOUT, handshake).await else {
        return HealthState::Down;
    };
    let failure = match reached {
        Ok(_reached) => return HealthState::Up,
        Err(failure) => failed_dial(failure),
    };
    match failure {
        DialFailure::Destination(_answered) => HealthState::Up,
        DialFailure::Upstream(_failure) => HealthState::Down,
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    const PATIENT: Duration = Duration::from_secs(60);
    const NO_AUTH: [u8; 2] = [0x05, 0x00];
    const GRANTED: [u8; 10] = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    const REFUSED: [u8; 10] = [0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    const GENERAL_FAILURE: [u8; 10] = [0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    const OFF_RFC: [u8; 10] = [0x05, 0x09, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

    fn hop(upstream: SocketAddr, state: HealthState, interval: Duration) -> UpstreamHop {
        let published = LiveUpstream::default();
        published.publish(upstream);
        let health = HealthHandle::default();
        health.set(state);
        UpstreamHop::start(published, health, interval, PATIENT)
    }

    fn upstream_decision(class: RuleClass, rule: usize) -> Decision {
        Decision::Upstream {
            class,
            rule: RuleId(rule),
        }
    }

    async fn destination() -> (TcpListener, Host, Port) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, Host(addr.ip().to_string()), Port(addr.port()))
    }

    async fn closed_port() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    }

    async fn upstream_answering(reply: [u8; 10]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _peer)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut greeting = [0u8; 2];
                    let Ok(_read) = stream.read_exact(&mut greeting).await else {
                        return;
                    };
                    let [_version, methods] = greeting;
                    let mut offered = vec![0u8; usize::from(methods)];
                    let Ok(_read) = stream.read_exact(&mut offered).await else {
                        return;
                    };
                    let Ok(()) = stream.write_all(&NO_AUTH).await else {
                        return;
                    };
                    let mut request = [0u8; 4];
                    let Ok(_read) = stream.read_exact(&mut request).await else {
                        return;
                    };
                    let _answered = stream.write_all(&reply).await;
                });
            }
        });
        addr
    }

    fn armed_keepalive(stream: &TcpStream) {
        let socket = SockRef::from(stream);
        assert!(
            socket.keepalive().unwrap(),
            "a relay socket must carry SO_KEEPALIVE"
        );
        assert_eq!(socket.tcp_keepalive_time().unwrap(), KEEPALIVE_IDLE);
        assert_eq!(socket.tcp_keepalive_interval().unwrap(), KEEPALIVE_INTERVAL);
        assert_eq!(socket.tcp_keepalive_retries().unwrap(), KEEPALIVE_RETRIES);
    }

    #[tokio::test]
    async fn a_direct_socket_carries_keepalive() {
        let (_listener, host, port) = destination().await;

        let dialled = direct(&host, port).await.unwrap();

        armed_keepalive(&dialled);
    }

    #[tokio::test]
    async fn an_upstream_socket_carries_keepalive_through_into_inner() {
        let (_listener, host, port) = destination().await;
        let upstream = upstream_answering(GRANTED).await;

        let dialled = through(&host, port, upstream).await.unwrap();

        armed_keepalive(&dialled);
    }

    #[tokio::test]
    async fn a_direct_decision_reaches_the_destination_itself() {
        let (listener, host, port) = destination().await;
        let hop = hop(closed_port().await, HealthState::Down, PATIENT);

        let dialled = hop.dial(&host, port, Decision::Direct).await.unwrap();

        assert_eq!(dialled.peer_addr().unwrap(), listener.local_addr().unwrap());
    }

    #[tokio::test]
    async fn a_never_decision_reaches_the_destination_itself() {
        let (listener, host, port) = destination().await;
        let hop = hop(closed_port().await, HealthState::Up, PATIENT);

        let dialled = hop
            .dial(&host, port, Decision::Never { rule: RuleId(2) })
            .await
            .unwrap();

        assert_eq!(dialled.peer_addr().unwrap(), listener.local_addr().unwrap());
        assert_eq!(hop.health().state(), HealthState::Up);
    }

    #[tokio::test]
    async fn a_never_class_reaching_the_upstream_arm_still_dials_directly() {
        let (listener, host, port) = destination().await;
        let hop = hop(closed_port().await, HealthState::Up, PATIENT);

        let dialled = hop
            .dial(&host, port, upstream_decision(RuleClass::Never, 0))
            .await
            .unwrap();

        assert_eq!(dialled.peer_addr().unwrap(), listener.local_addr().unwrap());
    }

    #[tokio::test]
    async fn a_require_decision_fails_at_once_while_the_verdict_is_down() {
        let (_listener, host, port) = destination().await;
        let upstream = closed_port().await;
        let hop = hop(upstream, HealthState::Down, PATIENT);

        let failure = hop
            .dial(&host, port, upstream_decision(RuleClass::Require, 4))
            .await
            .unwrap_err();

        let Some(down) = UpstreamDown::carried_by(&failure) else {
            panic!("a require rule must be refused with the upstream-down surface: {failure}");
        };
        assert_eq!(
            down.to_string(),
            format!("nhop: upstream {upstream} is down (require rule 4)")
        );
    }

    #[tokio::test]
    async fn a_prefer_decision_goes_direct_at_once_while_the_verdict_is_down() {
        let (listener, host, port) = destination().await;
        let hop = hop(closed_port().await, HealthState::Down, PATIENT);

        let dialled = hop
            .dial(&host, port, upstream_decision(RuleClass::Prefer, 0))
            .await
            .unwrap();

        assert_eq!(dialled.peer_addr().unwrap(), listener.local_addr().unwrap());
        assert_eq!(hop.health().state(), HealthState::Down);
    }

    #[tokio::test]
    async fn an_upstream_that_cannot_be_reached_flips_the_verdict_down() {
        let (_listener, host, port) = destination().await;
        let hop = hop(closed_port().await, HealthState::Up, PATIENT);

        let failure = hop
            .dial(&host, port, upstream_decision(RuleClass::Require, 3))
            .await
            .unwrap_err();

        let Some(_down) = UpstreamDown::carried_by(&failure) else {
            panic!("an unreachable upstream must be reported as down: {failure}");
        };
        assert_eq!(hop.health().state(), HealthState::Down);
    }

    #[tokio::test]
    async fn a_destination_the_upstream_refuses_leaves_the_verdict_up() {
        let (_listener, host, port) = destination().await;
        let hop = hop(upstream_answering(REFUSED).await, HealthState::Up, PATIENT);

        let failure = hop
            .dial(&host, port, upstream_decision(RuleClass::Require, 1))
            .await
            .unwrap_err();

        assert!(
            UpstreamDown::carried_by(&failure).is_none(),
            "a refused destination is not the upstream being down: {failure}"
        );
        assert_eq!(hop.health().state(), HealthState::Up);
    }

    #[tokio::test]
    async fn a_prefer_rule_goes_direct_when_the_upstream_refuses_the_destination() {
        let (listener, host, port) = destination().await;
        let hop = hop(upstream_answering(REFUSED).await, HealthState::Up, PATIENT);

        let dialled = hop
            .dial(&host, port, upstream_decision(RuleClass::Prefer, 0))
            .await
            .unwrap();

        assert_eq!(dialled.peer_addr().unwrap(), listener.local_addr().unwrap());
        assert_eq!(hop.health().state(), HealthState::Up);
    }

    #[tokio::test]
    async fn a_probe_against_a_closed_port_leaves_the_verdict_down() {
        assert_eq!(probe(closed_port().await).await, HealthState::Down);
    }

    #[tokio::test]
    async fn a_probe_the_upstream_refuses_still_flips_the_verdict_up() {
        let upstream = upstream_answering(REFUSED).await;

        assert_eq!(probe(upstream).await, HealthState::Up);
    }

    #[tokio::test]
    async fn a_probe_answered_off_the_rfc_still_flips_the_verdict_up() {
        let upstream = upstream_answering(OFF_RFC).await;

        assert_eq!(probe(upstream).await, HealthState::Up);
    }

    #[tokio::test]
    async fn a_reply_off_the_rfc_leaves_the_verdict_up() {
        let (_listener, host, port) = destination().await;
        let hop = hop(upstream_answering(OFF_RFC).await, HealthState::Up, PATIENT);

        let failure = hop
            .dial(&host, port, upstream_decision(RuleClass::Require, 1))
            .await
            .unwrap_err();

        assert!(
            UpstreamDown::carried_by(&failure).is_none(),
            "an upstream that answered at all is still serving: {failure}"
        );
        assert_eq!(hop.health().state(), HealthState::Up);
    }

    #[tokio::test]
    async fn a_general_failure_reply_leaves_the_verdict_up() {
        let (_listener, host, port) = destination().await;
        let hop = hop(
            upstream_answering(GENERAL_FAILURE).await,
            HealthState::Up,
            PATIENT,
        );

        let failure = hop
            .dial(&host, port, upstream_decision(RuleClass::Require, 1))
            .await
            .unwrap_err();

        assert!(
            UpstreamDown::carried_by(&failure).is_none(),
            "an upstream that answered 0x01 is still serving: {failure}"
        );
        assert_eq!(hop.health().state(), HealthState::Up);
    }
}
