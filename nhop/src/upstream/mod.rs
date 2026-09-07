mod health;

pub use health::{Health, HealthHandle, VerdictCause};

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use nhop_ipc::{EffectiveHop, HealthState, Host, Port, RuleClass};
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_socks::tcp::Socks5Stream;

use crate::daemon::state::{LOAD_TIMEOUT, LiveUpstream};
use crate::proxy::{Dialled, NO_UPSTREAM, NextHop, UpstreamDown};
use crate::rules::{Decision, RuleId};

/// How long a `prefer` dial through the upstream may take before it counts as a failure.
///
/// A `prefer` dial has a direct route waiting behind it, so the budget is not "how long may this
/// connection take" but "how long is it worth waiting before taking the route we already have".
/// Two seconds is that answer: long enough that a healthy upstream is never given up on, short
/// enough that the fallback is not felt as a hang.
pub const PREFER_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a `require` dial through the upstream may take before it counts as a failure.
///
/// A `require` destination has no direct route behind it, so this budget is the whole connection's
/// patience rather than a decision point: giving up early does not reach the destination faster, it
/// only fails sooner. Ten seconds covers the deepest stalls seen when the upstream host is merely
/// starved rather than gone - a degraded upstream answered ICMP in up to ten seconds while still
/// serving SOCKS - and it caps the one case that costs a full wait, an upstream whose SYNs queue
/// behind an ARP that never answers, measured at the full budget for the first minute after the
/// machine goes down.
///
/// It is a compile-time constant like every other timing constant here: the value is a property of
/// how long a person will wait for a page, not of a deployment.
pub const REQUIRE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long one dial through the upstream may take, chosen by the class of the rule that sent it.
///
/// The asymmetry is the point: `prefer` is timing how long to wait before taking the direct route
/// it already has, `require` is timing how long a user will wait for the only route there is.
#[derive(Debug, Clone, Copy)]
pub enum UpstreamBudget {
    /// The budget for a dial with a direct route waiting behind it, [`PREFER_CONNECT_TIMEOUT`].
    Prefer,
    /// The budget for a dial with no fallback, [`REQUIRE_CONNECT_TIMEOUT`].
    Require,
}

impl UpstreamBudget {
    fn allowance(self) -> Duration {
        match self {
            Self::Prefer => PREFER_CONNECT_TIMEOUT,
            Self::Require => REQUIRE_CONNECT_TIMEOUT,
        }
    }
}

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

/// How long the patrol looks at [`NO_UPSTREAM_TICK`] before falling back to the interval.
///
/// Only cold start is worth the fast tick, and cold start lasts as long as the first load may: a
/// load publishes its address on commit, so a script that runs for most of [`LOAD_TIMEOUT`] leaves
/// the snapshot at [`NO_UPSTREAM`] until the end of that window. Sizing the window on anything
/// shorter would hand a slow init file back the interval-long wait the tick exists to remove.
///
/// [`LOAD_TIMEOUT`] alone is not that size, because the two clocks do not start together: this one
/// starts when `spawn_frontends` spawns the patrol, the script's starts later, once the state task
/// exists, the startup `Reload` has been served and `init_script::run` has been spawned. A script
/// finishing just inside its own timeout therefore publishes just outside a window measured as the
/// timeout exactly. [`PROBE_INTERVAL`] of slack covers that startup order with orders of magnitude
/// to spare, and costs a daemon with no upstream one extra interval of ticking.
///
/// It is still a window rather than "until an address appears", because a daemon configured with
/// no upstream at all - no init file, or a ruleset of nothing but `never` rules - is a supported
/// steady state, and it must not wake four times a second for the rest of its life to keep finding
/// nothing.
const NO_UPSTREAM_EAGER: Duration = LOAD_TIMEOUT.saturating_add(PROBE_INTERVAL);

/// How long a relay socket may sit idle before the first keepalive probe goes out.
pub const KEEPALIVE_IDLE: Duration = Duration::from_secs(15);

/// How long the relay socket waits between keepalive probes once it has started sending them.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// How many unanswered keepalive probes end a relay socket.
pub const KEEPALIVE_RETRIES: u32 = 4;

/// Next hop that sends `require` and `prefer` traffic through the SOCKS5 upstream.
///
/// The verdict routes `prefer` only: while it is [`HealthState::Down`] a `prefer` destination goes
/// direct at once rather than paying a connect timeout for a route it does not need. `require` has
/// no direct route to fall back to, so it dials every configured address whatever the verdict says
/// and gives up only at [`REQUIRE_CONNECT_TIMEOUT`]; a refusal there would turn an upstream that is
/// merely slow into one that is dead.
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

    async fn routed(&self, host: &Host, port: Port, class: RuleClass, rule: RuleId) -> Dialled {
        let upstream = self.upstream.snapshot();
        match class {
            RuleClass::Never => Dialled::Attempted {
                hop: EffectiveHop::Direct,
                next: direct(host, port).await,
            },
            RuleClass::Require => self.required(host, port, rule, upstream).await,
            RuleClass::Prefer => {
                let (hop, next) = self.preferred(host, port, upstream).await;
                Dialled::Attempted { hop, next }
            }
        }
    }

    /// Dials a `require` destination, refusing before the network only with no upstream configured.
    ///
    /// [`NO_UPSTREAM`] is a configuration absence rather than a health judgment - port zero cannot
    /// be dialled - so it is the one address turned away without a socket. Every configured address
    /// is dialled whatever the verdict says, because a `require` destination has no direct route to
    /// be spared for: refusing early only fails sooner, and during an upstream that was slow rather
    /// than gone it failed everything the upstream could still have served.
    ///
    /// The refusal and a dial that failed upstream-side carry the same [`UpstreamDown`] surface on
    /// purpose - a `require` rule has one meaning for the client either way - so the two are told
    /// apart by the [`Dialled`] variant rather than by the error inside it.
    async fn required(
        &self,
        host: &Host,
        port: Port,
        rule: RuleId,
        upstream: SocketAddr,
    ) -> Dialled {
        if upstream == NO_UPSTREAM {
            return Dialled::Refused(UpstreamDown::new(upstream, rule).into());
        }
        let next = match through(host, port, upstream, UpstreamBudget::Require).await {
            Ok(next) => {
                self.observed(upstream, HealthState::Up, VerdictCause::Dial);
                Ok(next)
            }
            Err(DialFailure::Destination(failure)) => {
                self.observed(upstream, HealthState::Up, VerdictCause::Dial);
                Err(failure)
            }
            Err(DialFailure::Upstream(_failure)) => {
                self.observed(upstream, HealthState::Down, VerdictCause::Dial);
                Err(UpstreamDown::new(upstream, rule).into())
            }
        };
        Dialled::Attempted {
            hop: EffectiveHop::Upstream,
            next,
        }
    }

    /// Records what one real dial saw about the upstream it was made against.
    ///
    /// A connection, or a SOCKS reply about the destination, proves the upstream is serving - the
    /// split [`failed_dial`] already draws - so both move the verdict up at once instead of waiting
    /// out the patrol's two-probe hysteresis. The evidence is symmetric with the failure that
    /// already flips it down on one dial: a user paid for it either way.
    ///
    /// The write is guarded by the address the dial went to, the same guard [`Pending`] gives a
    /// probe sequence. A dial that started before a reload and lands after it has observed an
    /// upstream nobody routes to any more, and must not judge the one that replaced it.
    fn observed(&self, dialled: SocketAddr, state: HealthState, cause: VerdictCause) {
        if self.upstream.snapshot() != dialled {
            return;
        }
        self.health.set(state, cause);
    }

    /// Dials a `prefer` destination, reporting which of its two routes carried the connection.
    ///
    /// Every path that ends at [`direct`] reports [`EffectiveHop::FallbackDirect`], because from
    /// the client's side those connections are indistinguishable from an upstream one and the log
    /// is the only place the difference can be seen.
    async fn preferred(
        &self,
        host: &Host,
        port: Port,
        upstream: SocketAddr,
    ) -> (EffectiveHop, io::Result<TcpStream>) {
        match self.health.state() {
            HealthState::Down => (EffectiveHop::FallbackDirect, direct(host, port).await),
            HealthState::Up => match through(host, port, upstream, UpstreamBudget::Prefer).await {
                Ok(next) => {
                    self.observed(upstream, HealthState::Up, VerdictCause::Dial);
                    (EffectiveHop::Upstream, Ok(next))
                }
                Err(DialFailure::Destination(_failure)) => {
                    self.observed(upstream, HealthState::Up, VerdictCause::Dial);
                    (EffectiveHop::FallbackDirect, direct(host, port).await)
                }
                Err(DialFailure::Upstream(_failure)) => {
                    self.observed(upstream, HealthState::Down, VerdictCause::Dial);
                    (EffectiveHop::FallbackDirect, direct(host, port).await)
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
    ) -> Pin<Box<dyn Future<Output = Dialled> + Send + 'a>> {
        Box::pin(async move {
            match decision {
                Decision::Direct => Dialled::Attempted {
                    hop: EffectiveHop::Direct,
                    next: direct(host, port).await,
                },
                Decision::Never { rule: _ } => Dialled::Attempted {
                    hop: EffectiveHop::Direct,
                    next: direct(host, port).await,
                },
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

async fn through(
    host: &Host,
    port: Port,
    upstream: SocketAddr,
    budget: UpstreamBudget,
) -> Result<TcpStream, DialFailure> {
    let Host(host) = host;
    let Port(port) = port;
    let budget = budget.allowance();
    let dialling = Socks5Stream::connect(upstream, (host.as_str(), port));
    let Ok(dialled) = tokio::time::timeout(budget, dialling).await else {
        return Err(DialFailure::Upstream(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "the upstream {upstream} did not answer within {}s",
                budget.as_secs()
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
/// The `target` is what the sequence is trying to reach, and anchoring on it rather than on
/// "contradicts whatever the verdict is right now" is load-bearing: a contradiction banked against
/// [`HealthState::Up`], a dial failure flipping the verdict down underneath it, and then a
/// *successful* confirming probe would otherwise read as a second contradiction and declare the
/// upstream alive on one good probe. That anchor is also what retires a sequence whose verdict
/// moved by any other path - a real dial failure, an operator command - since an observation
/// aiming somewhere else opens a fresh sequence instead of closing the stale one.
///
/// The `addr` is the upstream the observation was made against. `patrol` re-reads the published
/// address every iteration, so without it a contradiction banked against the old upstream could be
/// closed by the first probe of the one a reload put in its place.
#[derive(Debug, Clone, Copy)]
struct Pending {
    target: HealthState,
    addr: SocketAddr,
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
    let mut looking = Duration::ZERO;
    loop {
        let addr = upstream.snapshot();
        if addr == NO_UPSTREAM {
            let tick = match looking < NO_UPSTREAM_EAGER {
                true => NO_UPSTREAM_TICK.min(interval),
                false => interval,
            };
            looking = looking.saturating_add(tick);
            tokio::time::sleep(tick).await;
            continue;
        }
        looking = Duration::ZERO;
        pending = advance(pending, probe(addr).await, addr, &health);
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
fn advance(
    pending: Option<Pending>,
    seen: HealthState,
    addr: SocketAddr,
    health: &HealthHandle,
) -> Option<Pending> {
    let settled = health.state();
    match (settled, seen) {
        (HealthState::Up, HealthState::Up) | (HealthState::Down, HealthState::Down) => return None,
        (HealthState::Up, HealthState::Down) | (HealthState::Down, HealthState::Up) => {}
    }
    let confirms = match pending {
        None => false,
        Some(Pending {
            target,
            addr: probed,
        }) => target == seen && probed == addr,
    };
    if confirms {
        health.set(seen, VerdictCause::Probe);
        return None;
    }
    Some(Pending { target: seen, addr })
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
        health.seed(state);
        UpstreamHop::start(published, health, interval, PATIENT)
    }

    fn upstream_decision(class: RuleClass, rule: usize) -> Decision {
        Decision::Upstream {
            class,
            rule: RuleId(rule),
        }
    }

    async fn dial(
        hop: &UpstreamHop,
        host: &Host,
        port: Port,
        decision: Decision,
    ) -> io::Result<TcpStream> {
        match hop.dial(host, port, decision).await {
            Dialled::Refused(failure) => Err(failure),
            Dialled::Attempted { hop: _, next } => next,
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

    async fn black_hole() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    return;
                };
                held.push(stream);
            }
        });
        addr
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
                    let mut carried = Vec::new();
                    let _relayed = stream.read_to_end(&mut carried).await;
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

        let dialled = through(&host, port, upstream, UpstreamBudget::Prefer)
            .await
            .unwrap();

        armed_keepalive(&dialled);
    }

    #[tokio::test(start_paused = true)]
    async fn a_prefer_budget_gives_up_at_the_prefer_timeout() {
        let (_listener, host, port) = destination().await;
        let upstream = black_hole().await;
        let started = tokio::time::Instant::now();

        let failure = through(&host, port, upstream, UpstreamBudget::Prefer)
            .await
            .unwrap_err();

        assert_eq!(started.elapsed(), PREFER_CONNECT_TIMEOUT);
        match failure {
            DialFailure::Upstream(_failure) => (),
            DialFailure::Destination(answered) => {
                panic!("a black hole answers nothing, got {answered}")
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_require_budget_gives_up_at_the_require_timeout() {
        let (_listener, host, port) = destination().await;
        let upstream = black_hole().await;
        let started = tokio::time::Instant::now();

        let failure = through(&host, port, upstream, UpstreamBudget::Require)
            .await
            .unwrap_err();

        assert_eq!(started.elapsed(), REQUIRE_CONNECT_TIMEOUT);
        match failure {
            DialFailure::Upstream(_failure) => (),
            DialFailure::Destination(answered) => {
                panic!("a black hole answers nothing, got {answered}")
            }
        }
    }

    #[tokio::test]
    async fn a_direct_decision_reaches_the_destination_itself() {
        let (listener, host, port) = destination().await;
        let hop = hop(closed_port().await, HealthState::Down, PATIENT);

        let dialled = dial(&hop, &host, port, Decision::Direct).await.unwrap();

        assert_eq!(dialled.peer_addr().unwrap(), listener.local_addr().unwrap());
    }

    #[tokio::test]
    async fn a_never_decision_reaches_the_destination_itself() {
        let (listener, host, port) = destination().await;
        let hop = hop(closed_port().await, HealthState::Up, PATIENT);

        let dialled = dial(&hop, &host, port, Decision::Never { rule: RuleId(2) })
            .await
            .unwrap();

        assert_eq!(dialled.peer_addr().unwrap(), listener.local_addr().unwrap());
        assert_eq!(hop.health().state(), HealthState::Up);
    }

    #[tokio::test]
    async fn a_never_class_reaching_the_upstream_arm_still_dials_directly() {
        let (listener, host, port) = destination().await;
        let hop = hop(closed_port().await, HealthState::Up, PATIENT);

        let dialled = dial(&hop, &host, port, upstream_decision(RuleClass::Never, 0))
            .await
            .unwrap();

        assert_eq!(dialled.peer_addr().unwrap(), listener.local_addr().unwrap());
    }

    #[tokio::test]
    async fn a_require_decision_dials_a_configured_upstream_while_the_verdict_is_down() {
        let (_listener, host, port) = destination().await;
        let upstream = closed_port().await;
        let hop = hop(upstream, HealthState::Down, PATIENT);

        let dialled = hop
            .dial(&host, port, upstream_decision(RuleClass::Require, 4))
            .await;

        let Dialled::Attempted { hop: _, next } = dialled else {
            panic!("a configured upstream is dialled whatever the verdict says");
        };
        let failure = next.unwrap_err();
        let Some(down) = UpstreamDown::carried_by(&failure) else {
            panic!("a require rule must fail with the upstream-down surface: {failure}");
        };
        assert_eq!(
            down.to_string(),
            format!("nhop: upstream {upstream} is down (require rule 4)")
        );
    }

    #[tokio::test]
    async fn a_require_refusal_reports_that_nothing_was_dialled() {
        let (_listener, host, port) = destination().await;
        let hop = hop(NO_UPSTREAM, HealthState::Down, PATIENT);

        let dialled = hop
            .dial(&host, port, upstream_decision(RuleClass::Require, 4))
            .await;

        let Dialled::Refused(_refusal) = dialled else {
            panic!("a require rule with no upstream configured never touched the network");
        };
    }

    #[tokio::test]
    async fn a_require_dial_that_fails_upstream_side_still_reports_an_attempt() {
        let (_listener, host, port) = destination().await;
        let hop = hop(closed_port().await, HealthState::Up, PATIENT);

        let dialled = hop
            .dial(&host, port, upstream_decision(RuleClass::Require, 4))
            .await;

        let Dialled::Attempted { hop: _, next } = dialled else {
            panic!("a dial that reached the network must be reported as attempted");
        };
        let failure = next.unwrap_err();
        assert!(
            UpstreamDown::carried_by(&failure).is_some(),
            "the client still sees the upstream-down surface: {failure}"
        );
    }

    #[tokio::test]
    async fn a_prefer_fallback_reports_fallback_direct() {
        let (_listener, host, port) = destination().await;
        let hop = hop(closed_port().await, HealthState::Down, PATIENT);

        let dialled = hop
            .dial(&host, port, upstream_decision(RuleClass::Prefer, 7))
            .await;

        let Dialled::Attempted { hop, next } = dialled else {
            panic!("a prefer decision dials whichever route it takes");
        };
        let _next = next.unwrap();
        assert_eq!(hop, EffectiveHop::FallbackDirect);
    }

    #[tokio::test]
    async fn a_require_dial_reports_upstream() {
        let (_listener, host, port) = destination().await;
        let upstream = hop(
            upstream_answering(GRANTED).await,
            HealthState::Down,
            PATIENT,
        );

        let dialled = upstream
            .dial(&host, port, upstream_decision(RuleClass::Require, 7))
            .await;

        let Dialled::Attempted { hop, next } = dialled else {
            panic!("a configured upstream is dialled whatever the verdict says");
        };
        let _next = next.unwrap();
        assert_eq!(hop, EffectiveHop::Upstream);
    }

    #[tokio::test]
    async fn a_prefer_decision_goes_direct_at_once_while_the_verdict_is_down() {
        let (listener, host, port) = destination().await;
        let hop = hop(closed_port().await, HealthState::Down, PATIENT);

        let dialled = dial(&hop, &host, port, upstream_decision(RuleClass::Prefer, 0))
            .await
            .unwrap();

        assert_eq!(dialled.peer_addr().unwrap(), listener.local_addr().unwrap());
        assert_eq!(hop.health().state(), HealthState::Down);
    }

    #[tokio::test]
    async fn an_upstream_that_cannot_be_reached_flips_the_verdict_down() {
        let (_listener, host, port) = destination().await;
        let hop = hop(closed_port().await, HealthState::Up, PATIENT);

        let failure = dial(&hop, &host, port, upstream_decision(RuleClass::Require, 3))
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

        let failure = dial(&hop, &host, port, upstream_decision(RuleClass::Require, 1))
            .await
            .unwrap_err();

        assert!(
            UpstreamDown::carried_by(&failure).is_none(),
            "a refused destination is not the upstream being down: {failure}"
        );
        assert_eq!(hop.health().state(), HealthState::Up);
    }

    #[tokio::test]
    async fn a_require_dial_that_connects_flips_the_verdict_up() {
        let (_listener, host, port) = destination().await;
        let hop = hop(
            upstream_answering(GRANTED).await,
            HealthState::Down,
            PATIENT,
        );
        let settled = hop.health().changed_at();

        let _dialled = dial(&hop, &host, port, upstream_decision(RuleClass::Require, 5))
            .await
            .unwrap();

        assert_eq!(hop.health().state(), HealthState::Up);
        assert!(
            hop.health().changed_at() > settled,
            "a dial that connects turns the verdict over"
        );
    }

    #[tokio::test]
    async fn a_destination_refusal_flips_the_verdict_up() {
        let (_listener, host, port) = destination().await;
        let hop = hop(
            upstream_answering(REFUSED).await,
            HealthState::Down,
            PATIENT,
        );

        let failure = dial(&hop, &host, port, upstream_decision(RuleClass::Require, 5))
            .await
            .unwrap_err();

        assert!(
            UpstreamDown::carried_by(&failure).is_none(),
            "an upstream that answered about the destination is serving: {failure}"
        );
        assert_eq!(hop.health().state(), HealthState::Up);
    }

    #[tokio::test]
    async fn a_dial_landing_after_a_reload_leaves_the_new_verdict_alone() {
        let before = closed_port().await;
        let after = closed_port().await;
        let published = LiveUpstream::default();
        published.publish(before);
        let health = HealthHandle::default();
        health.seed(HealthState::Down);
        let hop = UpstreamHop::start(published.clone(), health, PATIENT, PATIENT);
        published.publish(after);

        hop.observed(before, HealthState::Up, VerdictCause::Dial);

        assert_eq!(hop.health().state(), HealthState::Down);

        hop.observed(after, HealthState::Up, VerdictCause::Dial);

        assert_eq!(hop.health().state(), HealthState::Up);
    }

    #[tokio::test]
    async fn a_prefer_rule_goes_direct_when_the_upstream_refuses_the_destination() {
        let (listener, host, port) = destination().await;
        let hop = hop(upstream_answering(REFUSED).await, HealthState::Up, PATIENT);

        let dialled = dial(&hop, &host, port, upstream_decision(RuleClass::Prefer, 0))
            .await
            .unwrap();

        assert_eq!(dialled.peer_addr().unwrap(), listener.local_addr().unwrap());
        assert_eq!(hop.health().state(), HealthState::Up);
    }

    #[test]
    fn the_eager_window_outlasts_a_load_that_publishes_late() {
        assert!(
            NO_UPSTREAM_EAGER > LOAD_TIMEOUT,
            "the first load publishes on commit and its timeout starts after this window does, so \
             the fast tick has to outlast the whole run: {NO_UPSTREAM_EAGER:?} against \
             {LOAD_TIMEOUT:?}"
        );
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

        let failure = dial(&hop, &host, port, upstream_decision(RuleClass::Require, 1))
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

        let failure = dial(&hop, &host, port, upstream_decision(RuleClass::Require, 1))
            .await
            .unwrap_err();

        assert!(
            UpstreamDown::carried_by(&failure).is_none(),
            "an upstream that answered 0x01 is still serving: {failure}"
        );
        assert_eq!(hop.health().state(), HealthState::Up);
    }
}
