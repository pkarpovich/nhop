mod health;

pub use health::{Health, HealthHandle};

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use nhop_ipc::{HealthState, Host, Port, RuleClass};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_socks::tcp::Socks5Stream;

use crate::daemon::state::LiveUpstream;
use crate::proxy::{NextHop, UpstreamDown};
use crate::rules::{Decision, RuleId};

/// How long a dial through the upstream may take before it counts as a failure.
pub const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// How long the dialer waits between probes while the verdict is down.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(5);

/// How long one probe may take before it counts as a failure.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Next hop that sends `require` and `prefer` traffic through the SOCKS5 upstream.
///
/// While the verdict is [`HealthState::Down`] no connection is dialled through the upstream at
/// all: `prefer` goes direct at once and `require` fails at once, so a powered-off upstream costs
/// a decision rather than a connect timeout per connection.
#[derive(Debug)]
pub struct UpstreamHop {
    upstream: LiveUpstream,
    health: HealthHandle,
    probing: JoinHandle<()>,
}

impl Drop for UpstreamHop {
    fn drop(&mut self) {
        let Self {
            upstream: _,
            health: _,
            probing,
        } = self;
        probing.abort();
    }
}

impl UpstreamHop {
    /// Starts dialling through the published upstream, probing it while the verdict is down.
    ///
    /// The interval is a parameter so tests do not wait out [`PROBE_INTERVAL`].
    pub fn start(upstream: LiveUpstream, health: HealthHandle, interval: Duration) -> Self {
        let probing = tokio::spawn(probe_while_down(upstream.clone(), health.clone(), interval));
        Self {
            upstream,
            health,
            probing,
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
                Err(_failure) => {
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
                Err(_failure) => {
                    self.health.set(HealthState::Down);
                    direct(host, port).await
                }
            },
        }
    }
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

async fn direct(host: &Host, port: Port) -> io::Result<TcpStream> {
    let Host(host) = host;
    let Port(port) = port;
    TcpStream::connect((host.as_str(), port)).await
}

async fn through(host: &Host, port: Port, upstream: SocketAddr) -> io::Result<TcpStream> {
    let Host(host) = host;
    let Port(port) = port;
    let dialling = Socks5Stream::connect(upstream, (host.as_str(), port));
    let Ok(dialled) = tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, dialling).await else {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "the upstream {upstream} did not answer within {}s",
                UPSTREAM_CONNECT_TIMEOUT.as_secs()
            ),
        ));
    };
    let dialled = match dialled {
        Ok(dialled) => dialled,
        Err(failure) => return Err(io::Error::other(failure)),
    };
    Ok(dialled.into_inner())
}

async fn probe_while_down(upstream: LiveUpstream, health: HealthHandle, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        match health.state() {
            HealthState::Up => continue,
            HealthState::Down => {}
        }
        match probe(upstream.snapshot()).await {
            HealthState::Down => continue,
            HealthState::Up => health.set(HealthState::Up),
        }
    }
}

async fn probe(upstream: SocketAddr) -> HealthState {
    let handshake = Socks5Stream::connect(upstream, upstream);
    let Ok(reached) = tokio::time::timeout(PROBE_TIMEOUT, handshake).await else {
        return HealthState::Down;
    };
    let Ok(_reached) = reached else {
        return HealthState::Down;
    };
    HealthState::Up
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    const PATIENT: Duration = Duration::from_secs(60);

    fn hop(upstream: SocketAddr, state: HealthState, interval: Duration) -> UpstreamHop {
        let published = LiveUpstream::default();
        published.publish(upstream);
        let health = HealthHandle::default();
        health.set(state);
        UpstreamHop::start(published, health, interval)
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
    async fn a_probe_against_a_closed_port_leaves_the_verdict_down() {
        assert_eq!(probe(closed_port().await).await, HealthState::Down);
    }
}
