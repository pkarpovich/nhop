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
///
/// Only a failure of the upstream itself flips the verdict down. An upstream that answers about a
/// destination it could not reach has proven it is serving, so one dead destination never sends
/// every `prefer` connection past the proxy.
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

async fn direct(host: &Host, port: Port) -> io::Result<TcpStream> {
    let Host(host) = host;
    let Port(port) = port;
    TcpStream::connect((host.as_str(), port)).await
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
    Ok(dialled.into_inner())
}

fn failed_dial(failure: tokio_socks::Error) -> DialFailure {
    match failure {
        tokio_socks::Error::ConnectionNotAllowedByRuleset
        | tokio_socks::Error::NetworkUnreachable
        | tokio_socks::Error::HostUnreachable
        | tokio_socks::Error::ConnectionRefused
        | tokio_socks::Error::TtlExpired
        | tokio_socks::Error::AddressTypeNotSupported
        | tokio_socks::Error::InvalidTargetAddress(_) => {
            DialFailure::Destination(io::Error::other(failure))
        }
        tokio_socks::Error::Io(_)
        | tokio_socks::Error::ParseError(_)
        | tokio_socks::Error::ProxyServerUnreachable
        | tokio_socks::Error::InvalidResponseVersion
        | tokio_socks::Error::NoAcceptableAuthMethods
        | tokio_socks::Error::UnknownAuthMethod
        | tokio_socks::Error::GeneralSocksServerFailure
        | tokio_socks::Error::CommandNotSupported
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    const PATIENT: Duration = Duration::from_secs(60);
    const NO_AUTH: [u8; 2] = [0x05, 0x00];
    const REFUSED: [u8; 10] = [0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

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

    async fn upstream_refusing_every_destination() -> SocketAddr {
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
                    let _refused = stream.write_all(&REFUSED).await;
                });
            }
        });
        addr
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
        let hop = hop(
            upstream_refusing_every_destination().await,
            HealthState::Up,
            PATIENT,
        );

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
        let hop = hop(
            upstream_refusing_every_destination().await,
            HealthState::Up,
            PATIENT,
        );

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
}
