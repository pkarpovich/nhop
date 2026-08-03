mod support;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use nhop::daemon::state::LiveUpstream;
use nhop::proxy::{NextHop, UpstreamDown};
use nhop::rules::{Decision, RuleClass, RuleId};
use nhop::upstream::{HealthHandle, UpstreamHop};
use nhop_ipc::{HealthState, Host, Port};
use tokio::net::TcpListener;

use support::{SocksRequest, StubOrigin, StubSocks5, ephemeral};

const PATIENT: Duration = Duration::from_secs(60);
const EAGER: Duration = Duration::from_millis(50);
const PATIENCE: usize = 200;

fn published(upstream: SocketAddr) -> LiveUpstream {
    let published = LiveUpstream::default();
    published.publish(upstream);
    published
}

fn verdict(state: HealthState) -> HealthHandle {
    let health = HealthHandle::default();
    health.set(state);
    health
}

fn hop(upstream: SocketAddr, state: HealthState) -> UpstreamHop {
    UpstreamHop::start(published(upstream), verdict(state), PATIENT)
}

async fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind(ephemeral()).await.unwrap();
    listener.local_addr().unwrap()
}

fn named(addr: SocketAddr) -> (Host, Port) {
    (Host(addr.ip().to_string()), Port(addr.port()))
}

fn require(rule: usize) -> Decision {
    Decision::Upstream {
        class: RuleClass::Require,
        rule: RuleId(rule),
    }
}

fn prefer(rule: usize) -> Decision {
    Decision::Upstream {
        class: RuleClass::Prefer,
        rule: RuleId(rule),
    }
}

async fn await_state(health: &HealthHandle, state: HealthState) {
    for _attempt in 0..PATIENCE {
        if health.state() == state {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("the verdict never became {state:?}");
}

#[tokio::test]
async fn a_prefer_rule_reaches_the_destination_while_the_upstream_is_closed() {
    let origin = StubOrigin::start().await;
    let upstream = closed_port().await;
    let hop = hop(upstream, HealthState::Up);
    let (host, port) = named(origin.addr());

    let dialled = hop.dial(&host, port, prefer(1)).await.unwrap();

    assert_eq!(dialled.peer_addr().unwrap(), origin.addr());
    assert_eq!(hop.health().state(), HealthState::Down);
}

#[tokio::test]
async fn a_require_rule_is_refused_while_the_upstream_is_closed() {
    let origin = StubOrigin::start().await;
    let upstream = closed_port().await;
    let hop = hop(upstream, HealthState::Up);
    let (host, port) = named(origin.addr());

    let failure = hop.dial(&host, port, require(2)).await.unwrap_err();

    let Some(down) = UpstreamDown::carried_by(&failure) else {
        panic!("a require rule must be refused with the upstream-down surface: {failure}");
    };
    assert_eq!(
        down.to_string(),
        format!("nhop: upstream {upstream} is down (require rule 2)")
    );
    assert_eq!(hop.health().state(), HealthState::Down);
    assert_eq!(origin.connections(), 0);
}

#[tokio::test]
async fn a_require_rule_travels_through_the_upstream_as_the_name_the_client_wrote() {
    let stub = StubSocks5::start().await;
    let hop = hop(stub.addr(), HealthState::Up);

    let dialled = hop
        .dial(&Host("example.com".to_owned()), Port(443), require(0))
        .await
        .unwrap();

    assert_eq!(dialled.peer_addr().unwrap(), stub.addr());
    assert_eq!(
        stub.requests(),
        vec![SocksRequest {
            atyp: 0x03,
            host: "example.com".to_owned(),
            port: 443,
        }]
    );
    assert_eq!(hop.health().state(), HealthState::Up);
}

#[tokio::test]
async fn a_prefer_rule_travels_through_the_upstream_while_the_verdict_is_up() {
    let stub = StubSocks5::start().await;
    let hop = hop(stub.addr(), HealthState::Up);

    let dialled = hop
        .dial(&Host("example.net".to_owned()), Port(80), prefer(0))
        .await
        .unwrap();

    assert_eq!(dialled.peer_addr().unwrap(), stub.addr());
    assert_eq!(
        stub.requests(),
        vec![SocksRequest {
            atyp: 0x03,
            host: "example.net".to_owned(),
            port: 80,
        }]
    );
}

#[tokio::test]
async fn a_down_verdict_reaches_no_upstream_at_all() {
    let stub = StubSocks5::start().await;
    let origin = StubOrigin::start().await;
    let hop = hop(stub.addr(), HealthState::Down);
    let (host, port) = named(origin.addr());

    let refused = hop.dial(&host, port, require(0)).await;
    let dialled = hop.dial(&host, port, prefer(1)).await.unwrap();

    assert!(refused.is_err(), "a require rule must be refused");
    assert_eq!(dialled.peer_addr().unwrap(), origin.addr());
    assert_eq!(stub.requests(), Vec::new());
}

#[tokio::test]
async fn the_verdict_flips_up_once_the_upstream_answers_a_probe() {
    let published = published(closed_port().await);
    let health = HealthHandle::default();
    let _hop = UpstreamHop::start(published.clone(), health.clone(), EAGER);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(health.state(), HealthState::Down);
    let settled = health.changed_at();

    let stub = StubSocks5::start().await;
    published.publish(stub.addr());

    await_state(&health, HealthState::Up).await;
    assert!(health.changed_at() > settled);
    assert_eq!(
        stub.requests(),
        vec![SocksRequest {
            atyp: 0x01,
            host: stub.addr().ip().to_string(),
            port: stub.addr().port(),
        }]
    );
}

#[tokio::test]
async fn no_probe_is_sent_while_the_verdict_is_up() {
    let stub = StubSocks5::start().await;
    let _hop = UpstreamHop::start(published(stub.addr()), verdict(HealthState::Up), EAGER);

    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(stub.requests(), Vec::new());
}

#[tokio::test]
async fn a_dial_to_a_black_holed_upstream_fails_within_three_seconds() {
    let blackhole: SocketAddr = "192.0.2.1:1080".parse().unwrap();
    let hop = hop(blackhole, HealthState::Up);
    let started = Instant::now();

    let failure = hop
        .dial(&Host("example.com".to_owned()), Port(443), require(0))
        .await
        .unwrap_err();

    let waited = started.elapsed();
    assert!(waited < Duration::from_secs(3), "waited {waited:?}");
    assert!(
        UpstreamDown::carried_by(&failure).is_some(),
        "{failure} must carry the upstream-down surface"
    );
    assert_eq!(hop.health().state(), HealthState::Down);
}
