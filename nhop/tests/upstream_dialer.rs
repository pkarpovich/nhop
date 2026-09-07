mod support;

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use nhop::daemon::state::LiveUpstream;
use nhop::proxy::{Dialled, NextHop, UpstreamDown};
use nhop::rules::{Decision, RuleClass, RuleId};
use nhop::upstream::{
    HealthHandle, PREFER_CONNECT_TIMEOUT, PROBE_INTERVAL, PROBE_TIMEOUT, REQUIRE_CONNECT_TIMEOUT,
    UpstreamHop,
};
use nhop_ipc::{HealthState, Host, Port};
use tokio::net::{TcpListener, TcpStream};

use support::{Answers, SocksRequest, StubOrigin, StubSocks5, ephemeral};

const PATIENT: Duration = Duration::from_secs(60);
const EAGER: Duration = Duration::from_millis(50);
const SNAPPY: Duration = Duration::from_millis(100);
const DELIBERATE: Duration = Duration::from_millis(500);
const GRACE: Duration = Duration::from_millis(500);

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
    UpstreamHop::start(published(upstream), verdict(state), PATIENT, PATIENT)
}

/// Dials through the hop, keeping only whether a connection came back.
///
/// Whether the network was touched is asserted where it is the point, so every other test reads
/// the dial as the plain result it used to be.
async fn dial(
    hop: &UpstreamHop,
    host: &Host,
    port: Port,
    decision: Decision,
) -> io::Result<TcpStream> {
    match hop.dial(host, port, decision).await {
        Dialled::Refused(failure) => Err(failure),
        Dialled::Attempted(next) => next,
    }
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

async fn await_state(health: &HealthHandle, state: HealthState, budget: Duration) {
    let started = Instant::now();
    loop {
        if health.state() == state {
            return;
        }
        let waited = started.elapsed();
        assert!(
            waited <= budget,
            "the verdict never became {state:?}, waited {waited:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn a_prefer_rule_reaches_the_destination_while_the_upstream_is_closed() {
    let origin = StubOrigin::start().await;
    let upstream = closed_port().await;
    let hop = hop(upstream, HealthState::Up);
    let (host, port) = named(origin.addr());

    let dialled = dial(&hop, &host, port, prefer(1)).await.unwrap();

    assert_eq!(dialled.peer_addr().unwrap(), origin.addr());
    assert_eq!(hop.health().state(), HealthState::Down);
}

#[tokio::test]
async fn a_require_rule_is_refused_while_the_upstream_is_closed() {
    let origin = StubOrigin::start().await;
    let upstream = closed_port().await;
    let hop = hop(upstream, HealthState::Up);
    let (host, port) = named(origin.addr());

    let failure = dial(&hop, &host, port, require(2)).await.unwrap_err();

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

    let dialled = dial(&hop, &Host("example.com".to_owned()), Port(443), require(0))
        .await
        .unwrap();

    assert_eq!(dialled.peer_addr().unwrap(), stub.addr());
    assert_eq!(
        stub.client_dials(),
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

    let dialled = dial(&hop, &Host("example.net".to_owned()), Port(80), prefer(0))
        .await
        .unwrap();

    assert_eq!(dialled.peer_addr().unwrap(), stub.addr());
    assert_eq!(
        stub.client_dials(),
        vec![SocksRequest {
            atyp: 0x03,
            host: "example.net".to_owned(),
            port: 80,
        }]
    );
}

#[tokio::test]
async fn a_require_dial_reaches_the_upstream_while_the_verdict_is_down() {
    let stub = StubSocks5::start().await;
    let origin = StubOrigin::start().await;
    let hop = hop(stub.addr(), HealthState::Down);
    let (host, port) = named(origin.addr());

    let preferred = dial(&hop, &host, port, prefer(1)).await.unwrap();
    let required = dial(&hop, &host, port, require(0)).await.unwrap();

    assert_eq!(required.peer_addr().unwrap(), stub.addr());
    assert_eq!(preferred.peer_addr().unwrap(), origin.addr());
    assert_eq!(
        stub.client_dials(),
        vec![SocksRequest {
            atyp: 0x01,
            host: origin.addr().ip().to_string(),
            port: origin.addr().port(),
        }]
    );
}

#[tokio::test]
async fn the_verdict_flips_up_once_the_upstream_answers_a_probe() {
    let published = published(closed_port().await);
    let health = HealthHandle::default();
    let _hop = UpstreamHop::start(published.clone(), health.clone(), EAGER, SNAPPY);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(health.state(), HealthState::Down);
    let settled = health.changed_at();

    let stub = StubSocks5::start().await;
    published.publish(stub.addr());

    await_state(&health, HealthState::Up, Duration::from_secs(5)).await;
    assert!(health.changed_at() > settled);
    let probes = stub.requests();
    assert!(
        probes.len() >= 2,
        "the verdict must not move on one probe: {probes:?}"
    );
    for SocksRequest { atyp, host, port } in probes {
        assert_eq!(atyp, 0x01);
        assert_eq!(host, stub.addr().ip().to_string());
        assert_eq!(port, stub.addr().port());
    }
}

#[tokio::test]
async fn a_probe_is_sent_while_the_verdict_is_up() {
    let stub = StubSocks5::start().await;
    let _hop = UpstreamHop::start(
        published(stub.addr()),
        verdict(HealthState::Up),
        EAGER,
        PATIENT,
    );

    tokio::time::sleep(Duration::from_millis(300)).await;

    let probes = stub.requests();
    assert!(
        !probes.is_empty(),
        "the patrol must probe a healthy upstream too"
    );
    assert_eq!(stub.client_dials(), Vec::new());
}

#[tokio::test]
async fn a_cold_start_reaches_up_shortly_after_the_confirm_delay() {
    let stub = StubSocks5::start().await;
    let health = HealthHandle::default();
    let _hop = UpstreamHop::start(published(stub.addr()), health.clone(), PATIENT, SNAPPY);
    let started = Instant::now();

    await_state(&health, HealthState::Up, SNAPPY + GRACE).await;

    let waited = started.elapsed();
    assert!(
        waited >= SNAPPY,
        "two probes must be a confirm delay apart: {waited:?}"
    );
}

#[tokio::test]
async fn an_upstream_published_after_the_hop_starts_is_probed_without_waiting_an_interval() {
    let live = LiveUpstream::default();
    let health = HealthHandle::default();
    let _hop = UpstreamHop::start(live.clone(), health.clone(), PROBE_INTERVAL, SNAPPY);
    let stub = StubSocks5::start().await;
    tokio::time::sleep(SNAPPY).await;
    live.publish(stub.addr());
    let started = Instant::now();

    await_state(&health, HealthState::Up, Duration::from_secs(2)).await;

    let waited = started.elapsed();
    assert!(
        waited < PROBE_INTERVAL,
        "the address published after the hop started must not wait out an interval: {waited:?}"
    );
}

#[tokio::test]
async fn an_upstream_that_answers_exactly_once_never_flips_the_verdict_up() {
    let stub = StubSocks5::answering(Answers::Once).await;
    let health = HealthHandle::default();
    let _hop = UpstreamHop::start(published(stub.addr()), health.clone(), EAGER, SNAPPY);

    tokio::time::sleep(Duration::from_millis(600)).await;

    assert_eq!(health.state(), HealthState::Down);
    assert_eq!(stub.requests().len(), 1);
}

#[tokio::test]
async fn a_vanished_upstream_reaches_down_inside_the_stated_budget() {
    let health = verdict(HealthState::Up);
    let _hop = UpstreamHop::start(
        published(closed_port().await),
        health.clone(),
        EAGER,
        SNAPPY,
    );
    let started = Instant::now();

    await_state(&health, HealthState::Down, EAGER + SNAPPY + GRACE).await;

    let waited = started.elapsed();
    assert!(
        waited >= SNAPPY,
        "an upstream that refuses fast still costs two probes a confirm delay apart: {waited:?}"
    );
}

#[tokio::test]
async fn an_upstream_that_never_answers_is_discovered_by_the_patrol() {
    let mute = StubSocks5::answering(Answers::Never).await;
    let health = verdict(HealthState::Up);
    let _hop = UpstreamHop::start(published(mute.addr()), health.clone(), EAGER, SNAPPY);
    let started = Instant::now();

    await_state(
        &health,
        HealthState::Down,
        EAGER + SNAPPY + 2 * PROBE_TIMEOUT + GRACE,
    )
    .await;

    let waited = started.elapsed();
    assert!(
        waited >= 2 * PROBE_TIMEOUT,
        "both observations must have waited out the probe timeout: {waited:?}"
    );
}

#[tokio::test]
async fn one_missed_probe_leaves_the_verdict_up() {
    let stub = StubSocks5::answering(Answers::AfterOneDrop).await;
    let health = verdict(HealthState::Up);
    let hop = UpstreamHop::start(published(stub.addr()), health.clone(), EAGER, SNAPPY);

    tokio::time::sleep(Duration::from_millis(400)).await;

    assert_eq!(health.state(), HealthState::Up);
    let dialled = dial(&hop, &Host("example.com".to_owned()), Port(443), require(0))
        .await
        .unwrap();
    assert_eq!(dialled.peer_addr().unwrap(), stub.addr());
}

#[tokio::test]
async fn a_verdict_that_moves_mid_sequence_still_needs_two_agreeing_probes() {
    let stub = StubSocks5::answering(Answers::AfterOneDrop).await;
    let live = published(stub.addr());
    let health = verdict(HealthState::Up);
    let hop = UpstreamHop::start(live.clone(), health.clone(), PATIENT, DELIBERATE);
    tokio::time::sleep(SNAPPY).await;
    assert_eq!(
        health.state(),
        HealthState::Up,
        "one missed probe must not move the verdict"
    );

    live.publish(closed_port().await);
    let failure = dial(&hop, &Host("example.com".to_owned()), Port(443), require(0))
        .await
        .unwrap_err();
    assert!(
        UpstreamDown::carried_by(&failure).is_some(),
        "{failure} must carry the upstream-down surface"
    );
    assert_eq!(
        health.state(),
        HealthState::Down,
        "a real dial failure still flips down on one failure"
    );
    live.publish(stub.addr());

    tokio::time::sleep(DELIBERATE).await;
    assert_eq!(
        health.state(),
        HealthState::Down,
        "the probe confirming a sequence banked against Up must not raise a Down verdict"
    );
    await_state(&health, HealthState::Up, DELIBERATE + GRACE).await;
}

#[tokio::test]
async fn a_sequence_banked_against_one_upstream_is_not_closed_by_the_next() {
    let live = published(closed_port().await);
    let health = verdict(HealthState::Up);
    let _hop = UpstreamHop::start(live.clone(), health.clone(), PATIENT, DELIBERATE);
    tokio::time::sleep(SNAPPY).await;

    live.publish(closed_port().await);

    tokio::time::sleep(DELIBERATE + SNAPPY).await;
    assert_eq!(
        health.state(),
        HealthState::Up,
        "the first probe of a replaced upstream must not close a sequence banked against the one before it"
    );
    await_state(&health, HealthState::Down, DELIBERATE + GRACE).await;
}

#[tokio::test]
async fn a_dial_to_a_black_holed_upstream_fails_within_three_seconds() {
    let origin = StubOrigin::start().await;
    let blackhole: SocketAddr = "192.0.2.1:1080".parse().unwrap();
    let hop = hop(blackhole, HealthState::Up);
    let (host, port) = named(origin.addr());
    let started = Instant::now();

    let dialled = dial(&hop, &host, port, prefer(0)).await.unwrap();

    let waited = started.elapsed();
    assert!(waited < Duration::from_secs(3), "waited {waited:?}");
    assert_eq!(dialled.peer_addr().unwrap(), origin.addr());
    assert_eq!(hop.health().state(), HealthState::Down);
}

#[tokio::test]
async fn a_require_dial_is_served_by_a_slow_upstream() {
    let stub = StubSocks5::answering(Answers::Slow(Duration::from_secs(3))).await;
    let hop = hop(stub.addr(), HealthState::Down);

    let dialled = dial(&hop, &Host("example.com".to_owned()), Port(443), require(3))
        .await
        .unwrap();

    assert_eq!(dialled.peer_addr().unwrap(), stub.addr());
    assert_eq!(
        stub.client_dials(),
        vec![SocksRequest {
            atyp: 0x03,
            host: "example.com".to_owned(),
            port: 443,
        }]
    );
    assert_eq!(hop.health().state(), HealthState::Up);
}

#[tokio::test]
async fn a_prefer_dial_leaves_a_slow_upstream_for_the_direct_route() {
    let stub = StubSocks5::answering(Answers::Slow(Duration::from_secs(3))).await;
    let origin = StubOrigin::start().await;
    let hop = hop(stub.addr(), HealthState::Up);
    let (host, port) = named(origin.addr());
    let started = Instant::now();

    let dialled = dial(&hop, &host, port, prefer(4)).await.unwrap();

    let waited = started.elapsed();
    assert_eq!(dialled.peer_addr().unwrap(), origin.addr());
    assert!(
        waited >= PREFER_CONNECT_TIMEOUT,
        "the direct route is taken only once the prefer budget is spent: {waited:?}"
    );
    assert!(
        waited < Duration::from_secs(3),
        "a prefer dial must not wait out an upstream slower than its budget: {waited:?}"
    );
    assert_eq!(hop.health().state(), HealthState::Down);
}

#[tokio::test(start_paused = true)]
async fn a_require_dial_into_a_black_hole_costs_the_require_budget() {
    let stub = StubSocks5::answering(Answers::Never).await;
    let hop = hop(stub.addr(), HealthState::Down);
    let started = tokio::time::Instant::now();

    let dialled = hop
        .dial(&Host("example.com".to_owned()), Port(443), require(5))
        .await;

    let Dialled::Attempted(next) = dialled else {
        panic!("a configured upstream must be dialled whatever the verdict says");
    };
    let failure = next.unwrap_err();
    assert!(
        UpstreamDown::carried_by(&failure).is_some(),
        "{failure} must carry the upstream-down surface"
    );
    assert_eq!(started.elapsed(), REQUIRE_CONNECT_TIMEOUT);
    assert_eq!(hop.health().state(), HealthState::Down);
}
