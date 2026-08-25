mod support;

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use nhop::proxy::{ConnCtx, EventTx, NextHop, socks5};
use nhop::rules::{Decision, Host, Port, RuleClass, RuleId, RuleKind, RuleValue, Ruleset};
use nhop::upstream::HealthHandle;
use nhop_ipc::{EventView, Paths};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use support::{DownHop, Refusal, StubHop, StubOrigin, TestDaemon, ephemeral};

const GREETING: [u8; 3] = [0x05, 0x01, 0x00];
const GRANTED: [u8; 10] = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
const NOT_ALLOWED: [u8; 10] = [0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
const HOST_UNREACHABLE: [u8; 10] = [0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
const PATIENCE: Duration = Duration::from_secs(5);

/// How long a tunnel is held open, and how long a failing dial is made to take.
const HELD_MS: u64 = 300;

fn temp_paths() -> (TempDir, Paths) {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(home.path());
    (home, paths)
}

async fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind(ephemeral()).await.unwrap();
    listener.local_addr().unwrap()
}

async fn serve_once(ctx: ConnCtx, hop: Arc<dyn NextHop>) -> SocketAddr {
    let listener = TcpListener::bind(ephemeral()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((stream, _peer)) = listener.accept().await else {
            return;
        };
        let _served = socks5::serve(stream, ctx, hop.as_ref()).await;
    });
    addr
}

fn require(value: &str) -> Ruleset {
    let mut rules = Ruleset::default();
    rules
        .push(
            RuleClass::Require,
            RuleKind::Suffix,
            RuleValue(value.to_owned()),
        )
        .unwrap();
    rules
}

fn ctx_of(rules: Ruleset, upstream: SocketAddr) -> ConnCtx {
    ConnCtx {
        rules: Arc::new(rules),
        health: HealthHandle::default(),
        upstream,
        events: EventTx::default(),
    }
}

fn watched(rules: Ruleset, upstream: SocketAddr) -> (ConnCtx, mpsc::Receiver<EventView>) {
    let events = EventTx::default();
    let decisions = events.subscribe();
    let ctx = ConnCtx {
        rules: Arc::new(rules),
        health: HealthHandle::default(),
        upstream,
        events,
    };
    (ctx, decisions)
}

async fn next_decision(decisions: &mut mpsc::Receiver<EventView>) -> EventView {
    let Ok(published) = tokio::time::timeout(PATIENCE, decisions.recv()).await else {
        panic!("the connection published no decision");
    };
    let Some(event) = published else {
        panic!("the decision stream ended before the connection was routed");
    };
    event
}

fn ipv4_request(addr: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(addr) = addr else {
        panic!("the harness listens on IPv4: {addr}");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&addr.ip().octets());
    request.extend_from_slice(&addr.port().to_be_bytes());
    request
}

fn domain_request(name: &str, port: u16) -> Vec<u8> {
    let mut request = vec![0x05, 0x01, 0x00, 0x03, name.len() as u8];
    request.extend_from_slice(name.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    request
}

fn ipv6_request(addr: Ipv6Addr, port: u16) -> Vec<u8> {
    let mut request = vec![0x05, 0x01, 0x00, 0x04];
    request.extend_from_slice(&addr.octets());
    request.extend_from_slice(&port.to_be_bytes());
    request
}

async fn handshake(front: SocketAddr) -> TcpStream {
    let mut client = TcpStream::connect(front).await.unwrap();
    client.write_all(&GREETING).await.unwrap();
    let mut chosen = [0u8; 2];
    client.read_exact(&mut chosen).await.unwrap();
    assert_eq!(chosen, [0x05, 0x00]);
    client
}

async fn reply_to(front: SocketAddr, request: &[u8]) -> [u8; 10] {
    let mut client = handshake(front).await;
    client.write_all(request).await.unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    reply
}

async fn connected(front: SocketAddr, request: &[u8]) -> TcpStream {
    let mut client = handshake(front).await;
    client.write_all(request).await.unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, GRANTED);
    client
}

async fn echoed(mut client: TcpStream, payload: &[u8]) -> Vec<u8> {
    client.write_all(payload).await.unwrap();
    client.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    client.read_to_end(&mut echoed).await.unwrap();
    echoed
}

#[tokio::test]
async fn an_ipv4_request_tunnels_to_the_destination() {
    let (_home, paths) = temp_paths();
    let origin = StubOrigin::start().await;
    let daemon = TestDaemon::start(&paths, ephemeral()).await;

    let client = connected(daemon.socks_addr(), &ipv4_request(origin.addr())).await;

    assert_eq!(echoed(client, b"ping").await, b"ping");
    assert_eq!(origin.connections(), 1);
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_domain_request_reaches_the_next_hop_as_a_name() {
    let origin = StubOrigin::start().await;
    let hop = Arc::new(StubHop::new(origin.addr()));
    let front = serve_once(ctx_of(require("example.com"), ephemeral()), hop.clone()).await;

    let client = connected(front, &domain_request("example.com", 443)).await;

    assert_eq!(echoed(client, b"ping").await, b"ping");
    assert_eq!(
        hop.asked(),
        vec![(
            Host("example.com".to_owned()),
            Port(443),
            Decision::Upstream {
                class: RuleClass::Require,
                rule: RuleId(0),
            },
        )]
    );
}

#[tokio::test]
async fn an_ipv6_request_reaches_the_next_hop_as_an_address() {
    let origin = StubOrigin::start().await;
    let hop = Arc::new(StubHop::new(origin.addr()));
    let front = serve_once(ctx_of(Ruleset::default(), ephemeral()), hop.clone()).await;

    let client = connected(front, &ipv6_request(Ipv6Addr::LOCALHOST, 80)).await;

    assert_eq!(echoed(client, b"ping").await, b"ping");
    assert_eq!(
        hop.asked(),
        vec![(Host("::1".to_owned()), Port(80), Decision::Direct)]
    );
}

#[tokio::test]
async fn an_ipv4_request_reaches_the_next_hop_as_an_address() {
    let origin = StubOrigin::start().await;
    let hop = Arc::new(StubHop::new(origin.addr()));
    let front = serve_once(ctx_of(Ruleset::default(), ephemeral()), hop.clone()).await;

    let client = connected(front, &ipv4_request("127.0.0.1:8443".parse().unwrap())).await;

    assert_eq!(echoed(client, b"ping").await, b"ping");
    assert_eq!(
        hop.asked(),
        vec![(Host("127.0.0.1".to_owned()), Port(8443), Decision::Direct)]
    );
}

#[tokio::test]
async fn a_request_for_the_front_ends_own_address_is_refused_before_any_dial() {
    let origin = StubOrigin::start().await;
    let hop = Arc::new(StubHop::new(origin.addr()));
    let front = serve_once(ctx_of(Ruleset::default(), ephemeral()), hop.clone()).await;

    let reply = reply_to(front, &ipv4_request(front)).await;

    assert_eq!(reply, NOT_ALLOWED);
    assert_eq!(hop.asked(), Vec::new(), "the loop must reach no next hop");
    assert_eq!(origin.connections(), 0);
}

#[tokio::test]
async fn the_front_ends_own_address_by_name_is_refused_identically() {
    let origin = StubOrigin::start().await;
    let hop = Arc::new(StubHop::new(origin.addr()));
    let front = serve_once(ctx_of(Ruleset::default(), ephemeral()), hop.clone()).await;

    let reply = reply_to(front, &domain_request("localhost", front.port())).await;

    assert_eq!(reply, NOT_ALLOWED);
    assert_eq!(hop.asked(), Vec::new(), "the loop must reach no next hop");
    assert_eq!(origin.connections(), 0);
}

#[tokio::test]
async fn a_bind_request_is_refused_as_a_command_not_supported() {
    let (_home, paths) = temp_paths();
    let daemon = TestDaemon::start(&paths, ephemeral()).await;
    let mut request = ipv4_request("127.0.0.1:443".parse().unwrap());
    request[1] = 0x02;

    let reply = reply_to(daemon.socks_addr(), &request).await;

    assert_eq!(reply, [0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_udp_associate_request_is_refused_as_a_command_not_supported() {
    let (_home, paths) = temp_paths();
    let daemon = TestDaemon::start(&paths, ephemeral()).await;
    let mut request = ipv4_request("127.0.0.1:443".parse().unwrap());
    request[1] = 0x03;

    let reply = reply_to(daemon.socks_addr(), &request).await;

    assert_eq!(reply, [0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    daemon.shutdown().await;
}

#[tokio::test]
async fn an_unknown_address_type_is_refused() {
    let (_home, paths) = temp_paths();
    let daemon = TestDaemon::start(&paths, ephemeral()).await;

    let reply = reply_to(daemon.socks_addr(), &[0x05, 0x01, 0x00, 0x02, 0, 0]).await;

    assert_eq!(reply, [0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_client_offering_no_supported_method_is_turned_away() {
    let (_home, paths) = temp_paths();
    let daemon = TestDaemon::start(&paths, ephemeral()).await;

    let mut client = TcpStream::connect(daemon.socks_addr()).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut answer = Vec::new();
    client.read_to_end(&mut answer).await.unwrap();

    assert_eq!(answer, vec![0x05, 0xff]);
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_destination_that_refuses_the_dial_is_answered_with_a_general_failure() {
    let (_home, paths) = temp_paths();
    let daemon = TestDaemon::start(&paths, ephemeral()).await;
    let closed = closed_port().await;

    let reply = reply_to(daemon.socks_addr(), &ipv4_request(closed)).await;

    assert_eq!(reply, [0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_require_rule_is_refused_as_host_unreachable_while_the_upstream_is_down() {
    let upstream: SocketAddr = "192.0.2.10:1080".parse().unwrap();
    let front = serve_once(
        ctx_of(require("example.com"), upstream),
        Arc::new(DownHop::new(upstream, Refusal::BeforeDialling)),
    )
    .await;

    let reply = reply_to(front, &domain_request("example.com", 443)).await;

    assert_eq!(reply, [0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
}

#[tokio::test]
async fn the_dial_time_covers_the_dial_alone_while_the_duration_covers_the_whole_connection() {
    let origin = StubOrigin::start().await;
    let hop = Arc::new(StubHop::new(origin.addr()));
    let (ctx, mut decisions) = watched(Ruleset::default(), ephemeral());
    let front = serve_once(ctx, hop).await;

    let client = connected(front, &ipv4_request(origin.addr())).await;
    tokio::time::sleep(Duration::from_millis(HELD_MS)).await;
    assert_eq!(echoed(client, b"ping").await, b"ping");

    let event = next_decision(&mut decisions).await;
    let Some(connect_ms) = event.connect_ms else {
        panic!("a tunnel that dialled must report its dial time: {event:?}");
    };
    assert!(event.duration_ms >= HELD_MS, "{event:?}");
    assert!(connect_ms < HELD_MS, "{event:?}");
}

#[tokio::test]
async fn a_require_refusal_reports_no_dial_time() {
    let upstream: SocketAddr = "192.0.2.10:1080".parse().unwrap();
    let (ctx, mut decisions) = watched(require("example.com"), upstream);
    let front = serve_once(
        ctx,
        Arc::new(DownHop::new(upstream, Refusal::BeforeDialling)),
    )
    .await;

    let reply = reply_to(front, &domain_request("example.com", 443)).await;

    assert_eq!(reply, HOST_UNREACHABLE);
    let event = next_decision(&mut decisions).await;
    assert_eq!(event.connect_ms, None, "{event:?}");
}

#[tokio::test]
async fn a_dial_that_failed_upstream_side_still_reports_what_it_cost() {
    let upstream: SocketAddr = "192.0.2.10:1080".parse().unwrap();
    let (ctx, mut decisions) = watched(require("example.com"), upstream);
    let front = serve_once(
        ctx,
        Arc::new(DownHop::new(
            upstream,
            Refusal::AfterDialling(Duration::from_millis(HELD_MS)),
        )),
    )
    .await;

    let reply = reply_to(front, &domain_request("example.com", 443)).await;

    assert_eq!(reply, HOST_UNREACHABLE);
    let event = next_decision(&mut decisions).await;
    let Some(connect_ms) = event.connect_ms else {
        panic!("a dial that was made and then failed must still report its time: {event:?}");
    };
    assert!(connect_ms >= HELD_MS, "{event:?}");
}
