mod support;

use std::net::SocketAddr;
use std::time::Duration;

use nhop_ipc::{
    CheckView, Command, DecisionKind, DecisionView, EventView, HealthState, Host, Paths, Port,
    Response, RuleClass, RuleCountsView, RuleKind, RuleValue, StatusView,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use support::{SocksRequest, StubOrigin, StubSocks5, TestDaemon, ephemeral};

const GREETING: [u8; 3] = [0x05, 0x01, 0x00];
const GRANTED: [u8; 10] = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
const UNREACHABLE: [u8; 10] = [0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

const PATIENCE: Duration = Duration::from_secs(5);

const CHECKS: [&str; 7] = [
    "daemon_reachable",
    "ports_bound",
    "system_proxy",
    "upstream_reachable",
    "init_file",
    "last_load",
    "log_writable",
];

fn temp_paths() -> (TempDir, Paths) {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(home.path());
    (home, paths)
}

async fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind(ephemeral()).await.unwrap();
    listener.local_addr().unwrap()
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

fn asked_for(addr: SocketAddr) -> SocksRequest {
    SocksRequest {
        atyp: 0x01,
        host: addr.ip().to_string(),
        port: addr.port(),
    }
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

async fn relayed(front: SocketAddr, destination: SocketAddr) {
    let client = connected(front, &ipv4_request(destination)).await;
    assert_eq!(echoed(client, b"ping").await, b"ping");
}

async fn add_rule(daemon: &TestDaemon, class: RuleClass, destination: SocketAddr) {
    let answer = daemon
        .call(Command::AddRule {
            class,
            kind: RuleKind::Port,
            value: RuleValue(destination.port().to_string()),
            load: None,
        })
        .await;
    assert_eq!(answer, Response::Ok, "the rule must be accepted");
}

async fn decision_of(daemon: &TestDaemon, destination: SocketAddr) -> DecisionView {
    let answer = daemon
        .call(Command::Test {
            host: Host(destination.ip().to_string()),
            port: Port(destination.port()),
        })
        .await;
    let Response::Decision(decision) = answer else {
        panic!("test must answer with a decision view: {answer:?}");
    };
    decision
}

fn through(class: RuleClass, upstream: SocketAddr) -> DecisionView {
    DecisionView {
        decision: DecisionKind::Upstream,
        rule_index: Some(0),
        class: Some(class),
        next_hop: format!("socks5://{upstream}"),
    }
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

fn same_decision(asked: &DecisionView, routed: &EventView) {
    let DecisionView {
        decision,
        rule_index,
        class,
        next_hop: _,
    } = asked;
    let EventView {
        host: _,
        port: _,
        decision: taken,
        rule_index: taken_index,
        class: taken_class,
        upstream: _,
        connect_ms: _,
        hop: _,
        duration_ms: _,
        error: _,
    } = routed;
    assert_eq!(taken, decision, "test must report the decision that routed");
    assert_eq!(
        taken_index, rule_index,
        "test must report the rule that matched"
    );
    assert_eq!(
        taken_class, class,
        "test must report the class that matched"
    );
}

async fn status_of(daemon: &TestDaemon) -> StatusView {
    let answer = daemon.call(Command::Status).await;
    let Response::Status(status) = answer else {
        panic!("status must answer with a status view: {answer:?}");
    };
    status
}

async fn diagnosed(paths: &Paths) -> Vec<CheckView> {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let _exit = nhop::cli::run(paths, &["doctor", "--json"], &mut out, &mut err).await;
    let out = String::from_utf8(out).unwrap();
    assert!(String::from_utf8(err).unwrap().is_empty());
    assert_eq!(out.lines().count(), 1, "{out}");
    serde_json::from_str(&out).unwrap()
}

fn names(checks: &[CheckView]) -> Vec<String> {
    let mut names = Vec::new();
    for CheckView {
        name,
        ok: _,
        detail: _,
    } in checks
    {
        names.push(name.clone());
    }
    names
}

fn passed(checks: &[CheckView], wanted: &str) -> bool {
    for CheckView {
        name,
        ok,
        detail: _,
    } in checks
    {
        if name == wanted {
            return *ok;
        }
    }
    panic!("the report must carry {wanted}");
}

#[tokio::test]
async fn require_reaches_upstream() {
    let (_home, paths) = temp_paths();
    let origin = StubOrigin::start().await;
    let upstream = StubSocks5::start().await;
    let daemon = TestDaemon::start(&paths, upstream.addr()).await;
    daemon.state().live().health().set(HealthState::Up);
    add_rule(&daemon, RuleClass::Require, origin.addr()).await;
    let mut decisions = daemon.state().live().events().subscribe();

    let decision = decision_of(&daemon, origin.addr()).await;
    relayed(daemon.socks_addr(), origin.addr()).await;

    assert_eq!(decision, through(RuleClass::Require, upstream.addr()));
    assert_eq!(upstream.client_dials(), vec![asked_for(origin.addr())]);
    assert_eq!(
        origin.connections(),
        0,
        "a require rule must not reach the destination itself"
    );
    same_decision(&decision, &next_decision(&mut decisions).await);

    let checks = diagnosed(&paths).await;
    assert_eq!(names(&checks), CHECKS);
    assert!(passed(&checks, "daemon_reachable"), "{checks:?}");
    assert!(passed(&checks, "ports_bound"), "{checks:?}");
    assert!(passed(&checks, "upstream_reachable"), "{checks:?}");

    daemon.shutdown().await;
}

#[tokio::test]
async fn prefer_reaches_upstream() {
    let (_home, paths) = temp_paths();
    let origin = StubOrigin::start().await;
    let upstream = StubSocks5::start().await;
    let daemon = TestDaemon::start(&paths, upstream.addr()).await;
    daemon.state().live().health().set(HealthState::Up);
    add_rule(&daemon, RuleClass::Prefer, origin.addr()).await;
    let mut decisions = daemon.state().live().events().subscribe();

    let decision = decision_of(&daemon, origin.addr()).await;
    relayed(daemon.socks_addr(), origin.addr()).await;

    assert_eq!(decision, through(RuleClass::Prefer, upstream.addr()));
    assert_eq!(upstream.client_dials(), vec![asked_for(origin.addr())]);
    assert_eq!(
        origin.connections(),
        0,
        "a prefer rule must take the upstream while the verdict is up"
    );
    same_decision(&decision, &next_decision(&mut decisions).await);

    daemon.shutdown().await;
}

#[tokio::test]
async fn prefer_falls_back_direct_when_upstream_closed() {
    let (_home, paths) = temp_paths();
    let origin = StubOrigin::start().await;
    let closed = closed_port().await;
    let daemon = TestDaemon::start(&paths, closed).await;
    add_rule(&daemon, RuleClass::Prefer, origin.addr()).await;
    let mut decisions = daemon.state().live().events().subscribe();

    let decision = decision_of(&daemon, origin.addr()).await;
    relayed(daemon.socks_addr(), origin.addr()).await;

    assert_eq!(decision, through(RuleClass::Prefer, closed));
    assert_eq!(
        origin.connections(),
        1,
        "a prefer rule must fall back to the destination itself"
    );
    same_decision(&decision, &next_decision(&mut decisions).await);

    daemon.shutdown().await;
}

#[tokio::test]
async fn require_fails_when_upstream_closed() {
    let (_home, paths) = temp_paths();
    let origin = StubOrigin::start().await;
    let closed = closed_port().await;
    let daemon = TestDaemon::start(&paths, closed).await;
    add_rule(&daemon, RuleClass::Require, origin.addr()).await;
    let mut decisions = daemon.state().live().events().subscribe();

    let decision = decision_of(&daemon, origin.addr()).await;
    let reply = reply_to(daemon.socks_addr(), &ipv4_request(origin.addr())).await;

    assert_eq!(reply, UNREACHABLE);
    assert_eq!(decision, through(RuleClass::Require, closed));
    assert_eq!(
        origin.connections(),
        0,
        "a require rule must fail rather than reach the destination itself"
    );
    same_decision(&decision, &next_decision(&mut decisions).await);

    assert_eq!(daemon.call(Command::Off).await, Response::Ok);

    let StatusView {
        uptime_secs: _,
        http_listen,
        http_bound,
        socks_listen,
        socks_bound,
        upstream: _,
        health: _,
        health_changed_at: _,
        init_path: _,
        last_load: _,
        rules,
        system_proxy: _,
    } = status_of(&daemon).await;
    assert!(
        http_bound,
        "clearing the rules must not close the http port"
    );
    assert!(
        socks_bound,
        "clearing the rules must not close the socks port"
    );
    assert_eq!(http_listen, daemon.http_addr());
    assert_eq!(socks_listen, daemon.socks_addr());
    assert_eq!(
        rules,
        RuleCountsView {
            require: 0,
            prefer: 0,
            never: 0,
        }
    );

    relayed(daemon.socks_addr(), origin.addr()).await;

    assert_eq!(
        decision_of(&daemon, origin.addr()).await,
        DecisionView {
            decision: DecisionKind::Direct,
            rule_index: None,
            class: None,
            next_hop: format!("{}:{}", origin.addr().ip(), origin.addr().port()),
        }
    );
    assert_eq!(
        origin.connections(),
        1,
        "a client on the socks port must get a direct connection, not a refusal"
    );

    daemon.shutdown().await;
}
