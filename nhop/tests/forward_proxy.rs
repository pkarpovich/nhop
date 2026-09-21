mod support;

use std::net::SocketAddr;
use std::time::Duration;

use nhop_ipc::{
    Command, DecisionKind, EffectiveHop, EventView, ForwardView, Host, Paths, Port, Response,
    RuleClass, RuleKind, RuleValue,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use support::{SocksRequest, StubOrigin, StubSocks5, TestDaemon, ephemeral};

const PATIENCE: Duration = Duration::from_secs(5);

fn temp_paths() -> (TempDir, Paths) {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(home.path());
    (home, paths)
}

async fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind(ephemeral()).await.unwrap();
    listener.local_addr().unwrap()
}

async fn forward(daemon: &TestDaemon, listen: SocketAddr, host: &str, port: u16) -> SocketAddr {
    let answer = daemon
        .call(Command::AddForward {
            listen,
            host: Host(host.to_owned()),
            port: Port(port),
            load: None,
        })
        .await;
    assert_eq!(answer, Response::Ok, "the forward must be accepted");
    let Response::Status(status) = daemon.call(Command::Status).await else {
        panic!("status must answer with a status view");
    };
    let [
        ForwardView {
            listen,
            host: _,
            port: _,
        },
    ] = status.forwards.as_slice()
    else {
        panic!("one forward must be held: {:?}", status.forwards);
    };
    *listen
}

async fn require_suffix(daemon: &TestDaemon, suffix: &str) {
    let answer = daemon
        .call(Command::AddRule {
            class: RuleClass::Require,
            kind: RuleKind::Suffix,
            value: RuleValue(suffix.to_owned()),
            load: None,
        })
        .await;
    assert_eq!(answer, Response::Ok, "the rule must be accepted");
}

async fn echoed(mut client: TcpStream, payload: &[u8]) -> Vec<u8> {
    client.write_all(payload).await.unwrap();
    client.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    client.read_to_end(&mut echoed).await.unwrap();
    echoed
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

#[tokio::test]
async fn a_forward_routes_its_destination_by_the_rules_through_the_upstream() {
    let (_home, paths) = temp_paths();
    let upstream = StubSocks5::start().await;
    let daemon = TestDaemon::start(&paths, upstream.addr()).await;
    require_suffix(&daemon, "example.com").await;
    let listen = forward(&daemon, ephemeral(), "api.example.com", 9000).await;
    let mut decisions = daemon.state().live().events().subscribe();

    let client = TcpStream::connect(listen).await.unwrap();
    assert_eq!(echoed(client, b"ping").await, b"ping");

    assert_eq!(
        upstream.client_dials(),
        vec![SocksRequest {
            atyp: 0x03,
            host: "api.example.com".to_owned(),
            port: 9000,
        }]
    );
    let routed = next_decision(&mut decisions).await;
    assert_eq!(routed.host, Host("api.example.com".to_owned()));
    assert_eq!(routed.port, Port(9000));
    assert_eq!(routed.decision, DecisionKind::Upstream);
    assert_eq!(routed.class, Some(RuleClass::Require));
    assert_eq!(routed.hop, Some(EffectiveHop::Upstream));
    assert_eq!(routed.error, None);

    daemon.shutdown().await;
}

#[tokio::test]
async fn a_forward_with_no_matching_rule_dials_its_destination_directly() {
    let (_home, paths) = temp_paths();
    let upstream = StubSocks5::start().await;
    let origin = StubOrigin::start().await;
    let daemon = TestDaemon::start(&paths, upstream.addr()).await;
    let listen = forward(
        &daemon,
        ephemeral(),
        &origin.addr().ip().to_string(),
        origin.addr().port(),
    )
    .await;

    let client = TcpStream::connect(listen).await.unwrap();
    assert_eq!(echoed(client, b"ping").await, b"ping");

    assert_eq!(origin.connections(), 1);
    assert_eq!(upstream.client_dials(), Vec::new());

    daemon.shutdown().await;
}

#[tokio::test]
async fn a_forward_whose_dial_fails_closes_the_client_and_logs_the_failure() {
    let (_home, paths) = temp_paths();
    let upstream = StubSocks5::start().await;
    let daemon = TestDaemon::start(&paths, upstream.addr()).await;
    let gone = closed_port().await;
    let listen = forward(&daemon, ephemeral(), &gone.ip().to_string(), gone.port()).await;
    let mut decisions = daemon.state().live().events().subscribe();

    let mut client = TcpStream::connect(listen).await.unwrap();
    let mut read = Vec::new();
    let _closed = client.read_to_end(&mut read).await;

    assert!(read.is_empty(), "{read:?}");
    let routed = next_decision(&mut decisions).await;
    assert_eq!(routed.decision, DecisionKind::Direct);
    assert!(routed.connect_ms.is_some());
    assert!(routed.error.is_some(), "{routed:?}");

    daemon.shutdown().await;
}

#[tokio::test]
async fn a_forward_pointed_at_its_own_address_refuses_without_dialling() {
    let (_home, paths) = temp_paths();
    let upstream = StubSocks5::start().await;
    let daemon = TestDaemon::start(&paths, upstream.addr()).await;
    let own = closed_port().await;
    let listen = forward(&daemon, own, &own.ip().to_string(), own.port()).await;
    assert_eq!(listen, own);
    let mut decisions = daemon.state().live().events().subscribe();

    let mut client = TcpStream::connect(listen).await.unwrap();
    let mut read = Vec::new();
    let _closed = client.read_to_end(&mut read).await;

    let routed = next_decision(&mut decisions).await;
    assert_eq!(routed.connect_ms, None);
    let Some(error) = routed.error else {
        panic!("a loop must be recorded as a failure: {routed:?}");
    };
    assert!(error.contains("own listening address"), "{error}");

    daemon.shutdown().await;
}
