mod support;

use std::net::SocketAddr;
use std::sync::Arc;

use nhop::proxy::{ConnCtx, EventTx, NextHop, http};
use nhop::rules::{RuleClass, RuleKind, RuleValue, Ruleset};
use nhop::upstream::HealthHandle;
use nhop_ipc::{Command, ErrKind, Paths, Response};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use support::{DownHop, StubOrigin, TestDaemon, ephemeral};

const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";

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
        let _served = http::serve(stream, ctx, hop.as_ref()).await;
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

async fn establish(front: SocketAddr, destination: SocketAddr) -> TcpStream {
    let mut client = TcpStream::connect(front).await.unwrap();
    let request = format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    let mut established = [0u8; ESTABLISHED.len()];
    client.read_exact(&mut established).await.unwrap();
    assert_eq!(&established, ESTABLISHED);
    client
}

async fn answer_of(front: SocketAddr, request: &str) -> String {
    let mut client = TcpStream::connect(front).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    let mut answer = String::new();
    client.read_to_string(&mut answer).await.unwrap();
    answer
}

async fn echoed(mut client: TcpStream, payload: &[u8]) -> Vec<u8> {
    client.write_all(payload).await.unwrap();
    client.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    client.read_to_end(&mut echoed).await.unwrap();
    echoed
}

async fn status_of(daemon: &TestDaemon) -> (SocketAddr, SocketAddr) {
    let Response::Status(status) = daemon.call(Command::Status).await else {
        panic!("status must answer with a status view");
    };
    assert!(status.http_bound);
    assert!(status.socks_bound);
    (status.http_listen, status.socks_listen)
}

#[tokio::test]
async fn a_connect_request_tunnels_to_the_destination() {
    let (_home, paths) = temp_paths();
    let origin = StubOrigin::start().await;
    let daemon = TestDaemon::start(&paths, ephemeral()).await;

    let client = establish(daemon.http_addr(), origin.addr()).await;

    assert_eq!(echoed(client, b"ping").await, b"ping");
    assert_eq!(origin.connections(), 1);
    daemon.shutdown().await;
}

#[tokio::test]
async fn an_absolute_form_request_is_forwarded_verbatim() {
    let (_home, paths) = temp_paths();
    let origin = StubOrigin::start().await;
    let daemon = TestDaemon::start(&paths, ephemeral()).await;
    let request = format!(
        "GET http://{origin}/index.html HTTP/1.1\r\nHost: {origin}\r\nAccept: */*\r\n\r\n",
        origin = origin.addr()
    );

    let client = TcpStream::connect(daemon.http_addr()).await.unwrap();

    let relayed = echoed(client, request.as_bytes()).await;
    assert_eq!(String::from_utf8(relayed).unwrap(), request);
    assert_eq!(origin.connections(), 1);
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_second_request_on_the_same_connection_is_not_forwarded() {
    let (_home, paths) = temp_paths();
    let origin = StubOrigin::start().await;
    let daemon = TestDaemon::start(&paths, ephemeral()).await;
    let first = format!(
        "GET http://{origin}/first HTTP/1.1\r\nHost: {origin}\r\n\r\n",
        origin = origin.addr()
    );
    let second = format!(
        "GET http://{origin}/second HTTP/1.1\r\nHost: {origin}\r\n\r\n",
        origin = origin.addr()
    );

    let client = TcpStream::connect(daemon.http_addr()).await.unwrap();

    let relayed = echoed(client, format!("{first}{second}").as_bytes()).await;
    assert_eq!(String::from_utf8(relayed).unwrap(), first);
    assert_eq!(origin.connections(), 1);
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_malformed_request_line_is_answered_with_400() {
    let (_home, paths) = temp_paths();
    let daemon = TestDaemon::start(&paths, ephemeral()).await;

    let answer = answer_of(daemon.http_addr(), "GARBAGE\r\n\r\n").await;

    assert!(answer.starts_with("HTTP/1.1 400 Bad Request"), "{answer}");
    assert!(answer.ends_with("nhop: malformed request"), "{answer}");
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_head_over_the_cap_closes_the_connection() {
    let (_home, paths) = temp_paths();
    let daemon = TestDaemon::start(&paths, ephemeral()).await;
    let head = vec![b'a'; http::HEAD_LIMIT];

    let mut client = TcpStream::connect(daemon.http_addr()).await.unwrap();
    client.write_all(&head).await.unwrap();
    let mut answer = Vec::new();
    let _closed = client.read_to_end(&mut answer).await;

    assert!(answer.is_empty(), "{answer:?}");
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_destination_that_refuses_the_dial_is_answered_with_502() {
    let (_home, paths) = temp_paths();
    let daemon = TestDaemon::start(&paths, ephemeral()).await;
    let closed = closed_port().await;

    let answer = answer_of(
        daemon.http_addr(),
        &format!("CONNECT {closed} HTTP/1.1\r\n\r\n"),
    )
    .await;

    assert!(answer.starts_with("HTTP/1.1 502 Bad Gateway"), "{answer}");
    assert!(
        answer.ends_with(&format!("nhop: cannot reach {closed}")),
        "{answer}"
    );
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_require_rule_is_refused_with_502_while_the_upstream_is_down() {
    let upstream: SocketAddr = "192.0.2.10:1080".parse().unwrap();
    let ctx = ConnCtx {
        rules: Arc::new(require("example.com")),
        health: HealthHandle::default(),
        upstream,
        events: EventTx::default(),
    };
    let front = serve_once(ctx, Arc::new(DownHop::new(upstream))).await;

    let answer = answer_of(front, "CONNECT example.com:443 HTTP/1.1\r\n\r\n").await;

    assert!(answer.starts_with("HTTP/1.1 502 Bad Gateway"), "{answer}");
    assert!(
        answer.ends_with("nhop: upstream 192.0.2.10:1080 is down (require rule 0)"),
        "{answer}"
    );
}

#[tokio::test]
async fn moving_the_front_ends_keeps_an_open_connection_alive() {
    let (_home, paths) = temp_paths();
    let origin = StubOrigin::start().await;
    let daemon = TestDaemon::start(&paths, ephemeral()).await;
    let (was_http, _was_socks) = status_of(&daemon).await;
    let client = establish(was_http, origin.addr()).await;

    let moved = daemon
        .call(Command::SetListen {
            http: ephemeral(),
            socks: ephemeral(),
            load: None,
        })
        .await;

    assert_eq!(moved, Response::Ok);
    let (now_http, now_socks) = status_of(&daemon).await;
    assert_ne!(now_http, was_http);
    assert_ne!(now_http.port(), 0);
    assert_ne!(now_socks.port(), 0);
    assert!(TcpStream::connect(was_http).await.is_err());
    assert_eq!(echoed(client, b"ping").await, b"ping");
    let moved_client = establish(now_http, origin.addr()).await;
    assert_eq!(echoed(moved_client, b"pong").await, b"pong");
    assert_eq!(origin.connections(), 2);
    daemon.shutdown().await;
}

#[tokio::test]
async fn an_address_that_cannot_be_bound_leaves_the_front_ends_where_they_are() {
    let (_home, paths) = temp_paths();
    let origin = StubOrigin::start().await;
    let daemon = TestDaemon::start(&paths, ephemeral()).await;
    let (was_http, was_socks) = status_of(&daemon).await;
    let squatter = TcpListener::bind(ephemeral()).await.unwrap();

    let refused = daemon
        .call(Command::SetListen {
            http: squatter.local_addr().unwrap(),
            socks: ephemeral(),
            load: None,
        })
        .await;

    let Response::Err { kind, message } = refused else {
        panic!("a held address must be refused: {refused:?}");
    };
    assert_eq!(kind, ErrKind::Internal);
    assert!(message.contains("front ends"), "{message}");
    assert_eq!(status_of(&daemon).await, (was_http, was_socks));
    let client = establish(was_http, origin.addr()).await;
    assert_eq!(echoed(client, b"ping").await, b"ping");
    daemon.shutdown().await;
}
