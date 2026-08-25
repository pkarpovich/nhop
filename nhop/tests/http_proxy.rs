mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use nhop::proxy::{ConnCtx, EventTx, NextHop, http};
use nhop::rules::{RuleClass, RuleKind, RuleValue, Ruleset};
use nhop::upstream::HealthHandle;
use nhop_ipc::{Command, DecisionKind, ErrKind, EventView, Paths, Response};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;

use support::{DownHop, Refusal, StubHop, StubHttpOrigin, StubOrigin, TestDaemon, ephemeral};

const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
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

async fn serve_once(ctx: ConnCtx, hop: Arc<dyn NextHop>) -> SocketAddr {
    serve_once_bound(ephemeral(), ctx, hop).await
}

async fn serve_once_bound(bind: SocketAddr, ctx: ConnCtx, hop: Arc<dyn NextHop>) -> SocketAddr {
    let listener = TcpListener::bind(bind).await.unwrap();
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

fn never(value: &str) -> Ruleset {
    let mut rules = Ruleset::default();
    rules
        .push(
            RuleClass::Never,
            RuleKind::Suffix,
            RuleValue(value.to_owned()),
        )
        .unwrap();
    rules
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
async fn an_absolute_form_request_is_rebuilt_for_the_origin() {
    let (_home, paths) = temp_paths();
    let origin = StubHttpOrigin::start().await;
    let daemon = TestDaemon::start(&paths, ephemeral()).await;
    let request = format!(
        "GET http://{origin}/index.html HTTP/1.1\r\nHost: stale.example\r\n\
         Proxy-Connection: Keep-Alive\r\nAccept: */*\r\n\r\n",
        origin = origin.addr()
    );

    let client = TcpStream::connect(daemon.http_addr()).await.unwrap();
    let answer = echoed(client, request.as_bytes()).await;

    let [seen] = origin
        .received()
        .try_into()
        .expect("one request reaches the origin");
    assert!(seen.starts_with("GET /index.html HTTP/1.1\r\n"), "{seen}");
    assert!(
        seen.contains(&format!("Host: {}\r\n", origin.addr())),
        "{seen}"
    );
    assert!(seen.contains("Connection: close\r\n"), "{seen}");
    assert!(
        !seen.to_ascii_lowercase().contains("proxy-connection"),
        "{seen}"
    );
    assert!(!seen.contains("stale.example"), "{seen}");
    assert!(seen.contains("Accept: */*\r\n"), "{seen}");
    assert!(
        String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 200 OK"),
        "the origin's answer reaches the client"
    );
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_request_body_arriving_with_its_head_reaches_the_origin() {
    let (_home, paths) = temp_paths();
    let origin = StubHttpOrigin::start().await;
    let daemon = TestDaemon::start(&paths, ephemeral()).await;
    let request = format!(
        "POST http://{origin}/submit HTTP/1.1\r\nHost: {origin}\r\nContent-Length: 7\r\n\r\na=1&b=2",
        origin = origin.addr()
    );

    let client = TcpStream::connect(daemon.http_addr()).await.unwrap();
    let _answer = echoed(client, request.as_bytes()).await;

    let [seen] = origin
        .received()
        .try_into()
        .expect("one request reaches the origin");
    assert!(seen.starts_with("POST /submit HTTP/1.1\r\n"), "{seen}");
    assert!(seen.ends_with("\r\n\r\na=1&b=2"), "{seen}");
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_body_is_forwarded_but_a_request_pipelined_behind_it_is_not() {
    let (_home, paths) = temp_paths();
    let origin = StubHttpOrigin::start().await;
    let daemon = TestDaemon::start(&paths, ephemeral()).await;
    let first = format!(
        "POST http://{origin}/first HTTP/1.1\r\nContent-Length: 3\r\nHost: {origin}\r\n\r\na=1",
        origin = origin.addr()
    );
    let second = format!(
        "GET http://{origin}/second HTTP/1.1\r\nHost: {origin}\r\n\r\n",
        origin = origin.addr()
    );

    let client = TcpStream::connect(daemon.http_addr()).await.unwrap();
    let _answer = echoed(client, format!("{first}{second}").as_bytes()).await;

    let [seen] = origin
        .received()
        .try_into()
        .expect("only the first request is forwarded");
    assert!(seen.starts_with("POST /first HTTP/1.1\r\n"), "{seen}");
    assert!(seen.ends_with("a=1"), "{seen}");
    assert!(!seen.contains("/second"), "{seen}");
    daemon.shutdown().await;
}
#[tokio::test]
async fn payload_sent_ahead_of_the_tunnel_answer_still_reaches_the_destination() {
    let (_home, paths) = temp_paths();
    let origin = StubOrigin::start().await;
    let daemon = TestDaemon::start(&paths, ephemeral()).await;
    let request = format!(
        "CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\nearly",
        origin = origin.addr()
    );

    let mut client = TcpStream::connect(daemon.http_addr()).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    let mut established = [0u8; ESTABLISHED.len()];
    client.read_exact(&mut established).await.unwrap();

    assert_eq!(&established, ESTABLISHED);
    assert_eq!(echoed(client, b" late").await, b"early late");
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_second_request_on_the_same_connection_is_not_forwarded() {
    let (_home, paths) = temp_paths();
    let origin = StubHttpOrigin::start().await;
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
    let _answer = echoed(client, format!("{first}{second}").as_bytes()).await;

    let [seen] = origin
        .received()
        .try_into()
        .expect("only the first request reaches the origin");
    assert!(seen.starts_with("GET /first HTTP/1.1\r\n"), "{seen}");
    assert!(!seen.contains("/second"), "{seen}");
    daemon.shutdown().await;
}

#[tokio::test]
async fn a_request_sent_after_the_answer_never_reaches_the_first_next_hop() {
    let (_home, paths) = temp_paths();
    let origin = StubHttpOrigin::start().await;
    let daemon = TestDaemon::start(&paths, ephemeral()).await;
    let first = format!(
        "GET http://{origin}/first HTTP/1.1\r\nHost: {origin}\r\n\r\n",
        origin = origin.addr()
    );
    let second = format!(
        "GET http://{origin}/second HTTP/1.1\r\nHost: {origin}\r\n\r\n",
        origin = origin.addr()
    );

    let mut client = TcpStream::connect(daemon.http_addr()).await.unwrap();
    client.write_all(first.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let reading = tokio::time::timeout(PATIENCE, client.read_to_end(&mut answer)).await;
    assert!(
        reading.is_ok(),
        "the front end must close the connection after one answer"
    );
    let _sent = client.write_all(second.as_bytes()).await;

    assert!(
        String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 200 OK"),
        "the origin's answer reaches the client"
    );
    let [seen] = origin
        .received()
        .try_into()
        .expect("only the first request reaches the origin");
    assert!(seen.starts_with("GET /first HTTP/1.1\r\n"), "{seen}");
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
    let (ctx, mut decisions) = watched(require("example.com"), upstream);
    let front = serve_once(
        ctx,
        Arc::new(DownHop::new(upstream, Refusal::BeforeDialling)),
    )
    .await;

    let answer = answer_of(front, "CONNECT example.com:443 HTTP/1.1\r\n\r\n").await;

    assert!(answer.starts_with("HTTP/1.1 502 Bad Gateway"), "{answer}");
    assert!(
        answer.ends_with("nhop: upstream 192.0.2.10:1080 is down (require rule 0)"),
        "{answer}"
    );
    let event = next_decision(&mut decisions).await;
    assert_eq!(event.connect_ms, None, "{event:?}");
}

#[tokio::test]
async fn a_connect_request_for_the_front_ends_own_address_is_refused_before_any_dial() {
    let origin = StubOrigin::start().await;
    let hop = Arc::new(StubHop::new(origin.addr()));
    let (ctx, _decisions) = watched(Ruleset::default(), ephemeral());
    let front = serve_once(ctx, hop.clone()).await;

    let answer = answer_of(
        front,
        &format!("CONNECT {front} HTTP/1.1\r\nHost: {front}\r\n\r\n"),
    )
    .await;

    assert!(answer.starts_with("HTTP/1.1 502 Bad Gateway"), "{answer}");
    assert!(
        answer.ends_with(&format!(
            "nhop: refusing to dial my own listening address {front}"
        )),
        "{answer}"
    );
    assert_eq!(hop.asked(), Vec::new(), "the loop must reach no next hop");
    assert_eq!(origin.connections(), 0);
}

#[tokio::test]
async fn an_absolute_form_request_for_the_front_ends_own_address_is_refused_the_same_way() {
    let origin = StubOrigin::start().await;
    let hop = Arc::new(StubHop::new(origin.addr()));
    let (ctx, _decisions) = watched(Ruleset::default(), ephemeral());
    let front = serve_once(ctx, hop.clone()).await;

    let answer = answer_of(
        front,
        &format!("GET http://{front}/ HTTP/1.1\r\nHost: {front}\r\n\r\n"),
    )
    .await;

    assert!(answer.starts_with("HTTP/1.1 502 Bad Gateway"), "{answer}");
    assert!(
        answer.ends_with(&format!(
            "nhop: refusing to dial my own listening address {front}"
        )),
        "{answer}"
    );
    assert_eq!(hop.asked(), Vec::new(), "the loop must reach no next hop");
    assert_eq!(origin.connections(), 0);
}

#[tokio::test]
async fn the_front_ends_own_address_by_name_is_refused_the_same_way() {
    let origin = StubOrigin::start().await;
    let hop = Arc::new(StubHop::new(origin.addr()));
    let (ctx, _decisions) = watched(Ruleset::default(), ephemeral());
    let front = serve_once(ctx, hop.clone()).await;
    let named = format!("localhost:{}", front.port());

    let answer = answer_of(
        front,
        &format!("CONNECT {named} HTTP/1.1\r\nHost: {named}\r\n\r\n"),
    )
    .await;

    assert!(answer.starts_with("HTTP/1.1 502 Bad Gateway"), "{answer}");
    assert!(
        answer.ends_with(&format!(
            "nhop: refusing to dial my own listening address {front}"
        )),
        "{answer}"
    );
    assert_eq!(hop.asked(), Vec::new(), "the loop must reach no next hop");
    assert_eq!(origin.connections(), 0);
}

#[tokio::test]
async fn an_origin_form_request_naming_the_front_end_in_its_host_header_is_refused_the_same_way() {
    let origin = StubOrigin::start().await;
    let hop = Arc::new(StubHop::new(origin.addr()));
    let (ctx, _decisions) = watched(Ruleset::default(), ephemeral());
    let front = serve_once(ctx, hop.clone()).await;

    let answer = answer_of(front, &format!("GET / HTTP/1.1\r\nHost: {front}\r\n\r\n")).await;

    assert!(answer.starts_with("HTTP/1.1 502 Bad Gateway"), "{answer}");
    assert!(
        answer.ends_with(&format!(
            "nhop: refusing to dial my own listening address {front}"
        )),
        "{answer}"
    );
    assert_eq!(hop.asked(), Vec::new(), "the loop must reach no next hop");
    assert_eq!(origin.connections(), 0);
}

#[tokio::test]
async fn a_never_rule_matching_the_front_ends_own_name_does_not_bypass_the_refusal() {
    let origin = StubOrigin::start().await;
    let hop = Arc::new(StubHop::new(origin.addr()));
    let (ctx, mut decisions) = watched(never("localhost"), ephemeral());
    let front = serve_once(ctx, hop.clone()).await;
    let named = format!("localhost:{}", front.port());

    let answer = answer_of(
        front,
        &format!("CONNECT {named} HTTP/1.1\r\nHost: {named}\r\n\r\n"),
    )
    .await;

    assert!(answer.starts_with("HTTP/1.1 502 Bad Gateway"), "{answer}");
    assert_eq!(hop.asked(), Vec::new(), "the loop must reach no next hop");
    assert_eq!(origin.connections(), 0);
    let event = next_decision(&mut decisions).await;
    assert_eq!(event.decision, DecisionKind::Never, "{event:?}");
    assert_eq!(event.rule_index, Some(0), "{event:?}");
    assert_eq!(event.class, Some(RuleClass::Never), "{event:?}");
    assert_eq!(
        event.error,
        Some(format!(
            "nhop: refusing to dial my own listening address {front}"
        )),
        "{event:?}"
    );
}

#[tokio::test]
async fn a_front_end_bound_to_the_wildcard_refuses_the_interface_the_client_reached() {
    let origin = StubOrigin::start().await;
    let hop = Arc::new(StubHop::new(origin.addr()));
    let (ctx, _decisions) = watched(Ruleset::default(), ephemeral());
    let bound = serve_once_bound("0.0.0.0:0".parse().unwrap(), ctx, hop.clone()).await;
    let reached: SocketAddr = format!("127.0.0.1:{}", bound.port()).parse().unwrap();

    let answer = answer_of(
        reached,
        &format!("CONNECT {reached} HTTP/1.1\r\nHost: {reached}\r\n\r\n"),
    )
    .await;

    assert!(answer.starts_with("HTTP/1.1 502 Bad Gateway"), "{answer}");
    assert!(
        answer.ends_with(&format!(
            "nhop: refusing to dial my own listening address {reached}"
        )),
        "{answer}"
    );
    assert_eq!(hop.asked(), Vec::new(), "the loop must reach no next hop");
    assert_eq!(origin.connections(), 0);
}

#[tokio::test]
async fn a_refused_loop_is_published_as_one_decision_carrying_the_refusal() {
    let origin = StubOrigin::start().await;
    let hop = Arc::new(StubHop::new(origin.addr()));
    let (ctx, mut decisions) = watched(Ruleset::default(), ephemeral());
    let front = serve_once(ctx, hop).await;

    let answer = answer_of(
        front,
        &format!("CONNECT {front} HTTP/1.1\r\nHost: {front}\r\n\r\n"),
    )
    .await;
    assert!(answer.starts_with("HTTP/1.1 502 Bad Gateway"), "{answer}");

    let event = next_decision(&mut decisions).await;
    assert_eq!(
        event.error,
        Some(format!(
            "nhop: refusing to dial my own listening address {front}"
        )),
        "{event:?}"
    );
    assert_eq!(event.connect_ms, None, "{event:?}");
    match decisions.try_recv() {
        Ok(extra) => panic!("a refused loop must publish exactly one decision: {extra:?}"),
        Err(TryRecvError::Empty) => (),
        Err(TryRecvError::Disconnected) => (),
    }
}

#[tokio::test]
async fn an_ordinary_local_destination_still_reaches_its_origin() {
    let origin = StubOrigin::start().await;
    let hop = Arc::new(StubHop::new(origin.addr()));
    let (ctx, _decisions) = watched(Ruleset::default(), ephemeral());
    let front = serve_once(ctx, hop.clone()).await;

    let mut client = TcpStream::connect(front).await.unwrap();
    let request = "CONNECT localhost:19998 HTTP/1.1\r\nHost: localhost:19998\r\n\r\n";
    client.write_all(request.as_bytes()).await.unwrap();
    let mut established = [0u8; ESTABLISHED.len()];
    client.read_exact(&mut established).await.unwrap();

    assert_eq!(&established, ESTABLISHED);
    assert_eq!(echoed(client, b"ping").await, b"ping");
    assert_eq!(hop.asked().len(), 1, "{:?}", hop.asked());
    assert_eq!(origin.connections(), 1);
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
async fn moving_the_front_ends_to_the_addresses_they_hold_keeps_them_serving() {
    let (_home, paths) = temp_paths();
    let origin = StubOrigin::start().await;
    let daemon = TestDaemon::start(&paths, ephemeral()).await;
    let (http, socks) = status_of(&daemon).await;

    let moved = daemon
        .call(Command::SetListen {
            http,
            socks,
            load: None,
        })
        .await;

    assert_eq!(moved, Response::Ok);
    assert_eq!(status_of(&daemon).await, (http, socks));
    let client = establish(http, origin.addr()).await;
    assert_eq!(echoed(client, b"ping").await, b"ping");
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
