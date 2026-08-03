mod support;

use std::net::SocketAddr;
use std::time::Duration;

use nhop::logging::{self, LoggedDecision};
use nhop_ipc::{DecisionKind, EventView, HealthState, Host, Paths, Port};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use support::{StubOrigin, TestDaemon, ephemeral};

const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
const GREETING: [u8; 3] = [0x05, 0x01, 0x00];
const GRANTED: [u8; 10] = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
const PATIENCE: usize = 200;

fn ipv4_request(addr: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(addr) = addr else {
        panic!("the harness listens on IPv4: {addr}");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&addr.ip().octets());
    request.extend_from_slice(&addr.port().to_be_bytes());
    request
}

async fn echoed(mut client: TcpStream, payload: &[u8]) -> Vec<u8> {
    client.write_all(payload).await.unwrap();
    client.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    client.read_to_end(&mut echoed).await.unwrap();
    echoed
}

async fn tunnelled(front: SocketAddr, destination: SocketAddr, payload: &[u8]) {
    let mut client = TcpStream::connect(front).await.unwrap();
    let request = format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    let mut established = [0u8; ESTABLISHED.len()];
    client.read_exact(&mut established).await.unwrap();
    assert_eq!(&established, ESTABLISHED);
    assert_eq!(echoed(client, payload).await, payload);
}

async fn relayed(front: SocketAddr, destination: SocketAddr, payload: &[u8]) {
    let mut client = TcpStream::connect(front).await.unwrap();
    client.write_all(&GREETING).await.unwrap();
    let mut chosen = [0u8; 2];
    client.read_exact(&mut chosen).await.unwrap();
    client.write_all(&ipv4_request(destination)).await.unwrap();
    let mut granted = [0u8; GRANTED.len()];
    client.read_exact(&mut granted).await.unwrap();
    assert_eq!(granted, GRANTED);
    assert_eq!(echoed(client, payload).await, payload);
}

async fn await_decisions(paths: &Paths, wanted: usize) -> Vec<LoggedDecision> {
    for _attempt in 0..PATIENCE {
        let mut decisions = Vec::new();
        for file in logging::files(paths).unwrap() {
            let (lines, _offset) = logging::read_from(&file, 0).unwrap();
            for line in lines {
                let Some(decision) = logging::logged(&line) else {
                    panic!("the log must hold decisions only: {line}");
                };
                decisions.push(decision);
            }
        }
        if decisions.len() >= wanted {
            return decisions;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the front ends never logged {wanted} decisions");
}

#[tokio::test]
async fn every_routed_connection_leaves_one_line_in_the_log() {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(home.path());
    let subscriber = logging::subscriber(&paths).unwrap();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let origin = StubOrigin::start().await;
    let daemon = TestDaemon::start(&paths, ephemeral()).await;

    tunnelled(daemon.http_addr(), origin.addr(), b"ping").await;
    relayed(daemon.socks_addr(), origin.addr(), b"pong").await;

    let decisions = await_decisions(&paths, 2).await;
    assert_eq!(decisions.len(), 2, "{decisions:?}");
    let expected = EventView {
        host: Host(origin.addr().ip().to_string()),
        port: Port(origin.addr().port()),
        decision: DecisionKind::Direct,
        rule_index: None,
        class: None,
        upstream: HealthState::Down,
        duration_ms: 0,
        error: None,
    };
    for LoggedDecision { at: _, event } in decisions {
        let EventView {
            host,
            port,
            decision,
            rule_index,
            class,
            upstream,
            duration_ms: _,
            error,
        } = event;
        assert_eq!(host, expected.host);
        assert_eq!(port, expected.port);
        assert_eq!(decision, expected.decision);
        assert_eq!(rule_index, expected.rule_index);
        assert_eq!(class, expected.class);
        assert_eq!(upstream, expected.upstream);
        assert_eq!(error, expected.error);
    }
    assert_eq!(origin.connections(), 2);

    daemon.shutdown().await;
}
