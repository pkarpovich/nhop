mod support;

use std::net::SocketAddr;
use std::time::Duration;

use nhop_ipc::{DecisionKind, EventView, Host, Paths, Port};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use support::{Shared, StubOrigin, TestDaemon, ephemeral};

const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
const PATIENCE: usize = 200;

async fn tunnelled(front: SocketAddr, destination: SocketAddr, payload: &[u8]) {
    let mut client = TcpStream::connect(front).await.unwrap();
    let request = format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    let mut established = [0u8; ESTABLISHED.len()];
    client.read_exact(&mut established).await.unwrap();
    assert_eq!(&established, ESTABLISHED);
    client.write_all(payload).await.unwrap();
    client.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    client.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
}

async fn await_subscriber(daemon: &TestDaemon) {
    for _attempt in 0..PATIENCE {
        if daemon.state().live().events().subscribers() == 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("tail never subscribed");
}

async fn await_lines(out: &Shared, wanted: usize) -> Vec<String> {
    for _attempt in 0..PATIENCE {
        let lines = out.lines();
        if lines.len() >= wanted {
            return lines;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("tail never printed {wanted} decisions");
}

#[tokio::test]
async fn tail_prints_one_document_per_routed_connection() {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(home.path());
    let origin = StubOrigin::start().await;
    let daemon = TestDaemon::start(&paths, ephemeral()).await;
    let out = Shared::default();
    let err = Shared::default();
    let mut printed = out.clone();
    let mut failed = err.clone();
    let tailing = nhop::cli::run(&paths, &["tail", "--json"], &mut printed, &mut failed);
    let driving = async {
        await_subscriber(&daemon).await;
        tunnelled(daemon.http_addr(), origin.addr(), b"ping").await;
        tunnelled(daemon.http_addr(), origin.addr(), b"pong").await;
        await_lines(&out, 2).await
    };

    let lines = tokio::select! {
        exit = tailing => panic!("tail must keep following while the daemon runs: {exit:?}"),
        lines = driving => lines,
    };

    assert_eq!(lines.len(), 2, "{lines:?}");
    for line in lines {
        let published: EventView = serde_json::from_str(&line).unwrap();
        let EventView {
            host,
            port,
            decision,
            rule_index,
            class,
            upstream: _,
            connect_ms: _,
            hop: _,
            duration_ms: _,
            error,
        } = published;
        assert_eq!(host, Host(origin.addr().ip().to_string()));
        assert_eq!(port, Port(origin.addr().port()));
        assert_eq!(decision, DecisionKind::Direct);
        assert_eq!(rule_index, None);
        assert_eq!(class, None);
        assert_eq!(error, None);
    }
    assert!(err.text().is_empty(), "{}", err.text());

    daemon.shutdown().await;
}

#[tokio::test]
async fn a_subscriber_that_never_reads_still_lets_connections_through() {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(home.path());
    let origin = StubOrigin::start().await;
    let daemon = TestDaemon::start(&paths, ephemeral()).await;
    let mut deaf = tokio::net::UnixStream::connect(daemon.ipc_path())
        .await
        .unwrap();
    deaf.write_all(b"{\"cmd\":\"subscribe\"}\n").await.unwrap();
    deaf.flush().await.unwrap();
    await_subscriber(&daemon).await;

    for _connection in 0..4 {
        tunnelled(daemon.http_addr(), origin.addr(), b"ping").await;
    }

    assert_eq!(origin.connections(), 4);
    assert_eq!(daemon.state().live().events().subscribers(), 1);

    drop(deaf);
    daemon.shutdown().await;
}
