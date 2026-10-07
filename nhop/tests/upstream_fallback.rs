mod support;

use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};

use nhop::daemon::Pace;
use nhop::logging::{self, Logged, LoggedSwitch};
use nhop::upstream::SwitchCause;
use nhop_ipc::{
    Command, EffectiveHop, EventView, ForwardView, HealthState, Host, Paths, Port, Response,
    RuleClass, RuleKind, RuleValue, UpstreamAddr,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use support::{ScopedLog, SocksRequest, StubSocks5, TestDaemon, ephemeral};

const INTERVAL: Duration = Duration::from_millis(100);
const CONFIRM_DELAY: Duration = Duration::from_millis(50);
const HOLD: Duration = Duration::from_secs(2);
const PACE: Pace = Pace {
    interval: INTERVAL,
    confirm_delay: CONFIRM_DELAY,
    hold: HOLD,
};
const PATIENCE: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(20);
const GREETING: [u8; 3] = [0x05, 0x01, 0x00];
const GRANTED: [u8; 10] = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

fn temp_paths() -> (TempDir, Paths) {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(home.path());
    (home, paths)
}

fn written(upstream: SocketAddr) -> UpstreamAddr {
    UpstreamAddr(format!("socks5://{upstream}"))
}

fn dialled(host: &str, port: u16) -> SocksRequest {
    SocksRequest {
        atyp: 0x03,
        host: host.to_owned(),
        port,
    }
}

/// Returns the upstream a connection accepted now would be carried by.
fn selected(daemon: &TestDaemon) -> Option<SocketAddr> {
    let entries = daemon.state().live().upstream().snapshot();
    let index = entries.selected(SystemTime::now(), HOLD)?;
    let entry = entries.as_slice().get(index)?;
    Some(entry.upstream().socket())
}

async fn await_selected(daemon: &TestDaemon, upstream: SocketAddr) {
    let started = Instant::now();
    loop {
        let now = selected(daemon);
        if now == Some(upstream) {
            return;
        }
        let waited = started.elapsed();
        assert!(
            waited <= PATIENCE,
            "{upstream} was never selected, {now:?} still is after {waited:?}"
        );
        tokio::time::sleep(POLL).await;
    }
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

/// Starts a daemon on [primary, fallback], lets the primary serve, then turns it off.
///
/// Returns once the fallback is the selected upstream, with a `require` rule for `example.com`.
async fn failed_over(paths: &Paths) -> (StubSocks5, StubSocks5, TestDaemon) {
    let mut primary = StubSocks5::start().await;
    let fallback = StubSocks5::start().await;
    let daemon = TestDaemon::paced(paths, &[primary.addr(), fallback.addr()], PACE).await;
    require_suffix(&daemon, "example.com").await;
    await_selected(&daemon, primary.addr()).await;
    primary.stop().await;
    await_selected(&daemon, fallback.addr()).await;
    (primary, fallback, daemon)
}

/// Opens a SOCKS5 connection through the front end to `host`, returning it once granted.
async fn relayed(front: SocketAddr, host: &str, port: u16) -> TcpStream {
    let mut client = TcpStream::connect(front).await.unwrap();
    client.write_all(&GREETING).await.unwrap();
    let mut chosen = [0u8; 2];
    client.read_exact(&mut chosen).await.unwrap();
    let mut request = vec![0x05, 0x01, 0x00, 0x03, u8::try_from(host.len()).unwrap()];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut granted = [0u8; GRANTED.len()];
    client.read_exact(&mut granted).await.unwrap();
    assert_eq!(granted, GRANTED, "the connection to {host} must be granted");
    client
}

async fn exchanged(client: &mut TcpStream, payload: &[u8]) {
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
}

async fn finished(mut client: TcpStream, payload: &[u8]) {
    exchanged(&mut client, payload).await;
    client.shutdown().await.unwrap();
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).await.unwrap();
    assert_eq!(rest, b"");
}

async fn next_event(events: &mut mpsc::Receiver<EventView>) -> EventView {
    let Ok(published) = tokio::time::timeout(PATIENCE, events.recv()).await else {
        panic!("the connection published no decision");
    };
    let Some(event) = published else {
        panic!("the decision stream ended before the connection was routed");
    };
    event
}

async fn forward(daemon: &TestDaemon, host: &str, port: u16) -> SocketAddr {
    let answer = daemon
        .call(Command::AddForward {
            listen: ephemeral(),
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

/// One switch record of the log: the written addresses on either side and its cause.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Switched {
    from: Option<UpstreamAddr>,
    to: Option<UpstreamAddr>,
    cause: SwitchCause,
}

impl Switched {
    fn new(from: SocketAddr, to: SocketAddr, cause: SwitchCause) -> Self {
        Self {
            from: Some(written(from)),
            to: Some(written(to)),
            cause,
        }
    }
}

fn switches(paths: &Paths) -> Vec<Switched> {
    let mut switches = Vec::new();
    for file in logging::files(paths).unwrap() {
        let (lines, _offset) = logging::read_from(&file, 0).unwrap();
        for line in lines {
            let Some(Logged::Switch(LoggedSwitch {
                at: _,
                from,
                to,
                cause,
            })) = logging::logged(&line)
            else {
                continue;
            };
            switches.push(Switched { from, to, cause });
        }
    }
    switches
}

async fn await_switch(paths: &Paths, wanted: &Switched) -> Vec<Switched> {
    let started = Instant::now();
    loop {
        let switches = switches(paths);
        if switches.contains(wanted) {
            return switches;
        }
        let waited = started.elapsed();
        assert!(
            waited <= PATIENCE,
            "the log never recorded {wanted:?} after {waited:?}: {switches:?}"
        );
        tokio::time::sleep(POLL).await;
    }
}

#[tokio::test]
async fn a_down_primary_hands_new_connections_to_the_fallback() {
    let (_home, paths) = temp_paths();
    let (primary, fallback, daemon) = failed_over(&paths).await;
    let mut events = daemon.state().live().events().subscribe();

    let client = relayed(daemon.socks_addr(), "api.example.com", 443).await;
    finished(client, b"ping").await;

    assert_eq!(
        fallback.client_dials(),
        vec![dialled("api.example.com", 443)]
    );
    assert_eq!(primary.client_dials(), Vec::new());
    let EventView {
        host,
        port: _,
        decision: _,
        rule_index: _,
        class,
        upstream,
        connect_ms: _,
        hop,
        via,
        duration_ms: _,
        error,
    } = next_event(&mut events).await;
    assert_eq!(host, Host("api.example.com".to_owned()));
    assert_eq!(class, Some(RuleClass::Require));
    assert_eq!(upstream, HealthState::Up);
    assert_eq!(hop, Some(EffectiveHop::Upstream));
    assert_eq!(via, Some(written(fallback.addr())));
    assert_eq!(error, None);

    daemon.shutdown().await;
}

#[tokio::test]
async fn a_primary_back_takes_new_connections_only_after_the_hold() {
    let (_home, paths) = temp_paths();
    let (mut primary, fallback, daemon) = failed_over(&paths).await;

    primary.restart().await;
    let returned = Instant::now();
    let client = relayed(daemon.socks_addr(), "early.example.com", 443).await;
    finished(client, b"ping").await;
    assert!(
        returned.elapsed() < HOLD,
        "the early connection must be made inside the hold, took {:?}",
        returned.elapsed()
    );

    assert_eq!(
        fallback.client_dials(),
        vec![dialled("early.example.com", 443)]
    );
    assert_eq!(primary.client_dials(), Vec::new());

    await_selected(&daemon, primary.addr()).await;
    assert!(
        returned.elapsed() >= HOLD,
        "the primary took traffic back {:?} after it returned, inside the hold",
        returned.elapsed()
    );
    let client = relayed(daemon.socks_addr(), "late.example.com", 443).await;
    finished(client, b"pong").await;

    assert_eq!(
        primary.client_dials(),
        vec![dialled("late.example.com", 443)]
    );
    assert_eq!(
        fallback.client_dials(),
        vec![dialled("early.example.com", 443)]
    );

    daemon.shutdown().await;
}

#[tokio::test]
async fn an_open_connection_survives_a_switch() {
    let (_home, paths) = temp_paths();
    let (mut primary, fallback, daemon) = failed_over(&paths).await;
    let mut held = relayed(daemon.socks_addr(), "held.example.com", 443).await;
    exchanged(&mut held, b"before").await;

    primary.restart().await;
    await_selected(&daemon, primary.addr()).await;
    let client = relayed(daemon.socks_addr(), "fresh.example.com", 443).await;
    finished(client, b"ping").await;
    assert_eq!(
        primary.client_dials(),
        vec![dialled("fresh.example.com", 443)]
    );

    finished(held, b"after").await;
    assert_eq!(
        fallback.client_dials(),
        vec![dialled("held.example.com", 443)]
    );

    daemon.shutdown().await;
}

#[tokio::test]
async fn the_log_records_each_switch_with_its_cause() {
    let (_home, paths) = temp_paths();
    let _log = ScopedLog::install(&paths);
    let (mut primary, fallback, daemon) = failed_over(&paths).await;
    primary.restart().await;
    await_selected(&daemon, primary.addr()).await;

    let left = Switched::new(primary.addr(), fallback.addr(), SwitchCause::Down);
    let returned = Switched::new(fallback.addr(), primary.addr(), SwitchCause::Held);
    let switches = await_switch(&paths, &returned).await;

    let mut since = Vec::new();
    for switch in switches {
        if switch == left || !since.is_empty() {
            since.push(switch);
        }
    }
    assert_eq!(since, vec![left, returned]);

    daemon.shutdown().await;
}

#[tokio::test]
async fn a_forward_port_follows_selection() {
    let (_home, paths) = temp_paths();
    let (primary, fallback, daemon) = failed_over(&paths).await;
    let listen = forward(&daemon, "api.example.com", 9000).await;

    let client = TcpStream::connect(listen).await.unwrap();
    finished(client, b"ping").await;

    assert_eq!(
        fallback.client_dials(),
        vec![dialled("api.example.com", 9000)]
    );
    assert_eq!(primary.client_dials(), Vec::new());

    daemon.shutdown().await;
}
