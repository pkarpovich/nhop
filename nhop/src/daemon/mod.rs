mod init_script;
mod ipc_server;
mod staging;
pub mod state;

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::time::Duration;

use fs2::FileExt;
use nhop_ipc::{Command, Paths};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::cli::system_proxy::Networksetup;
use crate::daemon::state::{
    DEFAULT_HTTP_LISTEN, DEFAULT_SOCKS_LISTEN, LOAD_TIMEOUT, Live, StateConfig, StateHandle,
};
use crate::logging;
use crate::proxy::{self, Listen, NextHop};
use crate::upstream::{PROBE_INTERVAL, UpstreamHop};

/// Addresses both front ends bind until an init script moves them.
pub const DEFAULT_LISTEN: Listen = Listen {
    http: DEFAULT_HTTP_LISTEN,
    socks: DEFAULT_SOCKS_LISTEN,
};

/// How long a listener waits after a failed accept, so a lasting failure cannot spin its task.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Identifier of a process on this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pid(pub u32);

impl fmt::Display for Pid {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(pid) = self;
        write!(out, "{pid}")
    }
}

/// Process the single-instance lock belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockOwner {
    /// The pid file named its owner.
    Known(Pid),
    /// The pid file held nothing readable.
    Unknown,
}

impl fmt::Display for LockOwner {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(pid) => write!(out, "pid {pid}"),
            Self::Unknown => out.write_str("pid unknown"),
        }
    }
}

/// Reason the daemon refused to start.
#[derive(Debug, thiserror::Error)]
pub enum StartFailure {
    #[error("another nhop daemon is already running ({0})")]
    AlreadyRunning(LockOwner),
    /// The state directory, the pid file or the socket could not be prepared.
    #[error("cannot start the daemon: {0}")]
    Io(#[from] io::Error),
}

/// Exclusive claim on the pid file, held for as long as the daemon runs.
#[derive(Debug)]
pub struct InstanceGuard {
    file: File,
    pid_file: PathBuf,
}

impl InstanceGuard {
    /// Claims the pid file, clearing the leftovers of a daemon that is gone.
    ///
    /// # Errors
    ///
    /// Returns [`StartFailure::AlreadyRunning`] when a live daemon holds the lock, and
    /// [`StartFailure::Io`] when the state directory or the pid file is unusable.
    pub fn acquire(paths: &Paths) -> Result<Self, StartFailure> {
        paths.state_dir()?;
        let pid_file = paths.pid_file();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&pid_file)?;
        let Ok(()) = file.try_lock_exclusive() else {
            return Err(StartFailure::AlreadyRunning(read_owner(&mut file)));
        };
        remove_if_present(&paths.socket_file())?;
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        writeln!(file, "{}", process::id())?;
        file.flush()?;
        Ok(Self { file, pid_file })
    }
}

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        let _ = remove_if_present(&self.pid_file);
        let _ = FileExt::unlock(&self.file);
    }
}

fn read_owner(file: &mut File) -> LockOwner {
    let mut written = String::new();
    let Ok(_read) = file.read_to_string(&mut written) else {
        return LockOwner::Unknown;
    };
    let Ok(pid) = written.trim().parse::<u32>() else {
        return LockOwner::Unknown;
    };
    LockOwner::Known(Pid(pid))
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    let Err(failure) = std::fs::remove_file(path) else {
        return Ok(());
    };
    match failure.kind() {
        io::ErrorKind::NotFound => Ok(()),
        _ => Err(failure),
    }
}

/// One listener and the task accepting on it.
#[derive(Debug)]
struct Accepting {
    addr: SocketAddr,
    accepting: JoinHandle<()>,
}

impl Drop for Accepting {
    fn drop(&mut self) {
        let Self { addr: _, accepting } = self;
        accepting.abort();
    }
}

/// The two listeners a running daemon accepts traffic on.
#[derive(Debug)]
pub struct Bound {
    live: Live,
    hop: Arc<dyn NextHop>,
    http: Accepting,
    socks: Accepting,
}

impl Bound {
    fn rebind(&mut self, listen: Listen) -> io::Result<Listen> {
        let Listen { http, socks } = listen;
        let Listen {
            http: held_http,
            socks: held_socks,
        } = self.listen();
        let http = bind_unless_held(http, held_http)?;
        let socks = bind_unless_held(socks, held_socks)?;
        if let Some(http) = http {
            self.http = accept_http(http, self.live.clone(), self.hop.clone())?;
        }
        if let Some(socks) = socks {
            self.socks = accept_socks(socks, self.live.clone(), self.hop.clone())?;
        }
        Ok(self.listen())
    }

    fn listen(&self) -> Listen {
        let Self {
            live: _,
            hop: _,
            http,
            socks,
        } = self;
        Listen {
            http: http.addr,
            socks: socks.addr,
        }
    }
}

/// Front ends the daemon serves traffic on.
#[derive(Debug)]
pub enum Frontends {
    /// Nothing is listening, so a load that moves the addresses only records them.
    Unbound,
    /// Both front ends hold an address.
    Bound(Bound),
}

impl Frontends {
    /// Binds both front ends and starts accepting on them.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when either address cannot be bound, leaving neither bound.
    ///
    /// [`io::Error`]: std::io::Error
    pub fn bind(live: Live, hop: Arc<dyn NextHop>, listen: Listen) -> io::Result<Self> {
        let Listen { http, socks } = listen;
        let http = bind_tcp(http)?;
        let socks = bind_tcp(socks)?;
        let http = accept_http(http, live.clone(), hop.clone())?;
        let socks = accept_socks(socks, live.clone(), hop.clone())?;
        Ok(Self::Bound(Bound {
            live,
            hop,
            http,
            socks,
        }))
    }

    /// Returns the addresses the front ends hold, absent while nothing is bound.
    pub fn listening(&self) -> Option<Listen> {
        match self {
            Self::Unbound => None,
            Self::Bound(bound) => Some(bound.listen()),
        }
    }

    /// Moves both front ends, leaving the connections they already accepted alone.
    ///
    /// A front end already holding the requested address keeps its listener: binding a second
    /// socket to a live address fails, so an init script that re-declares the current addresses
    /// would otherwise fail every load it takes part in.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when either address cannot be bound, leaving the addresses held.
    ///
    /// [`io::Error`]: std::io::Error
    pub fn rebind(&mut self, listen: Listen) -> io::Result<Listen> {
        match self {
            Self::Unbound => Ok(listen),
            Self::Bound(bound) => bound.rebind(listen),
        }
    }
}

fn bind_unless_held(addr: SocketAddr, held: SocketAddr) -> io::Result<Option<TcpListener>> {
    if addr == held {
        return Ok(None);
    }
    Ok(Some(bind_tcp(addr)?))
}

fn bind_tcp(addr: SocketAddr) -> io::Result<TcpListener> {
    let listener = std::net::TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    TcpListener::from_std(listener)
}

/// Returns the next client, outliving the failures one accept can end with.
///
/// Stopping at the first failure would leave the port bound with nothing serving it, while
/// `status` and `doctor` keep reporting a front end that answers no one. A reset between SYN and
/// accept, or a moment with no free descriptor, is transient.
async fn next_client(listener: &TcpListener) -> TcpStream {
    loop {
        let failure = match listener.accept().await {
            Ok((stream, _peer)) => return stream,
            Err(failure) => failure,
        };
        tracing::warn!(error = %failure, "accepting a client failed");
        tokio::time::sleep(ACCEPT_BACKOFF).await;
    }
}

fn accept_http(listener: TcpListener, live: Live, hop: Arc<dyn NextHop>) -> io::Result<Accepting> {
    let addr = listener.local_addr()?;
    let accepting = tokio::spawn(async move {
        loop {
            let stream = next_client(&listener).await;
            let ctx = live.accepted();
            let hop = hop.clone();
            tokio::spawn(async move {
                let _served = proxy::http::serve(stream, ctx, hop.as_ref()).await;
            });
        }
    });
    Ok(Accepting { addr, accepting })
}

fn accept_socks(listener: TcpListener, live: Live, hop: Arc<dyn NextHop>) -> io::Result<Accepting> {
    let addr = listener.local_addr()?;
    let accepting = tokio::spawn(async move {
        loop {
            let stream = next_client(&listener).await;
            let ctx = live.accepted();
            let hop = hop.clone();
            tokio::spawn(async move {
                let _served = proxy::socks5::serve(stream, ctx, hop.as_ref()).await;
            });
        }
    });
    Ok(Accepting { addr, accepting })
}

/// Binds both front ends before the init script runs, so no rule can land on an unbound port.
///
/// # Errors
///
/// Returns [`io::Error`] when either address cannot be bound.
///
/// [`io::Error`]: std::io::Error
pub fn spawn_frontends(live: &Live, listen: Listen) -> io::Result<Frontends> {
    let hop = UpstreamHop::start(
        live.upstream().clone(),
        live.health().clone(),
        PROBE_INTERVAL,
    );
    Frontends::bind(live.clone(), Arc::new(hop), listen)
}

/// Running daemon: the single-instance claim, the state task and the IPC server.
#[derive(Debug)]
pub struct Daemon {
    guard: InstanceGuard,
    state: StateHandle,
    socket_file: PathBuf,
    listen: Listen,
    shutdown: oneshot::Sender<()>,
    served: JoinHandle<()>,
}

impl Daemon {
    /// Returns the handle every command travels through.
    pub fn state(&self) -> &StateHandle {
        &self.state
    }

    /// Returns the addresses the front ends were bound on.
    pub fn listen(&self) -> Listen {
        self.listen
    }

    /// Returns the path clients connect to.
    pub fn socket_file(&self) -> &Path {
        &self.socket_file
    }

    /// Stops serving, then removes the socket and the pid file.
    pub async fn shutdown(self) {
        let Self {
            guard,
            state: _,
            socket_file,
            listen: _,
            shutdown,
            served,
        } = self;
        let _ = shutdown.send(());
        let _ = served.await;
        let _ = remove_if_present(&socket_file);
        drop(guard);
    }
}

/// Claims the pid file, binds every listener and starts serving.
///
/// The init script runs in the background once the socket is served, so a script that calls back
/// into the CLI reaches a daemon that is already answering.
///
/// # Errors
///
/// Returns [`StartFailure`] when another daemon is running or a listener cannot be bound.
pub fn start(paths: &Paths) -> Result<Daemon, StartFailure> {
    start_on(paths, DEFAULT_LISTEN)
}

/// Starts the daemon with front ends on addresses other than [`DEFAULT_LISTEN`].
///
/// # Errors
///
/// Returns [`StartFailure`] when another daemon is running or a listener cannot be bound.
pub fn start_on(paths: &Paths, listen: Listen) -> Result<Daemon, StartFailure> {
    let guard = InstanceGuard::acquire(paths)?;
    let socket_file = paths.socket_file();
    let listener = ipc_server::bind(&socket_file)?;
    let live = Live::default();
    let frontends = spawn_frontends(&live, listen)?;
    let listen = frontends.listening().unwrap_or(listen);
    let state = state::spawn(
        paths,
        StateConfig {
            live,
            frontends,
            listen,
            load_timeout: LOAD_TIMEOUT,
            proxy: Arc::new(Networksetup),
        },
    );
    let (shutdown, signalled) = oneshot::channel();
    let served = tokio::spawn(ipc_server::serve(listener, state.clone(), signalled));
    tokio::spawn({
        let state = state.clone();
        async move {
            let _ = state.call(Command::Reload { path: None }).await;
        }
    });
    Ok(Daemon {
        guard,
        state,
        socket_file,
        listen,
        shutdown,
        served,
    })
}

/// Runs the daemon until SIGINT or SIGTERM arrives.
///
/// This is the one entry point that installs the log: [`start`] and [`start_on`] leave the log of
/// the process alone, so a test can run several daemons at once.
///
/// # Errors
///
/// Returns [`StartFailure`] when the log cannot be opened, the daemon cannot start or the signal
/// handlers cannot be installed.
pub async fn run(paths: &Paths) -> Result<(), StartFailure> {
    logging::start(paths)?;
    let daemon = start(paths)?;
    await_stop_signal().await?;
    daemon.shutdown().await;
    Ok(())
}

async fn await_stop_signal() -> io::Result<()> {
    let mut interrupted = signal(SignalKind::interrupt())?;
    let mut terminated = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = interrupted.recv() => Ok(()),
        _ = terminated.recv() => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::time::Duration;

    use nhop_ipc::{
        Command, DecisionKind, ErrKind, EventView, HealthState, Host, Port, Response, StatusView,
    };
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    use crate::proxy::EventTx;

    use super::*;

    const PATIENCE: usize = 600;

    fn paths_in(home: &tempfile::TempDir) -> Paths {
        Paths::from_home(home.path())
    }

    fn ephemeral() -> Listen {
        let addr = "127.0.0.1:0".parse().unwrap();
        Listen {
            http: addr,
            socks: addr,
        }
    }

    fn start_ephemeral(paths: &Paths) -> Daemon {
        start_on(paths, ephemeral()).unwrap()
    }

    async fn ask(socket_file: &Path, line: &str) -> Response {
        let stream = UnixStream::connect(socket_file).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        writer.write_all(line.as_bytes()).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
        let mut reader = BufReader::new(reader);
        let mut answer = String::new();
        reader.read_line(&mut answer).await.unwrap();
        serde_json::from_str(&answer).unwrap()
    }

    async fn ask_command(socket_file: &Path, command: &Command) -> Response {
        ask(socket_file, &serde_json::to_string(command).unwrap()).await
    }

    #[tokio::test]
    async fn a_fresh_daemon_answers_status_over_the_socket() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_in(&home);
        let daemon = start_ephemeral(&paths);

        let answer = ask_command(daemon.socket_file(), &Command::Status).await;

        let Response::Status(status) = answer else {
            panic!("status must answer with a status view: {answer:?}");
        };
        let StatusView {
            uptime_secs: _,
            http_listen,
            http_bound,
            socks_listen,
            socks_bound,
            upstream: _,
            health: _,
            health_changed_at: _,
            init_path,
            last_load: _,
            rules,
            system_proxy: _,
        } = status;
        assert_eq!(rules.require, 0);
        assert_eq!(rules.prefer, 0);
        assert_eq!(rules.never, 0);
        assert_eq!(init_path, None);
        let Listen { http, socks } = daemon.listen();
        assert_eq!(http_listen, http);
        assert_eq!(socks_listen, socks);
        assert!(http_bound);
        assert!(socks_bound);

        daemon.shutdown().await;
    }

    #[tokio::test]
    async fn both_front_ends_answer_before_any_rule_is_loaded() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_in(&home);
        let daemon = start_ephemeral(&paths);
        let Listen { http, socks } = daemon.listen();

        assert!(tokio::net::TcpStream::connect(http).await.is_ok());
        assert!(tokio::net::TcpStream::connect(socks).await.is_ok());
        assert_ne!(http.port(), 0);
        assert_ne!(socks.port(), 0);

        daemon.shutdown().await;
    }

    #[tokio::test]
    async fn an_address_another_listener_holds_refuses_the_start() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_in(&home);
        let squatter = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let Listen { http: _, socks } = ephemeral();

        let started = start_on(
            &paths,
            Listen {
                http: squatter.local_addr().unwrap(),
                socks,
            },
        );

        let Err(failure) = started else {
            panic!("a held address must refuse the start");
        };
        let StartFailure::Io(_failure) = &failure else {
            panic!("a held address must fail with io: {failure}");
        };
    }

    #[tokio::test]
    async fn one_connection_carries_one_command_per_line() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_in(&home);
        let daemon = start_ephemeral(&paths);

        let stream = UnixStream::connect(daemon.socket_file()).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        writer
            .write_all(b"{\"cmd\":\"status\"}\n{\"cmd\":\"rules\"}\n")
            .await
            .unwrap();
        let mut reader = BufReader::new(reader);
        let mut first = String::new();
        let mut second = String::new();
        reader.read_line(&mut first).await.unwrap();
        reader.read_line(&mut second).await.unwrap();

        let first: Response = serde_json::from_str(&first).unwrap();
        let second: Response = serde_json::from_str(&second).unwrap();
        let Response::Status(_) = first else {
            panic!("the first line must answer status: {first:?}");
        };
        assert_eq!(second, Response::Rules(Vec::new()));

        daemon.shutdown().await;
    }

    fn event() -> EventView {
        EventView {
            host: Host("api.example.com".to_owned()),
            port: Port(443),
            decision: DecisionKind::Direct,
            rule_index: None,
            class: None,
            upstream: HealthState::Down,
            duration_ms: 3,
            error: None,
        }
    }

    async fn await_subscribers(events: &EventTx, wanted: usize) {
        for _attempt in 0..PATIENCE {
            if events.subscribers() == wanted {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the daemon never held {wanted} subscribers");
    }

    async fn await_unsubscribed(events: &EventTx) {
        for _attempt in 0..PATIENCE {
            events.publish(&event());
            if events.subscribers() == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the subscriber that hung up was never removed");
    }

    #[tokio::test]
    async fn a_subscribed_connection_is_answered_with_one_line_per_decision() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_in(&home);
        let daemon = start_ephemeral(&paths);
        let events = daemon.state().live().events().clone();

        let stream = UnixStream::connect(daemon.socket_file()).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        writer
            .write_all(b"{\"cmd\":\"subscribe\"}\n")
            .await
            .unwrap();
        let mut reader = BufReader::new(reader);
        await_subscribers(&events, 1).await;

        events.publish(&event());
        events.publish(&event());

        for _published in 0..2 {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let answer: Response = serde_json::from_str(&line).unwrap();
            let Response::Event(published) = answer else {
                panic!("a subscribed connection must be answered with events: {answer:?}");
            };
            assert_eq!(published, event());
        }

        daemon.shutdown().await;
    }

    #[tokio::test]
    async fn a_subscriber_that_hangs_up_is_dropped_by_the_daemon() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_in(&home);
        let daemon = start_ephemeral(&paths);
        let events = daemon.state().live().events().clone();
        let stream = UnixStream::connect(daemon.socket_file()).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        writer
            .write_all(b"{\"cmd\":\"subscribe\"}\n")
            .await
            .unwrap();
        await_subscribers(&events, 1).await;

        drop(reader);
        drop(writer);

        await_unsubscribed(&events).await;

        daemon.shutdown().await;
    }

    #[tokio::test]
    async fn a_malformed_line_is_answered_with_invalid_args() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_in(&home);
        let daemon = start_ephemeral(&paths);

        let answer = ask(daemon.socket_file(), "{not json").await;

        let Response::Err { kind, message } = answer else {
            panic!("a malformed line must answer with an error: {answer:?}");
        };
        assert_eq!(kind, ErrKind::InvalidArgs);
        assert!(!message.is_empty());

        daemon.shutdown().await;
    }

    #[tokio::test]
    async fn the_socket_is_readable_only_by_its_owner() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_in(&home);
        let daemon = start_ephemeral(&paths);

        let socket = fs::metadata(daemon.socket_file()).unwrap();
        assert!(socket.file_type().is_socket());
        assert_eq!(socket.permissions().mode() & 0o777, 0o600);

        daemon.shutdown().await;
    }

    #[tokio::test]
    async fn a_clean_shutdown_removes_the_socket_and_the_pid_file() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_in(&home);
        let daemon = start_ephemeral(&paths);
        assert!(paths.socket_file().exists());
        assert!(paths.pid_file().exists());

        daemon.shutdown().await;

        assert!(!paths.socket_file().exists());
        assert!(!paths.pid_file().exists());
    }

    #[tokio::test]
    async fn a_stale_pid_file_and_socket_do_not_block_a_start() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_in(&home);
        paths.state_dir().unwrap();
        fs::write(paths.pid_file(), b"4294967294\n").unwrap();
        fs::write(paths.socket_file(), b"not a socket").unwrap();

        let daemon = start_ephemeral(&paths);

        assert!(
            fs::metadata(paths.socket_file())
                .unwrap()
                .file_type()
                .is_socket()
        );
        let written = fs::read_to_string(paths.pid_file()).unwrap();
        assert_eq!(written.trim().parse::<u32>().unwrap(), process::id());

        daemon.shutdown().await;
    }

    #[test]
    fn a_held_lock_refuses_a_second_start() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_in(&home);
        let guard = InstanceGuard::acquire(&paths).unwrap();

        let failure = InstanceGuard::acquire(&paths).unwrap_err();

        let StartFailure::AlreadyRunning(owner) = &failure else {
            panic!("a held lock must report the owner: {failure}");
        };
        assert_eq!(owner, &LockOwner::Known(Pid(process::id())));
        assert!(failure.to_string().contains(&process::id().to_string()));
        drop(guard);
    }

    #[test]
    fn a_released_lock_lets_the_next_daemon_in() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_in(&home);
        let guard = InstanceGuard::acquire(&paths).unwrap();
        drop(guard);

        let guard = InstanceGuard::acquire(&paths).unwrap();
        drop(guard);
    }

    #[test]
    fn an_unreadable_pid_file_reports_an_unknown_owner() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_in(&home);
        paths.state_dir().unwrap();
        fs::write(paths.pid_file(), b"").unwrap();
        let guard = InstanceGuard::acquire(&paths).unwrap();
        fs::write(paths.pid_file(), b"who knows").unwrap();

        let failure = InstanceGuard::acquire(&paths).unwrap_err();

        let StartFailure::AlreadyRunning(owner) = &failure else {
            panic!("a held lock must report the owner: {failure}");
        };
        assert_eq!(owner, &LockOwner::Unknown);
        drop(guard);
    }

    #[test]
    fn a_state_directory_that_is_a_file_fails_to_start() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_in(&home);
        fs::create_dir_all(home.path().join(".local").join("state")).unwrap();
        fs::write(home.path().join(".local").join("state").join("nhop"), b"").unwrap();

        let failure = InstanceGuard::acquire(&paths).unwrap_err();

        let StartFailure::Io(_failure) = &failure else {
            panic!("an unusable state directory must fail with io: {failure}");
        };
    }
}
