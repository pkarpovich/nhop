mod ipc_server;
pub mod state;

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process;

use fs2::FileExt;
use nhop_ipc::Paths;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::daemon::state::StateHandle;

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
    /// Another daemon holds the single-instance lock.
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

/// Running daemon: the single-instance claim, the state task and the IPC server.
pub struct Daemon {
    guard: InstanceGuard,
    state: StateHandle,
    socket_file: PathBuf,
    shutdown: oneshot::Sender<()>,
    served: JoinHandle<()>,
}

impl Daemon {
    /// Returns the handle every command travels through.
    pub fn state(&self) -> &StateHandle {
        &self.state
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
            shutdown,
            served,
        } = self;
        let _ = shutdown.send(());
        let _ = served.await;
        let _ = remove_if_present(&socket_file);
        drop(guard);
    }
}

/// Claims the pid file, starts the state task and begins serving IPC clients.
///
/// # Errors
///
/// Returns [`StartFailure`] when another daemon is running or the socket cannot be bound.
pub fn start(paths: &Paths) -> Result<Daemon, StartFailure> {
    let guard = InstanceGuard::acquire(paths)?;
    let socket_file = paths.socket_file();
    let listener = ipc_server::bind(&socket_file)?;
    let state = state::spawn();
    let (shutdown, signalled) = oneshot::channel();
    let served = tokio::spawn(ipc_server::serve(listener, state.clone(), signalled));
    Ok(Daemon {
        guard,
        state,
        socket_file,
        shutdown,
        served,
    })
}

/// Runs the daemon until SIGINT or SIGTERM arrives.
///
/// # Errors
///
/// Returns [`StartFailure`] when the daemon cannot start or the signal handlers cannot be
/// installed.
pub async fn run(paths: &Paths) -> Result<(), StartFailure> {
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

    use nhop_ipc::{Command, ErrKind, Response, StatusView};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    use crate::daemon::state::{DEFAULT_HTTP_LISTEN, DEFAULT_SOCKS_LISTEN};

    use super::*;

    fn paths_in(home: &tempfile::TempDir) -> Paths {
        Paths::from_home(home.path())
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
        let daemon = start(&paths).unwrap();

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
        assert_eq!(http_listen, DEFAULT_HTTP_LISTEN);
        assert_eq!(socks_listen, DEFAULT_SOCKS_LISTEN);
        assert!(!http_bound);
        assert!(!socks_bound);

        daemon.shutdown().await;
    }

    #[tokio::test]
    async fn one_connection_carries_one_command_per_line() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_in(&home);
        let daemon = start(&paths).unwrap();

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

    #[tokio::test]
    async fn a_malformed_line_is_answered_with_invalid_args() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_in(&home);
        let daemon = start(&paths).unwrap();

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
        let daemon = start(&paths).unwrap();

        let socket = fs::metadata(daemon.socket_file()).unwrap();
        assert!(socket.file_type().is_socket());
        assert_eq!(socket.permissions().mode() & 0o777, 0o600);

        daemon.shutdown().await;
    }

    #[tokio::test]
    async fn a_clean_shutdown_removes_the_socket_and_the_pid_file() {
        let home = tempfile::tempdir().unwrap();
        let paths = paths_in(&home);
        let daemon = start(&paths).unwrap();
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

        let daemon = start(&paths).unwrap();

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
