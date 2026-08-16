use std::io;
use std::path::{Path, PathBuf};

use nhop_ipc::{Command, Response};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Reason the client got no answer out of the daemon.
#[derive(Debug, thiserror::Error)]
pub enum Unreachable {
    #[error("no daemon is listening on {}, run `nhop start`", .0.display())]
    NoDaemon(PathBuf),
    #[error("the daemon closed the connection without answering")]
    Closed,
    #[error("cannot talk to the daemon: {0}")]
    Io(io::Error),
    #[error("the daemon answered with a line this client cannot read: {0}")]
    Malformed(serde_json::Error),
}

/// Sends one command over the IPC socket and returns the single answer to it.
///
/// # Errors
///
/// Returns [`Unreachable`] when the socket cannot be connected, the conversation fails or the
/// answer is not a [`Response`].
pub async fn ask(socket_file: &Path, command: &Command) -> Result<Response, Unreachable> {
    let stream = connect(socket_file).await?;
    let (reader, mut writer) = stream.into_split();
    let mut wire = serde_json::to_vec(command)
        .map_err(io::Error::other)
        .map_err(Unreachable::Io)?;
    wire.push(b'\n');
    writer.write_all(&wire).await.map_err(Unreachable::Io)?;
    writer.flush().await.map_err(Unreachable::Io)?;

    let mut reader = BufReader::new(reader);
    let mut answer = String::new();
    let read = read_or_hangup(reader.read_line(&mut answer).await)?;
    if read == 0 {
        return Err(Unreachable::Closed);
    }
    serde_json::from_str(&answer).map_err(Unreachable::Malformed)
}

/// Folds a reset read into the end of file it stands for.
///
/// A peer that closes the socket while bytes it never read are still queued makes the next read
/// fail with `ConnectionReset` rather than return zero - which is what a daemon shutting down on a
/// command it never answered does. Both are the same event, and reporting one of them as a raw
/// errno tells the caller nothing the other does not.
pub(crate) fn read_or_hangup(read: io::Result<usize>) -> Result<usize, Unreachable> {
    let failure = match read {
        Ok(read) => return Ok(read),
        Err(failure) => failure,
    };
    match failure.kind() {
        io::ErrorKind::ConnectionReset => Ok(0),
        _ => Err(Unreachable::Io(failure)),
    }
}

/// Opens the IPC socket, naming an absent daemon rather than the errno behind it.
///
/// # Errors
///
/// Returns [`Unreachable`] when nothing is listening on the socket or it cannot be connected.
pub async fn connect(socket_file: &Path) -> Result<UnixStream, Unreachable> {
    let failure = match UnixStream::connect(socket_file).await {
        Ok(stream) => return Ok(stream),
        Err(failure) => failure,
    };
    Err(unconnectable(socket_file, failure))
}

fn unconnectable(socket_file: &Path, failure: io::Error) -> Unreachable {
    match failure.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
            Unreachable::NoDaemon(socket_file.to_owned())
        }
        _ => Unreachable::Io(failure),
    }
}

#[cfg(test)]
mod tests {
    use nhop_ipc::Paths;

    use super::*;

    #[tokio::test]
    async fn a_missing_socket_reports_that_no_daemon_is_listening() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());

        let failure = ask(&paths.socket_file(), &Command::Status)
            .await
            .unwrap_err();

        let Unreachable::NoDaemon(socket_file) = &failure else {
            panic!("a missing socket must report an absent daemon: {failure}");
        };
        assert_eq!(socket_file, &paths.socket_file());
        assert!(failure.to_string().contains("nhop start"), "{failure}");
    }

    #[test]
    fn a_socket_nobody_listens_on_reports_that_no_daemon_is_listening() {
        let socket_file = Path::new("/nowhere/nhop.sock");

        let failure = unconnectable(
            socket_file,
            io::Error::from(io::ErrorKind::ConnectionRefused),
        );

        let Unreachable::NoDaemon(named) = &failure else {
            panic!("a dead socket must report an absent daemon: {failure}");
        };
        assert_eq!(named, socket_file);
    }

    #[test]
    fn a_reset_read_counts_as_the_hang_up_it_is() {
        let read = read_or_hangup(Err(io::Error::from(io::ErrorKind::ConnectionReset)));

        assert_eq!(read.unwrap(), 0);
    }

    #[test]
    fn any_other_read_failure_is_still_reported_as_itself() {
        let read = read_or_hangup(Err(io::Error::from(io::ErrorKind::PermissionDenied)));

        let Err(Unreachable::Io(failure)) = read else {
            panic!("a read that did not hang up must carry its own error");
        };
        assert_eq!(failure.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn a_daemon_that_hangs_up_reports_a_closed_connection() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());
        paths.state_dir().unwrap();
        let socket_file = paths.socket_file();
        let listener = tokio::net::UnixListener::bind(&socket_file).unwrap();
        tokio::spawn(async move {
            let (stream, _address) = listener.accept().await.unwrap();
            drop(stream);
        });

        let failure = ask(&socket_file, &Command::Status).await.unwrap_err();

        let Unreachable::Closed = &failure else {
            panic!("a hang-up must report a closed connection: {failure}");
        };
    }

    #[tokio::test]
    async fn a_line_that_is_not_a_response_is_reported_as_malformed() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());
        paths.state_dir().unwrap();
        let socket_file = paths.socket_file();
        let listener = tokio::net::UnixListener::bind(&socket_file).unwrap();
        tokio::spawn(async move {
            let (mut stream, _address) = listener.accept().await.unwrap();
            stream
                .write_all(b"{\"resp\":\"teleport\"}\n")
                .await
                .unwrap();
            stream.flush().await.unwrap();
        });

        let failure = ask(&socket_file, &Command::Status).await.unwrap_err();

        let Unreachable::Malformed(_failure) = &failure else {
            panic!("an unreadable line must be reported as malformed: {failure}");
        };
    }

    #[tokio::test]
    async fn one_command_travels_out_and_one_response_comes_back() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());
        paths.state_dir().unwrap();
        let socket_file = paths.socket_file();
        let listener = tokio::net::UnixListener::bind(&socket_file).unwrap();
        let served = tokio::spawn(async move {
            let (stream, _address) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut asked = String::new();
            reader.read_line(&mut asked).await.unwrap();
            writer.write_all(b"{\"resp\":\"ok\"}\n").await.unwrap();
            writer.flush().await.unwrap();
            asked
        });

        let answer = ask(&socket_file, &Command::Off).await.unwrap();

        assert_eq!(answer, Response::Ok);
        assert_eq!(served.await.unwrap().trim(), r#"{"cmd":"off"}"#);
    }
}
