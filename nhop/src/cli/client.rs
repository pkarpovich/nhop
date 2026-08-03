use std::io;
use std::path::{Path, PathBuf};

use nhop_ipc::{Command, Response};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Reason the client got no answer out of the daemon.
#[derive(Debug, thiserror::Error)]
pub enum Unreachable {
    /// Nothing is listening on the IPC socket.
    #[error("no daemon is listening on {}, run `nhop start`", .0.display())]
    NoDaemon(PathBuf),
    /// The daemon dropped the connection before answering.
    #[error("the daemon closed the connection without answering")]
    Closed,
    /// The conversation failed while the command was in flight.
    #[error("cannot talk to the daemon: {0}")]
    Io(io::Error),
    /// The answer was not a response this client understands.
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
    let read = reader
        .read_line(&mut answer)
        .await
        .map_err(Unreachable::Io)?;
    if read == 0 {
        return Err(Unreachable::Closed);
    }
    serde_json::from_str(&answer).map_err(Unreachable::Malformed)
}

async fn connect(socket_file: &Path) -> Result<UnixStream, Unreachable> {
    let failure = match UnixStream::connect(socket_file).await {
        Ok(stream) => return Ok(stream),
        Err(failure) => failure,
    };
    match failure.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
            Err(Unreachable::NoDaemon(socket_file.to_owned()))
        }
        _ => Err(Unreachable::Io(failure)),
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

    #[tokio::test]
    async fn a_socket_nobody_listens_on_reports_that_no_daemon_is_listening() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());
        paths.state_dir().unwrap();
        let listener = tokio::net::UnixListener::bind(paths.socket_file()).unwrap();
        drop(listener);
        assert!(paths.socket_file().exists());

        let failure = ask(&paths.socket_file(), &Command::Status)
            .await
            .unwrap_err();

        let Unreachable::NoDaemon(_socket_file) = &failure else {
            panic!("a dead socket must report an absent daemon: {failure}");
        };
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
