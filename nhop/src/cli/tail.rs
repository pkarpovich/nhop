use std::io::{self, Write};
use std::path::Path;

use nhop_ipc::{Command, Response};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::cli::client::{self, Unreachable};

use super::{Exit, Output, render};

/// Prints one line per routing decision until the daemon closes the connection, which a shutting
/// down `nhop start` does; until then this never returns.
pub async fn follow(
    socket_file: &Path,
    output: Output,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Exit {
    let mut decisions = match subscribe(socket_file).await {
        Ok(decisions) => decisions,
        Err(failure) => return report(&failure, err),
    };
    loop {
        let published = match decisions.next().await {
            Ok(published) => published,
            Err(failure) => return report(&failure, err),
        };
        let Some(response) = published else {
            return Exit::Success;
        };
        let exit = render(&response, output, out, err);
        let Response::Event(_decision) = response else {
            return exit;
        };
    }
}

fn report(failure: &Unreachable, err: &mut dyn Write) -> Exit {
    let _ = writeln!(err, "nhop: {failure}");
    Exit::of_unreachable(failure)
}

/// Stream of decisions the daemon publishes, one response per line.
#[derive(Debug)]
pub struct Decisions {
    lines: BufReader<UnixStream>,
    line: String,
}

impl Decisions {
    /// Reads the next response, or nothing once the daemon closes the connection.
    ///
    /// # Errors
    ///
    /// Returns [`Unreachable`] when the connection fails or a line cannot be read.
    pub async fn next(&mut self) -> Result<Option<Response>, Unreachable> {
        loop {
            self.line.clear();
            let read = self
                .lines
                .read_line(&mut self.line)
                .await
                .map_err(Unreachable::Io)?;
            if read == 0 {
                return Ok(None);
            }
            let line = self.line.trim();
            if line.is_empty() {
                continue;
            }
            let response = serde_json::from_str(line).map_err(Unreachable::Malformed)?;
            return Ok(Some(response));
        }
    }
}

/// Switches one connection to the stream of decisions and returns it.
///
/// The write half stays open for the life of the stream: closing it tells the daemon the
/// subscriber is gone.
///
/// # Errors
///
/// Returns [`Unreachable`] when the socket cannot be connected or the command cannot be sent.
pub async fn subscribe(socket_file: &Path) -> Result<Decisions, Unreachable> {
    let mut stream = client::connect(socket_file).await?;
    let mut wire = serde_json::to_vec(&Command::Subscribe)
        .map_err(io::Error::other)
        .map_err(Unreachable::Io)?;
    wire.push(b'\n');
    stream.write_all(&wire).await.map_err(Unreachable::Io)?;
    stream.flush().await.map_err(Unreachable::Io)?;
    Ok(Decisions {
        lines: BufReader::new(stream),
        line: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use nhop_ipc::{DecisionKind, ErrKind, EventView, HealthState, Host, Paths, Port};
    use tokio::net::UnixListener;

    use super::*;

    fn event() -> EventView {
        EventView {
            host: Host("api.example.com".to_owned()),
            port: Port(443),
            decision: DecisionKind::Upstream,
            rule_index: Some(2),
            class: None,
            upstream: HealthState::Up,
            connect_ms: None,
            duration_ms: 9,
            error: None,
        }
    }

    fn temp_paths() -> (tempfile::TempDir, Paths) {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());
        paths.state_dir().unwrap();
        (home, paths)
    }

    fn write_lines(socket_file: &Path, lines: Vec<String>) {
        let listener = UnixListener::bind(socket_file).unwrap();
        tokio::spawn(async move {
            let (mut stream, _address) = listener.accept().await.unwrap();
            for line in lines {
                stream.write_all(line.as_bytes()).await.unwrap();
                stream.write_all(b"\n").await.unwrap();
            }
            stream.flush().await.unwrap();
        });
    }

    async fn followed(paths: &Paths, output: Output) -> (Exit, String, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let exit = follow(&paths.socket_file(), output, &mut out, &mut err).await;
        (
            exit,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[tokio::test]
    async fn every_published_decision_is_printed_until_the_daemon_hangs_up() {
        let (_home, paths) = temp_paths();
        let published = serde_json::to_string(&Response::Event(event())).unwrap();
        write_lines(&paths.socket_file(), vec![published.clone(), published]);

        let (exit, out, err) = followed(&paths, Output::Json).await;

        assert_eq!(exit, Exit::Success);
        assert!(err.is_empty(), "{err}");
        assert_eq!(out.lines().count(), 2, "{out}");
        for line in out.lines() {
            assert_eq!(serde_json::from_str::<EventView>(line).unwrap(), event());
        }
    }

    #[tokio::test]
    async fn the_human_form_prints_one_text_line_per_decision() {
        let (_home, paths) = temp_paths();
        let published = serde_json::to_string(&Response::Event(event())).unwrap();
        write_lines(&paths.socket_file(), vec![published]);

        let (exit, out, err) = followed(&paths, Output::Human).await;

        assert_eq!(exit, Exit::Success);
        assert!(err.is_empty(), "{err}");
        assert_eq!(
            out,
            "api.example.com:443  upstream via no rule  upstream up  9ms  -\n"
        );
    }

    #[tokio::test]
    async fn a_daemon_error_ends_the_stream_with_its_own_exit_code() {
        let (_home, paths) = temp_paths();
        let refused = serde_json::to_string(&Response::Err {
            kind: ErrKind::Internal,
            message: "the daemon said no".to_owned(),
        })
        .unwrap();
        write_lines(&paths.socket_file(), vec![refused]);

        let (exit, out, err) = followed(&paths, Output::Json).await;

        assert_eq!(exit, Exit::Failed);
        assert!(out.is_empty(), "{out}");
        assert!(err.contains("said no"), "{err}");
    }

    #[tokio::test]
    async fn a_missing_socket_exits_two_with_a_hint() {
        let (_home, paths) = temp_paths();

        let (exit, out, err) = followed(&paths, Output::Human).await;

        assert_eq!(exit, Exit::Missing);
        assert_eq!(exit.code(), 2);
        assert!(out.is_empty(), "{out}");
        assert_eq!(err.lines().count(), 1, "{err}");
        assert!(err.contains("nhop start"), "{err}");
    }

    #[tokio::test]
    async fn a_line_that_is_not_a_response_is_reported_as_malformed() {
        let (_home, paths) = temp_paths();
        write_lines(&paths.socket_file(), vec!["{not json".to_owned()]);

        let (exit, out, err) = followed(&paths, Output::Json).await;

        assert_eq!(exit, Exit::Failed);
        assert!(out.is_empty(), "{out}");
        assert!(err.contains("cannot read"), "{err}");
    }
}
