use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use nhop_ipc::{Command, ErrKind, Response};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;

use crate::daemon::state::StateHandle;

const SOCKET_MODE: u32 = 0o600;

/// Binds the IPC socket and restricts it to its owner before anyone can connect.
///
/// # Errors
///
/// Returns [`io::Error`] when the socket cannot be bound or its mode cannot be set.
///
/// [`io::Error`]: std::io::Error
pub fn bind(socket_file: &Path) -> io::Result<UnixListener> {
    let listener = UnixListener::bind(socket_file)?;
    fs::set_permissions(socket_file, fs::Permissions::from_mode(SOCKET_MODE))?;
    Ok(listener)
}

/// Serves clients until the shutdown signal arrives.
pub async fn serve(listener: UnixListener, state: StateHandle, shutdown: oneshot::Receiver<()>) {
    tokio::pin!(shutdown);
    loop {
        let accepted = tokio::select! {
            _ = &mut shutdown => return,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, _address)) = accepted else {
            return;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let _ = converse(stream, state).await;
        });
    }
}

async fn converse(stream: UnixStream, state: StateHandle) -> io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Command>(line) {
            Ok(command) => state.call(command).await,
            Err(failure) => Response::Err {
                kind: ErrKind::InvalidArgs,
                message: failure.to_string(),
            },
        };
        let mut wire = serde_json::to_vec(&response).map_err(io::Error::other)?;
        wire.push(b'\n');
        writer.write_all(&wire).await?;
        writer.flush().await?;
    }
}
