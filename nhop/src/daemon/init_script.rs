use std::env;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use nhop_ipc::{LOAD_ID_ENV, LoadId};
use tokio::process::Command;

const SEARCH_PATH_ENV: &str = "PATH";

/// How an init-script run ended.
#[derive(Debug)]
pub enum ScriptOutcome {
    /// The script exited zero, so its staged commands may be committed.
    Succeeded,
    /// The script exited non-zero or was killed by a signal.
    Exited(ExitStatus),
    /// The script outlived the load timeout and was killed.
    TimedOut,
    /// The script could not be run at all.
    NotRun(io::Error),
}

/// Runs an init script to completion, killing it when it outlives `timeout`.
///
/// The script is executed as a program, so its shebang chooses the interpreter. It runs with
/// `config_dir` as its working directory, with the directory of the running executable prepended
/// to `PATH` so that `nhop` resolves to this binary, and with [`LOAD_ID_ENV`] naming the run.
pub async fn run(
    script: &Path,
    config_dir: &Path,
    load: LoadId,
    timeout: Duration,
) -> ScriptOutcome {
    let mut program = Command::new(script);
    program
        .current_dir(config_dir)
        .env(LOAD_ID_ENV, load.to_string())
        .env(SEARCH_PATH_ENV, search_path())
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let mut child = match program.spawn() {
        Ok(child) => child,
        Err(failure) => return ScriptOutcome::NotRun(failure),
    };
    let Ok(waited) = tokio::time::timeout(timeout, child.wait()).await else {
        let _ = child.kill().await;
        return ScriptOutcome::TimedOut;
    };
    let status = match waited {
        Ok(status) => status,
        Err(failure) => return ScriptOutcome::NotRun(failure),
    };
    if status.success() {
        return ScriptOutcome::Succeeded;
    }
    ScriptOutcome::Exited(status)
}

fn search_path() -> OsString {
    let inherited = env::var_os(SEARCH_PATH_ENV).unwrap_or_default();
    let Some(directory) = executable_dir() else {
        return inherited;
    };
    let mut search = OsString::from(directory);
    if !inherited.is_empty() {
        search.push(":");
        search.push(inherited);
    }
    search
}

fn executable_dir() -> Option<PathBuf> {
    let Ok(executable) = env::current_exe() else {
        return None;
    };
    Some(executable.parent()?.to_owned())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Instant;

    use super::*;

    struct Script {
        home: tempfile::TempDir,
    }

    impl Script {
        fn new(body: &str) -> Self {
            let home = tempfile::tempdir().unwrap();
            let script = Self { home };
            fs::create_dir_all(script.config_dir()).unwrap();
            fs::write(script.path(), body).unwrap();
            fs::set_permissions(script.path(), fs::Permissions::from_mode(0o755)).unwrap();
            script
        }

        fn config_dir(&self) -> PathBuf {
            self.home.path().join("config")
        }

        fn path(&self) -> PathBuf {
            self.config_dir().join("init")
        }

        fn report(&self, name: &str) -> PathBuf {
            self.home.path().join(name)
        }

        async fn run(&self, timeout: Duration) -> ScriptOutcome {
            run(&self.path(), &self.config_dir(), LoadId(11), timeout).await
        }
    }

    #[tokio::test]
    async fn a_script_that_exits_zero_succeeds() {
        let script = Script::new("#!/bin/sh\nexit 0\n");

        let outcome = script.run(Duration::from_secs(5)).await;

        let ScriptOutcome::Succeeded = outcome else {
            panic!("a zero exit must succeed: {outcome:?}");
        };
    }

    #[tokio::test]
    async fn a_script_that_exits_non_zero_reports_its_status() {
        let script = Script::new("#!/bin/sh\nexit 3\n");

        let outcome = script.run(Duration::from_secs(5)).await;

        let ScriptOutcome::Exited(status) = outcome else {
            panic!("a non-zero exit must be reported: {outcome:?}");
        };
        assert_eq!(status.code(), Some(3));
    }

    #[tokio::test]
    async fn the_child_runs_in_the_config_directory_with_the_load_id_and_the_executable_on_path() {
        let script = Script::new(
            "#!/bin/sh\nprintf '%s' \"$NHOP_LOAD_ID\" > ../load\nprintf '%s' \"$PATH\" > ../path\npwd > ../pwd\n",
        );

        let outcome = script.run(Duration::from_secs(5)).await;

        let ScriptOutcome::Succeeded = outcome else {
            panic!("the script must succeed: {outcome:?}");
        };
        assert_eq!(fs::read_to_string(script.report("load")).unwrap(), "11");
        let search = fs::read_to_string(script.report("path")).unwrap();
        let directory = executable_dir().unwrap();
        assert!(
            search.starts_with(directory.to_str().unwrap()),
            "{search} must start with {}",
            directory.display()
        );
        assert!(
            search.contains(':'),
            "{search} must keep the inherited path"
        );
        let visited = fs::read_to_string(script.report("pwd")).unwrap();
        assert!(
            visited.trim().ends_with("config"),
            "{visited} must be the config directory"
        );
    }

    #[tokio::test]
    async fn a_script_that_outlives_the_timeout_is_killed() {
        let script = Script::new("#!/bin/sh\nsleep 30\n");

        let started = Instant::now();
        let outcome = script.run(Duration::from_millis(100)).await;

        let ScriptOutcome::TimedOut = outcome else {
            panic!("an overlong script must time out: {outcome:?}");
        };
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_script_that_cannot_be_executed_did_not_run() {
        let script = Script::new("#!/bin/sh\nexit 0\n");
        fs::set_permissions(script.path(), fs::Permissions::from_mode(0o644)).unwrap();

        let outcome = script.run(Duration::from_secs(5)).await;

        let ScriptOutcome::NotRun(failure) = outcome else {
            panic!("an unexecutable script must not run: {outcome:?}");
        };
        assert_eq!(failure.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn a_missing_script_did_not_run() {
        let home = tempfile::tempdir().unwrap();

        let outcome = run(
            &home.path().join("absent"),
            home.path(),
            LoadId(1),
            Duration::from_secs(5),
        )
        .await;

        let ScriptOutcome::NotRun(failure) = outcome else {
            panic!("a missing script must not run: {outcome:?}");
        };
        assert_eq!(failure.kind(), io::ErrorKind::NotFound);
    }
}
