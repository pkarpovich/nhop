use std::fs::DirBuilder;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

/// Failure to determine the home directory the paths hang off.
#[derive(Debug, thiserror::Error)]
#[error("cannot determine the home directory")]
pub struct HomeNotFound;

/// Filesystem locations the daemon and the client share.
///
/// Every entry point takes a `Paths` so no test has to mutate the environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    config_dir: PathBuf,
    state_dir: PathBuf,
}

impl Paths {
    /// Derives both directories from a home directory without touching the filesystem.
    pub fn from_home(home: &Path) -> Self {
        Self {
            config_dir: home.join(".config").join("nhop"),
            state_dir: home.join(".local").join("state").join("nhop"),
        }
    }

    /// Derives both directories from the current user's home directory.
    pub fn from_env() -> Result<Self, HomeNotFound> {
        let Some(home) = dirs::home_dir() else {
            return Err(HomeNotFound);
        };
        Ok(Self::from_home(&home))
    }

    /// Returns the directory the init script lives in.
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    /// Returns the state directory, creating it with mode 0700 when it is missing.
    pub fn state_dir(&self) -> io::Result<&Path> {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.state_dir)?;
        Ok(&self.state_dir)
    }

    /// Returns the path of the executable rule script.
    pub fn init_file(&self) -> PathBuf {
        self.config_dir.join("init")
    }

    /// Returns the path of the IPC socket.
    pub fn socket_file(&self) -> PathBuf {
        self.state_dir.join("nhop.sock")
    }

    /// Returns the path of the single-instance pid file.
    pub fn pid_file(&self) -> PathBuf {
        self.state_dir.join("nhop.pid")
    }

    /// Returns the path of the current log file.
    pub fn log_file(&self) -> PathBuf {
        self.state_dir.join("nhop.log")
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn from_home_derives_both_directories() {
        let paths = Paths::from_home(Path::new("/home/operator"));
        assert_eq!(paths.config_dir(), Path::new("/home/operator/.config/nhop"));
        assert_eq!(
            paths.init_file(),
            PathBuf::from("/home/operator/.config/nhop/init")
        );
        assert_eq!(
            paths.socket_file(),
            PathBuf::from("/home/operator/.local/state/nhop/nhop.sock")
        );
        assert_eq!(
            paths.pid_file(),
            PathBuf::from("/home/operator/.local/state/nhop/nhop.pid")
        );
        assert_eq!(
            paths.log_file(),
            PathBuf::from("/home/operator/.local/state/nhop/nhop.log")
        );
    }

    #[test]
    fn from_home_touches_nothing() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());
        assert!(!paths.config_dir().exists());
        assert!(!paths.socket_file().parent().unwrap().exists());
    }

    #[test]
    fn state_dir_creates_with_mode_0700() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());
        let created = paths.state_dir().unwrap();
        assert!(created.is_dir());
        assert_eq!(mode_of(created), 0o700);
    }

    #[test]
    fn state_dir_is_idempotent() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());
        let first = paths.state_dir().unwrap().to_owned();
        let second = paths.state_dir().unwrap().to_owned();
        assert_eq!(first, second);
        assert_eq!(mode_of(&second), 0o700);
    }

    #[test]
    fn state_dir_fails_when_the_path_is_a_file() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());
        fs::create_dir_all(home.path().join(".local").join("state")).unwrap();
        fs::write(home.path().join(".local").join("state").join("nhop"), b"").unwrap();
        assert!(paths.state_dir().is_err());
    }
}
