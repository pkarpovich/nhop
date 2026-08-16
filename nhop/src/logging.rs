use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use nhop_ipc::{DecisionKind, EventView, HealthState, Host, Paths, Port, RuleClass, Timestamp};
use tracing::Subscriber;
use tracing_appender::rolling::{Builder, Rotation};
use tracing_subscriber::EnvFilter;

/// Number of daily log files kept, the one being written included.
pub const KEPT_FILES: usize = 7;

const FILTER: &str = "nhop=info";
const TIMESTAMP_KEY: &str = "timestamp";
const FIELDS_KEY: &str = "fields";

/// Installs the daemon's log as the log of this process.
///
/// # Errors
///
/// Returns [`io::Error`] when the state directory is unusable or another log is already installed.
///
/// [`io::Error`]: std::io::Error
pub fn start(paths: &Paths) -> io::Result<()> {
    let subscriber = subscriber(paths)?;
    let Err(failure) = tracing::subscriber::set_global_default(subscriber) else {
        return Ok(());
    };
    Err(io::Error::other(failure))
}

/// Builds the subscriber writing one JSON line per event, rotated daily.
///
/// # Errors
///
/// Returns [`io::Error`] when the state directory cannot be created or opened.
///
/// [`io::Error`]: std::io::Error
pub fn subscriber(paths: &Paths) -> io::Result<impl Subscriber + Send + Sync> {
    let dir = paths.state_dir()?;
    let appender = Builder::new()
        .rotation(Rotation::DAILY)
        .filename_prefix(prefix(paths))
        .max_log_files(KEPT_FILES)
        .build(dir);
    let appender = match appender {
        Ok(appender) => appender,
        Err(failure) => return Err(io::Error::other(failure)),
    };
    Ok(tracing_subscriber::fmt()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .with_env_filter(EnvFilter::new(FILTER))
        .with_writer(appender)
        .finish())
}

/// Writes the one line a routed connection leaves in the log.
///
/// The line carries the fields of [`EventView`] and nothing else: no request line, header or
/// credential ever reaches the log.
pub fn decision(event: &EventView) {
    let EventView {
        host,
        port,
        decision,
        rule_index,
        class,
        upstream,
        connect_ms,
        duration_ms,
        error,
    } = event;
    let Host(host) = host;
    let Port(port) = port;
    tracing::info!(
        host = host.as_str(),
        port = u64::from(*port),
        decision = decision_name(*decision),
        rule_index = rule_index.map(u64::from),
        class = class.map(class_name),
        upstream = health_name(*upstream),
        connect_ms = *connect_ms,
        duration_ms = *duration_ms,
        error = error.as_deref(),
    );
}

/// Returns the kept log files in chronological order, the one being written last.
///
/// # Errors
///
/// Returns [`io::Error`] when the state directory cannot be created or read.
///
/// [`io::Error`]: std::io::Error
pub fn files(paths: &Paths) -> io::Result<Vec<PathBuf>> {
    let dir = paths.state_dir()?;
    let prefix = prefix(paths);
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(&prefix) {
            continue;
        }
        files.push(entry.path());
    }
    files.sort();
    Ok(files)
}

/// Reads the complete lines a log file holds past an offset, and the offset they end at.
///
/// A file shorter than the offset was rotated away underneath the reader and is read from its
/// start again.
///
/// # Errors
///
/// Returns [`io::Error`] when the file cannot be opened or read.
///
/// [`io::Error`]: std::io::Error
pub fn read_from(file: &Path, offset: u64) -> io::Result<(Vec<String>, u64)> {
    let mut handle = File::open(file)?;
    let len = handle.metadata()?.len();
    let offset = match len < offset {
        true => 0,
        false => offset,
    };
    handle.seek(SeekFrom::Start(offset))?;
    let mut read = String::new();
    handle.read_to_string(&mut read)?;
    let mut lines = Vec::new();
    let mut consumed = 0;
    for line in read.split_inclusive('\n') {
        if !line.ends_with('\n') {
            break;
        }
        consumed += line.len();
        lines.push(line.trim_end().to_owned());
    }
    let consumed = u64::try_from(consumed).unwrap_or(u64::MAX);
    Ok((lines, offset + consumed))
}

/// Stretch of the log `--since` asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Window {
    All,
    /// Only lines stamped at or after this instant are printed.
    Since(SystemTime),
}

impl Window {
    pub fn reaching_back(window: Duration) -> Self {
        let Some(cutoff) = SystemTime::now().checked_sub(window) else {
            return Self::All;
        };
        Self::Since(cutoff)
    }

    /// Returns whether a line falls inside the window; one that cannot be placed in time falls
    /// inside none but [`Window::All`].
    pub fn holds(&self, line: &str) -> bool {
        match self {
            Self::All => true,
            Self::Since(cutoff) => {
                let Some(at) = stamped(line) else {
                    return false;
                };
                at >= *cutoff
            }
        }
    }
}

/// One routing decision read back out of the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedDecision {
    pub at: Timestamp,
    pub event: EventView,
}

/// Reads back the decision a log line records, absent when it records anything else.
pub fn logged(line: &str) -> Option<LoggedDecision> {
    let Ok(line) = serde_json::from_str::<serde_json::Value>(line) else {
        return None;
    };
    let at = stamped_value(&line)?;
    let fields = line.get(FIELDS_KEY)?;
    let Ok(event) = serde_json::from_value::<EventView>(fields.clone()) else {
        return None;
    };
    Some(LoggedDecision {
        at: Timestamp(at),
        event,
    })
}

fn stamped(line: &str) -> Option<SystemTime> {
    let Ok(line) = serde_json::from_str::<serde_json::Value>(line) else {
        return None;
    };
    stamped_value(&line)
}

fn stamped_value(line: &serde_json::Value) -> Option<SystemTime> {
    let at = line.get(TIMESTAMP_KEY)?;
    let at = at.as_str()?;
    let Ok(at) = humantime::parse_rfc3339(at) else {
        return None;
    };
    Some(at)
}

fn prefix(paths: &Paths) -> String {
    let log = paths.log_file();
    let Some(name) = log.file_name() else {
        return String::new();
    };
    name.to_string_lossy().into_owned()
}

fn decision_name(decision: DecisionKind) -> &'static str {
    match decision {
        DecisionKind::Direct => "direct",
        DecisionKind::Never => "never",
        DecisionKind::Upstream => "upstream",
    }
}

fn class_name(class: RuleClass) -> &'static str {
    match class {
        RuleClass::Require => "require",
        RuleClass::Prefer => "prefer",
        RuleClass::Never => "never",
    }
}

fn health_name(health: HealthState) -> &'static str {
    match health {
        HealthState::Up => "up",
        HealthState::Down => "down",
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct LoggedFields {
        host: Host,
        port: Port,
        decision: DecisionKind,
        rule_index: Option<u32>,
        class: Option<RuleClass>,
        upstream: HealthState,
        connect_ms: Option<u64>,
        duration_ms: u64,
        error: Option<String>,
    }

    fn temp_paths() -> (tempfile::TempDir, Paths) {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());
        (home, paths)
    }

    fn matched() -> EventView {
        EventView {
            host: Host("api.example.com".to_owned()),
            port: Port(443),
            decision: DecisionKind::Upstream,
            rule_index: Some(3),
            class: Some(RuleClass::Require),
            upstream: HealthState::Up,
            connect_ms: Some(2),
            duration_ms: 17,
            error: Some("reset by peer".to_owned()),
        }
    }

    fn unmatched() -> EventView {
        EventView {
            host: Host("example.net".to_owned()),
            port: Port(80),
            decision: DecisionKind::Direct,
            rule_index: None,
            class: None,
            upstream: HealthState::Down,
            connect_ms: None,
            duration_ms: 4,
            error: None,
        }
    }

    fn emit(paths: &Paths, events: &[EventView]) -> Vec<String> {
        let subscriber = subscriber(paths).unwrap();
        tracing::subscriber::with_default(subscriber, || {
            for event in events {
                decision(event);
            }
        });
        let files = files(paths).unwrap();
        let mut lines = Vec::new();
        for file in files {
            let (read, _offset) = read_from(&file, 0).unwrap();
            lines.extend(read);
        }
        lines
    }

    fn fields_of(line: &str) -> LoggedFields {
        let line: serde_json::Value = serde_json::from_str(line).unwrap();
        let fields = line.get(FIELDS_KEY).unwrap().clone();
        serde_json::from_value(fields).unwrap()
    }

    fn stamp(at: &str, host: &str) -> String {
        format!(
            r#"{{"timestamp":"{at}","level":"INFO","fields":{{"host":"{host}","port":443,"decision":"direct","upstream":"down","duration_ms":1}},"target":"nhop::logging"}}"#
        )
    }

    #[test]
    fn an_emitted_line_carries_the_event_fields_and_nothing_else() {
        let (_home, paths) = temp_paths();

        let lines = emit(&paths, &[matched(), unmatched()]);

        assert_eq!(lines.len(), 2, "{lines:?}");
        let EventView {
            host,
            port,
            decision,
            rule_index,
            class,
            upstream,
            connect_ms,
            duration_ms,
            error,
        } = matched();
        assert_eq!(
            fields_of(&lines[0]),
            LoggedFields {
                host,
                port,
                decision,
                rule_index,
                class,
                upstream,
                connect_ms,
                duration_ms,
                error,
            }
        );
        let absent = fields_of(&lines[1]);
        assert_eq!(absent.rule_index, None);
        assert_eq!(absent.connect_ms, None);
        assert_eq!(absent.class, None);
        assert_eq!(absent.error, None);
    }

    #[test]
    fn an_emitted_line_reads_back_as_the_event_it_was_written_from() {
        let (_home, paths) = temp_paths();

        let lines = emit(&paths, &[matched()]);

        let Some(LoggedDecision { at: _, event }) = logged(&lines[0]) else {
            panic!("a decision line must read back as a decision: {}", lines[0]);
        };
        assert_eq!(event, matched());
    }

    #[test]
    fn the_log_file_is_named_after_the_filesystem_contract() {
        let (_home, paths) = temp_paths();

        let _lines = emit(&paths, &[matched()]);

        let files = files(&paths).unwrap();
        assert_eq!(files.len(), 1, "{files:?}");
        let name = files[0].file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("nhop.log."), "{name}");
        assert_eq!(files[0].parent().unwrap(), paths.state_dir().unwrap());
    }

    #[test]
    fn the_kept_files_are_returned_in_chronological_order() {
        let (_home, paths) = temp_paths();
        let dir = paths.state_dir().unwrap().to_owned();
        for day in ["2026-08-03", "2026-08-01", "2026-08-02"] {
            fs::write(dir.join(format!("nhop.log.{day}")), b"").unwrap();
        }
        fs::write(dir.join("nhop.pid"), b"1").unwrap();

        let files = files(&paths).unwrap();

        let mut names = Vec::new();
        for file in files {
            names.push(file.file_name().unwrap().to_str().unwrap().to_owned());
        }
        assert_eq!(
            names,
            vec![
                "nhop.log.2026-08-01".to_owned(),
                "nhop.log.2026-08-02".to_owned(),
                "nhop.log.2026-08-03".to_owned(),
            ]
        );
    }

    #[test]
    fn a_window_holds_only_the_lines_stamped_inside_it() {
        let fresh = humantime::format_rfc3339_seconds(SystemTime::now()).to_string();
        let fresh = stamp(&fresh, "fresh.example.com");
        let old = stamp("2026-08-01T00:00:00Z", "old.example.com");
        let window = Window::reaching_back(Duration::from_secs(900));

        assert!(window.holds(&fresh));
        assert!(!window.holds(&old));
        assert!(Window::All.holds(&old));
    }

    #[test]
    fn a_line_that_cannot_be_placed_in_time_is_outside_every_window() {
        let window = Window::reaching_back(Duration::from_secs(900));

        assert!(!window.holds("not json"));
        assert!(!window.holds(r#"{"level":"INFO"}"#));
        assert!(!window.holds(r#"{"timestamp":"yesterday"}"#));
        assert!(Window::All.holds("not json"));
    }

    #[test]
    fn a_line_that_is_not_a_decision_does_not_read_back_as_one() {
        assert_eq!(logged("not json"), None);
        assert_eq!(
            logged(r#"{"timestamp":"2026-08-01T00:00:00Z","level":"INFO"}"#),
            None
        );
        assert_eq!(
            logged(r#"{"timestamp":"2026-08-01T00:00:00Z","fields":{"message":"hello"}}"#),
            None
        );
    }

    #[test]
    fn a_file_is_read_from_the_offset_the_previous_read_ended_at() {
        let (_home, paths) = temp_paths();
        let file = paths.state_dir().unwrap().join("nhop.log.2026-08-03");
        fs::write(&file, "first\nsecond\npart").unwrap();

        let (lines, offset) = read_from(&file, 0).unwrap();
        assert_eq!(lines, vec!["first".to_owned(), "second".to_owned()]);
        assert_eq!(offset, "first\nsecond\n".len() as u64);

        fs::write(&file, "first\nsecond\npart of a line\n").unwrap();
        let (lines, offset) = read_from(&file, offset).unwrap();
        assert_eq!(lines, vec!["part of a line".to_owned()]);
        assert_eq!(offset, "first\nsecond\npart of a line\n".len() as u64);

        let (lines, _offset) = read_from(&file, offset).unwrap();
        assert!(lines.is_empty(), "{lines:?}");
    }

    #[test]
    fn a_file_shorter_than_the_offset_is_read_from_its_start() {
        let (_home, paths) = temp_paths();
        let file = paths.state_dir().unwrap().join("nhop.log.2026-08-03");
        fs::write(&file, "only\n").unwrap();

        let (lines, offset) = read_from(&file, 4096).unwrap();

        assert_eq!(lines, vec!["only".to_owned()]);
        assert_eq!(offset, "only\n".len() as u64);
    }

    #[test]
    fn a_missing_file_is_an_error() {
        let (_home, paths) = temp_paths();
        let file = paths.state_dir().unwrap().join("nhop.log.2026-08-03");

        assert!(read_from(&file, 0).is_err());
    }

    #[test]
    fn the_logged_names_are_the_names_the_wire_uses() {
        let kinds = [
            DecisionKind::Direct,
            DecisionKind::Never,
            DecisionKind::Upstream,
        ];
        for kind in kinds {
            assert_eq!(
                serde_json::to_string(&kind).unwrap(),
                format!("\"{}\"", decision_name(kind))
            );
        }
        for class in [RuleClass::Require, RuleClass::Prefer, RuleClass::Never] {
            assert_eq!(
                serde_json::to_string(&class).unwrap(),
                format!("\"{}\"", class_name(class))
            );
        }
        for health in [HealthState::Up, HealthState::Down] {
            assert_eq!(
                serde_json::to_string(&health).unwrap(),
                format!("\"{}\"", health_name(health))
            );
        }
    }
}
