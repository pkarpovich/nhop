mod support;

use std::fs::OpenOptions;
use std::io::Write;
use std::time::Duration;

use nhop_ipc::Paths;

use support::Shared;

const PATIENCE: usize = 400;

fn append(paths: &Paths, day: &str, line: &str) {
    let file = paths.state_dir().unwrap().join(format!("nhop.log.{day}"));
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file)
        .unwrap();
    writeln!(file, "{line}").unwrap();
}

async fn await_lines(out: &Shared, wanted: usize) -> Vec<String> {
    for _attempt in 0..PATIENCE {
        let lines = out.lines();
        if lines.len() >= wanted {
            return lines;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("logs -f never printed {wanted} lines: {:?}", out.lines());
}

#[tokio::test]
async fn following_the_log_prints_what_is_appended_and_moves_on_to_the_next_file() {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(home.path());
    append(&paths, "2026-08-03", "first");
    let out = Shared::default();
    let err = Shared::default();
    let mut printed = out.clone();
    let mut failed = err.clone();
    let following = nhop::cli::run(&paths, &["logs", "-f", "--json"], &mut printed, &mut failed);
    let driving = async {
        await_lines(&out, 1).await;
        append(&paths, "2026-08-03", "second");
        await_lines(&out, 2).await;
        append(&paths, "2026-08-04", "third");
        await_lines(&out, 3).await
    };

    let lines = tokio::select! {
        exit = following => panic!("logs -f must keep following: {exit:?}"),
        lines = driving => lines,
    };

    assert_eq!(lines, ["first", "second", "third"]);
    assert!(err.text().is_empty(), "{}", err.text());
}

#[tokio::test]
async fn a_log_directory_holding_no_file_yet_is_reported_and_not_followed() {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(home.path());
    let out = Shared::default();
    let err = Shared::default();
    let mut printed = out.clone();
    let mut failed = err.clone();

    let exit = nhop::cli::run(&paths, &["logs", "-f"], &mut printed, &mut failed).await;

    assert_eq!(exit, nhop::cli::Exit::Missing);
    assert!(out.text().is_empty(), "{}", out.text());
    assert!(err.text().contains("no log file yet"), "{}", err.text());
}
