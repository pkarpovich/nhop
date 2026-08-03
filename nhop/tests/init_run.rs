use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

mod support;

use nhop::daemon;
use nhop_ipc::{
    Command, LastLoadView, LoadOutcome, Paths, Response, RuleClass, RuleKind, RuleValue, RuleView,
    UpstreamAddr,
};

use support::ephemeral_listen;

const NHOP: &str = env!("CARGO_BIN_EXE_nhop");
const PATIENCE: usize = 300;

fn write_init(paths: &Paths, home: &Path, body: &str) {
    fs::create_dir_all(paths.config_dir()).unwrap();
    let init = paths.init_file();
    fs::write(
        &init,
        format!(
            "#!/bin/sh\nexport HOME='{home}'\n{body}",
            home = home.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&init, fs::Permissions::from_mode(0o755)).unwrap();
}

async fn await_load(state: &daemon::state::StateHandle) -> LoadOutcome {
    for _attempt in 0..PATIENCE {
        let Response::Status(status) = state.call(Command::Status).await else {
            panic!("status must answer with a status view");
        };
        let Some(LastLoadView {
            at: _,
            outcome,
            command: _,
        }) = status.last_load
        else {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        };
        return outcome;
    }
    panic!("the init run never finished");
}

#[tokio::test]
async fn an_init_script_declares_the_ruleset_through_the_command_line_client() {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(home.path());
    write_init(
        &paths,
        home.path(),
        &format!(
            "'{NHOP}' upstream socks5://192.0.2.10:1080\n'{NHOP}' never suffix intranet.example.com\n'{NHOP}' require suffix example.com\n'{NHOP}' prefer port 443\n"
        ),
    );

    let daemon = daemon::start_on(&paths, ephemeral_listen()).unwrap();

    assert_eq!(await_load(daemon.state()).await, LoadOutcome::Ok);
    let Response::Rules(rules) = daemon.state().call(Command::Rules).await else {
        panic!("rules must answer with rule views");
    };
    let mut declared = Vec::with_capacity(rules.len());
    for rule in &rules {
        let RuleView {
            index,
            class,
            kind,
            value,
        } = rule;
        declared.push((*index, *class, *kind, value.clone()));
    }
    assert_eq!(
        declared,
        vec![
            (
                0,
                RuleClass::Never,
                RuleKind::Suffix,
                RuleValue("intranet.example.com".to_owned())
            ),
            (
                1,
                RuleClass::Require,
                RuleKind::Suffix,
                RuleValue("example.com".to_owned())
            ),
            (
                2,
                RuleClass::Prefer,
                RuleKind::Port,
                RuleValue("443".to_owned())
            ),
        ]
    );
    let Response::Status(status) = daemon.state().call(Command::Status).await else {
        panic!("status must answer with a status view");
    };
    let UpstreamAddr(upstream) = status.upstream;
    assert_eq!(upstream, "socks5://192.0.2.10:1080");

    daemon.shutdown().await;
}

#[tokio::test]
async fn an_init_script_that_fails_halfway_leaves_no_rule_behind() {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(home.path());
    write_init(
        &paths,
        home.path(),
        &format!("'{NHOP}' require suffix example.com\nexit 1\n"),
    );

    let daemon = daemon::start_on(&paths, ephemeral_listen()).unwrap();

    assert_eq!(await_load(daemon.state()).await, LoadOutcome::Failed);
    assert_eq!(
        daemon.state().call(Command::Rules).await,
        Response::Rules(Vec::new())
    );

    daemon.shutdown().await;
}
