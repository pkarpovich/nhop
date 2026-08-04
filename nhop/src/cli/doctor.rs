use std::fs;
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use nhop_ipc::{CheckView, HealthState, LastLoadView, LoadOutcome, Timestamp, UpstreamAddr};
use tokio::net::TcpStream;

use crate::cli::Exit;
use crate::cli::system_proxy::{NetworkService, ProxyFailure, SystemProxy};
use crate::daemon::state::BindState;
use crate::proxy::{Listen, NO_UPSTREAM};
use crate::upstream::{Health, UPSTREAM_CONNECT_TIMEOUT};

/// Detail a check carries when nothing ran it.
const NOT_CHECKED: &str = "not checked, the daemon did not answer";

const OWNER_WRITE: u32 = 0o200;
const ANY_EXECUTE: u32 = 0o111;

/// One of the seven checks `doctor` runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// The CLI reached the daemon over the IPC socket.
    DaemonReachable,
    /// Both front ends hold the addresses they are configured to bind.
    PortsBound,
    /// The macOS system proxy points at those front ends.
    SystemProxy,
    /// The upstream answers a connection.
    UpstreamReachable,
    /// The init script exists and can be executed.
    InitFile,
    /// The most recent init run committed.
    LastLoad,
    /// The daemon can append to its log.
    LogWritable,
}

/// The seven checks, in the order `doctor` reports them.
pub const CHECKS: [Check; 7] = [
    Check::DaemonReachable,
    Check::PortsBound,
    Check::SystemProxy,
    Check::UpstreamReachable,
    Check::InitFile,
    Check::LastLoad,
    Check::LogWritable,
];

impl Check {
    /// Returns the stable identifier the wire carries.
    pub fn name(self) -> &'static str {
        match self {
            Self::DaemonReachable => "daemon_reachable",
            Self::PortsBound => "ports_bound",
            Self::SystemProxy => "system_proxy",
            Self::UpstreamReachable => "upstream_reachable",
            Self::InitFile => "init_file",
            Self::LastLoad => "last_load",
            Self::LogWritable => "log_writable",
        }
    }
}

/// Whether a check found something to fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing to fix.
    Passed,
    /// The detail names what to fix.
    Failed,
}

impl Outcome {
    /// Returns how the wire reports the outcome.
    pub fn is_ok(self) -> bool {
        match self {
            Self::Passed => true,
            Self::Failed => false,
        }
    }
}

/// What one check observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub check: Check,
    pub outcome: Outcome,
    /// What it observed, and the remedy when it failed.
    pub detail: String,
}

impl Finding {
    pub fn passed(check: Check, detail: String) -> Self {
        Self {
            check,
            outcome: Outcome::Passed,
            detail,
        }
    }

    pub fn failed(check: Check, detail: String) -> Self {
        Self {
            check,
            outcome: Outcome::Failed,
            detail,
        }
    }
}

/// Renders the seven checks in their fixed order, whatever order they were observed in; a check
/// nothing observed is reported as failed.
pub fn report(findings: &[Finding]) -> Vec<CheckView> {
    let mut views = Vec::with_capacity(CHECKS.len());
    for check in CHECKS {
        views.push(view(check, findings));
    }
    views
}

fn view(check: Check, findings: &[Finding]) -> CheckView {
    let mut found = None;
    for finding in findings {
        if finding.check == check {
            found = Some(finding);
            break;
        }
    }
    let Some(Finding {
        check: _,
        outcome,
        detail,
    }) = found
    else {
        return CheckView {
            name: check.name().to_owned(),
            ok: false,
            detail: NOT_CHECKED.to_owned(),
        };
    };
    CheckView {
        name: check.name().to_owned(),
        ok: outcome.is_ok(),
        detail: detail.clone(),
    }
}

/// Returns the code `doctor` exits with once every check has been made: an unreachable upstream is
/// the one routine failure - the operator powers the VM off - so it alone exits 3 rather than 1.
pub fn exit_of(checks: &[CheckView]) -> Exit {
    let mut failed = 0;
    let mut beyond_the_upstream = 0;
    for CheckView {
        name,
        ok,
        detail: _,
    } in checks
    {
        if *ok {
            continue;
        }
        failed += 1;
        if name != Check::UpstreamReachable.name() {
            beyond_the_upstream += 1;
        }
    }
    if failed == 0 {
        return Exit::Success;
    }
    if beyond_the_upstream == 0 {
        return Exit::UpstreamDown;
    }
    Exit::Failed
}

/// Reports that the daemon answered on its socket.
pub fn daemon_reachable(socket_file: &Path) -> Finding {
    Finding::passed(
        Check::DaemonReachable,
        format!("the daemon answered on {}", socket_file.display()),
    )
}

/// Reports that the daemon answered nothing, so no other check could be made.
pub fn unreachable(failure: &str) -> Finding {
    Finding::failed(
        Check::DaemonReachable,
        format!("{failure}, run `nhop start`"),
    )
}

/// Reports whether the front ends hold the addresses they were given.
pub fn ports_bound(listen: Listen, bound: BindState) -> Finding {
    let Listen { http, socks } = listen;
    match bound {
        BindState::Bound => Finding::passed(
            Check::PortsBound,
            format!("http on {http}, socks5 on {socks}"),
        ),
        BindState::Unbound => Finding::failed(
            Check::PortsBound,
            format!("nothing is listening on {http} or {socks}, restart the daemon"),
        ),
    }
}

/// Reports whether macOS sends traffic to the front ends this daemon holds.
pub fn system_proxy(
    read: Result<SystemProxy, ProxyFailure>,
    listen: Listen,
    service: &NetworkService,
) -> Finding {
    let proxy = match read {
        Ok(proxy) => proxy,
        Err(failure) => {
            return Finding::failed(
                Check::SystemProxy,
                format!("cannot read the settings of {service}: {failure}"),
            );
        }
    };
    let Listen { http, socks } = listen;
    let SystemProxy {
        http: web,
        https: secure,
        socks: firewall,
    } = proxy;
    let mut wrong = Vec::new();
    for (name, configured, wanted) in [
        ("http", web, http),
        ("https", secure, http),
        ("socks", firewall, socks),
    ] {
        let Some(configured) = configured else {
            wrong.push(format!("{name} is off"));
            continue;
        };
        let configured = configured.to_string();
        if configured == wanted.to_string() {
            continue;
        }
        wrong.push(format!("{name} points at {configured}, not at {wanted}"));
    }
    if wrong.is_empty() {
        return Finding::passed(
            Check::SystemProxy,
            format!("{service} sends http and https to {http} and socks to {socks}"),
        );
    }
    Finding::failed(
        Check::SystemProxy,
        format!("{service}: {}, run `sudo nhop proxy on`", wrong.join(", ")),
    )
}

/// Reports whether the upstream answers, and names the Local Network denial macOS hides.
pub async fn upstream_reachable(
    written: &UpstreamAddr,
    upstream: SocketAddr,
    health: Health,
) -> Finding {
    let UpstreamAddr(name) = written;
    if name.is_empty() || upstream == NO_UPSTREAM {
        return Finding::failed(
            Check::UpstreamReachable,
            "no upstream is configured, name one with `nhop upstream socks5://<ip>:<port>`"
                .to_owned(),
        );
    }
    let Health {
        state,
        changed_at: _,
    } = health;
    let state = verdict_name(state);
    let dialling = TcpStream::connect(upstream);
    let Ok(dialled) = tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, dialling).await else {
        return Finding::failed(
            Check::UpstreamReachable,
            format!(
                "{name} did not answer within {}s, the verdict is {state}",
                UPSTREAM_CONNECT_TIMEOUT.as_secs()
            ),
        );
    };
    let Err(failure) = dialled else {
        return Finding::passed(
            Check::UpstreamReachable,
            format!("{name} answered on {upstream}, the verdict is {state}"),
        );
    };
    Finding::failed(Check::UpstreamReachable, refusal(name, upstream, &failure))
}

fn refusal(name: &str, upstream: SocketAddr, failure: &io::Error) -> String {
    match failure.kind() {
        io::ErrorKind::HostUnreachable => format!(
            "cannot reach {name} on {upstream}: {failure} - macOS reports a denied Local Network permission as a routing error, so grant nhop Local Network access in System Settings > Privacy & Security and check that the binary is signed"
        ),
        _ => format!("cannot reach {name} on {upstream}: {failure}"),
    }
}

fn verdict_name(state: HealthState) -> &'static str {
    match state {
        HealthState::Up => "up",
        HealthState::Down => "down",
    }
}

/// Reports whether the init script exists and can be executed.
pub fn init_file(init_file: &Path) -> Finding {
    let path = init_file.display();
    let Ok(found) = fs::metadata(init_file) else {
        return Finding::failed(
            Check::InitFile,
            format!("no init script at {path}, every connection is direct until one exists"),
        );
    };
    if !found.is_file() {
        return Finding::failed(Check::InitFile, format!("{path} is not a file"));
    }
    if found.permissions().mode() & ANY_EXECUTE == 0 {
        return Finding::failed(
            Check::InitFile,
            format!("{path} is not executable, run `chmod +x {path}`"),
        );
    }
    Finding::passed(Check::InitFile, format!("{path} is executable"))
}

/// Reports how the most recent init run ended.
pub fn last_load(last_load: Option<&LastLoadView>) -> Finding {
    let Some(LastLoadView {
        at,
        outcome,
        command,
    }) = last_load
    else {
        return Finding::failed(
            Check::LastLoad,
            "no init script has been loaded, the ruleset is empty and every connection is direct"
                .to_owned(),
        );
    };
    let Timestamp(at) = at;
    let at = humantime::format_rfc3339_seconds(*at);
    match outcome {
        LoadOutcome::Ok => Finding::passed(Check::LastLoad, format!("the run at {at} committed")),
        LoadOutcome::Failed => Finding::failed(
            Check::LastLoad,
            format!(
                "the run at {at} failed{}, fix it and run `nhop reload`",
                on(command)
            ),
        ),
        LoadOutcome::TimedOut => Finding::failed(
            Check::LastLoad,
            format!("the run at {at} outlived the load timeout and was killed"),
        ),
    }
}

fn on(command: &Option<String>) -> String {
    let Some(command) = command else {
        return String::new();
    };
    format!(" on {command}")
}

/// Reports whether the daemon can still write the log the filesystem contract names.
pub fn log_writable(log_file: &Path) -> Finding {
    let Some(dir) = log_file.parent() else {
        return Finding::failed(
            Check::LogWritable,
            format!("{} names no directory to write into", log_file.display()),
        );
    };
    let path = dir.display();
    let Ok(found) = fs::metadata(dir) else {
        return Finding::failed(Check::LogWritable, format!("no state directory at {path}"));
    };
    if !found.is_dir() {
        return Finding::failed(Check::LogWritable, format!("{path} is not a directory"));
    }
    if found.permissions().mode() & OWNER_WRITE == 0 {
        return Finding::failed(
            Check::LogWritable,
            format!("{path} is not writable, run `chmod u+rwx {path}`"),
        );
    }
    Finding::passed(
        Check::LogWritable,
        format!("{} is writable", log_file.display()),
    )
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use tokio::net::TcpListener;

    use crate::cli::system_proxy::ProxyEndpoint;

    use super::*;

    fn listen() -> Listen {
        Listen {
            http: "127.0.0.1:7890".parse().unwrap(),
            socks: "127.0.0.1:7891".parse().unwrap(),
        }
    }

    fn service() -> NetworkService {
        NetworkService::default()
    }

    fn settled() -> Health {
        Health {
            state: HealthState::Up,
            changed_at: UNIX_EPOCH + Duration::from_secs(1_770_000_000),
        }
    }

    fn passing() -> Vec<Finding> {
        let mut findings = Vec::new();
        for check in CHECKS {
            findings.push(Finding::passed(check, "all is well".to_owned()));
        }
        findings
    }

    fn names(checks: &[CheckView]) -> Vec<String> {
        let mut names = Vec::new();
        for CheckView {
            name,
            ok: _,
            detail: _,
        } in checks
        {
            names.push(name.clone());
        }
        names
    }

    fn found(checks: &[CheckView], check: Check) -> &CheckView {
        for view in checks {
            if view.name == check.name() {
                return view;
            }
        }
        panic!("the report must carry {}", check.name());
    }

    #[test]
    fn the_report_names_the_seven_checks_in_their_fixed_order() {
        let checks = report(&passing());

        assert_eq!(
            names(&checks),
            vec![
                "daemon_reachable".to_owned(),
                "ports_bound".to_owned(),
                "system_proxy".to_owned(),
                "upstream_reachable".to_owned(),
                "init_file".to_owned(),
                "last_load".to_owned(),
                "log_writable".to_owned(),
            ]
        );
    }

    #[test]
    fn a_report_whose_checks_all_pass_exits_zero() {
        let checks = report(&passing());

        assert_eq!(exit_of(&checks), Exit::Success);
        assert_eq!(exit_of(&checks).code(), 0);
        for CheckView {
            name,
            ok,
            detail: _,
        } in &checks
        {
            assert!(ok, "{name}");
        }
    }

    #[test]
    fn a_report_whose_only_failure_is_the_upstream_exits_three() {
        let mut findings = passing();
        findings[3] = Finding::failed(Check::UpstreamReachable, "the vm is off".to_owned());

        let checks = report(&findings);

        assert_eq!(exit_of(&checks), Exit::UpstreamDown);
        assert_eq!(exit_of(&checks).code(), 3);
        assert_eq!(names(&checks).len(), CHECKS.len());
        assert!(!found(&checks, Check::UpstreamReachable).ok);
        assert!(found(&checks, Check::PortsBound).ok);
    }

    #[test]
    fn a_report_with_a_failure_beyond_the_upstream_exits_one() {
        let mut findings = passing();
        findings[3] = Finding::failed(Check::UpstreamReachable, "the vm is off".to_owned());
        findings[5] = Finding::failed(Check::LastLoad, "the run failed".to_owned());

        let checks = report(&findings);

        assert_eq!(exit_of(&checks), Exit::Failed);
        assert_eq!(exit_of(&checks).code(), 1);
        assert!(!found(&checks, Check::LastLoad).ok);
    }

    #[test]
    fn a_check_nobody_made_is_reported_as_failed() {
        let checks = report(&[unreachable("no daemon is listening")]);

        assert_eq!(names(&checks).len(), CHECKS.len());
        assert!(!found(&checks, Check::DaemonReachable).ok);
        assert!(
            found(&checks, Check::DaemonReachable)
                .detail
                .contains("nhop start")
        );
        assert_eq!(found(&checks, Check::PortsBound).detail, NOT_CHECKED);
        assert_eq!(exit_of(&checks), Exit::Failed);
    }

    #[test]
    fn a_reachable_daemon_names_the_socket_it_answered_on() {
        let finding = daemon_reachable(Path::new("/home/operator/.local/state/nhop/nhop.sock"));

        assert_eq!(finding.outcome, Outcome::Passed);
        assert!(finding.detail.contains("nhop.sock"), "{}", finding.detail);
    }

    #[test]
    fn bound_front_ends_pass_and_unbound_ones_name_both_addresses() {
        let bound = ports_bound(listen(), BindState::Bound);
        assert_eq!(bound.outcome, Outcome::Passed);
        assert!(bound.detail.contains("127.0.0.1:7890"), "{}", bound.detail);

        let unbound = ports_bound(listen(), BindState::Unbound);
        assert_eq!(unbound.outcome, Outcome::Failed);
        assert!(
            unbound.detail.contains("127.0.0.1:7891"),
            "{}",
            unbound.detail
        );
    }

    #[test]
    fn a_system_proxy_pointing_at_the_front_ends_passes() {
        let configured = SystemProxy {
            http: Some(ProxyEndpoint::new("127.0.0.1", 7890)),
            https: Some(ProxyEndpoint::new("127.0.0.1", 7890)),
            socks: Some(ProxyEndpoint::new("127.0.0.1", 7891)),
        };

        let finding = system_proxy(Ok(configured), listen(), &service());

        assert_eq!(finding.outcome, Outcome::Passed);
        assert!(finding.detail.contains("Wi-Fi"), "{}", finding.detail);
    }

    #[test]
    fn a_system_proxy_that_is_off_or_points_elsewhere_names_the_remedy() {
        let off = system_proxy(Ok(SystemProxy::default()), listen(), &service());
        assert_eq!(off.outcome, Outcome::Failed);
        assert!(off.detail.contains("http is off"), "{}", off.detail);
        assert!(off.detail.contains("sudo nhop proxy on"), "{}", off.detail);

        let elsewhere = SystemProxy {
            http: Some(ProxyEndpoint::new("127.0.0.1", 7890)),
            https: Some(ProxyEndpoint::new("127.0.0.1", 7890)),
            socks: Some(ProxyEndpoint::new("127.0.0.1", 1080)),
        };
        let elsewhere = system_proxy(Ok(elsewhere), listen(), &service());
        assert_eq!(elsewhere.outcome, Outcome::Failed);
        assert!(
            elsewhere.detail.contains("socks points at 127.0.0.1:1080"),
            "{}",
            elsewhere.detail
        );
    }

    #[test]
    fn settings_that_cannot_be_read_are_named_rather_than_reported_as_off() {
        let finding = system_proxy(
            Err(ProxyFailure::Unreadable("-getwebproxy")),
            listen(),
            &service(),
        );

        assert_eq!(finding.outcome, Outcome::Failed);
        assert!(
            finding.detail.contains("-getwebproxy"),
            "{}",
            finding.detail
        );
    }

    #[tokio::test]
    async fn an_upstream_that_answers_passes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let finding = upstream_reachable(&UpstreamAddr(addr.to_string()), addr, settled()).await;

        assert_eq!(finding.outcome, Outcome::Passed);
        assert!(finding.detail.contains("up"), "{}", finding.detail);
    }

    #[tokio::test]
    async fn an_upstream_on_a_closed_port_fails_and_names_the_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let finding = upstream_reachable(
            &UpstreamAddr(format!("socks5://{addr}")),
            addr,
            Health::default(),
        )
        .await;

        assert_eq!(finding.outcome, Outcome::Failed);
        assert!(
            finding.detail.contains(&addr.to_string()),
            "{}",
            finding.detail
        );
    }

    #[tokio::test]
    async fn an_unnamed_upstream_fails_without_dialling_anything() {
        let finding =
            upstream_reachable(&UpstreamAddr(String::new()), NO_UPSTREAM, Health::default()).await;

        assert_eq!(finding.outcome, Outcome::Failed);
        assert!(
            finding.detail.contains("nhop upstream"),
            "{}",
            finding.detail
        );
    }

    #[test]
    fn a_routing_error_is_reported_as_a_probable_local_network_denial() {
        let upstream: SocketAddr = "192.0.2.10:1080".parse().unwrap();
        let denied = refusal(
            "socks5://192.0.2.10:1080",
            upstream,
            &io::Error::from(io::ErrorKind::HostUnreachable),
        );
        assert!(denied.contains("Local Network"), "{denied}");
        assert!(denied.contains("signed"), "{denied}");

        let refused = refusal(
            "socks5://192.0.2.10:1080",
            upstream,
            &io::Error::from(io::ErrorKind::ConnectionRefused),
        );
        assert!(!refused.contains("Local Network"), "{refused}");
        assert!(refused.contains("192.0.2.10:1080"), "{refused}");
    }

    #[test]
    fn an_executable_init_script_passes_and_the_other_shapes_name_the_remedy() {
        let home = tempfile::tempdir().unwrap();
        let init = home.path().join("init");

        let missing = init_file(&init);
        assert_eq!(missing.outcome, Outcome::Failed);
        assert!(missing.detail.contains("direct"), "{}", missing.detail);

        fs::write(&init, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&init, fs::Permissions::from_mode(0o644)).unwrap();
        let unexecutable = init_file(&init);
        assert_eq!(unexecutable.outcome, Outcome::Failed);
        assert!(
            unexecutable.detail.contains("chmod +x"),
            "{}",
            unexecutable.detail
        );

        fs::set_permissions(&init, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(init_file(&init).outcome, Outcome::Passed);

        assert_eq!(init_file(home.path()).outcome, Outcome::Failed);
    }

    #[test]
    fn every_outcome_of_a_run_reads_back_as_a_finding() {
        let never = last_load(None);
        assert_eq!(never.outcome, Outcome::Failed);
        assert!(never.detail.contains("direct"), "{}", never.detail);

        let committed = last_load(Some(&LastLoadView {
            at: Timestamp(SystemTime::now()),
            outcome: LoadOutcome::Ok,
            command: None,
        }));
        assert_eq!(committed.outcome, Outcome::Passed);

        let failed = last_load(Some(&LastLoadView {
            at: Timestamp(SystemTime::now()),
            outcome: LoadOutcome::Failed,
            command: Some("add_rule".to_owned()),
        }));
        assert_eq!(failed.outcome, Outcome::Failed);
        assert!(failed.detail.contains("add_rule"), "{}", failed.detail);

        let killed = last_load(Some(&LastLoadView {
            at: Timestamp(SystemTime::now()),
            outcome: LoadOutcome::TimedOut,
            command: None,
        }));
        assert_eq!(killed.outcome, Outcome::Failed);
        assert!(killed.detail.contains("timeout"), "{}", killed.detail);
    }

    #[test]
    fn a_writable_state_directory_passes_and_a_read_only_one_names_the_remedy() {
        let state = tempfile::tempdir().unwrap();
        let log = state.path().join("nhop.log");

        assert_eq!(log_writable(&log).outcome, Outcome::Passed);

        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let refused = log_writable(&log);
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(refused.outcome, Outcome::Failed);
        assert!(refused.detail.contains("chmod"), "{}", refused.detail);

        let absent = log_writable(&state.path().join("gone").join("nhop.log"));
        assert_eq!(absent.outcome, Outcome::Failed);
        assert!(
            absent.detail.contains("no state directory"),
            "{}",
            absent.detail
        );
    }
}
