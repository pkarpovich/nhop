mod client;

use std::env;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use argh::{EarlyExit, FromArgs};
use nhop_ipc::{
    CheckView, Command, DecisionKind, DecisionView, ErrKind, EventView, HealthState, Host,
    LOAD_ID_ENV, LastLoadView, LoadId, LoadOutcome, Paths, Port, Response, RuleClass,
    RuleCountsView, RuleKind, RuleValue, RuleView, StatusView, SystemProxyView, Timestamp,
    UpstreamAddr,
};
use serde::Serialize;

use crate::cli::client::Unreachable;
use crate::daemon::{self, StartFailure};

const BINARY: &str = "nhop";

/// Code the process exits with, one variant per row of the exit-code table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The command succeeded.
    Success,
    /// The command failed for a reason the operator has to read the message for.
    Failed,
    /// The socket, the daemon or the addressed thing is not there.
    Missing,
    /// The upstream is down and a `require` rule demanded it.
    UpstreamDown,
    /// The arguments were malformed.
    InvalidArgs,
}

impl Exit {
    /// Returns the number handed to the operating system.
    pub fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Failed => 1,
            Self::Missing => 2,
            Self::UpstreamDown => 3,
            Self::InvalidArgs => 4,
        }
    }

    fn of_err(kind: ErrKind) -> Self {
        match kind {
            ErrKind::NotFound => Self::Missing,
            ErrKind::UpstreamDown => Self::UpstreamDown,
            ErrKind::InvalidArgs => Self::InvalidArgs,
            ErrKind::LoadInProgress | ErrKind::Internal => Self::Failed,
        }
    }

    fn of_unreachable(failure: &Unreachable) -> Self {
        match failure {
            Unreachable::NoDaemon(_socket_file) => Self::Missing,
            Unreachable::Closed => Self::Missing,
            Unreachable::Io(_failure) => Self::Missing,
            Unreachable::Malformed(_failure) => Self::Failed,
        }
    }

    fn of_start(failure: &StartFailure) -> Self {
        match failure {
            StartFailure::AlreadyRunning(_owner) => Self::Failed,
            StartFailure::Io(_failure) => Self::Failed,
        }
    }
}

/// Whether a read command prints JSON or text meant for a person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Output {
    Json,
    Human,
}

impl Output {
    fn of(json: bool) -> Self {
        if json { Self::Json } else { Self::Human }
    }
}

/// Destination a routing question is asked about, written as `host:port`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Destination {
    host: Host,
    port: Port,
}

/// Rejection of a destination that is not a `host:port` pair.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("expected host:port, got {0:?}")]
struct InvalidDestination(String);

impl FromStr for Destination {
    type Err = InvalidDestination;

    fn from_str(target: &str) -> Result<Self, Self::Err> {
        let Some((host, port)) = target.rsplit_once(':') else {
            return Err(InvalidDestination(target.to_owned()));
        };
        let host = host.strip_prefix('[').unwrap_or(host);
        let host = host.strip_suffix(']').unwrap_or(host);
        let Ok(port) = port.parse::<u16>() else {
            return Err(InvalidDestination(target.to_owned()));
        };
        if host.is_empty() {
            return Err(InvalidDestination(target.to_owned()));
        }
        Ok(Self {
            host: Host(host.to_owned()),
            port: Port(port),
        })
    }
}

/// macOS network service the system proxy settings belong to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworkService(String);

impl FromStr for NetworkService {
    type Err = InvalidDestination;

    fn from_str(service: &str) -> Result<Self, Self::Err> {
        if service.is_empty() {
            return Err(InvalidDestination(service.to_owned()));
        }
        Ok(Self(service.to_owned()))
    }
}

/// What `nhop proxy` does to the system proxy settings.
#[derive(argh::FromArgValue, Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyAction {
    On,
    Off,
    Status,
}

fn parse_kind(kind: &str) -> Result<RuleKind, String> {
    match kind {
        "suffix" => Ok(RuleKind::Suffix),
        "cidr" => Ok(RuleKind::Cidr),
        "port" => Ok(RuleKind::Port),
        "keyword" => Ok(RuleKind::Keyword),
        unknown => Err(format!(
            "unknown rule kind {unknown:?}, expected suffix, cidr, port or keyword"
        )),
    }
}

fn parse_value(value: &str) -> Result<RuleValue, String> {
    Ok(RuleValue(value.to_owned()))
}

fn parse_upstream(addr: &str) -> Result<UpstreamAddr, String> {
    Ok(UpstreamAddr(addr.to_owned()))
}

#[derive(FromArgs, Debug, PartialEq, Eq)]
/// rule-based local proxy router
struct Arguments {
    #[argh(subcommand)]
    command: Subcommand,
}

#[derive(FromArgs, Debug, PartialEq, Eq)]
#[argh(subcommand)]
enum Subcommand {
    Start(Start),
    Require(Require),
    Prefer(Prefer),
    Never(Never),
    Upstream(Upstream),
    Listen(Listen),
    Reload(Reload),
    On(On),
    Off(Off),
    Status(Status),
    Rules(Rules),
    Test(Test),
    Logs(Logs),
    Tail(Tail),
    Doctor(Doctor),
    Proxy(Proxy),
}

#[derive(FromArgs, Debug, PartialEq, Eq)]
/// run the daemon in the foreground until it is signalled
#[argh(subcommand, name = "start")]
struct Start {}

#[derive(FromArgs, Debug, PartialEq, Eq)]
/// route matching destinations through the upstream, failing when it is down
#[argh(subcommand, name = "require")]
struct Require {
    /// what the rule matches on: suffix, cidr, port or keyword
    #[argh(positional, from_str_fn(parse_kind))]
    kind: RuleKind,
    /// value the kind is matched against
    #[argh(positional, from_str_fn(parse_value))]
    value: RuleValue,
}

#[derive(FromArgs, Debug, PartialEq, Eq)]
/// route matching destinations through the upstream, direct when it is down
#[argh(subcommand, name = "prefer")]
struct Prefer {
    /// what the rule matches on: suffix, cidr, port or keyword
    #[argh(positional, from_str_fn(parse_kind))]
    kind: RuleKind,
    /// value the kind is matched against
    #[argh(positional, from_str_fn(parse_value))]
    value: RuleValue,
}

#[derive(FromArgs, Debug, PartialEq, Eq)]
/// dial matching destinations directly, whatever later rules say
#[argh(subcommand, name = "never")]
struct Never {
    /// what the rule matches on: suffix, cidr, port or keyword
    #[argh(positional, from_str_fn(parse_kind))]
    kind: RuleKind,
    /// value the kind is matched against
    #[argh(positional, from_str_fn(parse_value))]
    value: RuleValue,
}

#[derive(FromArgs, Debug, PartialEq, Eq)]
/// point the router at a SOCKS5 upstream
#[argh(subcommand, name = "upstream")]
struct Upstream {
    /// upstream address, as socks5://host:port
    #[argh(positional, from_str_fn(parse_upstream))]
    addr: UpstreamAddr,
}

#[derive(FromArgs, Debug, PartialEq, Eq)]
/// move the HTTP and SOCKS5 front ends
#[argh(subcommand, name = "listen")]
struct Listen {
    /// address the HTTP front end binds
    #[argh(positional)]
    http: SocketAddr,
    /// address the SOCKS5 front end binds
    #[argh(positional)]
    socks: SocketAddr,
}

#[derive(FromArgs, Debug, PartialEq, Eq)]
/// re-run the init script, optionally a different one
#[argh(subcommand, name = "reload")]
struct Reload {
    /// script to run instead of the remembered one
    #[argh(positional)]
    path: Option<PathBuf>,
}

#[derive(FromArgs, Debug, PartialEq, Eq)]
/// re-run the remembered init script
#[argh(subcommand, name = "on")]
struct On {}

#[derive(FromArgs, Debug, PartialEq, Eq)]
/// clear the live ruleset while both front ends keep listening
#[argh(subcommand, name = "off")]
struct Off {}

#[derive(FromArgs, Debug, PartialEq, Eq)]
/// report what the daemon knows about itself
#[argh(subcommand, name = "status")]
struct Status {
    /// print a single JSON document instead of text
    #[argh(switch)]
    json: bool,
}

#[derive(FromArgs, Debug, PartialEq, Eq)]
/// list the live ruleset in declaration order
#[argh(subcommand, name = "rules")]
struct Rules {
    /// print a single JSON document instead of text
    #[argh(switch)]
    json: bool,
}

#[derive(FromArgs, Debug, PartialEq, Eq)]
/// report where a destination would be routed, without dialling it
#[argh(subcommand, name = "test")]
struct Test {
    /// destination, as host:port
    #[argh(positional)]
    target: Destination,
    /// print a single JSON document instead of text
    #[argh(switch)]
    json: bool,
}

#[derive(FromArgs, Debug, PartialEq, Eq)]
/// print the daemon log
#[argh(subcommand, name = "logs")]
struct Logs {
    /// print the raw JSON lines
    #[argh(switch)]
    json: bool,
}

#[derive(FromArgs, Debug, PartialEq, Eq)]
/// follow routing decisions as they are made
#[argh(subcommand, name = "tail")]
struct Tail {
    /// print a JSON document per decision instead of text
    #[argh(switch)]
    json: bool,
}

#[derive(FromArgs, Debug, PartialEq, Eq)]
/// run the diagnostic checks
#[argh(subcommand, name = "doctor")]
struct Doctor {
    /// print a single JSON document instead of text
    #[argh(switch)]
    json: bool,
}

#[derive(FromArgs, Debug, PartialEq, Eq)]
/// read or set the system proxy settings
#[argh(subcommand, name = "proxy")]
struct Proxy {
    /// what to do: on, off or status
    #[argh(positional)]
    action: ProxyAction,
    /// network service the settings belong to
    #[argh(option, default = "NetworkService(String::from(\"Wi-Fi\"))")]
    service: NetworkService,
}

/// Runs one command-line invocation and returns the code the process exits with.
pub async fn run(
    paths: &Paths,
    arguments: &[&str],
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Exit {
    let parsed = match Arguments::from_args(&[BINARY], arguments) {
        Ok(parsed) => parsed,
        Err(EarlyExit { output, status }) => {
            let Err(()) = status else {
                let _ = writeln!(out, "{output}");
                return Exit::Success;
            };
            let _ = writeln!(err, "{output}");
            return Exit::InvalidArgs;
        }
    };
    let Arguments { command } = parsed;
    dispatch(paths, command, out, err).await
}

async fn dispatch(
    paths: &Paths,
    command: Subcommand,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Exit {
    let load = load_of_env();
    match command {
        Subcommand::Start(Start {}) => start(paths, err).await,
        Subcommand::Require(Require { kind, value }) => {
            let command = add_rule(RuleClass::Require, kind, value, load);
            ask(paths, command, Output::Human, out, err).await
        }
        Subcommand::Prefer(Prefer { kind, value }) => {
            let command = add_rule(RuleClass::Prefer, kind, value, load);
            ask(paths, command, Output::Human, out, err).await
        }
        Subcommand::Never(Never { kind, value }) => {
            let command = add_rule(RuleClass::Never, kind, value, load);
            ask(paths, command, Output::Human, out, err).await
        }
        Subcommand::Upstream(Upstream { addr }) => {
            let command = Command::SetUpstream { addr, load };
            ask(paths, command, Output::Human, out, err).await
        }
        Subcommand::Listen(Listen { http, socks }) => {
            let command = Command::SetListen { http, socks, load };
            ask(paths, command, Output::Human, out, err).await
        }
        Subcommand::Reload(Reload { path }) => {
            ask(paths, Command::Reload { path }, Output::Human, out, err).await
        }
        Subcommand::On(On {}) => ask(paths, Command::On, Output::Human, out, err).await,
        Subcommand::Off(Off {}) => ask(paths, Command::Off, Output::Human, out, err).await,
        Subcommand::Status(Status { json }) => {
            ask(paths, Command::Status, Output::of(json), out, err).await
        }
        Subcommand::Rules(Rules { json }) => {
            ask(paths, Command::Rules, Output::of(json), out, err).await
        }
        Subcommand::Test(Test {
            target: Destination { host, port },
            json,
        }) => {
            let command = Command::Test { host, port };
            ask(paths, command, Output::of(json), out, err).await
        }
        Subcommand::Logs(Logs { json: _ }) => unserved("logs", err),
        Subcommand::Tail(Tail { json: _ }) => unserved("tail", err),
        Subcommand::Doctor(Doctor { json }) => {
            ask(paths, Command::Doctor, Output::of(json), out, err).await
        }
        Subcommand::Proxy(Proxy {
            action: _,
            service: _,
        }) => unserved("proxy", err),
    }
}

fn add_rule(class: RuleClass, kind: RuleKind, value: RuleValue, load: Option<LoadId>) -> Command {
    Command::AddRule {
        class,
        kind,
        value,
        load,
    }
}

fn load_of_env() -> Option<LoadId> {
    let id = env::var_os(LOAD_ID_ENV)?;
    load_of(id.to_str()?)
}

fn load_of(id: &str) -> Option<LoadId> {
    let Ok(id) = id.parse::<LoadId>() else {
        return None;
    };
    Some(id)
}

fn unserved(name: &str, err: &mut dyn Write) -> Exit {
    let _ = writeln!(err, "nhop: {name} is not implemented yet");
    Exit::Failed
}

async fn start(paths: &Paths, err: &mut dyn Write) -> Exit {
    let Err(failure) = daemon::run(paths).await else {
        return Exit::Success;
    };
    let _ = writeln!(err, "nhop: {failure}");
    Exit::of_start(&failure)
}

async fn ask(
    paths: &Paths,
    command: Command,
    output: Output,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Exit {
    let answered = client::ask(&paths.socket_file(), &command).await;
    let response = match answered {
        Ok(response) => response,
        Err(failure) => {
            let _ = writeln!(err, "nhop: {failure}");
            return Exit::of_unreachable(&failure);
        }
    };
    render(&response, output, out, err)
}

fn render(response: &Response, output: Output, out: &mut dyn Write, err: &mut dyn Write) -> Exit {
    match response {
        Response::Ok => Exit::Success,
        Response::Rules(rules) => {
            match output {
                Output::Json => write_json(rules, out),
                Output::Human => render_rules(rules, out),
            }
            Exit::Success
        }
        Response::Status(status) => {
            match output {
                Output::Json => write_json(status, out),
                Output::Human => render_status(status, out),
            }
            Exit::Success
        }
        Response::Decision(decision) => {
            match output {
                Output::Json => write_json(decision, out),
                Output::Human => render_decision(decision, out),
            }
            Exit::Success
        }
        Response::Doctor(checks) => {
            match output {
                Output::Json => write_json(checks, out),
                Output::Human => render_checks(checks, out),
            }
            Exit::Success
        }
        Response::Event(event) => {
            match output {
                Output::Json => write_json(event, out),
                Output::Human => render_event(event, out),
            }
            Exit::Success
        }
        Response::Err { kind, message } => {
            let _ = writeln!(err, "nhop: {message}");
            Exit::of_err(*kind)
        }
    }
}

fn write_json<T: Serialize>(payload: &T, out: &mut dyn Write) {
    let Ok(document) = serde_json::to_string(payload) else {
        return;
    };
    let _ = writeln!(out, "{document}");
}

fn render_rules(rules: &[RuleView], out: &mut dyn Write) {
    for rule in rules {
        let RuleView {
            index,
            class,
            kind,
            value,
        } = rule;
        let RuleValue(value) = value;
        let _ = writeln!(
            out,
            "{index}  {}  {}  {value}",
            class_name(*class),
            kind_name(*kind)
        );
    }
}

fn render_status(status: &StatusView, out: &mut dyn Write) {
    let StatusView {
        uptime_secs,
        http_listen,
        http_bound,
        socks_listen,
        socks_bound,
        upstream,
        health,
        health_changed_at,
        init_path,
        last_load,
        rules,
        system_proxy,
    } = status;
    let UpstreamAddr(upstream) = upstream;
    let RuleCountsView {
        require,
        prefer,
        never,
    } = rules;
    let SystemProxyView { http, https, socks } = system_proxy;
    let Timestamp(changed_at) = health_changed_at;
    let changed_at = humantime::format_rfc3339_seconds(*changed_at);
    let _ = writeln!(out, "uptime        {uptime_secs}s");
    let _ = writeln!(
        out,
        "http          {http_listen} {}",
        bound_name(*http_bound)
    );
    let _ = writeln!(
        out,
        "socks         {socks_listen} {}",
        bound_name(*socks_bound)
    );
    let _ = writeln!(
        out,
        "upstream      {upstream} {} since {changed_at}",
        health_name(*health)
    );
    let _ = writeln!(
        out,
        "rules         require {require}, prefer {prefer}, never {never}"
    );
    let _ = writeln!(out, "init          {}", init_name(init_path));
    let _ = writeln!(out, "last load     {}", load_name(last_load));
    let _ = writeln!(
        out,
        "system proxy  http {}, https {}, socks {}",
        proxy_name(http),
        proxy_name(https),
        proxy_name(socks)
    );
}

fn render_decision(decision: &DecisionView, out: &mut dyn Write) {
    let DecisionView {
        decision,
        rule_index,
        class,
        next_hop,
    } = decision;
    let _ = writeln!(
        out,
        "{} via {} to {next_hop}",
        decision_name(*decision),
        rule_name(*rule_index, *class)
    );
}

fn render_checks(checks: &[CheckView], out: &mut dyn Write) {
    for check in checks {
        let CheckView { name, ok, detail } = check;
        let _ = writeln!(out, "{}  {name}  {detail}", check_name(*ok));
    }
}

fn render_event(event: &EventView, out: &mut dyn Write) {
    let EventView {
        host,
        port,
        decision,
        rule_index,
        class,
        upstream,
        duration_ms,
        error,
    } = event;
    let Host(host) = host;
    let Port(port) = port;
    let error = match error {
        Some(error) => error,
        None => "-",
    };
    let _ = writeln!(
        out,
        "{host}:{port}  {} via {}  upstream {}  {duration_ms}ms  {error}",
        decision_name(*decision),
        rule_name(*rule_index, *class),
        health_name(*upstream)
    );
}

fn class_name(class: RuleClass) -> &'static str {
    match class {
        RuleClass::Require => "require",
        RuleClass::Prefer => "prefer",
        RuleClass::Never => "never",
    }
}

fn kind_name(kind: RuleKind) -> &'static str {
    match kind {
        RuleKind::Suffix => "suffix",
        RuleKind::Cidr => "cidr",
        RuleKind::Port => "port",
        RuleKind::Keyword => "keyword",
    }
}

fn decision_name(decision: DecisionKind) -> &'static str {
    match decision {
        DecisionKind::Direct => "direct",
        DecisionKind::Never => "never",
        DecisionKind::Upstream => "upstream",
    }
}

fn health_name(health: HealthState) -> &'static str {
    match health {
        HealthState::Up => "up",
        HealthState::Down => "down",
    }
}

fn outcome_name(outcome: LoadOutcome) -> &'static str {
    match outcome {
        LoadOutcome::Ok => "ok",
        LoadOutcome::Failed => "failed",
        LoadOutcome::TimedOut => "timed out",
    }
}

fn bound_name(bound: bool) -> &'static str {
    if bound { "bound" } else { "unbound" }
}

fn check_name(ok: bool) -> &'static str {
    if ok { "ok  " } else { "FAIL" }
}

fn rule_name(rule_index: Option<u32>, class: Option<RuleClass>) -> String {
    let (Some(rule_index), Some(class)) = (rule_index, class) else {
        return "no rule".to_owned();
    };
    format!("rule {rule_index} ({})", class_name(class))
}

fn init_name(init_path: &Option<PathBuf>) -> String {
    match init_path {
        Some(init_path) => init_path.display().to_string(),
        None => "none".to_owned(),
    }
}

fn load_name(last_load: &Option<LastLoadView>) -> String {
    let Some(LastLoadView {
        at,
        outcome,
        command,
    }) = last_load
    else {
        return "never - the ruleset is empty and every connection is direct".to_owned();
    };
    let Timestamp(at) = at;
    let at = humantime::format_rfc3339_seconds(*at);
    let outcome = outcome_name(*outcome);
    match command {
        Some(command) => format!("{outcome} at {at}, on {command}"),
        None => format!("{outcome} at {at}"),
    }
}

fn proxy_name(proxy: &Option<String>) -> &str {
    match proxy {
        Some(proxy) => proxy,
        None => "off",
    }
}

#[cfg(test)]
mod tests {
    use crate::daemon::Daemon;

    use super::*;

    fn parse(arguments: &[&str]) -> Subcommand {
        let Arguments { command } = Arguments::from_args(&[BINARY], arguments).unwrap();
        command
    }

    fn value(value: &str) -> RuleValue {
        RuleValue(value.to_owned())
    }

    async fn invoke(paths: &Paths, arguments: &[&str]) -> (Exit, String, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let exit = run(paths, arguments, &mut out, &mut err).await;
        (
            exit,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    fn temp_paths() -> (tempfile::TempDir, Paths) {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());
        (home, paths)
    }

    async fn running_daemon() -> (tempfile::TempDir, Paths, Daemon) {
        let (home, paths) = temp_paths();
        let daemon = daemon::start(&paths).unwrap();
        (home, paths, daemon)
    }

    #[test]
    fn the_daemon_and_the_rule_verbs_parse() {
        assert_eq!(parse(&["start"]), Subcommand::Start(Start {}));
        assert_eq!(
            parse(&["require", "suffix", "example.com"]),
            Subcommand::Require(Require {
                kind: RuleKind::Suffix,
                value: value("example.com"),
            })
        );
        assert_eq!(
            parse(&["prefer", "port", "443"]),
            Subcommand::Prefer(Prefer {
                kind: RuleKind::Port,
                value: value("443"),
            })
        );
        assert_eq!(
            parse(&["never", "cidr", "192.0.2.0/24"]),
            Subcommand::Never(Never {
                kind: RuleKind::Cidr,
                value: value("192.0.2.0/24"),
            })
        );
        assert_eq!(
            parse(&["require", "keyword", "internal"]),
            Subcommand::Require(Require {
                kind: RuleKind::Keyword,
                value: value("internal"),
            })
        );
    }

    #[test]
    fn the_configuration_verbs_parse() {
        assert_eq!(
            parse(&["upstream", "socks5://192.0.2.10:1080"]),
            Subcommand::Upstream(Upstream {
                addr: UpstreamAddr("socks5://192.0.2.10:1080".to_owned()),
            })
        );
        assert_eq!(
            parse(&["listen", "127.0.0.1:7890", "127.0.0.1:7891"]),
            Subcommand::Listen(Listen {
                http: "127.0.0.1:7890".parse().unwrap(),
                socks: "127.0.0.1:7891".parse().unwrap(),
            })
        );
        assert_eq!(
            parse(&["reload"]),
            Subcommand::Reload(Reload { path: None })
        );
        assert_eq!(
            parse(&["reload", "/tmp/other-init"]),
            Subcommand::Reload(Reload {
                path: Some(PathBuf::from("/tmp/other-init")),
            })
        );
        assert_eq!(parse(&["on"]), Subcommand::On(On {}));
        assert_eq!(parse(&["off"]), Subcommand::Off(Off {}));
    }

    #[test]
    fn the_read_verbs_parse_with_and_without_json() {
        assert_eq!(
            parse(&["status"]),
            Subcommand::Status(Status { json: false })
        );
        assert_eq!(
            parse(&["status", "--json"]),
            Subcommand::Status(Status { json: true })
        );
        assert_eq!(parse(&["rules"]), Subcommand::Rules(Rules { json: false }));
        assert_eq!(
            parse(&["rules", "--json"]),
            Subcommand::Rules(Rules { json: true })
        );
        assert_eq!(
            parse(&["test", "api.example.com:443", "--json"]),
            Subcommand::Test(Test {
                target: Destination {
                    host: Host("api.example.com".to_owned()),
                    port: Port(443),
                },
                json: true,
            })
        );
        assert_eq!(parse(&["logs"]), Subcommand::Logs(Logs { json: false }));
        assert_eq!(
            parse(&["logs", "--json"]),
            Subcommand::Logs(Logs { json: true })
        );
        assert_eq!(parse(&["tail"]), Subcommand::Tail(Tail { json: false }));
        assert_eq!(
            parse(&["doctor", "--json"]),
            Subcommand::Doctor(Doctor { json: true })
        );
    }

    #[test]
    fn the_proxy_verb_parses_with_a_service_defaulting_to_wifi() {
        assert_eq!(
            parse(&["proxy", "on"]),
            Subcommand::Proxy(Proxy {
                action: ProxyAction::On,
                service: NetworkService("Wi-Fi".to_owned()),
            })
        );
        assert_eq!(
            parse(&["proxy", "status"]),
            Subcommand::Proxy(Proxy {
                action: ProxyAction::Status,
                service: NetworkService("Wi-Fi".to_owned()),
            })
        );
        assert_eq!(
            parse(&["proxy", "off", "--service", "Ethernet"]),
            Subcommand::Proxy(Proxy {
                action: ProxyAction::Off,
                service: NetworkService("Ethernet".to_owned()),
            })
        );
    }

    #[test]
    fn a_destination_reads_a_host_and_a_port() {
        assert_eq!(
            "example.com:443".parse::<Destination>().unwrap(),
            Destination {
                host: Host("example.com".to_owned()),
                port: Port(443),
            }
        );
        assert_eq!(
            "[2001:db8::1]:8443".parse::<Destination>().unwrap(),
            Destination {
                host: Host("2001:db8::1".to_owned()),
                port: Port(8443),
            }
        );
        assert!("example.com".parse::<Destination>().is_err());
        assert!("example.com:https".parse::<Destination>().is_err());
        assert!("example.com:70000".parse::<Destination>().is_err());
        assert!(":443".parse::<Destination>().is_err());
    }

    #[tokio::test]
    async fn an_unknown_rule_kind_exits_four_without_touching_stdout() {
        let (_home, paths) = temp_paths();

        let (exit, out, err) = invoke(&paths, &["require", "regex", "example.com"]).await;

        assert_eq!(exit, Exit::InvalidArgs);
        assert_eq!(exit.code(), 4);
        assert!(out.is_empty(), "{out}");
        assert!(err.contains("regex"), "{err}");
    }

    #[tokio::test]
    async fn an_unknown_subcommand_and_a_missing_argument_exit_four() {
        let (_home, paths) = temp_paths();

        let (exit, _out, _err) = invoke(&paths, &["teleport"]).await;
        assert_eq!(exit.code(), 4);

        let (exit, _out, _err) = invoke(&paths, &["require", "suffix"]).await;
        assert_eq!(exit.code(), 4);

        let (exit, _out, _err) = invoke(&paths, &[]).await;
        assert_eq!(exit.code(), 4);
    }

    #[tokio::test]
    async fn help_is_printed_on_stdout_and_exits_zero() {
        let (_home, paths) = temp_paths();

        let (exit, out, err) = invoke(&paths, &["--help"]).await;

        assert_eq!(exit, Exit::Success);
        assert_eq!(exit.code(), 0);
        assert!(out.contains("doctor"), "{out}");
        assert!(err.is_empty(), "{err}");
    }

    #[tokio::test]
    async fn a_missing_socket_exits_two_with_a_one_line_hint_on_stderr() {
        let (_home, paths) = temp_paths();

        let (exit, out, err) = invoke(&paths, &["status"]).await;

        assert_eq!(exit, Exit::Missing);
        assert_eq!(exit.code(), 2);
        assert!(out.is_empty(), "{out}");
        assert_eq!(err.lines().count(), 1, "{err}");
        assert!(err.contains("nhop start"), "{err}");
    }

    #[test]
    fn every_error_kind_maps_onto_its_row_of_the_exit_table() {
        let rows = [
            (ErrKind::NotFound, 2u8),
            (ErrKind::UpstreamDown, 3),
            (ErrKind::InvalidArgs, 4),
            (ErrKind::LoadInProgress, 1),
            (ErrKind::Internal, 1),
        ];
        for (kind, code) in rows {
            let mut out = Vec::new();
            let mut err = Vec::new();
            let response = Response::Err {
                kind,
                message: "the daemon said no".to_owned(),
            };

            let exit = render(&response, Output::Human, &mut out, &mut err);

            assert_eq!(exit.code(), code, "{kind:?}");
            assert!(out.is_empty(), "{kind:?}");
            assert!(!err.is_empty(), "{kind:?}");
        }
        assert_eq!(render_ok(), Exit::Success);
        assert_eq!(Exit::Success.code(), 0);
    }

    fn render_ok() -> Exit {
        let mut out = Vec::new();
        let mut err = Vec::new();
        render(&Response::Ok, Output::Human, &mut out, &mut err)
    }

    #[tokio::test]
    async fn status_json_prints_a_single_document_and_nothing_else() {
        let (_home, paths, daemon) = running_daemon().await;

        let (exit, out, err) = invoke(&paths, &["status", "--json"]).await;

        assert_eq!(exit, Exit::Success);
        assert!(err.is_empty(), "{err}");
        assert_eq!(out.lines().count(), 1, "{out}");
        let document: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            document.get("uptime_secs").and_then(|it| it.as_u64()),
            Some(0)
        );
        assert!(document.get("rules").is_some(), "{out}");

        daemon.shutdown().await;
    }

    #[tokio::test]
    async fn rules_json_prints_an_empty_array_and_the_human_form_prints_nothing() {
        let (_home, paths, daemon) = running_daemon().await;

        let (exit, out, err) = invoke(&paths, &["rules", "--json"]).await;
        assert_eq!(exit, Exit::Success);
        assert!(err.is_empty(), "{err}");
        assert_eq!(out.trim(), "[]");

        let (exit, out, err) = invoke(&paths, &["rules"]).await;
        assert_eq!(exit, Exit::Success);
        assert!(out.is_empty(), "{out}");
        assert!(err.is_empty(), "{err}");

        daemon.shutdown().await;
    }

    #[tokio::test]
    async fn the_human_status_is_text_and_never_json() {
        let (_home, paths, daemon) = running_daemon().await;

        let (exit, out, err) = invoke(&paths, &["status"]).await;

        assert_eq!(exit, Exit::Success);
        assert!(err.is_empty(), "{err}");
        assert!(out.contains("uptime"), "{out}");
        assert!(
            out.contains("rules         require 0, prefer 0, never 0"),
            "{out}"
        );
        assert!(
            out.contains(
                "last load     never - the ruleset is empty and every connection is direct"
            ),
            "{out}"
        );
        assert!(
            serde_json::from_str::<serde_json::Value>(&out).is_err(),
            "{out}"
        );

        daemon.shutdown().await;
    }

    #[tokio::test]
    async fn a_daemon_error_keeps_stdout_empty_even_with_json() {
        let (_home, paths, daemon) = running_daemon().await;

        let (exit, out, err) = invoke(&paths, &["test", "example.com:443", "--json"]).await;

        assert_eq!(exit, Exit::Failed);
        assert_eq!(exit.code(), 1);
        assert!(out.is_empty(), "{out}");
        assert!(err.contains("yet"), "{err}");

        daemon.shutdown().await;
    }

    #[tokio::test]
    async fn a_rule_verb_outside_an_init_run_applies_at_once() {
        let (_home, paths, daemon) = running_daemon().await;

        let (exit, out, err) = invoke(&paths, &["require", "suffix", "example.com"]).await;

        assert_eq!(exit, Exit::Success);
        assert!(out.is_empty(), "{out}");
        assert!(err.is_empty(), "{err}");

        let (exit, out, err) = invoke(&paths, &["rules"]).await;
        assert_eq!(exit, Exit::Success);
        assert_eq!(out, "0  require  suffix  example.com\n");
        assert!(err.is_empty(), "{err}");

        daemon.shutdown().await;
    }

    #[tokio::test]
    async fn a_rule_verb_with_a_malformed_value_exits_four() {
        let (_home, paths, daemon) = running_daemon().await;

        let (exit, out, err) = invoke(&paths, &["prefer", "cidr", "nonsense"]).await;

        assert_eq!(exit, Exit::InvalidArgs);
        assert_eq!(exit.code(), 4);
        assert!(out.is_empty(), "{out}");
        assert!(err.contains("cidr"), "{err}");

        daemon.shutdown().await;
    }

    #[test]
    fn a_load_id_is_forwarded_only_when_it_reads_as_a_number() {
        assert_eq!(load_of("7"), Some(LoadId(7)));
        assert_eq!(load_of(" 7 "), Some(LoadId(7)));
        assert_eq!(load_of("seven"), None);
        assert_eq!(load_of(""), None);
        let Command::AddRule {
            class,
            kind,
            value,
            load,
        } = add_rule(
            RuleClass::Require,
            RuleKind::Suffix,
            value("example.com"),
            Some(LoadId(7)),
        )
        else {
            panic!("a rule verb must build an add_rule command");
        };
        assert_eq!(class, RuleClass::Require);
        assert_eq!(kind, RuleKind::Suffix);
        assert_eq!(value, RuleValue("example.com".to_owned()));
        assert_eq!(load, Some(LoadId(7)));
    }

    #[tokio::test]
    async fn the_verbs_of_later_tasks_report_themselves_as_unimplemented() {
        let (_home, paths) = temp_paths();

        for verb in ["logs", "tail"] {
            let (exit, out, err) = invoke(&paths, &[verb]).await;
            assert_eq!(exit, Exit::Failed, "{verb}");
            assert!(out.is_empty(), "{verb}");
            assert!(err.contains(verb), "{err}");
        }

        let (exit, out, err) = invoke(&paths, &["proxy", "on"]).await;
        assert_eq!(exit, Exit::Failed);
        assert!(out.is_empty(), "{out}");
        assert!(err.contains("proxy"), "{err}");
    }

    #[test]
    fn the_views_render_as_json_and_as_text() {
        let rules = vec![RuleView {
            index: 0,
            class: RuleClass::Require,
            kind: RuleKind::Suffix,
            value: value("example.com"),
        }];
        let mut out = Vec::new();
        let mut err = Vec::new();
        render(
            &Response::Rules(rules.clone()),
            Output::Human,
            &mut out,
            &mut err,
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "0  require  suffix  example.com\n"
        );
        assert!(err.is_empty());

        let mut out = Vec::new();
        let mut err = Vec::new();
        render(&Response::Rules(rules), Output::Json, &mut out, &mut err);
        let out = String::from_utf8(out).unwrap();
        let document: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(document.is_array(), "{out}");
        assert!(err.is_empty());
    }

    #[test]
    fn a_decision_renders_with_and_without_a_matching_rule() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        render(
            &Response::Decision(DecisionView {
                decision: DecisionKind::Upstream,
                rule_index: Some(3),
                class: Some(RuleClass::Prefer),
                next_hop: "socks5://192.0.2.10:1080".to_owned(),
            }),
            Output::Human,
            &mut out,
            &mut err,
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "upstream via rule 3 (prefer) to socks5://192.0.2.10:1080\n"
        );

        let mut out = Vec::new();
        let mut err = Vec::new();
        render(
            &Response::Decision(DecisionView {
                decision: DecisionKind::Direct,
                rule_index: None,
                class: None,
                next_hop: "example.net:443".to_owned(),
            }),
            Output::Human,
            &mut out,
            &mut err,
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "direct via no rule to example.net:443\n"
        );
        assert!(err.is_empty());
    }
}
