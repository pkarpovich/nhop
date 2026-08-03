use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use arc_swap::ArcSwap;
use nhop_ipc::{
    Command, DecisionView, ErrKind, Host, LastLoadView, LoadId, LoadOutcome, Paths, Port, Response,
    RuleClass, RuleCountsView, RuleKind, RuleValue, RuleView, StatusView, Timestamp, UpstreamAddr,
};
use tokio::sync::{mpsc, oneshot};

use crate::cli::explain;
use crate::cli::status::{DaemonStatus, status_view};
use crate::cli::system_proxy::{NetworkService, NoSystemProxy, SystemProxyReader};
use crate::daemon::Frontends;
use crate::daemon::init_script::{self, ScriptOutcome};
use crate::daemon::staging::{Committed, FailedCommand, LoadIds, Staging};
use crate::proxy::{ConnCtx, EventTx, InvalidUpstream, Listen, NO_UPSTREAM, Upstream};
use crate::rules::{InvalidRule, Ruleset};
use crate::upstream::HealthHandle;

/// Address the HTTP front end binds until the init script moves it.
pub const DEFAULT_HTTP_LISTEN: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7890);

/// Address the SOCKS5 front end binds until the init script moves it.
pub const DEFAULT_SOCKS_LISTEN: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7891);

/// How long an init-script run may take before it is killed and its staging discarded.
pub const LOAD_TIMEOUT: Duration = Duration::from_secs(30);

const REQUEST_CAPACITY: usize = 64;

type Request = (Command, oneshot::Sender<Response>);

/// Whether a front end holds the address it is configured to bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindState {
    /// The front end holds the address.
    Bound,
    /// Nothing is listening on the address.
    Unbound,
}

impl BindState {
    /// Returns how the wire reports the state.
    pub fn is_bound(self) -> bool {
        match self {
            Self::Bound => true,
            Self::Unbound => false,
        }
    }
}

/// Ruleset serving traffic, published as one unit and read without locking.
///
/// A connection takes a single snapshot when it is accepted and routes by it for its whole life,
/// so a [`LiveRules::publish`] reaches only connections accepted afterwards.
#[derive(Debug, Clone)]
pub struct LiveRules(Arc<ArcSwap<Ruleset>>);

impl Default for LiveRules {
    fn default() -> Self {
        Self(Arc::new(ArcSwap::from_pointee(Ruleset::default())))
    }
}

impl LiveRules {
    /// Returns the ruleset serving traffic at this instant.
    pub fn snapshot(&self) -> Arc<Ruleset> {
        let Self(live) = self;
        live.load_full()
    }

    /// Swaps in a ruleset for connections accepted from now on.
    pub fn publish(&self, ruleset: Ruleset) {
        let Self(live) = self;
        live.store(Arc::new(ruleset));
    }
}

/// Upstream serving traffic, published the same way the ruleset is.
#[derive(Debug, Clone)]
pub struct LiveUpstream(Arc<ArcSwap<SocketAddr>>);

impl Default for LiveUpstream {
    fn default() -> Self {
        Self(Arc::new(ArcSwap::from_pointee(NO_UPSTREAM)))
    }
}

impl LiveUpstream {
    /// Returns the address new connections are handed to at this instant.
    pub fn snapshot(&self) -> SocketAddr {
        let Self(live) = self;
        **live.load()
    }

    /// Swaps in an address for connections accepted from now on.
    pub fn publish(&self, addr: SocketAddr) {
        let Self(live) = self;
        live.store(Arc::new(addr));
    }
}

/// Everything a front end reads without going through the state task.
#[derive(Debug, Clone, Default)]
pub struct Live {
    rules: LiveRules,
    upstream: LiveUpstream,
    health: HealthHandle,
    events: EventTx,
}

impl Live {
    /// Returns the context one accepted connection is routed by.
    pub fn accepted(&self) -> ConnCtx {
        let Self {
            rules,
            upstream,
            health,
            events,
        } = self;
        ConnCtx {
            rules: rules.snapshot(),
            health: health.clone(),
            upstream: upstream.snapshot(),
            events: events.clone(),
        }
    }

    /// Returns the ruleset publication.
    pub fn rules(&self) -> &LiveRules {
        &self.rules
    }

    /// Returns the upstream publication.
    pub fn upstream(&self) -> &LiveUpstream {
        &self.upstream
    }

    /// Returns the upstream verdict.
    pub fn health(&self) -> &HealthHandle {
        &self.health
    }
}

/// What the state task starts with.
#[derive(Debug)]
pub struct StateConfig {
    /// Cells the front ends read their per-connection snapshot from.
    pub live: Live,
    /// Front ends a committed load rebinds.
    pub frontends: Frontends,
    /// Addresses the front ends were bound on.
    pub listen: Listen,
    /// How long an init-script run may take before it is killed.
    pub load_timeout: Duration,
    /// Where `status` reads the system proxy settings from.
    pub proxy: Arc<dyn SystemProxyReader>,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            live: Live::default(),
            frontends: Frontends::Unbound,
            listen: Listen {
                http: DEFAULT_HTTP_LISTEN,
                socks: DEFAULT_SOCKS_LISTEN,
            },
            load_timeout: LOAD_TIMEOUT,
            proxy: Arc::new(NoSystemProxy),
        }
    }
}

/// Client end of the task that owns every piece of mutable daemon state.
#[derive(Debug, Clone)]
pub struct StateHandle {
    requests: mpsc::Sender<Request>,
    live: Live,
}

impl StateHandle {
    /// Returns the publication a connection takes its ruleset snapshot from.
    pub fn rules(&self) -> &LiveRules {
        self.live.rules()
    }

    /// Returns the cells the front ends read.
    pub fn live(&self) -> &Live {
        &self.live
    }

    /// Sends one command to the state task and waits for its single reply.
    pub async fn call(&self, command: Command) -> Response {
        let (reply, answer) = oneshot::channel();
        let Ok(()) = self.requests.send((command, reply)).await else {
            return state_gone();
        };
        let Ok(response) = answer.await else {
            return state_gone();
        };
        response
    }
}

fn state_gone() -> Response {
    Response::Err {
        kind: ErrKind::Internal,
        message: "the daemon state task is gone".to_owned(),
    }
}

/// Starts the state task and returns the handle every command travels through.
pub fn spawn(paths: &Paths, config: StateConfig) -> StateHandle {
    let StateConfig {
        live,
        frontends,
        listen,
        load_timeout,
        proxy,
    } = config;
    let (requests, inbox) = mpsc::channel(REQUEST_CAPACITY);
    let (finished, completions) = mpsc::channel(1);
    let state = DaemonState::new(
        paths.clone(),
        live.clone(),
        frontends,
        listen,
        load_timeout,
        proxy,
        finished,
    );
    tokio::spawn(serve(state, inbox, completions));
    StateHandle { requests, live }
}

async fn serve(
    mut state: DaemonState,
    mut inbox: mpsc::Receiver<Request>,
    mut completions: mpsc::Receiver<ScriptOutcome>,
) {
    loop {
        tokio::select! {
            request = inbox.recv() => {
                let Some((command, reply)) = request else {
                    return;
                };
                state.handle(command, reply);
            }
            completion = completions.recv() => {
                let Some(outcome) = completion else {
                    return;
                };
                state.finish(outcome);
            }
        }
    }
}

/// One init-script run the daemon is executing.
#[derive(Debug)]
struct InFlight {
    id: LoadId,
    staged: Staging,
    reply: oneshot::Sender<Response>,
}

/// Where a mutating command applies.
#[derive(Debug)]
enum Target {
    /// Appends to the run in flight.
    Staged,
    /// Applies at once, as a transaction of one command.
    Live,
    /// Belongs to no run the daemon is executing.
    Refused(Box<Response>),
}

/// How a finished run ended, as recorded and as answered.
#[derive(Debug)]
struct Settled {
    outcome: LoadOutcome,
    command: Option<String>,
    message: Option<String>,
}

#[derive(Debug)]
struct DaemonState {
    started: Instant,
    paths: Paths,
    live: Live,
    frontends: Frontends,
    http_listen: SocketAddr,
    socks_listen: SocketAddr,
    upstream: UpstreamAddr,
    init_path: Option<PathBuf>,
    last_load: Option<LastLoadView>,
    load_ids: LoadIds,
    load: Option<InFlight>,
    load_timeout: Duration,
    proxy: Arc<dyn SystemProxyReader>,
    service: NetworkService,
    finished: mpsc::Sender<ScriptOutcome>,
}

impl DaemonState {
    fn new(
        paths: Paths,
        live: Live,
        frontends: Frontends,
        listen: Listen,
        load_timeout: Duration,
        proxy: Arc<dyn SystemProxyReader>,
        finished: mpsc::Sender<ScriptOutcome>,
    ) -> Self {
        let Listen { http, socks } = listen;
        Self {
            started: Instant::now(),
            paths,
            live,
            frontends,
            http_listen: http,
            socks_listen: socks,
            upstream: UpstreamAddr(String::new()),
            init_path: None,
            last_load: None,
            load_ids: LoadIds::default(),
            load: None,
            load_timeout,
            proxy,
            service: NetworkService::default(),
            finished,
        }
    }

    fn handle(&mut self, command: Command, reply: oneshot::Sender<Response>) {
        match command {
            Command::Status => answer(reply, Response::Status(self.status())),
            Command::Rules => answer(reply, Response::Rules(self.rule_views())),
            Command::AddRule {
                class,
                kind,
                value,
                load,
            } => {
                let response = self.add_rule(class, kind, value, load);
                answer(reply, response);
            }
            Command::ClearRules { load } => {
                let response = self.clear_rules(load);
                answer(reply, response);
            }
            Command::SetUpstream { addr, load } => {
                let response = self.set_upstream(addr, load);
                answer(reply, response);
            }
            Command::SetListen { http, socks, load } => {
                let response = self.set_listen(Listen { http, socks }, load);
                answer(reply, response);
            }
            Command::Reload { path } => self.reload(path, reply),
            Command::On => self.reload(None, reply),
            Command::Off => {
                self.live.rules().publish(Ruleset::default());
                answer(reply, Response::Ok);
            }
            Command::Test { host, port } => {
                answer(reply, Response::Decision(self.decision(&host, port)));
            }
            Command::Doctor | Command::Subscribe => answer(reply, unserved()),
        }
    }

    fn add_rule(
        &mut self,
        class: RuleClass,
        kind: RuleKind,
        value: RuleValue,
        load: Option<LoadId>,
    ) -> Response {
        match self.target(load) {
            Target::Refused(refusal) => *refusal,
            Target::Staged => match &mut self.load {
                Some(InFlight {
                    id: _,
                    staged,
                    reply: _,
                }) => {
                    let Err(failure) = staged.push_rule(class, kind, value) else {
                        return Response::Ok;
                    };
                    invalid(&failure)
                }
                None => vanished(),
            },
            Target::Live => {
                let mut rules = self.live.rules().snapshot().as_ref().clone();
                let Err(failure) = rules.push(class, kind, value) else {
                    self.live.rules().publish(rules);
                    return Response::Ok;
                };
                invalid(&failure)
            }
        }
    }

    fn clear_rules(&mut self, load: Option<LoadId>) -> Response {
        match self.target(load) {
            Target::Refused(refusal) => *refusal,
            Target::Staged => match &mut self.load {
                Some(InFlight {
                    id: _,
                    staged,
                    reply: _,
                }) => {
                    staged.clear_rules();
                    Response::Ok
                }
                None => vanished(),
            },
            Target::Live => {
                self.live.rules().publish(Ruleset::default());
                Response::Ok
            }
        }
    }

    fn set_upstream(&mut self, addr: UpstreamAddr, load: Option<LoadId>) -> Response {
        let target = self.target(load);
        let upstream = match Upstream::parse(addr) {
            Ok(upstream) => upstream,
            Err(failure) => {
                self.reject_staged(&target);
                return unreadable(&failure);
            }
        };
        match target {
            Target::Refused(refusal) => *refusal,
            Target::Staged => match &mut self.load {
                Some(InFlight {
                    id: _,
                    staged,
                    reply: _,
                }) => {
                    staged.set_upstream(upstream);
                    Response::Ok
                }
                None => vanished(),
            },
            Target::Live => {
                self.adopt_upstream(Some(upstream));
                Response::Ok
            }
        }
    }

    fn set_listen(&mut self, listen: Listen, load: Option<LoadId>) -> Response {
        match self.target(load) {
            Target::Refused(refusal) => *refusal,
            Target::Staged => match &mut self.load {
                Some(InFlight {
                    id: _,
                    staged,
                    reply: _,
                }) => {
                    staged.set_listen(listen);
                    Response::Ok
                }
                None => vanished(),
            },
            Target::Live => {
                let Err(failure) = self.rebind(listen) else {
                    return Response::Ok;
                };
                unbindable(&failure)
            }
        }
    }

    fn reject_staged(&mut self, target: &Target) {
        match target {
            Target::Staged => {}
            Target::Live => return,
            Target::Refused(_refusal) => return,
        }
        let Some(InFlight {
            id: _,
            staged,
            reply: _,
        }) = &mut self.load
        else {
            return;
        };
        staged.fail(FailedCommand::SetUpstream);
    }

    fn rebind(&mut self, listen: Listen) -> io::Result<()> {
        let Listen { http, socks } = self.frontends.rebind(listen)?;
        self.http_listen = http;
        self.socks_listen = socks;
        Ok(())
    }

    fn in_flight(&self) -> Option<LoadId> {
        let InFlight {
            id,
            staged: _,
            reply: _,
        } = self.load.as_ref()?;
        Some(*id)
    }

    fn target(&self, load: Option<LoadId>) -> Target {
        let Some(id) = self.in_flight() else {
            match load {
                None => return Target::Live,
                Some(stale) => {
                    return refused(format!("init run {stale} is no longer in progress"));
                }
            }
        };
        match load {
            Some(carried) if carried == id => Target::Staged,
            Some(stale) => refused(format!(
                "init run {id} is in progress, this command carries {stale}"
            )),
            None => refused(format!("init run {id} is in progress")),
        }
    }

    fn reload(&mut self, path: Option<PathBuf>, reply: oneshot::Sender<Response>) {
        if let Some(id) = self.in_flight() {
            answer(reply, in_progress(format!("init run {id} is in progress")));
            return;
        }
        let path = match path {
            Some(path) => path,
            None => match &self.init_path {
                Some(remembered) => remembered.clone(),
                None => self.paths.init_file(),
            },
        };
        if !path.is_file() {
            answer(
                reply,
                Response::Err {
                    kind: ErrKind::NotFound,
                    message: format!("no init script at {}", path.display()),
                },
            );
            return;
        }
        let id = self.load_ids.issue();
        self.init_path = Some(path.clone());
        self.load = Some(InFlight {
            id,
            staged: Staging::default(),
            reply,
        });
        let config_dir = self.paths.config_dir().to_owned();
        let timeout = self.load_timeout;
        let finished = self.finished.clone();
        tokio::spawn(async move {
            let outcome = init_script::run(&path, &config_dir, id, timeout).await;
            let _ = finished.send(outcome).await;
        });
    }

    fn finish(&mut self, outcome: ScriptOutcome) {
        let Some(InFlight {
            id: _,
            staged,
            reply,
        }) = self.load.take()
        else {
            return;
        };
        let Settled {
            outcome,
            command,
            message,
        } = self.settle(staged, outcome);
        self.last_load = Some(LastLoadView {
            at: Timestamp(SystemTime::now()),
            outcome,
            command,
        });
        let Some(message) = message else {
            answer(reply, Response::Status(self.status()));
            return;
        };
        answer(
            reply,
            Response::Err {
                kind: ErrKind::Internal,
                message,
            },
        );
    }

    fn settle(&mut self, staged: Staging, outcome: ScriptOutcome) -> Settled {
        match outcome {
            ScriptOutcome::Succeeded => {
                let Some(failed) = staged.failure() else {
                    let Err(failure) = self.commit(staged) else {
                        return Settled {
                            outcome: LoadOutcome::Ok,
                            command: None,
                            message: None,
                        };
                    };
                    return Settled {
                        outcome: LoadOutcome::Failed,
                        command: Some(FailedCommand::SetListen.name().to_owned()),
                        message: Some(format!(
                            "the init script could not move the front ends: {failure}"
                        )),
                    };
                };
                Settled {
                    outcome: LoadOutcome::Failed,
                    command: Some(failed.name().to_owned()),
                    message: Some(format!("the init script was rejected on {}", failed.name())),
                }
            }
            ScriptOutcome::Exited(status) => {
                let ended = match status.code() {
                    Some(code) => format!("exited with status {code}"),
                    None => "was killed by a signal".to_owned(),
                };
                Settled {
                    outcome: LoadOutcome::Failed,
                    command: named(staged.failure()),
                    message: Some(format!("the init script {ended}, its rules were discarded")),
                }
            }
            ScriptOutcome::TimedOut => Settled {
                outcome: LoadOutcome::TimedOut,
                command: None,
                message: Some(format!(
                    "the init script did not finish within {}s and was killed",
                    self.load_timeout.as_secs()
                )),
            },
            ScriptOutcome::NotRun(failure) => Settled {
                outcome: LoadOutcome::Failed,
                command: None,
                message: Some(format!("the init script could not be run: {failure}")),
            },
        }
    }

    fn commit(&mut self, staged: Staging) -> io::Result<()> {
        let Committed {
            rules,
            upstream,
            listen,
        } = staged.commit();
        let Some(listen) = listen else {
            self.publish(rules, upstream);
            return Ok(());
        };
        self.rebind(listen)?;
        self.publish(rules, upstream);
        Ok(())
    }

    fn publish(&mut self, rules: Ruleset, upstream: Option<Upstream>) {
        self.live.rules().publish(rules);
        self.adopt_upstream(upstream);
    }

    fn adopt_upstream(&mut self, upstream: Option<Upstream>) {
        let Some(upstream) = upstream else {
            return;
        };
        self.upstream = upstream.written().clone();
        self.live.upstream().publish(upstream.socket());
    }

    fn bind_state(&self) -> BindState {
        match &self.frontends {
            Frontends::Unbound => BindState::Unbound,
            Frontends::Bound(_bound) => BindState::Bound,
        }
    }

    fn status(&self) -> StatusView {
        let rules = self.live.rules().snapshot();
        let proxy = self.proxy.read(&self.service).unwrap_or_default();
        status_view(
            &DaemonStatus {
                uptime_secs: self.started.elapsed().as_secs(),
                listen: Listen {
                    http: self.http_listen,
                    socks: self.socks_listen,
                },
                bound: self.bind_state(),
                upstream: self.upstream.clone(),
                health: self.live.health().verdict(),
                init_path: self.init_path.clone(),
                last_load: self.last_load.clone(),
                rules: RuleCountsView {
                    require: counted(rules.count(RuleClass::Require)),
                    prefer: counted(rules.count(RuleClass::Prefer)),
                    never: counted(rules.count(RuleClass::Never)),
                },
            },
            &proxy,
        )
    }

    fn rule_views(&self) -> Vec<RuleView> {
        explain::rule_views(&self.live.rules().snapshot())
    }

    fn decision(&self, host: &Host, port: Port) -> DecisionView {
        explain::decision_view(&self.live.rules().snapshot(), &self.upstream, host, port)
    }
}

fn counted(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

fn answer(reply: oneshot::Sender<Response>, response: Response) {
    let _ = reply.send(response);
}

fn refused(message: String) -> Target {
    Target::Refused(Box::new(in_progress(message)))
}

fn in_progress(message: String) -> Response {
    Response::Err {
        kind: ErrKind::LoadInProgress,
        message,
    }
}

fn invalid(failure: &InvalidRule) -> Response {
    Response::Err {
        kind: failure.err_kind(),
        message: failure.message().to_owned(),
    }
}

fn unreadable(failure: &InvalidUpstream) -> Response {
    Response::Err {
        kind: ErrKind::InvalidArgs,
        message: failure.to_string(),
    }
}

fn unbindable(failure: &io::Error) -> Response {
    Response::Err {
        kind: ErrKind::Internal,
        message: format!("cannot move the front ends: {failure}"),
    }
}

fn unserved() -> Response {
    Response::Err {
        kind: ErrKind::Internal,
        message: "the daemon does not serve this command yet".to_owned(),
    }
}

fn vanished() -> Response {
    Response::Err {
        kind: ErrKind::Internal,
        message: "the init run ended while this command was in flight".to_owned(),
    }
}

fn named(failed: Option<FailedCommand>) -> Option<String> {
    let failed = failed?;
    Some(failed.name().to_owned())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use nhop_ipc::{DecisionKind, HealthState, RuleKind, RuleValue, SystemProxyView};

    use crate::cli::system_proxy::{ProxyEndpoint, ProxyFailure, SystemProxy};
    use crate::rules::{Decision, RuleId};

    use super::*;

    const PATIENCE: usize = 200;

    fn ruleset(rules: &[(RuleClass, RuleKind, &str)]) -> Ruleset {
        let mut ruleset = Ruleset::default();
        for (class, kind, value) in rules {
            ruleset
                .push(*class, *kind, RuleValue((*value).to_owned()))
                .unwrap();
        }
        ruleset
    }

    fn decide(ruleset: &Ruleset, host: &str) -> Decision {
        ruleset.decide(&Host(host.to_owned()), Port(443))
    }

    fn temp_paths() -> (tempfile::TempDir, Paths) {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());
        (home, paths)
    }

    fn spawn_here() -> (tempfile::TempDir, StateHandle) {
        let (home, paths) = temp_paths();
        let state = spawn(&paths, StateConfig::default());
        (home, state)
    }

    fn write_script(paths: &Paths, body: &str) {
        fs::create_dir_all(paths.config_dir()).unwrap();
        let init = paths.init_file();
        fs::write(&init, body).unwrap();
        fs::set_permissions(&init, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Writes an init script that reports its load id and then waits to be released.
    fn write_handshake_script(paths: &Paths, home: &Path, exit: i32) {
        let reported = home.join("load");
        let release = home.join("release");
        write_script(
            paths,
            &format!(
                "#!/bin/sh\nprintf '%s' \"$NHOP_LOAD_ID\" > {reported}\nwhile [ ! -f {release} ]; do sleep 0.05; done\nexit {exit}\n",
                reported = reported.display(),
                release = release.display(),
            ),
        );
    }

    async fn await_load_id(home: &Path) -> LoadId {
        let reported = home.join("load");
        for _attempt in 0..PATIENCE {
            let Ok(id) = fs::read_to_string(&reported) else {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            };
            let Ok(id) = id.parse::<LoadId>() else {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            };
            return id;
        }
        panic!("the init script never reported its load id");
    }

    fn release(home: &Path) {
        fs::write(home.join("release"), b"go").unwrap();
    }

    fn add_rule_command(
        class: RuleClass,
        kind: RuleKind,
        value: &str,
        load: Option<LoadId>,
    ) -> Command {
        Command::AddRule {
            class,
            kind,
            value: RuleValue(value.to_owned()),
            load,
        }
    }

    async fn status_of(state: &StateHandle) -> StatusView {
        let Response::Status(status) = state.call(Command::Status).await else {
            panic!("status must answer with a status view");
        };
        status
    }

    #[tokio::test]
    async fn an_init_run_that_exits_zero_swaps_its_rules_in() {
        let (home, paths) = temp_paths();
        write_handshake_script(&paths, home.path(), 0);
        let state = spawn(&paths, StateConfig::default());
        let reloading = tokio::spawn({
            let state = state.clone();
            async move { state.call(Command::Reload { path: None }).await }
        });

        let id = await_load_id(home.path()).await;
        let staged = state
            .call(add_rule_command(
                RuleClass::Require,
                RuleKind::Suffix,
                "example.com",
                Some(id),
            ))
            .await;
        assert_eq!(staged, Response::Ok);
        assert_eq!(
            decide(&state.rules().snapshot(), "example.com"),
            Decision::Direct
        );
        release(home.path());

        let answer = reloading.await.unwrap();

        let Response::Status(status) = answer else {
            panic!("a committed run must answer with a status view: {answer:?}");
        };
        assert_eq!(status.rules.require, 1);
        assert_eq!(status.init_path, Some(paths.init_file()));
        let Some(LastLoadView {
            at: _,
            outcome,
            command,
        }) = status.last_load
        else {
            panic!("a finished run must be recorded");
        };
        assert_eq!(outcome, LoadOutcome::Ok);
        assert_eq!(command, None);
        assert_eq!(
            decide(&state.rules().snapshot(), "example.com"),
            Decision::Upstream {
                class: RuleClass::Require,
                rule: RuleId(0),
            }
        );
    }

    #[tokio::test]
    async fn an_init_run_that_exits_non_zero_leaves_the_previous_rules_live() {
        let (home, paths) = temp_paths();
        write_handshake_script(&paths, home.path(), 1);
        let state = spawn(&paths, StateConfig::default());
        state.rules().publish(ruleset(&[(
            RuleClass::Prefer,
            RuleKind::Suffix,
            "example.net",
        )]));
        let reloading = tokio::spawn({
            let state = state.clone();
            async move { state.call(Command::Reload { path: None }).await }
        });

        let id = await_load_id(home.path()).await;
        state
            .call(add_rule_command(
                RuleClass::Require,
                RuleKind::Suffix,
                "example.com",
                Some(id),
            ))
            .await;
        release(home.path());

        let answer = reloading.await.unwrap();

        let Response::Err { kind, message } = answer else {
            panic!("a failed run must answer with an error: {answer:?}");
        };
        assert_eq!(kind, ErrKind::Internal);
        assert!(message.contains("status 1"), "{message}");
        assert_eq!(
            decide(&state.rules().snapshot(), "example.com"),
            Decision::Direct
        );
        assert_eq!(
            decide(&state.rules().snapshot(), "example.net"),
            Decision::Upstream {
                class: RuleClass::Prefer,
                rule: RuleId(0),
            }
        );
        let status = status_of(&state).await;
        let Some(LastLoadView {
            at: _,
            outcome,
            command: _,
        }) = status.last_load
        else {
            panic!("a finished run must be recorded");
        };
        assert_eq!(outcome, LoadOutcome::Failed);
    }

    #[tokio::test]
    async fn a_command_of_another_run_is_refused_while_one_is_in_flight() {
        let (home, paths) = temp_paths();
        write_handshake_script(&paths, home.path(), 0);
        let state = spawn(&paths, StateConfig::default());
        let reloading = tokio::spawn({
            let state = state.clone();
            async move { state.call(Command::Reload { path: None }).await }
        });

        let LoadId(id) = await_load_id(home.path()).await;
        let refusals = [
            add_rule_command(RuleClass::Require, RuleKind::Suffix, "example.com", None),
            add_rule_command(
                RuleClass::Require,
                RuleKind::Suffix,
                "example.com",
                Some(LoadId(id + 1)),
            ),
            Command::ClearRules { load: None },
            Command::SetUpstream {
                addr: UpstreamAddr("socks5://192.0.2.10:1080".to_owned()),
                load: None,
            },
            Command::Reload { path: None },
            Command::On,
        ];
        for command in refusals {
            let answer = state.call(command.clone()).await;
            let Response::Err { kind, message } = answer else {
                panic!("{command:?} must be refused: {answer:?}");
            };
            assert_eq!(kind, ErrKind::LoadInProgress, "{command:?}");
            assert!(message.contains("in progress"), "{message}");
        }
        release(home.path());

        let answer = reloading.await.unwrap();
        let Response::Status(_status) = answer else {
            panic!("the run must still commit: {answer:?}");
        };
    }

    #[tokio::test]
    async fn a_command_carrying_a_stale_run_is_refused_once_the_run_is_over() {
        let (_home, paths) = temp_paths();
        let state = spawn(&paths, StateConfig::default());

        let answer = state
            .call(add_rule_command(
                RuleClass::Require,
                RuleKind::Suffix,
                "example.com",
                Some(LoadId(9)),
            ))
            .await;

        let Response::Err { kind, message } = answer else {
            panic!("a stale load id must be refused: {answer:?}");
        };
        assert_eq!(kind, ErrKind::LoadInProgress);
        assert!(message.contains('9'), "{message}");
        assert!(state.rules().snapshot().rules().is_empty());
    }

    #[tokio::test]
    async fn a_run_that_outlives_the_timeout_is_killed_and_discarded() {
        let (home, paths) = temp_paths();
        write_script(&paths, "#!/bin/sh\nsleep 30\n");
        let state = spawn(
            &paths,
            StateConfig {
                load_timeout: Duration::from_millis(100),
                ..Default::default()
            },
        );
        state.rules().publish(ruleset(&[(
            RuleClass::Prefer,
            RuleKind::Suffix,
            "example.net",
        )]));

        let answer = state.call(Command::Reload { path: None }).await;

        let Response::Err { kind, message } = answer else {
            panic!("a timed-out run must answer with an error: {answer:?}");
        };
        assert_eq!(kind, ErrKind::Internal);
        assert!(message.contains("did not finish"), "{message}");
        let status = status_of(&state).await;
        let Some(LastLoadView {
            at: _,
            outcome,
            command,
        }) = status.last_load
        else {
            panic!("a finished run must be recorded");
        };
        assert_eq!(outcome, LoadOutcome::TimedOut);
        assert_eq!(command, None);
        assert_eq!(status.rules.prefer, 1);
        drop(home);
    }

    #[tokio::test]
    async fn a_rejected_rule_fails_the_run_even_when_the_script_exits_zero() {
        let (home, paths) = temp_paths();
        write_handshake_script(&paths, home.path(), 0);
        let state = spawn(&paths, StateConfig::default());
        let reloading = tokio::spawn({
            let state = state.clone();
            async move { state.call(Command::Reload { path: None }).await }
        });

        let id = await_load_id(home.path()).await;
        let answer = state
            .call(add_rule_command(
                RuleClass::Require,
                RuleKind::Port,
                "80-90",
                Some(id),
            ))
            .await;
        let Response::Err { kind, message: _ } = answer else {
            panic!("a malformed value must be rejected: {answer:?}");
        };
        assert_eq!(kind, ErrKind::InvalidArgs);
        state
            .call(add_rule_command(
                RuleClass::Require,
                RuleKind::Suffix,
                "example.com",
                Some(id),
            ))
            .await;
        release(home.path());

        let answer = reloading.await.unwrap();

        let Response::Err { kind, message } = answer else {
            panic!("a rejected command must fail the run: {answer:?}");
        };
        assert_eq!(kind, ErrKind::Internal);
        assert!(message.contains("add_rule"), "{message}");
        assert!(state.rules().snapshot().rules().is_empty());
        let status = status_of(&state).await;
        let Some(LastLoadView {
            at: _,
            outcome,
            command,
        }) = status.last_load
        else {
            panic!("a finished run must be recorded");
        };
        assert_eq!(outcome, LoadOutcome::Failed);
        assert_eq!(command, Some("add_rule".to_owned()));
    }

    #[tokio::test]
    async fn a_missing_init_file_is_reported_and_leaves_the_ruleset_empty() {
        let (_home, paths) = temp_paths();
        let state = spawn(&paths, StateConfig::default());

        let answer = state.call(Command::Reload { path: None }).await;

        let Response::Err { kind, message } = answer else {
            panic!("a missing script must be reported: {answer:?}");
        };
        assert_eq!(kind, ErrKind::NotFound);
        assert!(message.contains("init"), "{message}");
        let status = status_of(&state).await;
        assert_eq!(status.init_path, None);
        assert_eq!(status.last_load, None);
        assert!(state.rules().snapshot().rules().is_empty());
    }

    #[tokio::test]
    async fn a_reload_of_another_path_runs_it_and_remembers_it() {
        let (home, paths) = temp_paths();
        let elsewhere = home.path().join("other-init");
        fs::create_dir_all(paths.config_dir()).unwrap();
        fs::write(&elsewhere, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o755)).unwrap();
        let state = spawn(&paths, StateConfig::default());

        let answer = state
            .call(Command::Reload {
                path: Some(elsewhere.clone()),
            })
            .await;

        let Response::Status(status) = answer else {
            panic!("a committed run must answer with a status view: {answer:?}");
        };
        assert_eq!(status.init_path, Some(elsewhere));
    }

    #[tokio::test]
    async fn off_clears_the_rules_and_on_re_runs_the_remembered_script() {
        let (home, paths) = temp_paths();
        let elsewhere = home.path().join("other-init");
        fs::create_dir_all(paths.config_dir()).unwrap();
        fs::write(&elsewhere, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o755)).unwrap();
        let state = spawn(&paths, StateConfig::default());
        state
            .call(Command::Reload {
                path: Some(elsewhere.clone()),
            })
            .await;
        state.rules().publish(ruleset(&[(
            RuleClass::Require,
            RuleKind::Suffix,
            "example.com",
        )]));

        assert_eq!(state.call(Command::Off).await, Response::Ok);

        let status = status_of(&state).await;
        assert_eq!(status.rules.require, 0);
        assert_eq!(status.init_path, Some(elsewhere.clone()));

        let answer = state.call(Command::On).await;
        let Response::Status(status) = answer else {
            panic!("on must re-run the remembered script: {answer:?}");
        };
        assert_eq!(status.init_path, Some(elsewhere));
    }

    #[tokio::test]
    async fn a_command_outside_a_run_applies_at_once() {
        let (_home, paths) = temp_paths();
        let state = spawn(&paths, StateConfig::default());

        assert_eq!(
            state
                .call(add_rule_command(
                    RuleClass::Require,
                    RuleKind::Suffix,
                    "example.com",
                    None
                ))
                .await,
            Response::Ok
        );
        assert_eq!(
            state
                .call(Command::SetUpstream {
                    addr: UpstreamAddr("socks5://192.0.2.10:1080".to_owned()),
                    load: None,
                })
                .await,
            Response::Ok
        );
        assert_eq!(
            state
                .call(Command::SetListen {
                    http: "127.0.0.1:18080".parse().unwrap(),
                    socks: "127.0.0.1:18081".parse().unwrap(),
                    load: None,
                })
                .await,
            Response::Ok
        );

        let status = status_of(&state).await;
        assert_eq!(status.rules.require, 1);
        assert_eq!(
            status.upstream,
            UpstreamAddr("socks5://192.0.2.10:1080".to_owned())
        );
        assert_eq!(status.http_listen, "127.0.0.1:18080".parse().unwrap());
        assert_eq!(status.socks_listen, "127.0.0.1:18081".parse().unwrap());

        assert_eq!(
            state.call(Command::ClearRules { load: None }).await,
            Response::Ok
        );
        assert_eq!(status_of(&state).await.rules.require, 0);
    }

    #[tokio::test]
    async fn a_malformed_value_outside_a_run_leaves_the_live_rules_alone() {
        let (_home, paths) = temp_paths();
        let state = spawn(&paths, StateConfig::default());
        state
            .call(add_rule_command(
                RuleClass::Require,
                RuleKind::Suffix,
                "example.com",
                None,
            ))
            .await;

        let answer = state
            .call(add_rule_command(
                RuleClass::Prefer,
                RuleKind::Cidr,
                "nonsense",
                None,
            ))
            .await;

        let Response::Err { kind, message } = answer else {
            panic!("a malformed value must be rejected: {answer:?}");
        };
        assert_eq!(kind, ErrKind::InvalidArgs);
        assert!(message.contains("cidr"), "{message}");
        assert_eq!(state.rules().snapshot().rules().len(), 1);
    }

    #[tokio::test]
    async fn the_upstream_and_the_listen_addresses_of_a_run_move_only_on_commit() {
        let (home, paths) = temp_paths();
        write_handshake_script(&paths, home.path(), 0);
        let state = spawn(&paths, StateConfig::default());
        let reloading = tokio::spawn({
            let state = state.clone();
            async move { state.call(Command::Reload { path: None }).await }
        });

        let id = await_load_id(home.path()).await;
        state
            .call(Command::SetUpstream {
                addr: UpstreamAddr("socks5://192.0.2.10:1080".to_owned()),
                load: Some(id),
            })
            .await;
        state
            .call(Command::SetListen {
                http: "127.0.0.1:18080".parse().unwrap(),
                socks: "127.0.0.1:18081".parse().unwrap(),
                load: Some(id),
            })
            .await;

        let staged = status_of(&state).await;
        assert_eq!(staged.upstream, UpstreamAddr(String::new()));
        assert_eq!(staged.http_listen, DEFAULT_HTTP_LISTEN);
        release(home.path());
        reloading.await.unwrap();

        let committed = status_of(&state).await;
        assert_eq!(
            committed.upstream,
            UpstreamAddr("socks5://192.0.2.10:1080".to_owned())
        );
        assert_eq!(committed.http_listen, "127.0.0.1:18080".parse().unwrap());
        assert_eq!(committed.socks_listen, "127.0.0.1:18081".parse().unwrap());
    }

    #[tokio::test]
    async fn a_run_that_cannot_be_executed_is_recorded_as_failed() {
        let (_home, paths) = temp_paths();
        write_script(&paths, "#!/bin/sh\nexit 0\n");
        fs::set_permissions(paths.init_file(), fs::Permissions::from_mode(0o644)).unwrap();
        let state = spawn(&paths, StateConfig::default());

        let answer = state.call(Command::Reload { path: None }).await;

        let Response::Err { kind, message } = answer else {
            panic!("an unexecutable script must be reported: {answer:?}");
        };
        assert_eq!(kind, ErrKind::Internal);
        assert!(message.contains("could not be run"), "{message}");
        let Some(LastLoadView {
            at: _,
            outcome,
            command: _,
        }) = status_of(&state).await.last_load
        else {
            panic!("a finished run must be recorded");
        };
        assert_eq!(outcome, LoadOutcome::Failed);
    }

    #[tokio::test]
    async fn status_describes_a_daemon_that_has_loaded_nothing() {
        let (_home, state) = spawn_here();

        let Response::Status(status) = state.call(Command::Status).await else {
            panic!("status must answer with a status view");
        };
        let StatusView {
            uptime_secs: _,
            http_listen,
            http_bound,
            socks_listen,
            socks_bound,
            upstream,
            health,
            health_changed_at: _,
            init_path,
            last_load,
            rules,
            system_proxy,
        } = status;
        assert_eq!(http_listen, DEFAULT_HTTP_LISTEN);
        assert_eq!(socks_listen, DEFAULT_SOCKS_LISTEN);
        assert!(!http_bound);
        assert!(!socks_bound);
        assert_eq!(upstream, UpstreamAddr(String::new()));
        assert_eq!(health, HealthState::Down);
        assert_eq!(init_path, None);
        assert_eq!(last_load, None);
        assert_eq!(
            rules,
            RuleCountsView {
                require: 0,
                prefer: 0,
                never: 0,
            }
        );
        assert_eq!(
            system_proxy,
            SystemProxyView {
                http: None,
                https: None,
                socks: None,
            }
        );
    }

    #[tokio::test]
    async fn status_counts_the_live_rules_per_class() {
        let (_home, state) = spawn_here();
        state.rules().publish(ruleset(&[
            (RuleClass::Require, RuleKind::Suffix, "example.com"),
            (RuleClass::Prefer, RuleKind::Port, "443"),
            (RuleClass::Prefer, RuleKind::Keyword, "cdn"),
            (RuleClass::Never, RuleKind::Cidr, "192.0.2.0/24"),
        ]));

        let Response::Status(status) = state.call(Command::Status).await else {
            panic!("status must answer with a status view");
        };
        assert_eq!(
            status.rules,
            RuleCountsView {
                require: 1,
                prefer: 2,
                never: 1,
            }
        );
    }

    #[tokio::test]
    async fn rules_lists_the_live_ruleset_in_declaration_order() {
        let (_home, state) = spawn_here();
        state.rules().publish(ruleset(&[
            (RuleClass::Require, RuleKind::Suffix, "example.com"),
            (RuleClass::Never, RuleKind::Port, "22"),
        ]));

        let Response::Rules(rules) = state.call(Command::Rules).await else {
            panic!("rules must answer with rule views");
        };
        assert_eq!(
            rules,
            vec![
                RuleView {
                    index: 0,
                    class: RuleClass::Require,
                    kind: RuleKind::Suffix,
                    value: RuleValue("example.com".to_owned()),
                },
                RuleView {
                    index: 1,
                    class: RuleClass::Never,
                    kind: RuleKind::Port,
                    value: RuleValue("22".to_owned()),
                },
            ]
        );
    }

    /// Reader that reports a configured proxy for the service the operator uses, and nothing else.
    #[derive(Debug)]
    struct WifiProxy;

    impl SystemProxyReader for WifiProxy {
        fn read(&self, service: &NetworkService) -> Result<SystemProxy, ProxyFailure> {
            let NetworkService(service) = service;
            if service != "Wi-Fi" {
                return Ok(SystemProxy::default());
            }
            Ok(SystemProxy {
                http: Some(ProxyEndpoint::new("127.0.0.1", 7890)),
                https: Some(ProxyEndpoint::new("127.0.0.1", 7890)),
                socks: None,
            })
        }
    }

    /// Reader that cannot reach macOS at all.
    #[derive(Debug)]
    struct UnreadableProxy;

    impl SystemProxyReader for UnreadableProxy {
        fn read(&self, _service: &NetworkService) -> Result<SystemProxy, ProxyFailure> {
            Err(ProxyFailure::Unreadable("-getwebproxy"))
        }
    }

    fn spawn_reading(paths: &Paths, proxy: Arc<dyn SystemProxyReader>) -> StateHandle {
        spawn(
            paths,
            StateConfig {
                proxy,
                ..Default::default()
            },
        )
    }

    #[tokio::test]
    async fn status_reports_the_settings_the_reader_answered_for_the_wifi_service() {
        let (_home, paths) = temp_paths();
        let state = spawn_reading(&paths, Arc::new(WifiProxy));

        let status = status_of(&state).await;

        assert_eq!(
            status.system_proxy,
            SystemProxyView {
                http: Some("127.0.0.1:7890".to_owned()),
                https: Some("127.0.0.1:7890".to_owned()),
                socks: None,
            }
        );
    }

    #[tokio::test]
    async fn settings_that_cannot_be_read_are_reported_as_off() {
        let (_home, paths) = temp_paths();
        let state = spawn_reading(&paths, Arc::new(UnreadableProxy));

        let status = status_of(&state).await;

        assert_eq!(
            status.system_proxy,
            SystemProxyView {
                http: None,
                https: None,
                socks: None,
            }
        );
    }

    #[tokio::test]
    async fn test_reports_where_a_destination_would_go_without_dialling_it() {
        let (_home, state) = spawn_here();
        state
            .call(Command::SetUpstream {
                addr: UpstreamAddr("socks5://192.0.2.10:1080".to_owned()),
                load: None,
            })
            .await;
        state.rules().publish(ruleset(&[
            (RuleClass::Never, RuleKind::Suffix, "intranet.example.com"),
            (RuleClass::Require, RuleKind::Suffix, "example.com"),
        ]));

        let answer = state
            .call(Command::Test {
                host: Host("api.example.com".to_owned()),
                port: Port(443),
            })
            .await;

        assert_eq!(
            answer,
            Response::Decision(DecisionView {
                decision: DecisionKind::Upstream,
                rule_index: Some(1),
                class: Some(RuleClass::Require),
                next_hop: "socks5://192.0.2.10:1080".to_owned(),
            })
        );

        let answer = state
            .call(Command::Test {
                host: Host("example.net".to_owned()),
                port: Port(443),
            })
            .await;

        assert_eq!(
            answer,
            Response::Decision(DecisionView {
                decision: DecisionKind::Direct,
                rule_index: None,
                class: None,
                next_hop: "example.net:443".to_owned(),
            })
        );
    }

    #[tokio::test]
    async fn a_command_of_a_later_task_reports_an_internal_error() {
        let (_home, state) = spawn_here();

        let Response::Err { kind, message } = state.call(Command::Doctor).await else {
            panic!("an unserved command must answer with an error");
        };
        assert_eq!(kind, ErrKind::Internal);
        assert!(message.contains("yet"), "{message}");
    }

    #[tokio::test]
    async fn a_swap_leaves_an_open_connection_on_its_own_snapshot() {
        let live = LiveRules::default();
        let (accepted, open) = oneshot::channel();
        let (resume, wait) = oneshot::channel();
        let connection = tokio::spawn({
            let live = live.clone();
            async move {
                let snapshot = live.snapshot();
                accepted.send(()).unwrap();
                wait.await.unwrap();
                decide(&snapshot, "example.com")
            }
        });

        open.await.unwrap();
        live.publish(ruleset(&[(
            RuleClass::Require,
            RuleKind::Suffix,
            "example.com",
        )]));
        resume.send(()).unwrap();

        assert_eq!(connection.await.unwrap(), Decision::Direct);
        assert_eq!(
            decide(&live.snapshot(), "example.com").kind(),
            DecisionKind::Upstream
        );
    }

    #[test]
    fn bind_state_renders_as_the_wire_boolean() {
        assert!(BindState::Bound.is_bound());
        assert!(!BindState::Unbound.is_bound());
    }
}
