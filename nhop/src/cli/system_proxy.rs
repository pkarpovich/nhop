use std::fmt;
use std::io;
use std::process::{Command, ExitStatus, Output};
use std::str::FromStr;

use nhop_ipc::SystemProxyView;

use crate::proxy::Listen;

/// Network service the system proxy is applied to on the target machine.
pub const DEFAULT_SERVICE: &str = "Wi-Fi";

/// Hosts and networks macOS must reach without going through the router.
///
/// This is not the daemon's `never` class: those rules apply to traffic that already reached a
/// front end, while this list keeps traffic from being sent to one at all.
pub const BYPASS: [&str; 4] = ["localhost", "127.0.0.1", "*.local", "169.254/16"];

const NETWORKSETUP: &str = "/usr/sbin/networksetup";
const BYPASS_FLAG: &str = "-setproxybypassdomains";
const OFF: &str = "off";

const ENABLED_FIELD: &str = "Enabled";
const SERVER_FIELD: &str = "Server";
const PORT_FIELD: &str = "Port";
const ENABLED_YES: &str = "Yes";

/// macOS network service the system proxy settings belong to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkService(pub String);

impl Default for NetworkService {
    fn default() -> Self {
        Self(DEFAULT_SERVICE.to_owned())
    }
}

impl fmt::Display for NetworkService {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(service) = self;
        out.write_str(service)
    }
}

/// Rejection of a service name macOS cannot be asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("network service must not be empty")]
pub struct EmptyService;

impl FromStr for NetworkService {
    type Err = EmptyService;

    fn from_str(service: &str) -> Result<Self, Self::Err> {
        if service.is_empty() {
            return Err(EmptyService);
        }
        Ok(Self(service.to_owned()))
    }
}

/// One of the three proxy settings macOS keeps per network service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    /// Proxy plain HTTP traffic is sent to.
    Http,
    /// Proxy HTTPS traffic is sent to.
    Https,
    /// Proxy SOCKS traffic is sent to.
    Socks,
}

impl ProxyKind {
    /// Returns the `networksetup` flag that reports this setting.
    pub fn read_flag(self) -> &'static str {
        match self {
            Self::Http => "-getwebproxy",
            Self::Https => "-getsecurewebproxy",
            Self::Socks => "-getsocksfirewallproxy",
        }
    }

    /// Returns the `networksetup` flag that points this setting at an address and turns it on.
    pub fn write_flag(self) -> &'static str {
        match self {
            Self::Http => "-setwebproxy",
            Self::Https => "-setsecurewebproxy",
            Self::Socks => "-setsocksfirewallproxy",
        }
    }

    /// Returns the `networksetup` flag that turns this setting on or off without moving it.
    pub fn state_flag(self) -> &'static str {
        match self {
            Self::Http => "-setwebproxystate",
            Self::Https => "-setsecurewebproxystate",
            Self::Socks => "-setsocksfirewallproxystate",
        }
    }
}

/// Whether this process may change settings macOS keeps for the whole machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    /// Running as root, so `networksetup` accepts a write.
    Root,
    /// Running as somebody else, so a write would be refused.
    Unprivileged,
}

impl Privilege {
    /// Returns the privilege the running process holds.
    pub fn current() -> Self {
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            return Self::Root;
        }
        Self::Unprivileged
    }
}

/// One `networksetup` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// Flag naming what `networksetup` is asked to change.
    pub flag: &'static str,
    /// Arguments following the flag, the network service first.
    pub arguments: Vec<String>,
}

impl Invocation {
    /// Returns the whole command line, as `networksetup` is run with it.
    pub fn argv(&self) -> Vec<String> {
        let Self { flag, arguments } = self;
        let mut argv = vec![(*flag).to_owned()];
        for argument in arguments {
            argv.push(argument.clone());
        }
        argv
    }
}

fn invocation(flag: &'static str, service: &NetworkService, rest: Vec<String>) -> Invocation {
    let NetworkService(service) = service;
    let mut arguments = vec![service.clone()];
    for argument in rest {
        arguments.push(argument);
    }
    Invocation { flag, arguments }
}

/// Returns the invocations that point a service at the front ends and set the bypass list.
pub fn enabling(listen: Listen, service: &NetworkService) -> Vec<Invocation> {
    let Listen { http, socks } = listen;
    let mut invocations = Vec::new();
    for (kind, addr) in [
        (ProxyKind::Http, http),
        (ProxyKind::Https, http),
        (ProxyKind::Socks, socks),
    ] {
        let rest = vec![addr.ip().to_string(), addr.port().to_string()];
        invocations.push(invocation(kind.write_flag(), service, rest));
    }
    let mut bypass = Vec::new();
    for host in BYPASS {
        bypass.push(host.to_owned());
    }
    invocations.push(invocation(BYPASS_FLAG, service, bypass));
    invocations
}

/// Returns the invocations that turn all three settings of a service off.
pub fn disabling(service: &NetworkService) -> Vec<Invocation> {
    let mut invocations = Vec::new();
    for kind in [ProxyKind::Http, ProxyKind::Https, ProxyKind::Socks] {
        invocations.push(invocation(kind.state_flag(), service, vec![OFF.to_owned()]));
    }
    invocations
}

/// Runs the invocations in order, stopping at the first one macOS refuses.
///
/// `networksetup` is named by its absolute path: these writes run under `sudo`, which keeps the
/// invoking user's `PATH` on macOS, so a bare name would let any directory on that `PATH` decide
/// what runs as root.
///
/// # Errors
///
/// Returns [`ProxyFailure`] when `networksetup` cannot be run or exits non-zero.
pub fn apply(invocations: &[Invocation]) -> Result<(), ProxyFailure> {
    for Invocation { flag, arguments } in invocations {
        let Output {
            status,
            stdout: _,
            stderr: _,
        } = Command::new(NETWORKSETUP)
            .arg(flag)
            .args(arguments)
            .output()?;
        if !status.success() {
            return Err(ProxyFailure::Refused { flag, status });
        }
    }
    Ok(())
}

/// Address of one configured proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEndpoint {
    host: String,
    port: u16,
}

impl ProxyEndpoint {
    /// Names the host and port macOS reports for a setting that is on.
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_owned(),
            port,
        }
    }
}

impl fmt::Display for ProxyEndpoint {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { host, port } = self;
        write!(out, "{host}:{port}")
    }
}

/// Proxy settings macOS reports for one network service.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemProxy {
    /// Configured HTTP proxy, absent when the setting is off.
    pub http: Option<ProxyEndpoint>,
    /// Configured HTTPS proxy, absent when the setting is off.
    pub https: Option<ProxyEndpoint>,
    /// Configured SOCKS proxy, absent when the setting is off.
    pub socks: Option<ProxyEndpoint>,
}

impl SystemProxy {
    /// Renders the settings as the IPC contract carries them.
    pub fn view(&self) -> SystemProxyView {
        let Self { http, https, socks } = self;
        SystemProxyView {
            http: named(http),
            https: named(https),
            socks: named(socks),
        }
    }
}

fn named(endpoint: &Option<ProxyEndpoint>) -> Option<String> {
    let endpoint = endpoint.as_ref()?;
    Some(endpoint.to_string())
}

/// Reason the system proxy settings could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ProxyFailure {
    /// `networksetup` could not be run at all.
    #[error("cannot run networksetup: {0}")]
    NotRun(#[from] io::Error),
    /// `networksetup` ran and refused the question.
    #[error("networksetup {flag} exited with {status}")]
    Refused {
        /// Flag `networksetup` was asked with.
        flag: &'static str,
        /// Status it exited with.
        status: ExitStatus,
    },
    /// `networksetup` answered with bytes that are not text.
    #[error("networksetup {0} answered with something that is not utf-8")]
    Unreadable(&'static str),
}

/// Reads the proxy settings macOS holds for a network service.
pub trait SystemProxyReader: fmt::Debug + Send + Sync + 'static {
    /// Returns the three proxy settings of `service`.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyFailure`] when macOS cannot be asked or does not answer.
    fn read(&self, service: &NetworkService) -> Result<SystemProxy, ProxyFailure>;
}

/// Reader that asks macOS through `networksetup`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Networksetup;

impl SystemProxyReader for Networksetup {
    fn read(&self, service: &NetworkService) -> Result<SystemProxy, ProxyFailure> {
        Ok(SystemProxy {
            http: parse(&report(ProxyKind::Http, service)?),
            https: parse(&report(ProxyKind::Https, service)?),
            socks: parse(&report(ProxyKind::Socks, service)?),
        })
    }
}

/// Reader that reports every setting off without asking macOS.
///
/// This is what a daemon on a machine without `networksetup` reads, and what tests read so that a
/// status never depends on the proxy settings of the machine running them.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSystemProxy;

impl SystemProxyReader for NoSystemProxy {
    fn read(&self, _service: &NetworkService) -> Result<SystemProxy, ProxyFailure> {
        Ok(SystemProxy::default())
    }
}

fn report(kind: ProxyKind, service: &NetworkService) -> Result<String, ProxyFailure> {
    let NetworkService(service) = service;
    let flag = kind.read_flag();
    let Output {
        status,
        stdout,
        stderr: _,
    } = Command::new(NETWORKSETUP).arg(flag).arg(service).output()?;
    if !status.success() {
        return Err(ProxyFailure::Refused { flag, status });
    }
    let Ok(reported) = String::from_utf8(stdout) else {
        return Err(ProxyFailure::Unreadable(flag));
    };
    Ok(reported)
}

/// Reads one `networksetup` proxy report.
///
/// Returns [`None`] when the setting is off or names no address that can be dialled.
pub fn parse(reported: &str) -> Option<ProxyEndpoint> {
    let mut enabled = false;
    let mut host = "";
    let mut port = 0;
    for line in reported.lines() {
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let field = field.trim();
        let value = value.trim();
        if field == ENABLED_FIELD {
            enabled = value == ENABLED_YES;
            continue;
        }
        if field == SERVER_FIELD {
            host = value;
            continue;
        }
        if field == PORT_FIELD {
            port = value.parse::<u16>().unwrap_or(0);
        }
    }
    if !enabled || host.is_empty() || port == 0 {
        return None;
    }
    Some(ProxyEndpoint::new(host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ON: &str =
        "Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\nAuthenticated Proxy Enabled: 0\n";
    const OFF: &str = "Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n";

    #[test]
    fn an_enabled_setting_reads_as_its_endpoint() {
        assert_eq!(parse(ON), Some(ProxyEndpoint::new("127.0.0.1", 7890)));
        assert_eq!(
            parse("Enabled: Yes\nServer: proxy.example.com\nPort: 3128\n"),
            Some(ProxyEndpoint::new("proxy.example.com", 3128))
        );
    }

    #[test]
    fn a_disabled_setting_reads_as_nothing() {
        assert_eq!(parse(OFF), None);
        assert_eq!(parse(""), None);
    }

    #[test]
    fn an_enabled_setting_without_a_usable_address_reads_as_nothing() {
        assert_eq!(parse("Enabled: Yes\nServer: \nPort: 7890\n"), None);
        assert_eq!(parse("Enabled: Yes\nServer: 127.0.0.1\nPort: 0\n"), None);
        assert_eq!(
            parse("Enabled: Yes\nServer: 127.0.0.1\nPort: seventy\n"),
            None
        );
        assert_eq!(parse("Enabled: Yes\nServer: 127.0.0.1\n"), None);
    }

    #[test]
    fn a_report_that_is_not_a_setting_reads_as_nothing() {
        assert_eq!(parse("** Error: The parameters were not valid. **\n"), None);
        assert_eq!(parse("Authenticated Proxy Enabled: 1\n"), None);
    }

    #[test]
    fn every_setting_names_its_own_networksetup_flag() {
        assert_eq!(ProxyKind::Http.read_flag(), "-getwebproxy");
        assert_eq!(ProxyKind::Https.read_flag(), "-getsecurewebproxy");
        assert_eq!(ProxyKind::Socks.read_flag(), "-getsocksfirewallproxy");

        assert_eq!(ProxyKind::Http.write_flag(), "-setwebproxy");
        assert_eq!(ProxyKind::Https.write_flag(), "-setsecurewebproxy");
        assert_eq!(ProxyKind::Socks.write_flag(), "-setsocksfirewallproxy");

        assert_eq!(ProxyKind::Http.state_flag(), "-setwebproxystate");
        assert_eq!(ProxyKind::Https.state_flag(), "-setsecurewebproxystate");
        assert_eq!(ProxyKind::Socks.state_flag(), "-setsocksfirewallproxystate");
    }

    fn listen() -> Listen {
        Listen {
            http: "127.0.0.1:7890".parse().unwrap(),
            socks: "127.0.0.1:7891".parse().unwrap(),
        }
    }

    fn argv(invocations: &[Invocation]) -> Vec<Vec<String>> {
        let mut rendered = Vec::new();
        for invocation in invocations {
            rendered.push(invocation.argv());
        }
        rendered
    }

    #[test]
    fn turning_the_proxy_on_points_all_three_settings_at_the_front_ends() {
        let argv = argv(&enabling(listen(), &NetworkService::default()));

        assert_eq!(argv.len(), 4, "{argv:?}");
        assert_eq!(argv[0], ["-setwebproxy", "Wi-Fi", "127.0.0.1", "7890"]);
        assert_eq!(
            argv[1],
            ["-setsecurewebproxy", "Wi-Fi", "127.0.0.1", "7890"]
        );
        assert_eq!(
            argv[2],
            ["-setsocksfirewallproxy", "Wi-Fi", "127.0.0.1", "7891"]
        );
    }

    #[test]
    fn turning_the_proxy_on_sets_the_bypass_list_to_the_constant() {
        assert_eq!(BYPASS, ["localhost", "127.0.0.1", "*.local", "169.254/16"]);

        let argv = argv(&enabling(listen(), &NetworkService::default()));

        assert_eq!(
            argv[3],
            [
                "-setproxybypassdomains",
                "Wi-Fi",
                "localhost",
                "127.0.0.1",
                "*.local",
                "169.254/16"
            ]
        );
    }

    #[test]
    fn turning_the_proxy_off_disables_all_three_settings() {
        let argv = argv(&disabling(&NetworkService::default()));

        assert_eq!(argv.len(), 3, "{argv:?}");
        assert_eq!(argv[0], ["-setwebproxystate", "Wi-Fi", "off"]);
        assert_eq!(argv[1], ["-setsecurewebproxystate", "Wi-Fi", "off"]);
        assert_eq!(argv[2], ["-setsocksfirewallproxystate", "Wi-Fi", "off"]);
    }

    #[test]
    fn a_service_whose_name_carries_a_space_stays_one_argument() {
        let service = "Thunderbolt Ethernet".parse::<NetworkService>().unwrap();

        let on = argv(&enabling(listen(), &service));
        let off = argv(&disabling(&service));

        assert_eq!(
            on[0],
            ["-setwebproxy", "Thunderbolt Ethernet", "127.0.0.1", "7890"]
        );
        assert_eq!(
            off[2],
            ["-setsocksfirewallproxystate", "Thunderbolt Ethernet", "off"]
        );
    }

    #[test]
    fn front_ends_on_other_addresses_are_written_as_a_host_and_a_port() {
        let listen = Listen {
            http: "192.168.1.5:18080".parse().unwrap(),
            socks: "192.168.1.5:18081".parse().unwrap(),
        };

        let argv = argv(&enabling(listen, &NetworkService::default()));

        assert_eq!(argv[0], ["-setwebproxy", "Wi-Fi", "192.168.1.5", "18080"]);
        assert_eq!(
            argv[2],
            ["-setsocksfirewallproxy", "Wi-Fi", "192.168.1.5", "18081"]
        );
    }

    #[test]
    fn the_settings_render_as_the_wire_strings() {
        let proxy = SystemProxy {
            http: parse(ON),
            https: parse(ON),
            socks: parse(OFF),
        };
        assert_eq!(
            proxy.view(),
            SystemProxyView {
                http: Some("127.0.0.1:7890".to_owned()),
                https: Some("127.0.0.1:7890".to_owned()),
                socks: None,
            }
        );
        assert_eq!(
            SystemProxy::default().view(),
            SystemProxyView {
                http: None,
                https: None,
                socks: None,
            }
        );
    }

    #[test]
    fn the_service_defaults_to_the_one_the_operator_configures() {
        assert_eq!(
            NetworkService::default(),
            NetworkService("Wi-Fi".to_owned())
        );
        assert_eq!(NetworkService::default().to_string(), "Wi-Fi");
        assert_eq!(
            "Ethernet".parse::<NetworkService>().unwrap(),
            NetworkService("Ethernet".to_owned())
        );
        assert_eq!("".parse::<NetworkService>().unwrap_err(), EmptyService);
    }

    #[test]
    fn a_reader_that_asks_nobody_reports_every_setting_off() {
        let read = NoSystemProxy.read(&NetworkService::default()).unwrap();
        assert_eq!(read, SystemProxy::default());
    }

    #[test]
    fn the_real_reader_either_answers_or_names_what_stopped_it() {
        match Networksetup.read(&NetworkService::default()) {
            Ok(_read) => {}
            Err(ProxyFailure::NotRun(failure)) => {
                assert_eq!(failure.kind(), io::ErrorKind::NotFound);
            }
            Err(ProxyFailure::Refused { flag, status: _ }) => {
                assert!(flag.starts_with("-get"), "{flag}");
            }
            Err(ProxyFailure::Unreadable(flag)) => assert!(flag.starts_with("-get"), "{flag}"),
        }
    }
}
