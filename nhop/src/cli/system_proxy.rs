use std::fmt;
use std::io;
use std::process::{Command, ExitStatus, Output};
use std::str::FromStr;

use nhop_ipc::SystemProxyView;

/// Network service the system proxy is applied to on the target machine.
pub const DEFAULT_SERVICE: &str = "Wi-Fi";

const NETWORKSETUP: &str = "networksetup";

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
