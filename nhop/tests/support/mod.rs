#![allow(dead_code)]

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use nhop::daemon::{self, Daemon};
use nhop::proxy::{Listen, NextHop, UpstreamDown};
use nhop::rules::{Decision, RuleId};
use nhop_ipc::{Command, Host, Paths, Port, Response, UpstreamAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const NO_AUTH: [u8; 2] = [0x05, 0x00];
const GRANTED: [u8; 10] = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

/// Returns an address the kernel picks a free port for.
pub fn ephemeral() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// Buffer a test reads while the command it was handed to keeps writing.
#[derive(Debug, Clone, Default)]
pub struct Shared(Arc<Mutex<Vec<u8>>>);

impl Shared {
    /// Returns everything written so far.
    pub fn text(&self) -> String {
        let Self(written) = self;
        let written = written.lock().unwrap();
        String::from_utf8(written.clone()).unwrap()
    }

    /// Returns the complete lines written so far.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for line in self.text().lines() {
            lines.push(line.to_owned());
        }
        lines
    }
}

impl io::Write for Shared {
    fn write(&mut self, written: &[u8]) -> io::Result<usize> {
        let Self(buffer) = self;
        buffer.lock().unwrap().extend_from_slice(written);
        Ok(written.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Returns front-end addresses the kernel picks free ports for.
pub fn ephemeral_listen() -> Listen {
    Listen {
        http: ephemeral(),
        socks: ephemeral(),
    }
}

/// Task that stops accepting once the handle owning it is dropped.
#[derive(Debug)]
struct Serving(JoinHandle<()>);

impl Drop for Serving {
    fn drop(&mut self) {
        let Self(serving) = self;
        serving.abort();
    }
}

/// Destination that echoes whatever is sent to it and counts its callers.
#[derive(Debug)]
pub struct StubOrigin {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    serving: Serving,
}

impl StubOrigin {
    /// Starts the origin on an ephemeral port.
    pub async fn start() -> Self {
        let listener = TcpListener::bind(ephemeral()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let serving = Serving(tokio::spawn({
            let connections = connections.clone();
            async move {
                loop {
                    let Ok((stream, _peer)) = listener.accept().await else {
                        return;
                    };
                    connections.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        let _echoed = echo(stream).await;
                    });
                }
            }
        }));
        Self {
            addr,
            connections,
            serving,
        }
    }

    /// Returns the address the origin listens on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns how many connections the origin has accepted.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

/// What a SOCKS5 client asked the stub upstream to connect to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksRequest {
    /// Address type byte the client sent.
    pub atyp: u8,
    /// Destination as the client spelled it.
    pub host: String,
    /// Destination port.
    pub port: u16,
}

/// SOCKS5 upstream that records every request and echoes the payload that follows.
#[derive(Debug)]
pub struct StubSocks5 {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<SocksRequest>>>,
    serving: Serving,
}

impl StubSocks5 {
    /// Starts the upstream on an ephemeral port.
    pub async fn start() -> Self {
        let listener = TcpListener::bind(ephemeral()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let serving = Serving(tokio::spawn({
            let requests = requests.clone();
            async move {
                loop {
                    let Ok((stream, _peer)) = listener.accept().await else {
                        return;
                    };
                    let requests = requests.clone();
                    tokio::spawn(async move {
                        let _served = socks5(stream, requests).await;
                    });
                }
            }
        }));
        Self {
            addr,
            requests,
            serving,
        }
    }

    /// Returns the address the upstream listens on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns what the upstream has been asked to connect to, in arrival order.
    pub fn requests(&self) -> Vec<SocksRequest> {
        self.requests.lock().unwrap().clone()
    }
}

async fn socks5(mut stream: TcpStream, requests: Arc<Mutex<Vec<SocksRequest>>>) -> io::Result<()> {
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    let [_version, methods] = greeting;
    let mut offered = vec![0u8; usize::from(methods)];
    stream.read_exact(&mut offered).await?;
    stream.write_all(&NO_AUTH).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    let [_version, _command, _reserved, atyp] = head;
    let host = match atyp {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            Ipv4Addr::from(octets).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let [len] = len;
            let mut name = vec![0u8; usize::from(len)];
            stream.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).into_owned()
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            Ipv6Addr::from(octets).to_string()
        }
        _ => return Ok(()),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    requests
        .lock()
        .unwrap()
        .push(SocksRequest { atyp, host, port });
    stream.write_all(&GRANTED).await?;
    echo(stream).await
}

async fn echo(mut stream: TcpStream) -> io::Result<()> {
    let (mut reader, mut writer) = stream.split();
    let _copied = tokio::io::copy(&mut reader, &mut writer).await?;
    writer.shutdown().await
}

/// Next hop that dials one address whatever it is asked for, recording the asking.
#[derive(Debug)]
pub struct StubHop {
    target: SocketAddr,
    asked: Mutex<Vec<(Host, Port, Decision)>>,
}

impl StubHop {
    /// Points the next hop at an address.
    pub fn new(target: SocketAddr) -> Self {
        Self {
            target,
            asked: Mutex::new(Vec::new()),
        }
    }

    /// Returns what the front end asked to dial, in arrival order.
    pub fn asked(&self) -> Vec<(Host, Port, Decision)> {
        self.asked.lock().unwrap().clone()
    }
}

impl NextHop for StubHop {
    fn dial<'a>(
        &'a self,
        host: &'a Host,
        port: Port,
        decision: Decision,
    ) -> Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + 'a>> {
        self.asked
            .lock()
            .unwrap()
            .push((host.clone(), port, decision));
        Box::pin(async move { TcpStream::connect(self.target).await })
    }
}

/// Next hop that refuses every dial as if the upstream were down.
#[derive(Debug)]
pub struct DownHop {
    upstream: SocketAddr,
}

impl DownHop {
    /// Names the upstream the refusals report.
    pub fn new(upstream: SocketAddr) -> Self {
        Self { upstream }
    }
}

impl NextHop for DownHop {
    fn dial<'a>(
        &'a self,
        _host: &'a Host,
        _port: Port,
        decision: Decision,
    ) -> Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + 'a>> {
        let rule = decision.rule().unwrap_or(RuleId(0));
        let upstream = self.upstream;
        Box::pin(async move { Err(UpstreamDown::new(upstream, rule).into()) })
    }
}

/// Daemon on ephemeral ports, pointed at a stub upstream.
#[derive(Debug)]
pub struct TestDaemon {
    daemon: Daemon,
    http: SocketAddr,
    socks: SocketAddr,
}

impl TestDaemon {
    /// Starts a daemon whose front ends and IPC socket live under `paths`.
    pub async fn start(paths: &Paths, upstream: SocketAddr) -> Self {
        let daemon = daemon::start_on(paths, ephemeral_listen()).unwrap();
        let answer = daemon
            .state()
            .call(Command::SetUpstream {
                addr: UpstreamAddr(format!("socks5://{upstream}")),
                load: None,
            })
            .await;
        assert_eq!(answer, Response::Ok, "the upstream must be accepted");
        let Listen { http, socks } = daemon.listen();
        Self {
            daemon,
            http,
            socks,
        }
    }

    /// Returns the address of the HTTP front end.
    pub fn http_addr(&self) -> SocketAddr {
        self.http
    }

    /// Returns the address of the SOCKS5 front end.
    pub fn socks_addr(&self) -> SocketAddr {
        self.socks
    }

    /// Returns the path clients send commands to.
    pub fn ipc_path(&self) -> &Path {
        self.daemon.socket_file()
    }

    /// Returns the handle every command travels through.
    pub fn state(&self) -> &nhop::daemon::state::StateHandle {
        self.daemon.state()
    }

    /// Sends one command to the daemon and returns its answer.
    pub async fn call(&self, command: Command) -> Response {
        self.daemon.state().call(command).await
    }

    /// Stops the daemon and removes its socket.
    pub async fn shutdown(self) {
        let Self {
            daemon,
            http: _,
            socks: _,
        } = self;
        daemon.shutdown().await;
    }
}
