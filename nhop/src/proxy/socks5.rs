use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str;

use nhop_ipc::{Host, Port};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpStream;

use crate::proxy::{ConnCtx, NextHop, Routed, UpstreamDown};
use crate::rules::Decision;

const VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const NO_ACCEPTABLE_METHOD: u8 = 0xff;
const RESERVED: u8 = 0x00;
const CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const MAX_METHODS: usize = 255;
const MAX_NAME: usize = 255;

/// Authentication the front end agreed on with the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Greeting {
    /// The client offered the no-auth method, the only one served.
    NoAuth,
    /// The client speaks another version, or no method the front end serves.
    Rejected,
}

/// Code the front end answers a request with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reply {
    /// The next hop is open and the relay starts.
    Granted,
    /// The dial failed for a reason of its own.
    Failure,
    /// A `require` rule needs an upstream that is down.
    HostUnreachable,
    /// The request was neither `CONNECT` nor anything else served.
    CommandNotSupported,
    /// The request named an address type the front end cannot read.
    AddressNotSupported,
}

impl Reply {
    fn code(self) -> u8 {
        match self {
            Self::Granted => 0x00,
            Self::Failure => 0x01,
            Self::HostUnreachable => 0x04,
            Self::CommandNotSupported => 0x07,
            Self::AddressNotSupported => 0x08,
        }
    }
}

/// What the client asked for, or why it cannot be served.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Requested {
    /// A tunnel to this destination.
    Connect {
        /// As the client spelled it, never resolved here.
        host: Host,
        port: Port,
    },
    /// Nothing to dial, only a code to answer with.
    Refused(Reply),
}

/// Serves one connection of the SOCKS5 front end and closes it.
///
/// A domain-type request travels to the next hop as the name the client wrote: internal names
/// resolve only inside the upstream's network, so resolving here would route them nowhere.
///
/// # Errors
///
/// Returns [`io::Error`] when the client or the next hop fails while the request is served.
///
/// [`io::Error`]: std::io::Error
pub async fn serve(mut client: TcpStream, ctx: ConnCtx, hop: &dyn NextHop) -> io::Result<()> {
    let Greeting::NoAuth = greet(&mut client).await? else {
        return chosen(&mut client, NO_ACCEPTABLE_METHOD).await;
    };
    chosen(&mut client, NO_AUTH).await?;
    let (host, port) = match request(&mut client).await? {
        Requested::Connect { host, port } => (host, port),
        Requested::Refused(reply) => return answer(&mut client, reply).await,
    };
    let decision = ctx.rules.decide(&host, port);
    let routed = Routed::begun(&ctx, &host, port, decision);
    let served = relay(&mut client, &host, port, decision, hop).await;
    routed.ended(served.as_ref().err());
    served
}

async fn relay(
    client: &mut TcpStream,
    host: &Host,
    port: Port,
    decision: Decision,
    hop: &dyn NextHop,
) -> io::Result<()> {
    let dialled = hop.dial(host, port, decision).await;
    let mut next = match dialled {
        Ok(next) => next,
        Err(failure) => {
            answer(client, refusal(&failure)).await?;
            return Err(failure);
        }
    };
    answer(client, Reply::Granted).await?;
    let _relayed = copy_bidirectional(client, &mut next).await?;
    Ok(())
}

async fn greet<R: AsyncRead + Unpin>(client: &mut R) -> io::Result<Greeting> {
    // VER | NMETHODS | METHODS[NMETHODS]
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).await?;
    let [version, count] = greeting;
    if version != VERSION {
        return Ok(Greeting::Rejected);
    }
    let count = usize::from(count);
    let mut offered = [0u8; MAX_METHODS];
    client.read_exact(&mut offered[..count]).await?;
    for method in &offered[..count] {
        if *method == NO_AUTH {
            return Ok(Greeting::NoAuth);
        }
    }
    Ok(Greeting::Rejected)
}

async fn request<R: AsyncRead + Unpin>(client: &mut R) -> io::Result<Requested> {
    // VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
    let mut head = [0u8; 4];
    client.read_exact(&mut head).await?;
    let [version, command, _reserved, atyp] = head;
    if version != VERSION {
        return Ok(Requested::Refused(Reply::Failure));
    }
    if command != CONNECT {
        return Ok(Requested::Refused(Reply::CommandNotSupported));
    }
    let host = match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            client.read_exact(&mut octets).await?;
            Host(Ipv4Addr::from(octets).to_string())
        }
        ATYP_DOMAIN => {
            // LEN | NAME[LEN]
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let [len] = len;
            let mut name = [0u8; MAX_NAME];
            let name = &mut name[..usize::from(len)];
            client.read_exact(name).await?;
            let Ok(name) = str::from_utf8(name) else {
                return Ok(Requested::Refused(Reply::Failure));
            };
            if name.is_empty() {
                return Ok(Requested::Refused(Reply::Failure));
            }
            Host(name.to_owned())
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            client.read_exact(&mut octets).await?;
            Host(Ipv6Addr::from(octets).to_string())
        }
        _atyp => return Ok(Requested::Refused(Reply::AddressNotSupported)),
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port).await?;
    Ok(Requested::Connect {
        host,
        port: Port(u16::from_be_bytes(port)),
    })
}

fn refusal(failure: &io::Error) -> Reply {
    let Some(_down) = UpstreamDown::carried_by(failure) else {
        return Reply::Failure;
    };
    Reply::HostUnreachable
}

async fn chosen<W: AsyncWrite + Unpin>(client: &mut W, method: u8) -> io::Result<()> {
    // VER | METHOD
    client.write_all(&[VERSION, method]).await?;
    client.flush().await
}

async fn answer<W: AsyncWrite + Unpin>(client: &mut W, reply: Reply) -> io::Result<()> {
    // VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
    let reply = [VERSION, reply.code(), RESERVED, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    client.write_all(&reply).await?;
    client.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn greeting_of(bytes: &[u8]) -> Greeting {
        greet(&mut &bytes[..]).await.unwrap()
    }

    async fn request_of(bytes: &[u8]) -> Requested {
        request(&mut &bytes[..]).await.unwrap()
    }

    fn connect(host: &str, port: u16) -> Requested {
        Requested::Connect {
            host: Host(host.to_owned()),
            port: Port(port),
        }
    }

    async fn written(reply: Reply) -> Vec<u8> {
        let mut out = Vec::new();
        answer(&mut out, reply).await.unwrap();
        out
    }

    #[tokio::test]
    async fn a_client_offering_no_auth_is_accepted() {
        assert_eq!(greeting_of(&[0x05, 0x01, 0x00]).await, Greeting::NoAuth);
        assert_eq!(
            greeting_of(&[0x05, 0x02, 0x02, 0x00]).await,
            Greeting::NoAuth
        );
    }

    #[tokio::test]
    async fn a_client_offering_only_other_methods_is_rejected() {
        assert_eq!(greeting_of(&[0x05, 0x01, 0x02]).await, Greeting::Rejected);
        assert_eq!(greeting_of(&[0x05, 0x00]).await, Greeting::Rejected);
    }

    #[tokio::test]
    async fn a_client_speaking_another_version_is_rejected() {
        assert_eq!(greeting_of(&[0x04, 0x01, 0x00]).await, Greeting::Rejected);
    }

    #[tokio::test]
    async fn a_truncated_greeting_is_an_error() {
        let failure = greet(&mut &[0x05, 0x02, 0x00][..]).await.unwrap_err();
        assert_eq!(failure.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn an_ipv4_request_names_the_address() {
        assert_eq!(
            request_of(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb]).await,
            connect("127.0.0.1", 443)
        );
    }

    #[tokio::test]
    async fn a_domain_request_keeps_the_name_the_client_wrote() {
        let mut bytes = vec![0x05, 0x01, 0x00, 0x03, 11];
        bytes.extend_from_slice(b"example.com");
        bytes.extend_from_slice(&[0x1f, 0x90]);
        assert_eq!(request_of(&bytes).await, connect("example.com", 8080));
    }

    #[tokio::test]
    async fn an_ipv6_request_names_the_address() {
        let mut bytes = vec![0x05, 0x01, 0x00, 0x04];
        bytes.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        bytes.extend_from_slice(&[0x00, 0x50]);
        assert_eq!(request_of(&bytes).await, connect("::1", 80));
    }

    #[tokio::test]
    async fn bind_and_udp_associate_are_not_served() {
        assert_eq!(
            request_of(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb]).await,
            Requested::Refused(Reply::CommandNotSupported)
        );
        assert_eq!(
            request_of(&[0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb]).await,
            Requested::Refused(Reply::CommandNotSupported)
        );
    }

    #[tokio::test]
    async fn an_unknown_address_type_is_not_served() {
        assert_eq!(
            request_of(&[0x05, 0x01, 0x00, 0x02, 0, 0]).await,
            Requested::Refused(Reply::AddressNotSupported)
        );
    }

    #[tokio::test]
    async fn a_domain_that_is_not_a_name_is_refused() {
        assert_eq!(
            request_of(&[0x05, 0x01, 0x00, 0x03, 0x01, 0xff, 0x01, 0xbb]).await,
            Requested::Refused(Reply::Failure)
        );
        assert_eq!(
            request_of(&[0x05, 0x01, 0x00, 0x03, 0x00, 0x01, 0xbb]).await,
            Requested::Refused(Reply::Failure)
        );
    }

    #[tokio::test]
    async fn a_request_of_another_version_is_refused() {
        assert_eq!(
            request_of(&[0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb]).await,
            Requested::Refused(Reply::Failure)
        );
    }

    #[tokio::test]
    async fn the_success_reply_carries_an_opaque_bound_address() {
        assert_eq!(
            written(Reply::Granted).await,
            vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
    }

    #[tokio::test]
    async fn every_refusal_keeps_the_reply_shape() {
        assert_eq!(
            written(Reply::Failure).await,
            vec![0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            written(Reply::HostUnreachable).await,
            vec![0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            written(Reply::CommandNotSupported).await,
            vec![0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            written(Reply::AddressNotSupported).await,
            vec![0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        );
    }

    #[tokio::test]
    async fn the_chosen_method_is_two_bytes() {
        let mut out = Vec::new();
        chosen(&mut out, NO_ACCEPTABLE_METHOD).await.unwrap();
        assert_eq!(out, vec![0x05, 0xff]);
    }

    #[test]
    fn an_upstream_that_is_down_renders_as_host_unreachable() {
        let down = UpstreamDown::new("192.0.2.10:1080".parse().unwrap(), crate::rules::RuleId(0));
        assert_eq!(refusal(&down.into()), Reply::HostUnreachable);
    }

    #[test]
    fn any_other_dial_failure_renders_as_a_general_failure() {
        let failure = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert_eq!(refusal(&failure), Reply::Failure);
    }
}
