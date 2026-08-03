use std::io;
use std::str;

use nhop_ipc::{Host, Port};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy, copy_bidirectional};
use tokio::net::TcpStream;

use crate::proxy::{ConnCtx, NextHop, Routed, UpstreamDown};
use crate::rules::Decision;

/// Largest request head the front end reads, in bytes.
pub const HEAD_LIMIT: usize = 8192;

const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
const BAD_REQUEST: &str = "400 Bad Request";
const BAD_GATEWAY: &str = "502 Bad Gateway";
const DEFAULT_PORT: Port = Port(80);

/// What the client asked the front end to do with its connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    /// `CONNECT host:port`, an opaque tunnel.
    Connect,
    /// Any other method, carrying its authority in the request target or the `Host` header.
    Absolute,
}

/// How much of what arrived behind the head belongs to the request the head opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Body {
    /// A `Content-Length` body of this many bytes; anything past it is a later request.
    Sized(usize),
    /// A body only its own framing delimits, so everything already read belongs to it.
    Streamed,
}

/// The single request one client connection carries.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Request {
    method: Method,
    host: Host,
    port: Port,
    body: Body,
}

/// What one read of the client left in the buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Head {
    end: usize,
    read: usize,
}

/// How much of the request body has still to come from the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rest {
    /// Exactly this many bytes, after which the client has nothing more to say about this request.
    Bytes(usize),
    /// A body only its own framing delimits, so only the client can end it.
    Streamed,
}

impl Rest {
    fn limit(self) -> u64 {
        match self {
            Self::Bytes(bytes) => u64::try_from(bytes).unwrap_or(u64::MAX),
            Self::Streamed => u64::MAX,
        }
    }
}

/// The bytes of one request, as the next hop receives them.
#[derive(Debug, Clone, Copy)]
struct Forward<'a> {
    method: Method,
    head: &'a [u8],
    behind: &'a [u8],
    rest: Rest,
}

/// Serves one connection of the HTTP front end and closes it.
///
/// Exactly one request is routed per connection: the head and its body are forwarded, the answer
/// is relayed back and the connection is closed, so whatever the client sends afterwards - behind
/// the body it pipelined, or on the connection it meant to keep alive - can never inherit this
/// one's next hop. A connection that reached a decision leaves exactly one line in the log,
/// whether it was relayed or refused.
///
/// # Errors
///
/// Returns [`io::Error`] when the client or the next hop fails while the head is read, the answer
/// is written or the relay is running. A refused dial is such a failure, reported after the client
/// has been answered.
///
/// [`io::Error`]: std::io::Error
pub async fn serve(mut client: TcpStream, ctx: ConnCtx, hop: &dyn NextHop) -> io::Result<()> {
    let mut buffer = [0u8; HEAD_LIMIT];
    let Some(Head { end, read }) = read_head(&mut client, &mut buffer).await? else {
        return Ok(());
    };
    let head = &buffer[..end];
    let Some(request) = parse_head(head) else {
        return respond(&mut client, BAD_REQUEST, "nhop: malformed request").await;
    };
    let Request {
        method,
        host,
        port,
        body,
    } = request;
    let behind = behind_the_head(&buffer[end..read], method, body);
    let forward = Forward {
        method,
        head,
        behind,
        rest: rest_of_body(method, body, behind),
    };
    let decision = ctx.rules.decide(&host, port);
    let routed = Routed::begun(&ctx, &host, port, decision);
    let served = relay(&mut client, forward, &host, port, decision, hop).await;
    routed.ended(served.as_ref().err());
    served
}

fn behind_the_head(rest: &[u8], method: Method, body: Body) -> &[u8] {
    match method {
        Method::Connect => rest,
        Method::Absolute => match body {
            Body::Streamed => rest,
            Body::Sized(len) => {
                let len = len.min(rest.len());
                &rest[..len]
            }
        },
    }
}

fn rest_of_body(method: Method, body: Body, behind: &[u8]) -> Rest {
    match method {
        Method::Connect => Rest::Streamed,
        Method::Absolute => match body {
            Body::Streamed => Rest::Streamed,
            Body::Sized(len) => Rest::Bytes(len.saturating_sub(behind.len())),
        },
    }
}

async fn relay(
    client: &mut TcpStream,
    forward: Forward<'_>,
    host: &Host,
    port: Port,
    decision: Decision,
    hop: &dyn NextHop,
) -> io::Result<()> {
    let Forward {
        method,
        head,
        behind,
        rest,
    } = forward;
    let dialled = hop.dial(host, port, decision).await;
    let mut next = match dialled {
        Ok(next) => next,
        Err(failure) => {
            refuse(client, &failure, host, port).await?;
            return Err(failure);
        }
    };
    match method {
        Method::Connect => tunnel(client, &mut next, behind).await,
        Method::Absolute => forwarded(client, &mut next, head, behind, rest).await,
    }
}

/// Answers the tunnel request and then carries bytes both ways until either end stops.
async fn tunnel(client: &mut TcpStream, next: &mut TcpStream, behind: &[u8]) -> io::Result<()> {
    client.write_all(ESTABLISHED).await?;
    client.flush().await?;
    next.write_all(behind).await?;
    next.flush().await?;
    let _relayed = copy_bidirectional(client, next).await?;
    Ok(())
}

/// Forwards one request and its answer, and reads no further request from the client.
///
/// The client is read only as far as this request's body reaches, so a request behind it is never
/// forwarded and can never inherit this one's next hop; the next hop is then half-closed, which is
/// what tells an origin holding the connection open that the request is over. The two directions
/// run together, so an origin that answers before the body has arrived cannot wedge the upload.
///
/// A body only its own framing delimits ends where the client stops writing, so a chunked upload
/// is the one request whose end the front end cannot see: it holds the connection until the client
/// half-closes it.
async fn forwarded(
    client: &mut TcpStream,
    next: &mut TcpStream,
    head: &[u8],
    behind: &[u8],
    rest: Rest,
) -> io::Result<()> {
    next.write_all(head).await?;
    next.write_all(behind).await?;
    next.flush().await?;
    let (client_read, mut client_write) = client.split();
    let (mut next_read, mut next_write) = next.split();
    let mut body = client_read.take(rest.limit());
    let sending = async {
        let _sent = copy(&mut body, &mut next_write).await?;
        next_write.shutdown().await
    };
    let answering = async {
        let _answered = copy(&mut next_read, &mut client_write).await?;
        client_write.shutdown().await
    };
    let ((), ()) = tokio::try_join!(sending, answering)?;
    Ok(())
}

async fn read_head(
    client: &mut TcpStream,
    buffer: &mut [u8; HEAD_LIMIT],
) -> io::Result<Option<Head>> {
    let mut read = 0;
    loop {
        if read == buffer.len() {
            return Ok(None);
        }
        let taken = client.read(&mut buffer[read..]).await?;
        if taken == 0 {
            return Ok(None);
        }
        read += taken;
        let Some(end) = head_end(&buffer[..read]) else {
            continue;
        };
        return Ok(Some(Head { end, read }));
    }
}

fn head_end(buffer: &[u8]) -> Option<usize> {
    let last = buffer.len().checked_sub(4)?;
    for index in 0..=last {
        if &buffer[index..index + 4] == b"\r\n\r\n" {
            return Some(index + 4);
        }
    }
    None
}

fn parse_head(head: &[u8]) -> Option<Request> {
    let Ok(head) = str::from_utf8(head) else {
        return None;
    };
    let (line, headers) = head.split_once("\r\n")?;
    let mut fields = line.split(' ');
    let method = fields.next()?;
    let target = fields.next()?;
    let version = fields.next()?;
    if fields.next().is_some() {
        return None;
    }
    if !version.starts_with("HTTP/") {
        return None;
    }
    if method == "CONNECT" {
        let (host, port) = split_authority(target, None)?;
        return Some(Request {
            method: Method::Connect,
            host,
            port,
            body: Body::Streamed,
        });
    }
    let authority = match absolute_authority(target) {
        Some(authority) => authority,
        None => header(headers, "host")?,
    };
    let (host, port) = split_authority(authority, Some(DEFAULT_PORT))?;
    Some(Request {
        method: Method::Absolute,
        host,
        port,
        body: body_of(headers),
    })
}

fn body_of(headers: &str) -> Body {
    if header(headers, "transfer-encoding").is_some() {
        return Body::Streamed;
    }
    let Some(len) = header(headers, "content-length") else {
        return Body::Sized(0);
    };
    let Ok(len) = len.parse::<usize>() else {
        return Body::Sized(0);
    };
    Body::Sized(len)
}

fn absolute_authority(target: &str) -> Option<&str> {
    let rest = target.strip_prefix("http://")?;
    let Some((authority, _path)) = rest.split_once('/') else {
        return Some(rest);
    };
    Some(authority)
}

fn header<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    for line in headers.split("\r\n") {
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        if field.trim().eq_ignore_ascii_case(name) {
            return Some(value.trim());
        }
    }
    None
}

fn split_authority(authority: &str, fallback: Option<Port>) -> Option<(Host, Port)> {
    let Some(bracketed) = authority.strip_prefix('[') else {
        let Some((host, port)) = authority.rsplit_once(':') else {
            return named(authority, fallback?);
        };
        let Ok(port) = port.parse::<u16>() else {
            return None;
        };
        return named(host, Port(port));
    };
    let (host, rest) = bracketed.split_once(']')?;
    let Some(port) = rest.strip_prefix(':') else {
        return named(host, fallback?);
    };
    let Ok(port) = port.parse::<u16>() else {
        return None;
    };
    named(host, Port(port))
}

fn named(host: &str, port: Port) -> Option<(Host, Port)> {
    if host.is_empty() {
        return None;
    }
    Some((Host(host.to_owned()), port))
}

async fn refuse(
    client: &mut TcpStream,
    failure: &io::Error,
    host: &Host,
    port: Port,
) -> io::Result<()> {
    let Some(down) = UpstreamDown::carried_by(failure) else {
        let Host(host) = host;
        let Port(port) = port;
        let body = format!("nhop: cannot reach {host}:{port}");
        return respond(client, BAD_GATEWAY, &body).await;
    };
    respond(client, BAD_GATEWAY, &down.to_string()).await
}

async fn respond(client: &mut TcpStream, status: &str, body: &str) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
        len = body.len()
    );
    client.write_all(head.as_bytes()).await?;
    client.write_all(body.as_bytes()).await?;
    client.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(head: &str) -> Option<Request> {
        parse_head(head.as_bytes())
    }

    fn request(method: Method, host: &str, port: u16) -> Option<Request> {
        let body = match method {
            Method::Connect => Body::Streamed,
            Method::Absolute => Body::Sized(0),
        };
        carrying(method, host, port, body)
    }

    fn carrying(method: Method, host: &str, port: u16, body: Body) -> Option<Request> {
        Some(Request {
            method,
            host: Host(host.to_owned()),
            port: Port(port),
            body,
        })
    }

    #[test]
    fn a_connect_request_names_its_authority() {
        assert_eq!(
            parse("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"),
            request(Method::Connect, "example.com", 443)
        );
    }

    #[test]
    fn a_connect_request_without_a_port_is_malformed() {
        assert_eq!(parse("CONNECT example.com HTTP/1.1\r\n\r\n"), None);
        assert_eq!(parse("CONNECT example.com:https HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn an_absolute_form_request_takes_its_authority_from_the_target() {
        assert_eq!(
            parse(
                "GET http://example.com/index.html HTTP/1.1\r\nHost: elsewhere.example.net\r\n\r\n"
            ),
            request(Method::Absolute, "example.com", 80)
        );
        assert_eq!(
            parse("GET http://example.com:8080/ HTTP/1.1\r\n\r\n"),
            request(Method::Absolute, "example.com", 8080)
        );
        assert_eq!(
            parse("GET http://example.com HTTP/1.1\r\n\r\n"),
            request(Method::Absolute, "example.com", 80)
        );
    }

    #[test]
    fn an_origin_form_request_falls_back_to_the_host_header() {
        assert_eq!(
            parse("GET /index.html HTTP/1.1\r\nAccept: */*\r\nHost: example.com:8080\r\n\r\n"),
            request(Method::Absolute, "example.com", 8080)
        );
        assert_eq!(
            parse("POST /submit HTTP/1.1\r\nhost:  example.com \r\n\r\n"),
            request(Method::Absolute, "example.com", 80)
        );
    }

    #[test]
    fn an_origin_form_request_without_a_host_header_is_malformed() {
        assert_eq!(
            parse("GET /index.html HTTP/1.1\r\nAccept: */*\r\n\r\n"),
            None
        );
    }

    #[test]
    fn a_malformed_request_line_is_rejected() {
        assert_eq!(parse("GET\r\n\r\n"), None);
        assert_eq!(parse("GET /index.html\r\n\r\n"), None);
        assert_eq!(
            parse("GET / HTTP/1.1 extra\r\nHost: example.com\r\n\r\n"),
            None
        );
        assert_eq!(parse("GET / SPDY/1.1\r\nHost: example.com\r\n\r\n"), None);
        assert_eq!(parse("\r\n\r\n"), None);
    }

    #[test]
    fn a_bracketed_address_keeps_its_colons() {
        assert_eq!(
            parse("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n\r\n"),
            request(Method::Connect, "2001:db8::1", 443)
        );
        assert_eq!(
            parse("GET http://[2001:db8::1]/ HTTP/1.1\r\n\r\n"),
            request(Method::Absolute, "2001:db8::1", 80)
        );
    }

    #[test]
    fn an_empty_authority_is_rejected() {
        assert_eq!(parse("CONNECT :443 HTTP/1.1\r\n\r\n"), None);
        assert_eq!(parse("GET http://:80/ HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn the_head_ends_at_the_first_blank_line() {
        let head = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody";
        assert_eq!(head_end(head), Some(head.len() - 4));
    }

    #[test]
    fn a_head_that_has_not_ended_is_not_found() {
        assert_eq!(head_end(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(head_end(b"\r\n\r"), None);
        assert_eq!(head_end(b""), None);
    }

    #[test]
    fn a_terminator_split_across_two_reads_is_still_found() {
        let head = b"GET / HTTP/1.1\r\n\r\n";
        let boundary = head.len() - 2;
        assert_eq!(head_end(&head[..boundary]), None);
        assert_eq!(head_end(head), Some(head.len()));
    }

    #[test]
    fn a_content_length_says_how_much_of_the_rest_is_the_body() {
        assert_eq!(
            parse("POST http://example.com/submit HTTP/1.1\r\nContent-Length: 9\r\n\r\n"),
            carrying(Method::Absolute, "example.com", 80, Body::Sized(9))
        );
        assert_eq!(
            parse("POST http://example.com/submit HTTP/1.1\r\ncontent-length: none\r\n\r\n"),
            carrying(Method::Absolute, "example.com", 80, Body::Sized(0))
        );
    }

    #[test]
    fn a_chunked_body_is_read_until_the_client_stops() {
        assert_eq!(
            parse("POST http://example.com/submit HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"),
            carrying(Method::Absolute, "example.com", 80, Body::Streamed)
        );
    }

    #[test]
    fn only_the_body_of_this_request_is_forwarded_behind_its_head() {
        let rest = b"a=1&b=2GET http://example.com/next HTTP/1.1\r\n\r\n";
        assert_eq!(
            behind_the_head(rest, Method::Absolute, Body::Sized(7)),
            b"a=1&b=2"
        );
        assert_eq!(behind_the_head(rest, Method::Absolute, Body::Sized(0)), b"");
        assert_eq!(
            behind_the_head(rest, Method::Absolute, Body::Streamed),
            rest
        );
        assert_eq!(behind_the_head(rest, Method::Connect, Body::Sized(0)), rest);
    }

    #[test]
    fn a_body_shorter_than_its_content_length_is_forwarded_whole() {
        let rest = b"a=1";
        assert_eq!(
            behind_the_head(rest, Method::Absolute, Body::Sized(64)),
            rest
        );
    }

    #[test]
    fn the_client_is_read_only_as_far_as_this_requests_body_reaches() {
        assert_eq!(
            rest_of_body(Method::Absolute, Body::Sized(7), b"a=1&b=2"),
            Rest::Bytes(0)
        );
        assert_eq!(
            rest_of_body(Method::Absolute, Body::Sized(64), b"a=1"),
            Rest::Bytes(61)
        );
        assert_eq!(
            rest_of_body(Method::Absolute, Body::Streamed, b""),
            Rest::Streamed
        );
        assert_eq!(
            rest_of_body(Method::Connect, Body::Sized(0), b""),
            Rest::Streamed
        );
    }
}
