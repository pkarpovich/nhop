use std::io;
use std::net::SocketAddr;
use std::str;
use std::time::Instant;

use nhop_ipc::{Host, Port};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy, copy_bidirectional};
use tokio::net::TcpStream;

use crate::proxy::{
    ConnCtx, Connect, DialsItself, Loop, NextHop, Routed, UpstreamDown, own_address,
};
use crate::rules::Decision;

/// Largest request head the front end reads, in bytes.
pub const HEAD_LIMIT: usize = 8192;

const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
const BAD_REQUEST: &str = "400 Bad Request";
const BAD_GATEWAY: &str = "502 Bad Gateway";
const DEFAULT_PORT: Port = Port(80);

/// Fields that belong to one hop and must not reach the origin (RFC 9110 7.6.1).
///
/// `Transfer-Encoding` is deliberately absent: the body is forwarded with its framing intact, so
/// the origin needs the header that describes it.
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
];

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
    /// A `Content-Length` body; anything past it is a later request.
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
    /// After this many bytes the client has nothing more to say about this request.
    Bytes(usize),
    /// Only the client can end it.
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
/// Exactly one request is routed per connection, so whatever the client sends afterwards - behind
/// the body it pipelined, or on the connection it meant to keep alive - can never inherit this
/// one's next hop.
///
/// # Errors
///
/// Returns [`io::Error`] when the client or the next hop fails while the request is served.
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
    let rebuilt = match method {
        Method::Connect => Vec::new(),
        Method::Absolute => {
            let Some(rebuilt) = rewritten(head, &host, port) else {
                return respond(&mut client, BAD_REQUEST, "nhop: malformed request").await;
            };
            rebuilt
        }
    };
    let forward = Forward {
        method,
        head: &rebuilt,
        behind,
        rest: rest_of_body(method, body, behind),
    };
    let decision = ctx.rules.decide(&host, port);
    let mut routed = Routed::begun(&ctx, &host, port, decision);
    let served = match own_address(&client, &host, port) {
        Loop::Own(listening) => refuse_loop(&mut client, listening, &mut routed).await,
        Loop::Elsewhere => {
            relay(
                &mut client,
                forward,
                &host,
                port,
                decision,
                hop,
                &mut routed,
            )
            .await
        }
    };
    routed.ended(served.as_ref().err());
    served
}

/// Answers a loop with 502 and fails the connection, without opening any outbound socket.
///
/// The failure is returned rather than swallowed so [`Routed::ended`] fills the event's error with
/// the refusal, which is the one line that makes a loop answerable from `nhop logs`.
async fn refuse_loop(
    client: &mut TcpStream,
    listening: SocketAddr,
    routed: &mut Routed,
) -> io::Result<()> {
    routed.dialled(Connect::Refused);
    let refusal = DialsItself::new(listening);
    respond(client, BAD_GATEWAY, &refusal.to_string()).await?;
    Err(refusal.into())
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
    routed: &mut Routed,
) -> io::Result<()> {
    let Forward {
        method,
        head,
        behind,
        rest,
    } = forward;
    let dialling = Instant::now();
    let dialled = hop.dial(host, port, decision).await;
    let (connect, dialled) = dialled.timed(dialling.elapsed());
    routed.dialled(connect);
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
/// The client is read only as far as this request's body reaches. The answer ends when the origin
/// closes, which the `Connection: close` added by [`rewritten`] asks it to do; half-closing the
/// write side instead would be legal but leaves some origins silent. The two directions run
/// together, so an origin that answers before the body has arrived cannot wedge the upload.
///
/// A chunked upload is the one request whose end the front end cannot see, so it holds the
/// connection until the client half-closes it.
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
        next_write.flush().await
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

/// Rebuilds an absolute-form request as the origin must receive it.
///
/// The target becomes origin-form and `Host` is regenerated from it, which RFC 9112 3.2.1 requires
/// of a proxy and which forwarding the head unchanged would violate. Hop-by-hop fields are dropped
/// and `Connection: close` is added, so the origin ends the response by closing: half-closing the
/// write side instead is legal but silently unanswered by some origins, Apple's timestamp service
/// among them.
fn rewritten(head: &[u8], host: &Host, port: Port) -> Option<Vec<u8>> {
    let Ok(head) = str::from_utf8(head) else {
        return None;
    };
    let (line, headers) = head.split_once("\r\n")?;
    let mut fields = line.split(' ');
    let method = fields.next()?;
    let target = fields.next()?;
    let Host(name) = host;
    let Port(number) = port;
    let mut out = String::with_capacity(head.len() + 32);
    out.push_str(method);
    out.push(' ');
    out.push_str(origin_form(target));
    out.push_str(" HTTP/1.1\r\nHost: ");
    out.push_str(name);
    if number != 80 {
        out.push(':');
        out.push_str(&number.to_string());
    }
    out.push_str("\r\n");
    for field in headers.split("\r\n") {
        let Some((label, _value)) = field.split_once(':') else {
            continue;
        };
        let label = label.trim().to_ascii_lowercase();
        if label == "host" || HOP_BY_HOP.contains(&label.as_str()) {
            continue;
        }
        out.push_str(field);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    Some(out.into_bytes())
}

fn origin_form(target: &str) -> &str {
    let Some(rest) = target.strip_prefix("http://") else {
        return target;
    };
    let Some(slash) = rest.find('/') else {
        return "/";
    };
    &rest[slash..]
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

    fn rebuilt(head: &str, host: &str, port: u16) -> String {
        let out = rewritten(head.as_bytes(), &Host(host.to_owned()), Port(port)).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn the_target_becomes_origin_form() {
        let head = "GET http://example.com/a/b?c=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(rebuilt(head, "example.com", 80).starts_with("GET /a/b?c=1 HTTP/1.1\r\n"));

        let bare = "GET http://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(rebuilt(bare, "example.com", 80).starts_with("GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn the_host_is_regenerated_from_the_target_not_forwarded() {
        let head = "GET http://example.com/x HTTP/1.1\r\nHost: stale.example\r\n\r\n";
        let out = rebuilt(head, "example.com", 80);

        assert!(out.contains("Host: example.com\r\n"), "{out}");
        assert!(!out.contains("stale.example"), "{out}");
    }

    #[test]
    fn a_port_other_than_eighty_is_named_in_the_host() {
        let head = "GET http://example.com:8080/x HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";

        assert!(rebuilt(head, "example.com", 8080).contains("Host: example.com:8080\r\n"));
    }

    #[test]
    fn hop_by_hop_fields_do_not_reach_the_origin() {
        let head = "GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\n\
                    Proxy-Connection: Keep-Alive\r\nKeep-Alive: timeout=5\r\n\
                    Proxy-Authorization: Basic zzz\r\nTE: trailers\r\nUpgrade: h2c\r\n\
                    Accept: */*\r\n\r\n";
        let out = rebuilt(head, "example.com", 80).to_ascii_lowercase();

        for dropped in [
            "proxy-connection",
            "keep-alive",
            "proxy-authorization",
            "te:",
            "upgrade",
        ] {
            assert!(!out.contains(dropped), "{dropped} survived: {out}");
        }
        assert!(out.contains("accept: */*"), "{out}");
    }

    #[test]
    fn the_body_framing_header_survives() {
        let head = "POST http://example.com/x HTTP/1.1\r\nHost: example.com\r\n\
                    Transfer-Encoding: chunked\r\n\r\n";

        assert!(rebuilt(head, "example.com", 80).contains("Transfer-Encoding: chunked\r\n"));
    }

    #[test]
    fn the_origin_is_asked_to_close_so_the_answer_ends_without_a_half_close() {
        let head = "GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let out = rebuilt(head, "example.com", 80);

        assert!(out.contains("Connection: close\r\n"), "{out}");
        assert!(out.ends_with("\r\n\r\n"), "{out}");
    }
}
