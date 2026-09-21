//! The forward front end: a local port whose every connection goes to one destination.
//!
//! It parses nothing. The destination is fixed at bind time, and everything past that point -
//! the rule decision, the loop guard, the dial and the log line - is the path the other two front
//! ends take.
use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use nhop_ipc::{Host, Port};
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;

use crate::proxy::{ConnCtx, Connect, DialsItself, Loop, NextHop, Routed, Target, own_address};
use crate::rules::Decision;

/// Serves one connection of a forward front end and closes it.
///
/// A refused or failed dial closes the client without a word: there is no proxy protocol on this
/// connection to carry a reason, so the reason is on the log line alone.
///
/// # Errors
///
/// Returns [`io::Error`] when the dial is refused or fails, or when either side fails while the
/// connection is relayed.
///
/// [`io::Error`]: std::io::Error
pub async fn serve(
    mut client: TcpStream,
    ctx: ConnCtx,
    hop: &dyn NextHop,
    target: &Target,
) -> io::Result<()> {
    let Target { host, port } = target;
    let decision = ctx.rules.decide(host, *port);
    let mut routed = Routed::begun(&ctx, host, *port, decision);
    let served = match own_address(&client, host, *port) {
        Loop::Own(listening) => refuse_loop(listening, &mut routed),
        Loop::Elsewhere => relay(&mut client, host, *port, decision, hop, &mut routed).await,
    };
    routed.ended(served.as_ref().err());
    served
}

fn refuse_loop(listening: SocketAddr, routed: &mut Routed) -> io::Result<()> {
    routed.dialled(Connect::Refused);
    Err(DialsItself::new(listening).into())
}

async fn relay(
    client: &mut TcpStream,
    host: &Host,
    port: Port,
    decision: Decision,
    hop: &dyn NextHop,
    routed: &mut Routed,
) -> io::Result<()> {
    let dialling = Instant::now();
    let dialled = hop.dial(host, port, decision).await;
    let (connect, dialled) = dialled.timed(dialling.elapsed());
    routed.dialled(connect);
    let mut next = dialled?;
    let _relayed = copy_bidirectional(client, &mut next).await?;
    Ok(())
}
