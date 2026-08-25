# Refuse to dial itself

## Overview

A client can ask nhop to connect it to nhop. The router obliges: it dials its
own front end, the second connection waits for a request that never comes
because the first is relaying opaque tunnel bytes, and the connection dies a few
seconds later. Clients that retry without backoff turn this into a storm.

Observed in production on four separate days (14, 15, 16 and 18 August),
48-96 thousand such connections per day, arriving in bursts of ~8100 in a single
minute - 135 per second. Each loop costs four descriptors instead of two, and
`Too many open files` reappeared in the log on every one of those days despite
the 16384 limit raised in 0.1.2. On 18 August the storm ran from 16:10 to 16:51.

[RFC 9110 §7.6.3](https://httpwg.org/specs/rfc9110.html#field.via) requires a
proxy that detects a forwarding loop to answer with an error, normally 502. Its
mechanism is the `Via` header, which cannot help here: the storm arrives over
`CONNECT`, where nhop relays raw bytes and sees no headers at all, and SOCKS5 has
no headers to begin with. An address check is how that requirement is met on a
tunnelling front end.

Scope decision: **narrow**. Each front end refuses only the address it is itself
listening on. The cross-port case - arriving on 7890 and asking for 7891 - is
left alone; it never appeared in a week of logs, it produces one useless
connection rather than a carousel, and covering it would mean carrying the listen
addresses into `Live` and `ConnCtx`, which the whole hot path reads per
connection.

## Context (from discovery)

- Neither `Live` (`rules`, `upstream`, `health`, `events`) nor `ConnCtx` carries
  a listen address; they live in the actor (`daemon/state.rs:306`) and in
  `Frontends`. So the check cannot consult them without a new channel - which is
  exactly what the narrow scope avoids needing.
- **The accepted socket already knows the answer**: `client.local_addr()` is the
  address the client connected to, i.e. this front end's own listening address.
  Nothing has to be threaded through. Under a `0.0.0.0` bind it is also the only
  usable source: the listener would report the wildcard, while the accepted socket
  reports the concrete interface the client actually reached - which is the address
  the predicate compares against.
- Both `serve` functions decide first and dial second: `ctx.rules.decide(..)` ->
  `Routed::begun(..)` -> `relay(..)`, and the dial itself is `hop.dial(..)` inside
  `relay` (`proxy/http.rs:183`, `proxy/socks5.rs:105`).
- The refusal path exists on both sides: `respond(client, BAD_GATEWAY, ..)` in
  HTTP (`proxy/http.rs:448`), `answer(client, Reply::Failure)` in SOCKS5.
- `Connect::Refused` is what `Routed::dialled` consumes to leave `connect_ms`
  null (`proxy/mod.rs:239`, `:276`); `Routed::connect` even starts as `None`
  (`:270`). No new wire vocabulary is needed. `Dialled` is a different type - the
  return of `NextHop::dial` - and does not belong at a site that never dials.
- **How the storm spelled its destination**, from the decision log while it was
  still retained: `localhost` 40469 times and `127.0.0.1` 8078 times, on port
  7890. Those two forms are what the guard must catch to close the observed loop.
  The raw logs for 14-18 August have since rotated out (7-day retention), so
  these counts are the record; anything beyond the two forms is reasoning about
  reachability, not measurement.
- **Other spellings reach the same listener.** Verified on this machine against a
  `127.0.0.1:P` listener: `0.0.0.0:P` connects (BSD substitutes a local address
  for the unspecified one), `::ffff:127.0.0.1:P` connects, `127.1:P` connects.
  `Ipv6Addr::is_loopback()` is false for the v4-mapped form (RFC 4291 §2.5.3), and
  `"127.1".parse::<IpAddr>()` errors - Rust requires four octets - yet
  `direct()` dials it through `getaddrinfo`, which expands it to 127.0.0.1.
  `socks5.rs:178` renders an ATYP_IPV6 request as exactly `::ffff:a.b.c.d`.
- Local destinations that legitimately traverse the proxy today, over 48h:
  `localhost:19998` (253 times) and `localhost:8099` (once). Neither is a listen
  address, so neither is affected.
- The rule `never suffix localhost` currently sends `localhost:7890` straight to
  a direct dial, so the check must not be expressed as a rule - a `never` match
  would otherwise bypass it.
- Style contract (CLAUDE.md): no `//` comments, `let..else`, explicit
  destructuring, newtypes over bare types, no `matches!`, no wildcard `_ =>`
  outside `io::ErrorKind`.

## Development Approach

- **testing approach**: Regular (code and tests in the same task, repo convention)
- every task ends with `mise run check` green (fmt + clippy -D warnings + tests)
- no wire change, no new dependency, no new field in the hot-path snapshot
- version bump 0.1.3 -> 0.1.4 rides this PR (the release gate refuses a tag that
  disagrees with the crate version)

## Testing Strategy

- unit tests for the pure predicate, integration tests through both front ends
- a loop refusal must be observable as *no outbound connection at all*, not
  merely as an error the client sees - the stub destination must record zero
  dials
- existing local-destination behaviour must be pinned by a test, so a future
  widening of the predicate cannot silently start refusing `localhost:19998`

## Solution Overview

A front end refuses to dial the address it is listening on, before any socket is
opened. The event it leaves behind has the same *shape* as a `require`-while-down
refusal - one decision, `connect_ms: null` - but not the same wire answer on
SOCKS5; see below.

**The predicate, in two steps for cost.** First compare the destination port with
`client.local_addr().port()` - two integers, on every accepted connection, free.
Only when they match (rare) look at the host.

On a port match the destination is canonicalised before anything is decided: parse
it as an `IpAddr`, and fold an IPv4-mapped IPv6 address back to v4 with
`to_ipv4_mapped()` so `::ffff:127.0.0.1` and `127.0.0.1` are the same address.
Then it is a loop when any of these holds:

- the canonical destination equals `listening.ip()` - the front end's own address,
  whatever it is bound to;
- the destination is unspecified (`0.0.0.0`, `::`), because connecting to it lands
  on a local address, i.e. on us;
- the destination is not an IP literal but the name `localhost` (case-insensitive,
  trailing dot stripped), and `listening.ip()` is loopback.

Comparing against `listening.ip()` rather than "any loopback address" is what makes
the guard mean what the scope sentence says: a front end bound to `192.168.1.5:7890`
refuses `192.168.1.5:7890`, and a front end on `127.0.0.1:7890` does **not** refuse a
different service that happens to sit on `127.0.0.2:7890`.

**Names are not resolved** and that leaves a known gap: short forms like `127.1`,
which only `getaddrinfo` expands, are not caught. Covering them would mean a
resolution per connection on the hot path, which costs more than the case is worth -
the observed storm used `localhost` and `127.0.0.1`, both covered. This is a stated
limit, not an oversight.

**Where it sits.** After the request is parsed and the rule decision is made,
before `hop.dial(..)`. Placing it after the decision keeps the log event honest -
the decision that *would* have applied is still recorded - and placing it before
the dial is what stops the descriptor cost.

**What the client gets.** On HTTP, `502 Bad Gateway` whose body is the refusal
text. On SOCKS5, reply **`0x02`** - RFC 1928 calls it "connection not allowed by
ruleset", which is precisely what this is: a policy refusal, not a network
failure. `0x01` is the file's generic failure and `0x04` means the host is
unreachable, which would be untrue. Both answers go out immediately, with no
outbound socket.

**What the log gets.** An ordinary decision event carrying the refusal in
`error` and `connect_ms: null`. This is not decoration: the loop was invisible
for a week precisely because nothing distinguished it, and the next occurrence
should be answerable from `nhop logs` alone.

## Technical Details

- Contract (bodies born during execution):
  - `fn dials_itself(destination: &Host, port: Port, listening: SocketAddr) -> bool`
    in `nhop/src/proxy/mod.rs`, pure and unit-testable, taking the accepted
    socket's local address so neither front end needs a new parameter.
  - Both `serve` functions read `client.local_addr()` once. A failure to read it
    is not fatal: treat it as "not a loop" and carry on, since refusing traffic
    because a socket call failed would be worse than the loop it guards against.
- `Host` is a newtype over `String`; the predicate matches it case-insensitively
  with the trailing dot stripped, consistent with how `suffix` rules already
  treat host names.
- The refusal records `routed.dialled(Connect::Refused)`. `Connect` is what
  `Routed::dialled` consumes (`proxy/mod.rs:239`); `Dialled` is the return type of
  `NextHop::dial`, which this site never calls, and describing the refusal as
  `Dialled::Refused` would leave that type's doc comment and the CLAUDE.md
  invariant - both of which define it as the `require`-while-down case - stale.
- **The refusal is an error, not an early `Ok`.** `EventView.error` is filled from
  what `Routed::ended` receives, which in HTTP is `served.as_ref().err()`
  (`proxy/http.rs:150`). An early `return respond(..)` yields `Ok(())` and the
  event would carry `error: null`, silently losing the one line this plan exists
  to produce. Both front ends therefore return an `io::Error` after answering the
  client.
- **The refusal text is pinned**, so the log line is assertable rather than
  whatever the executor wrote: a `DialsItself` error beside `UpstreamDown` in
  `proxy/mod.rs`, whose `Display` is
  `nhop: refusing to dial my own listening address 127.0.0.1:7890` (the address
  rendered from `listening`). That one `Display` supplies the HTTP body, the
  reason behind the SOCKS reply and the event's `error`, so Tasks 2, 3 and 4
  cannot drift apart.
- No changes to `Live`, `ConnCtx`, `NextHop` or the wire.

## What Goes Where

- **Implementation Steps**: predicate, both front ends, tests, docs, version bump.
- **Post-Completion**: release mechanics, live verification, retiring the watcher,
  vault note update.

## Progress Tracking

- mark completed items with `[x]` immediately when done
- add newly discovered tasks with ➕, blockers with ⚠️
- update this file if implementation deviates

## Implementation Steps

### Task 1: the loop predicate

**Files:**
- Modify: `nhop/src/proxy/mod.rs`

- [x] add `dials_itself(destination, port, listening)` with a doc comment stating
      why the check exists (RFC 9110 §7.6.3 loop requirement; `Via` unusable on a
      tunnelling front end), and recording the deliberate gap: names are not
      resolved, so short forms like `127.1` are not caught
- [x] port comparison first, host inspection only on a port match
- [x] canonicalise a literal destination: parse to `IpAddr`, fold IPv4-mapped IPv6
      back to v4 with `to_ipv4_mapped()`
- [x] a loop is: canonical destination equals `listening.ip()`; or the destination
      is unspecified (`0.0.0.0`, `::`); or the destination is the name `localhost`
      (case-insensitive, trailing dot stripped) while `listening.ip()` is loopback
- [x] write tests for each arm: `127.0.0.1` and `localhost` against a
      `127.0.0.1:7890` front end are loops; `::ffff:127.0.0.1` is a loop (this is
      the exact string `socks5.rs:178` renders for an ATYP_IPV6 request);
      `0.0.0.0` and `::` are loops
- [x] write tests for the boundaries: `127.0.0.2:7890` against a `127.0.0.1:7890`
      front end is **not** a loop; a non-loopback front end (`192.168.1.5:7890`)
      refuses its own address and not `localhost`; the same host on a different
      port is not a loop; trailing dot and mixed case still match
- [x] write a test pinning the known gap: `127.1` is **not** caught, so the limit
      is visible in the suite rather than only in prose
- [x] run `mise run check` - must pass before task 2

### Task 2: refuse on the HTTP front end

**Files:**
- Modify: `nhop/src/proxy/http.rs`
- Modify: `nhop/tests/http_proxy.rs`

- [x] read `client.local_addr()` in `serve`, treating a read failure as "not a
      loop"
- [x] add the `DialsItself` error beside `UpstreamDown` in `proxy/mod.rs`, its
      `Display` rendering `nhop: refusing to dial my own listening address <addr>`
- [x] between the rule decision and `relay(..)`, refuse a loop: answer
      `502 Bad Gateway` with that text as the body, record
      `routed.dialled(Connect::Refused)`, and **return the error** from `serve` so
      `Routed::ended` fills the event's `error` rather than leaving it null
- [x] write a test: `CONNECT` to the front end's own address answers 502 **and
      the stub destination records no dial at all**
- [x] write a test: an absolute-form request aimed at the front end's own address
      is refused the same way
- [x] write a test: `localhost:19998` still reaches its destination, pinning the
      behaviour of ordinary local services
- [x] run `mise run check` - must pass before task 3

### Task 3: refuse on the SOCKS5 front end

**Files:**
- Modify: `nhop/src/proxy/socks5.rs`
- Modify: `nhop/tests/socks5_proxy.rs`

- [ ] same read of `client.local_addr()`, same placement between decision and
      `relay(..)`
- [ ] refuse with reply `0x02` (RFC 1928 "connection not allowed by ruleset"),
      record `routed.dialled(Connect::Refused)` and return the same `DialsItself`
      error, so the event's `error` matches the HTTP side character for character
- [ ] add `Reply::NotAllowed` (`0x02`) to the reply enum if it is not there yet -
      `socks5.rs:52` currently defines Granted/Failure/HostUnreachable/
      CommandNotSupported/AddressNotSupported
- [ ] write a test: a SOCKS request for the front end's own address answers
      `0x01` and dials nothing
- [ ] write a test: the same address by name (`localhost`) is refused identically
- [ ] run `mise run check` - must pass before task 4

### Task 4: the refusal is visible as an event

**Files:**
- Modify: `nhop/tests/http_proxy.rs`

- [ ] assert through the **event fan-out**, not the log file: the
      `watched()` / `next_decision()` idiom already used in `http_proxy.rs` and
      `socks5_proxy.rs`, which needs no tracing subscriber
- [ ] do **not** touch `nhop/tests/decision_log.rs`: it is a single-test binary
      whose test installs a process-global subscriber
      (`tracing::subscriber::set_global_default(..).unwrap()`, `decision_log.rs:82`)
      and reads events back out of its own tempdir. A second test in that binary
      either panics on the second `set_global_default`, or logs into the other
      test's tempdir, or races it through a shared `Paths`
- [ ] write a test: a refused loop produces exactly one decision event whose
      `error` is the pinned `DialsItself` text and whose `connect_ms` is null
- [ ] run `mise run check` - must pass before task 5

### Task 5: version bump and documentation

**Files:**
- Modify: `Cargo.toml` (+ `Cargo.lock` via cargo)
- Modify: `README.md`, `CLAUDE.md`

- [ ] bump the workspace version 0.1.3 -> 0.1.4
- [ ] README: a short paragraph under the front-end description - the router
      refuses to dial its own listening address, what the client sees (502 and
      SOCKS `0x02`), and the two deliberate limits: the cross-port case is not
      covered, and names are not resolved so short forms like `127.1` slip through
- [ ] CLAUDE.md: add the invariant that a front end never dials the address it
      accepted the connection on, that the check reads `client.local_addr()`
      rather than any shared state, and that it compares against `listening.ip()`
      rather than "any loopback"
- [ ] verify the existing `Dialled::Refused` doc comment (`proxy/mod.rs:332`) and
      its CLAUDE.md invariant still read true - this plan deliberately uses
      `Connect::Refused` so neither needs changing; if either was touched, put it
      back
- [ ] run `mise run check` - must pass before task 6

### Task 6: verify acceptance criteria

- [ ] a loop is refused on both front ends, by literal and by name
- [ ] no outbound socket is opened for a refused loop
- [ ] ordinary local destinations are untouched
- [ ] full gate: `mise run check`

### Task 7: [Final] close out the plan

- [ ] re-read the README/CLAUDE.md deltas against the final code
- [ ] move this plan to `docs/plans/completed/`

## Post-Completion

**Release** (docs/releasing.md): PR -> CI green -> squash-merge -> annotated tag
`v0.1.4` -> the workflow builds, signs, publishes and rewrites the tap formula ->
replace the generated notes with written ones -> `brew upgrade nhop && brew
services restart nhop`.

**Live verification on this machine:**
- ask the running daemon to dial itself and confirm the refusal:
  `curl -sS -o /dev/null -w '%{http_code}\n' -x http://127.0.0.1:7890 http://127.0.0.1:7890/`
  answers 502, and `nhop logs --since 1m --json` shows the event with a null
  `connect_ms`
- `localhost:19998` keeps working
- the loop watcher in tmux session `nhop-loopwatch` can be retired
  (`tmux kill-session -t nhop-loopwatch`), and
  `~/.local/state/nhop/loop-watch/` removed, once a storm-free day has passed on
  0.1.4 - though the storm's own client has been quiet since 18 August, so
  absence of storms is no longer evidence by itself

**Vault note** (`nhop proxy router.md`): add the loop to "Грабли" with the dates
and counts, and refresh the version reference to 0.1.4.
