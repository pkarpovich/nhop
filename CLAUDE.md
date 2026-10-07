# nhop

Rule-based local proxy router for macOS. See README.md for what it does and how
it is installed; this file is what a change to the code has to respect.

## Layout

- `nhop-ipc/` - the wire contract, and the only place it is spelled: `Command`,
  `Response`, the `*View` structs, `Paths`, `LoadId`, `RuleClass`, `RuleKind`,
  `Host`, `Port`. `#![warn(missing_docs)]`. Daemon and client both depend on it,
  so neither can drift.
- `nhop/` - lib plus bin. The lib target exists so the routing types are not
  dead code under `clippy -D warnings`.
  - `daemon/` - `state.rs` (the actor), `staging.rs` (a load in flight),
    `init_script.rs`, `ipc_server.rs`, `mod.rs` (start, listeners, pid lock)
  - `proxy/` - `http.rs`, `socks5.rs`, `forward.rs` front ends, `mod.rs`
    (`ConnCtx`, `NextHop`, `Dialled`, `Connect`, `Routed`, `Forwards`, the
    decision fan-out)
  - `rules/`, `upstream/`, `cli/`, `logging.rs`

## Commands

`mise run check` is the gate: `cargo fmt --all -- --check`, `cargo clippy
--all-targets -- -D warnings`, `cargo test`. Rust 1.97, edition 2024.

## Style

The whole tree obeys these; a change that breaks one reads as foreign.

- no `//` comments: `///` on public items, `//!` for module docs. The only
  exceptions are the protocol byte layouts in `proxy/socks5.rs` and
  `proxy/http.rs`
- no `matches!`, and no wildcard `_ =>` except on `std::io::ErrorKind` - adding
  a variant must break the build
- always destructure explicitly (`let Listen { http, socks } = listen;`), never
  reach through a value field by field
- `let ... else` for early returns, `for` loops over iterator chains
- newtypes over bare `String`, enums over `bool` parameters (`Output`, `Follow`,
  `BindState`, `Privilege`, `Delivery`, `Dialled`, `Connect`)

## Invariants

- **One actor owns mutable state.** `daemon/state.rs` serves every command over
  `mpsc<(Command, oneshot<Response>)>`. Nothing blocking belongs on that task -
  the system-proxy read goes through `spawn_blocking`, and a load runs as its
  own task so the script's own CLI calls can be served while it runs.
- **The hot path never touches the actor.** Front ends read `Live` (`ArcSwap`
  ruleset and upstream list, event fan-out). `ConnCtx` snapshots the ruleset
  once per accepted connection, and the upstream list - each entry with its own
  verdict - is read where it is used: once when the hop dials
  (`UpstreamHop::routed`) and once for `EventView.upstream` through
  `NextHop::verdict()` at `Routed::begun`. A load that commits mid-connection
  cannot move it.
- **Loads are atomic.** A run gets a `LoadId`, passed to the script as
  `NHOP_LOAD_ID` and carried back by every mutating command; those accumulate in
  `Staging` and go live only on a zero exit. A command with no id or a stale one
  while a run is in flight is refused with `ErrKind::LoadInProgress`. A line
  the daemon cannot parse never reaches the actor, so it fails no run: a
  command an older daemon may not know (`set_upstreams`) is followed, when
  refused within a load, by `Command::unreadable_upstream`, which every daemon
  parses and refuses inside the run.
- **`Command::Subscribe` never reaches the actor** - `ipc_server.rs` intercepts
  it and streams from the fan-out.
- **`cli::Exit` owns the exit-code table**, `of_err`/`of_unreachable`/`of_start`
  are the only ways into it.
- **Only an upstream failure flips the health verdict down, and the same dial
  flips it up.** A SOCKS reply about a destination proves the upstream is
  serving, so a connection through it and a `Destination` failure both write
  `Up` at once, with no hysteresis - the symmetric half of one failure writing
  `Down`. Every write from a real dial goes through `observed`, onto the
  `HealthHandle` of the `UpstreamEntry` that dial took from its snapshot; a
  reload keeps an entry's handle only while it keeps the address, so a dial
  landing after a reload cannot move the verdict of an address that replaced it
  (`upstream/mod.rs`, `upstream/entries.rs`). `failed_dial`
  splits three ways, not two: `DialFailure::Unsent` is a failure tokio-socks
  raised before it opened a socket - `InvalidTargetAddress`, which a client
  reaches with a host past the 255-byte SOCKS5 domain limit - and it writes no
  verdict at all, since reading it as a reply would let one request declare a
  dead upstream alive.
- **`require` is gated only by the absence of an upstream.** `required()`
  refuses before the network, against `NO_UPSTREAM`, only when the published
  list is empty, and otherwise dials the selected entry - the first while none
  is selected (`UpstreamEntries::required`) - whatever its verdict says, at
  `REQUIRE_CONNECT_TIMEOUT` rather than `PREFER_CONNECT_TIMEOUT`. The verdict
  gate that used to sit there was removed because a refusal only saves a dial
  timeout when the upstream is dead, and an upstream that was merely slow had
  every `require` destination refused for hours it could have served. `prefer`
  keeps its gate: fast fallback to the direct route is its purpose.
- **Each upstream has its own verdict, kept across reloads by address.**
  `UpstreamEntries` is the published list in operator order, each
  `UpstreamEntry` pairing an `Upstream` with its own `HealthHandle`.
  `UpstreamEntries::adopted` reuses the handle of every address the previous
  list held and gives a new address a fresh one (`Down`), so a reload neither
  drops the verdicts it keeps nor lets a stale dial reach an address removed
  and added back. A one-entry list behaves byte-for-byte as the single upstream
  did.
- **Selection is a pure function of the list, the verdicts and the time.**
  `select(&[Health], now, hold)` (`upstream/select.rs`) picks the first entry
  `Up` for at least the hold, else the `Up` entry up longest with ties to list
  order, else none; there is no selection state to keep consistent. `Selection`
  remembers the last answer only to log a switch, once, with its
  `SwitchCause` - every dial and every patrol round calls `observe`, since a
  hold expiring is a switch no verdict write announces - and routing always
  recomputes. Each published `UpstreamEntries` carries its publication count,
  and an observation made from a list a reload has since replaced records
  nothing, so a dial that read its snapshot just before the reload cannot log a
  switch back to the old list. The patrol stamps every verdict of one round with the round's
  start (`HealthHandle::set_at`), so entries confirmed together tie and the
  primary wins at cold start. Switches, like turnovers, are log records only
  (`Logged::Switch`, parsed after the decision and verdict shapes) and never
  reach `EventView` or `Command::Subscribe`.
- **A switch never touches an accepted connection.** A connection selects once,
  when it dials at accept time, and keeps that entry until it ends; nothing
  closes, re-dials or migrates it, and a failed dial is not retried on the next
  entry, since that would stack budgets.
- **The prober patrols both verdict states with two-probe hysteresis.** `patrol`
  probes every entry of the current list each round, from startup on, Up and
  Down alike, concurrently (`round` folds each probe in as it returns, so a
  black-holed entry cannot delay another's confirmation). A probe contradicting
  an entry's live verdict only opens a pending sequence recording the state it
  aims at, banked against that entry's `HealthHandle`; a confirming probe after
  `PROBE_CONFIRM_DELAY` has to agree with that recorded target, on that same
  handle (`HealthHandle::same`), before the verdict moves. An agreeing probe, a
  verdict change arriving by any other path, or a reload that drops the address
  discards the sequence - an address removed and added back can never close one.
  A round ends by observing the selection on the list published at that moment,
  not the one it probed. A real dial failure still flips Down on one failure -
  it is evidence a user already paid for, a self-generated timeout is not.
- **A verdict turnover is a log record, not an event.** `HealthHandle::set_at`
  writes it - the one place the settled verdict and the observation are both in
  hand - as `upstream` (the written address the handle judges; every handle
  judges one, made by `HealthHandle::judging`), `verdict_from`, `verdict_to` and `cause` (`probe` or
  `dial`); `seed` establishes a starting verdict and logs nothing. It never
  reaches `EventView`, `Command::Subscribe` or `nhop tail`. `logging::logged`
  returns `Logged::{Decision, Verdict, Switch}` and tries `EventView` first,
  because a verdict line fails a decision's required fields while the reverse
  is not true - a further record kind goes after those attempts, never before
  them.
- **Every outbound relay socket carries keepalive.** `direct()` and `through()`
  both apply `keep_alive` before handing the stream back, and a failed setsockopt
  warns rather than failing a dial that otherwise succeeded. Probe sockets are
  exempt: they live milliseconds.
- **A front end never dials the address it accepted the connection on.** The
  check reads `client.local_addr()` - under a wildcard bind the only source
  naming the interface the client reached - so nothing new is threaded through
  `Live`, `ConnCtx` or the wire. It compares against `listening.ip()` rather than
  "any loopback", so `127.0.0.2:7890` stays reachable from a front end on
  `127.0.0.1:7890`. It sits between the rule decision and the dial: after, so the
  decision that would have applied is still logged; before, so no descriptor is
  spent. Names are not resolved, leaving short forms like `127.1` a stated gap.
- **A forward is a front end whose destination is a constant.** `forward::serve`
  starts where the other two finish parsing - `decide`, `Routed::begun`, the
  loop guard, `hop.dial`, `copy_bidirectional`, `Routed::ended` - and adds no
  path of its own; a refused or failed dial closes the client, since no proxy
  protocol is on the wire to answer with. Forwards are keyed by listening
  address (`Forwards::push` refuses a duplicate) and travel with a load like
  rules: `Staging` collects them, `commit` applies the whole set after the
  listen rebind, and `Bound::rebind_forwards` binds every new address before
  closing any old one. A held address that stays declared is not re-bound - its
  accept task reads the destination from an `ArcSwap` and the reload stores a
  new one - because `JoinHandle::abort` releases the old socket only when the
  runtime next polls the task, after a synchronous re-bind would have failed.
- **A dial reports whether it touched the network; nothing asks afterwards.**
  `NextHop::dial` returns `Dialled` - `Refused` for a `require` rule turned away
  before any socket, `Attempted` for anything that reached the network - because
  both carry the same `UpstreamDown` surface and an instant failure times the
  same as a refusal. `Attempted` also carries the `EffectiveHop` the dial site
  produced - `Direct`, `Upstream` or `FallbackDirect` - so the path the bytes
  actually took travels with the dial instead of being re-derived from the
  decision, which cannot see a `prefer` rule that fell back. It carries `via`
  the same way: the written address of the entry the dial went through,
  present only on `Upstream`, never re-derived from selection afterwards,
  which a patrol round may have moved in between. The front end folds both with
  `Dialled::timed(elapsed)` into `Connect`, which `Routed::dialled` records as
  `connect_ms`, `hop` and `via`. Deriving the distinction from the error, or
  from re-reading the health verdict after the call, is banned: the first
  mislabels a two-second failing dial as "nothing dialled", the second races the
  patrol.

## Tests

- every entry point takes `Paths`, so no test touches `$HOME` or any process
  global; use `Paths::from_home(tempdir)`
- integration tests share `nhop/tests/support/mod.rs` (`StubSocks5`,
  `StubOrigin`, `StubHttpOrigin`, `TestDaemon`, `StubHop`, `DownHop`,
  `ScopedLog`) instead of new stubs
- `StubSocks5::requests()` records patrol probes too, since a probe is a CONNECT
  to the stub's own address. Assert what a front end dialled with
  `client_dials()`; `requests()` is for probe assertions
- bind port 0 everywhere - nothing in the suite may touch 7890/7891
- the logging subscriber is scoped with `tracing::subscriber::with_default`,
  since several daemons run in one test process. A test that reads a log while
  other tests run daemons holds `support::ScopedLog::install(&paths)` (or, in a
  unit test, keeps a `NoSubscriber` `Dispatch` alive beside its subscriber):
  tracing caches callsite interest process-wide, and with one dispatcher
  registered a parallel test can silence a callsite for good
- failover and return tests start the daemon with
  `TestDaemon::paced(&paths, &[p, f], Pace { .. })` (short interval, confirm
  delay and hold) and stay on the wall clock, since the hold is measured against
  `SystemTime`; wait for "after the hold" by polling with a deadline, never a
  fixed sleep. `daemon.verdict(addr).seed(..)` arranges one entry's verdict, and
  `StubSocks5::stop()` / `restart()` model an upstream turned off and on at the
  same address
- `HealthHandle::seed` arranges a starting verdict, `set` is the observation
  under test - seeding through `set` writes a turnover line the test did not
  mean to make
- a test that measures a dial budget uses `#[tokio::test(start_paused = true)]`
  (tokio `test-util`, a dev-dependency) and asserts on `tokio::time::Instant`;
  a test that also needs real sockets to answer stays on the wall clock, since
  the paused clock races real I/O readiness

## Plans

`docs/plans/`, and completed ones move to `docs/plans/completed/`.

## Releasing

`docs/releasing.md`. A release is an annotated `v*` tag on `main`; CI builds,
signs, publishes and rewrites the Homebrew formula. The tag has to agree with
the workspace version, so the bump belongs in the pull request being released.
