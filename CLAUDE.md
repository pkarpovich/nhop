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
  - `proxy/` - `http.rs`, `socks5.rs` front ends, `mod.rs` (`ConnCtx`, `NextHop`,
    `Dialled`, `Connect`, `Routed`, the decision fan-out)
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
  ruleset and upstream, health, event fan-out) and take one snapshot per
  accepted connection, so a load that commits mid-connection cannot move it.
- **Loads are atomic.** A run gets a `LoadId`, passed to the script as
  `NHOP_LOAD_ID` and carried back by every mutating command; those accumulate in
  `Staging` and go live only on a zero exit. A command with no id or a stale one
  while a run is in flight is refused with `ErrKind::LoadInProgress`.
- **`Command::Subscribe` never reaches the actor** - `ipc_server.rs` intercepts
  it and streams from the fan-out.
- **`cli::Exit` owns the exit-code table**, `of_err`/`of_unreachable`/`of_start`
  are the only ways into it.
- **Only an upstream failure flips the health verdict down.** A SOCKS reply
  about a destination proves the upstream is serving (`upstream/mod.rs`).
- **The prober patrols both verdict states with two-probe hysteresis.** `patrol`
  probes from startup on, Up and Down alike. A probe contradicting the live
  verdict only opens a pending sequence recording the state it aims at and the
  address it was made against; a confirming probe after `PROBE_CONFIRM_DELAY` has
  to agree with that recorded target, against that same address, before the
  verdict moves. An agreeing probe, a verdict change arriving by any other path,
  or a reload pointing the daemon elsewhere discards the sequence. A real dial
  failure still flips Down on one failure - it is evidence a user already paid
  for, a self-generated timeout is not.
- **Every outbound relay socket carries keepalive.** `direct()` and `through()`
  both apply `keep_alive` before handing the stream back, and a failed setsockopt
  warns rather than failing a dial that otherwise succeeded. Probe sockets are
  exempt: they live milliseconds.
- **A front end never dials the address it accepted the connection on.** The
  check reads `client.local_addr()`, which under a wildcard bind is the only
  source naming the interface the client actually reached, so nothing new is
  threaded through `Live`, `ConnCtx` or the wire. It compares the destination
  against `listening.ip()` rather than "any loopback", so a front end on
  `127.0.0.1:7890` refuses itself and leaves a different service on
  `127.0.0.2:7890` alone; `0.0.0.0` and `::` count as that address whatever it
  is, since connecting to one of them lands on a local one. Both sides of the
  comparison go through `canonical`, so an IPv4-mapped listening address is
  loopback for the `localhost` arm too. It sits between the rule decision and the dial - after,
  so the decision that would have applied is still logged; before, so no
  descriptor is spent - answers 502 or SOCKS `0x02` and returns `DialsItself` as
  an error, so the connection's one decision event carries that text and a null
  `connect_ms`. Names are not resolved: short forms like `127.1` are a stated
  gap, not an oversight.
- **A dial reports whether it touched the network; nothing asks afterwards.**
  `NextHop::dial` returns `Dialled` - `Refused` for a `require` rule turned away
  before any socket, `Attempted` for anything that reached the network - because
  both carry the same `UpstreamDown` surface and an instant failure times the
  same as a refusal. The front end folds it with `Dialled::timed(elapsed)` into
  `Connect`, which `Routed::dialled` records as `connect_ms`. Deriving the
  distinction from the error, or from re-reading the health verdict after the
  call, is banned: the first mislabels a two-second failing dial as "nothing
  dialled", the second races the patrol.

## Tests

- every entry point takes `Paths`, so no test touches `$HOME` or any process
  global; use `Paths::from_home(tempdir)`
- integration tests share `nhop/tests/support/mod.rs` (`StubSocks5`,
  `StubOrigin`, `StubHttpOrigin`, `TestDaemon`, `StubHop`, `DownHop`) instead of
  new stubs
- `StubSocks5::requests()` records patrol probes too, since a probe is a CONNECT
  to the stub's own address. Assert what a front end dialled with
  `client_dials()`; `requests()` is for probe assertions
- bind port 0 everywhere - nothing in the suite may touch 7890/7891
- the logging subscriber is scoped with `tracing::subscriber::with_default`,
  since several daemons run in one test process

## Plans

`docs/plans/`, and completed ones move to `docs/plans/completed/`.

## Releasing

`docs/releasing.md`. A release is an annotated `v*` tag on `main`; CI builds,
signs, publishes and rewrites the Homebrew formula. The tag has to agree with
the workspace version, so the bump belongs in the pull request being released.
