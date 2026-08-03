# nhop - rule-based local proxy router for macOS

## Overview

`nhop` decides, per outbound connection, what the next hop is: a SOCKS5 proxy running inside a
local VM, or the destination itself. It replaces ClashX, which burns ~60% of a CPU core on the
target machine.

The root cause of that burn was established with a stack profile and is **not** proxying:
ClashX's main thread spends ~46% of its samples in `NSStatusItem::_updateReplicantsUnlessMenuIsTracking`
-> `_redrawReplicantSnapshot` -> `_cacheDisplayInRect:toBitmapImageRep:`, i.e. macOS 26 re-snapshots
the menu bar status item into a bitmap on a repeating timer. Disabling the app's own speed
indicator did not help, and a menu bar manager was ruled out as the trigger. A tool with no GUI and
no status item cannot reproduce this failure class - that is the core reason for building rather
than migrating to another client.

Benefits: no menu bar presence, a single signed binary, and a rule set that is a readable shell
script instead of an opaque YAML dialect.

### Non-goals (v1)

- **No GUI, no menu bar item, no tray icon.** This is the whole point.
- **No DNS server, no fake-ip, no hosts table.** Verified unnecessary on the target machine: the
  system resolver is a LAN DNS server plus a public one and never pointed at ClashX, and the
  hostnames that must resolve to a machine on the local network already do so through `/etc/hosts`.
  Direct connections resolve through the OS; proxied ones send the hostname to the upstream.
- **No UDP.** No SOCKS5 `UDP ASSOCIATE`, no QUIC interception. TCP only.
- **No TUN/transparent interception.** Only apps that use the system proxy or point at our ports
  are covered - exactly the coverage the previous setup had.
- **No subscriptions, node lists, latency probing, or load balancing.** One upstream.
- **No profiles as a daemon concept.** The init file *is* the profile.
- **No log shipping to a remote collector.**
- **No daemon-managed system proxy.** Set once by hand, see Task 13.
- **No port ranges in rules.** `port` is exact equality (v1).
- **No HTTP keep-alive proxying.** One absolute-form request per client connection, then close.
- **No real hostnames, CIDRs or upstream addresses in this repo.** The operator's rule set lives in
  their own init file outside version control; everything here uses placeholders.

### Rejected alternatives

- **Switch to another Clash client.** Rejected: the failure is a macOS 26 status-item rendering
  path, so any client with a menu bar item can reproduce it; and a general-purpose client carries
  subscription/node/TUN machinery that this use case never touches.
- **PAC file, no daemon at all.** Rejected: `file://` PAC URLs no longer work on current macOS
  (sandboxed), so the PAC must be served over HTTP - which reintroduces a daemon.
- **Supervision by an existing user-level process supervisor.** Rejected: routing for the whole
  machine must not sit a tier below a script supervisor, and TCC attribution of the Local Network
  permission under a supervisor is unverified.
- **Daemon edits the system proxy itself via a sudoers NOPASSWD rule.** Rejected: `networksetup` is
  a broad privilege, and it recreates the "daemon is up but the system is not pointing at it" drift.
- **Named profiles inside the daemon.** Rejected as an abstraction for a single case: one init file
  per rule set is equivalent and needs no daemon-side concept.

## Skills to invoke

`Code-Quality Rules` below is the source of truth for style in this plan; do not enforce beyond it.
If the following skills are available, load them - they are where these rules come from. If they
cannot be loaded, this plan is authoritative and no task is blocked.

- `rust-style` - conventions for all code under `nhop/src/` and `nhop-ipc/src/`; its rules are
  materialized below and checked per task
- `rustdoc` - doc-comment conventions; the concrete bar required by this plan is stated below

Working note, **not a review criterion**: prefer rust-analyzer LSP over grep when renaming or
tracing call sites.

## Context (from discovery)

- Repository: this repo. Before Task 1 it holds only `.mise.toml`, `.gitignore`, `README.md` and
  this plan. There is no source yet; every task builds from scratch.
- Toolchain: `.mise.toml` pins Rust and defines `build`, `test`, `lint`, `fmt`, `check` tasks.
  `mise run check` = `cargo fmt --check` + `cargo clippy -D warnings` + `cargo test`.
- A `Developer ID Application` signing identity is present in the login keychain and valid;
  `security find-identity -v -p codesigning` lists it. Its team id is an input to the build script,
  never a literal in the repo.

### Environment facts that shape the design

- **An API client on the target machine is pinned to `127.0.0.1:7891` SOCKS5 manually** and ignores
  the macOS system proxy. Therefore nhop must listen on **7890 (HTTP) and 7891 (SOCKS5)**, and must
  **keep listening even when no rules are loaded** - stopping the daemon gives that client
  `connection refused` instead of a direct connection.
- macOS **Local Network privacy** denies local-subnet access to binaries that are not properly
  signed, and reports it as `EHOSTUNREACH` ("No route to host"), not as a permission error. Proven
  on the target machine: an Apple-signed interpreter reached the upstream's port while an
  ad-hoc-signed one got `No route to host` for the same host:port. The daemon must be signed, and
  the permission must be verified under launchd, not only from a terminal.
- The operator powers the upstream VM **off on weekends**, so "upstream unreachable" is a routine
  state, not an incident. It must be detected fast and must not stall connections.
- System proxy is applied to the **Wi-Fi** service only.

## Development Approach

- **testing approach**: Regular - implementation first, then tests, inside the same task.
- complete each task fully before moving to the next
- make small, focused changes
- **CRITICAL: every task MUST include new/updated tests** for code changes in that task, covering
  both success and error scenarios
- **CRITICAL: all tests must pass before starting the next task** - no exceptions
- **CRITICAL: update this plan file when scope changes during implementation**
- run `mise run check` after each task

## Code-Quality Rules (verify before marking each task complete)

### Rust

- **Use `for` loops with mutable accumulators, not iterator chains.** `.collect()` is allowed only
  where a collection is the direct return value of the expression.
- **Use `let ... else` for early returns** so the happy path stays unindented.
- **Minimize `if let`**; prefer `let ... else` or a full `match`.
- **Shadow, don't rename.** No `foo_str` / `foo_parsed` ladders.
- **Do not write `//` comments.** Express intent through names.
- **Prefer newtypes over bare `String`** for domain values.
- **Prefer strongly-typed enums over `bool`** parameters and fields.
- **Never use wildcard `_ =>` matches** except on `#[non_exhaustive]` upstream enums and
  `std::io::ErrorKind`.
- **Never use the `matches!` macro.**
- **Always destructure explicitly.**
- **rustdoc bar**: `nhop-ipc` carries `#![warn(missing_docs)]`; every public item has a `///`
  summary line, and `Command`/`Response` have one line per variant naming its wire `cmd` string.
  `nhop` (the binary crate) has no rustdoc requirement.

### Per-task gate

Before marking any task `[x]`, all four must hold:

- `mise run check` is green
- `rg -n 'matches!\(' nhop/src nhop-ipc/src` returns **zero** lines
- `rg -n '_ =>' nhop/src nhop-ipc/src` returns only lines inside matches on `std::io::ErrorKind` or
  a `#[non_exhaustive]` upstream type
- `rg -n '^\s*//' nhop/src nhop-ipc/src` matches only inside `nhop/src/proxy/socks5.rs` and
  `nhop/src/proxy/http.rs` (protocol byte layouts); `///` doc comments are exempt

## Testing Strategy

- **unit tests**: required in every task.
- **integration tests** use the shared harness created in Task 6 (`nhop/tests/support/mod.rs`) -
  a stub SOCKS5 upstream that records what it was asked to connect to, a stub origin server, and a
  daemon on ephemeral ports. Tasks 7, 8 and 15 reuse it and must not define their own stubs.
  Upstream-down behaviour is tested by pointing the upstream at a closed port.
- **no environment mutation in tests**: every entry point takes `Paths` (Task 1); no test sets
  `$HOME` or any other process-global variable.
- **no e2e/UI tests**: no UI exists.
- Anything needing the real VM, a browser, System Settings or a password is an operator task under
  Post-Completion and is **not** a review criterion.

## Progress Tracking

- mark completed items with `[x]` immediately when done
- add newly discovered tasks with the ➕ prefix
- document issues/blockers with the ⚠️ prefix

## Solution Overview

**One binary, two roles.** `nhop start` runs the daemon; every other subcommand is a thin client
that connects to a unix socket, sends one command, prints the response, and exits. Command and
response types live in a separate `nhop-ipc` crate so daemon and client cannot drift.

**Config is an executable script.** The daemon runs `$HOME/.config/nhop/init` as a program (its
shebang decides the interpreter), with the working directory set to the config directory and the
directory of the running executable prepended to `PATH`. The script calls back into the CLI, which
feeds commands to the daemon. Those two mechanics are the whole of the model and are fully
specified in Task 5; no external reference is needed.

**Loads are atomic.** Commands issued by an init run accumulate in a staging ruleset; the daemon
swaps it in only when the script exits successfully. A syntax error or a failed command leaves the
previous ruleset serving traffic. A half-applied rule set on a router means traffic silently taking
the wrong path, which is why this differs from an incremental model.

**Two rule classes.** `require` rules must traverse the upstream; if it is down, the connection
fails fast with the `UpstreamDown` surface defined in Technical Details. `prefer` rules try the
upstream and fall back to a direct connection when it is down. The intended split, which the
operator expresses in their own init file and which this repo never hardcodes: resources that only
exist behind the upstream are `require`; public services routed through the upstream merely for
traffic volume are `prefer`. The consequence is that no weekend toggling is needed - with the
upstream off, bulk traffic self-heals to direct and internal traffic fails honestly.

**Upstream health is explicit state** with fixed constants (Technical Details), so a down upstream
produces an immediate decision rather than a per-connection TCP timeout.

**The daemon never touches the system proxy.** It is set once with `sudo nhop proxy on`.

## Technical Details

### Layout

```
nhop-ipc/     Command, Response, view structs, Paths
nhop/         daemon + CLI (single binary)
```

### Dependencies to add

`tokio` (rt-multi-thread, macros, net, io-util, signal, time, sync), `tokio-socks`, `arc-swap`,
`serde` (derive), `serde_json`, `argh`, `ipnet`, `anyhow`, `thiserror`, `tracing`,
`tracing-subscriber` (json, env-filter), `tracing-appender`, `humantime`, `fs2`, `dirs`.
Dev: `tempfile`. No TOML/YAML parser: the config is a script.

### IPC contract (authoritative; Tasks 1, 3, 4, 10, 11, 12 all reference this)

Newline-delimited JSON over `UnixStream`: one `Command` per line in, one `Response` per line out.
`Command::Subscribe` is the sole exception - it switches that connection to stream mode, emitting
zero or more `Response::Event` lines until either side disconnects.

```rust
enum Command { AddRule{class,kind,value,load}, ClearRules{load}, SetUpstream{addr,load},
               SetListen{http,socks,load}, Reload{path}, On, Off, Status, Rules,
               Test{host,port}, Doctor, Subscribe }
enum Response { Ok, Rules(Vec<RuleView>), Status(StatusView), Decision(DecisionView),
                Doctor(Vec<CheckView>), Event(EventView), Err{kind,message} }
enum ErrKind { NotFound, UpstreamDown, InvalidArgs, LoadInProgress, Internal }
```

`class` is `require|prefer|never`; `kind` is `suffix|cidr|port|keyword`; `load` is
`Option<LoadId>` (see Task 5). View structs, with JSON key names and types:

- `RuleView { index: u32, class: String, kind: String, value: String }`
- `DecisionView { decision: "direct"|"never"|"upstream", rule_index: u32|null, class: String|null, next_hop: String }`
- `StatusView { uptime_secs: u64, http_listen: String, http_bound: bool, socks_listen: String, socks_bound: bool, upstream: String, health: "up"|"down", health_changed_at: RFC3339, init_path: String|null, last_load: {at: RFC3339, outcome: "ok"|"failed"|"timed_out", command: String|null}|null, rules: {require: u32, prefer: u32, never: u32}, system_proxy: {http: String|null, https: String|null, socks: String|null} }`
- `CheckView { name: String, ok: bool, detail: String }`
- `EventView { host: String, port: u16, decision: String, rule_index: u32|null, class: String|null, upstream: "up"|"down", duration_ms: u64, error: String|null }`

All timestamps are RFC3339 strings.

### Exit codes (CLI)

| Condition | Code |
|---|---|
| success | 0 |
| `ErrKind::NotFound`, socket missing, daemon unreachable | 2 |
| `ErrKind::UpstreamDown`; `doctor` where the only failures are upstream-reachability checks | 3 |
| `ErrKind::InvalidArgs` | 4 |
| anything else, including "another daemon already running" and `doctor` with any other failure | 1 |

### Rule surface (single canonical form, used by Tasks 2, 4, 5, 14)

`nhop <require|prefer|never> <suffix|cidr|port|keyword> <value>`

- `suffix` - exact-or-dot-boundary, case-insensitive, trailing dot stripped
- `cidr` - matches only hosts that parse as an IP literal; a hostname never matches a cidr rule
- `port` - exact `u16` equality, no ranges
- `keyword` - case-insensitive substring of the lowercased host only, never the port

### `UpstreamDown` surface (single definition; Tasks 6, 7, 8, 15 reference this)

One error, three renderings: HTTP front end -> `502 Bad Gateway`, body
`nhop: upstream <addr> is down (require rule <index>)`; SOCKS5 front end -> reply code `0x04`
(host unreachable); CLI -> exit code 3.

### Upstream constants (Task 8)

`UPSTREAM_CONNECT_TIMEOUT = 2s`, `PROBE_INTERVAL = 5s`, `PROBE_TIMEOUT = 2s`. The probe is a full
tokio-socks no-auth handshake plus CONNECT to the upstream's own address. One success flips Up, one
failure flips Down. No probing while Up - failures come from real dials. The probe interval is
injectable so tests use 50 ms.

### Filesystem contract

| Path | Purpose |
|---|---|
| `$HOME/.config/nhop/init` | executable rule script, run at daemon start and on `reload` |
| `$HOME/.local/state/nhop/nhop.sock` | IPC socket, mode 0600 |
| `$HOME/.local/state/nhop/nhop.pid` | single-instance guard, held under an advisory `flock` |
| `$HOME/.local/state/nhop/nhop.log` | JSON-lines log, daily rotation, 7 files kept |

The socket deliberately does **not** live in `/tmp`: a world-writable socket would let any local
process rewrite this machine's traffic routing.

### System proxy bypass list (Task 13)

A named constant, separate from the daemon's `never` rules (those apply only to traffic that
already reached nhop): `localhost`, `127.0.0.1`, `*.local`, `169.254/16`.

## What Goes Where

- **Implementation Steps** (`[ ]`): everything achievable in this repo by an automated session.
- **Post-Completion** (no checkboxes): operator actions needing the real VM, a password, a browser
  or System Settings. Not review criteria.

## Implementation Steps

### Task 1: Workspace and the `nhop-ipc` contract crate

**Files:**
- Create: `Cargo.toml`, `nhop-ipc/Cargo.toml`, `nhop-ipc/src/lib.rs`, `nhop-ipc/src/command.rs`,
  `nhop-ipc/src/view.rs`, `nhop-ipc/src/paths.rs`, `nhop/Cargo.toml`, `nhop/src/main.rs`

- [ ] create a two-member workspace (`nhop`, `nhop-ipc`) with shared `[workspace.package]` and
      `[workspace.dependencies]`
- [ ] define `Command`, `Response`, `ErrKind` and the five view structs **exactly** as listed in
      the IPC contract section, with serde derives and `#[serde(tag = "cmd", rename_all = "snake_case")]`
      so the wire form is readable in logs
- [ ] add `Paths { config_dir, state_dir }` with pure `Paths::from_home(&Path)` and
      `Paths::from_env()` (reads `$HOME` once, used only by `main`); every daemon and CLI entry
      point takes `Paths` as a parameter, so no test ever mutates the environment
- [ ] `state_dir()` creates the directory with mode 0700 when missing, idempotently
- [ ] add `#![warn(missing_docs)]` and rustdoc per the Code-Quality bar
- [ ] `nhop/src/main.rs` compiles as a stub printing the version
- [ ] write tests for `Paths::from_home` (creation, mode, idempotent second call) with `tempfile`
- [ ] write tests round-tripping every `Command` and `Response` variant through `serde_json`, plus
      one unknown-variant case asserting a clean error
- [ ] run `mise run check` - must pass before task 2

### Task 2: Rule model and the decision engine

**Files:**
- Create: `nhop/src/rules/mod.rs`, `nhop/src/rules/matcher.rs`, `nhop/src/rules/ruleset.rs`

- [ ] define newtypes `Host`, `Port`, `RuleId(usize)` (index in declaration order within the
      current ruleset, invalidated by a reload), and enums `RuleKind`, `RuleClass`, and
      `Decision { Direct, Never{rule}, Upstream{class, rule} }` - `Never` and `Direct` both dial
      directly but render differently in `test`, `status` and the log event
- [ ] implement each kind exactly as the Rule surface section defines it
- [ ] implement `Ruleset::decide(&self, host: &Host, port: Port) -> Decision` with precedence:
      `never` rules first, then rules in declaration order, first match wins, default `Direct`
- [ ] value parsers reject malformed input with `ErrKind::InvalidArgs`
- [ ] write tests for suffix (exact, sub-domain, shared-tail non-match, case, trailing dot)
- [ ] write tests for cidr (in range, out of range, hostname must not match), port, keyword
- [ ] write tests for precedence and for each parser's rejection case
- [ ] run `mise run check` - must pass before task 3

### Task 3: Daemon skeleton, state ownership and the IPC server

**Files:**
- Create: `nhop/src/daemon/mod.rs`, `nhop/src/daemon/ipc_server.rs`, `nhop/src/daemon/state.rs`
- Modify: `nhop/src/main.rs`

- [ ] **state ownership, one model only**: all mutation and query commands go to a single actor
      task via `mpsc::Sender<(Command, oneshot::Sender<Response>)>` (capacity 64, `send().await`
      for backpressure). The connection hot path never uses that channel: the live ruleset is
      published as `ArcSwap<Ruleset>` and each accepted connection loads **one snapshot** and uses
      it for its whole life - a swap therefore does not affect connections already accepted
- [ ] single-instance guard: open the pid file `O_CREAT|O_RDWR` and take an exclusive advisory
      `flock` (`fs2`). Lock acquired = no live owner: unlink a stale socket, write the current pid.
      Lock refused = print the owning pid and exit **1**. The lock is held for the process lifetime
- [ ] bind the unix socket, `chmod` it to 0600 before the accept loop starts, remove it and the pid
      file on clean shutdown; handle SIGINT/SIGTERM
- [ ] accept loop reads one `Command` per line, forwards it to the actor, writes one `Response` line
- [ ] write tests that start a daemon on a temp `Paths`, send `Command::Status` and assert
      `Response::Status` with `rules.require == 0`, `init_path == null` and both listeners reported
- [ ] write tests for the guard: stale pid file with no live owner starts; a held lock refuses with
      exit code 1
- [ ] write a test asserting a ruleset swap does not change the decision of an already-open connection
- [ ] run `mise run check` - must pass before task 4

### Task 4: CLI client and subcommand plumbing

**Files:**
- Create: `nhop/src/cli/mod.rs`, `nhop/src/cli/client.rs`
- Modify: `nhop/src/main.rs`

- [ ] declare the `argh` tree: `start`, `require`, `prefer`, `never`, `upstream`, `listen`,
      `reload`, `on`, `off`, `status`, `rules`, `test`, `logs`, `tail`, `doctor`, `proxy` - the
      rule verbs take `<kind> <value>` per the Rule surface section
- [ ] every read command takes `--json`: with it, a single JSON document on stdout and nothing else
- [ ] map `ErrKind` and transport failures onto the Exit codes table; a missing socket is exit 2
      with a one-line hint on stderr
- [ ] no interactive prompting anywhere
- [ ] write tests for parsing each subcommand, including an unknown rule kind (exit 4)
- [ ] write tests asserting `--json` output parses as JSON and human text never leaks to stdout
- [ ] write tests for the `ErrKind` -> exit code mapping, one case per row of the table
- [ ] run `mise run check` - must pass before task 5

### Task 5: Init script execution and the atomic load protocol

**Files:**
- Create: `nhop/src/daemon/init_script.rs`, `nhop/src/daemon/staging.rs`
- Modify: `nhop/src/daemon/state.rs`

- [ ] run `$HOME/.config/nhop/init` as a program (no explicit shell) so its shebang chooses the
      interpreter; set the working directory to the config directory and prepend the directory of
      the current executable to `PATH`
- [ ] **load protocol**: the daemon generates a `LoadId(u64)` per run and passes it to the child as
      env `NHOP_LOAD_ID`; the CLI forwards it in the `load` field of every mutating command.
      Commands carrying the current id append to staging. Commands with no id or a stale id while a
      load is in progress are rejected with `ErrKind::LoadInProgress`, as is a second `Reload`.
      Commands with no id outside a load apply immediately as a one-command transaction
- [ ] the run is bounded by a **30 s** timeout; on timeout the child is killed, staging is
      discarded and the previous ruleset stays live
- [ ] on exit status zero, swap staging into the live `ArcSwap`; on non-zero or a failed command,
      discard staging and record which command failed
- [ ] record `last_load { at, outcome: ok|failed|timed_out, command }`, returned by both `Reload`
      and `Status`
- [ ] a missing init file is not an error: the ruleset stays empty. **Until the first load commits,
      the ruleset is empty and every connection is `Direct`** - state this in `status`
- [ ] `Reload{path}` runs a different file and remembers it; `Off` clears the live ruleset without
      forgetting the path; `On` re-runs it
- [ ] write tests with a generated init script: success applies rules; non-zero exit after adding
      rules leaves the previous set intact; missing file yields an empty set
- [ ] write tests for a concurrent command rejected with `LoadInProgress` and for the timeout path
- [ ] write a test asserting the child receives the executable's directory on `PATH` and `NHOP_LOAD_ID`
- [ ] run `mise run check` - must pass before task 6

### Task 6: Front-end wiring and the HTTP proxy

**Files:**
- Create: `nhop/src/proxy/mod.rs`, `nhop/src/proxy/http.rs`, `nhop/tests/support/mod.rs`
- Modify: `nhop/src/daemon/mod.rs`

- [ ] in `proxy/mod.rs` define the single boundary the front ends use:
      `struct ConnCtx { rules: Arc<Ruleset>, health: HealthHandle, upstream: SocketAddr, events: EventTx }`
      and `trait NextHop { async fn dial(&self, host: &Host, port: Port, decision: Decision) -> io::Result<TcpStream> }`.
      Task 8 supplies the real implementation; this task uses a test double
- [ ] in `daemon/mod.rs` add `spawn_frontends(state)`: bind `TcpListener` on the configured HTTP and
      SOCKS addresses (defaults `127.0.0.1:7890` and `127.0.0.1:7891`), **before** the init script
      runs, and spawn a task per accepted stream with a `ConnCtx` carrying the ruleset snapshot
- [ ] `SetListen` inside a load takes effect only on commit; rebinding closes the old listener and
      keeps existing connections; if the new bind fails the old listener is retained and the load fails
- [ ] parse the request head into a single `[u8; 8192]` stack buffer up to `\r\n\r\n`; no `Vec` or
      `String` for the head; exceeding it closes the connection
- [ ] `CONNECT host:port` - reply `200 Connection established` only after the next hop is dialled,
      so a failed dial is a proper error response and not a dead tunnel
- [ ] absolute-form plain HTTP (`GET http://host/path`): authority from the request target, falling
      back to the `Host` header, default port 80; forward the original bytes verbatim; **handle
      exactly one such request per client connection and close after relaying the response**, so a
      later request can never inherit the first request's next hop
- [ ] failures: `UpstreamDown` rendering per Technical Details; a failed direct dial is `502` with a
      one-line body naming host:port; a malformed request line is `400`
- [ ] relay with `tokio::io::copy_bidirectional`
- [ ] create the shared harness in `nhop/tests/support/mod.rs`: `StubSocks5::start()` returning a
      handle whose `requests()` reports `{atyp, host, port}` and which echoes payload bytes;
      `StubOrigin::start()` echoing and counting connections; `TestDaemon::start(paths, upstream)`
      exposing ephemeral HTTP, SOCKS and IPC addresses. Tasks 7, 8 and 15 reuse this module
- [ ] write tests for CONNECT through to the stub origin, for absolute-form GET, for the 8 KiB cap,
      for a malformed request line, for the 502-on-require-down case, and for a second pipelined
      request not being proxied
- [ ] run `mise run check` - must pass before task 7

### Task 7: SOCKS5 front end

**Files:**
- Create: `nhop/src/proxy/socks5.rs`
- Modify: `nhop/src/proxy/mod.rs`

- [ ] no-auth handshake and `CONNECT` for address types IPv4 (`0x01`), domain (`0x03`) and IPv6
      (`0x04`); reject `BIND` and `UDP ASSOCIATE`
- [ ] reply codes: success `0x00`, general failure `0x01`, host unreachable `0x04`, command not
      supported `0x07`, address type not supported `0x08`. The success reply carries ATYP `0x01`
      with BND.ADDR `0.0.0.0` and BND.PORT `0` - deliberate, the tunnel is opaque
- [ ] pass the **domain name** to the upstream when the client sent one - never resolve locally
      first, because internal names only resolve inside the upstream's network
- [ ] `UpstreamDown` renders as reply code `0x04` per Technical Details
- [ ] byte-layout notes are the one place `//` comments are allowed
- [ ] write tests for the handshake and each address type against the shared stubs
- [ ] write tests asserting the exact reply bytes for success and for `BIND`
- [ ] write a test asserting a domain-type request reaches the stub upstream as a name, not an IP
- [ ] run `mise run check` - must pass before task 8

### Task 8: Upstream dialer and health state

**Files:**
- Create: `nhop/src/upstream/mod.rs`, `nhop/src/upstream/health.rs`
- Modify: `nhop/src/daemon/state.rs`

- [ ] implement the `NextHop` trait from Task 6 over `tokio_socks`, honouring the constants in
      Technical Details; this replaces the test double, it does not introduce a new call path
- [ ] `health.rs` owns the verdict as `{ state: Up|Down, changed_at: SystemTime }` - `SystemTime`,
      not `Instant`, because `status` and `doctor` must render it as RFC3339
- [ ] transitions exactly as specified: one failure (real dial or probe) flips Down, one success
      flips Up, no probing while Up, probe interval injectable for tests
- [ ] while Down, decisions are made without dialling: `Prefer` goes direct at once, `Require` fails
      at once with `UpstreamDown`
- [ ] a `Require` or `Prefer` dial failure while the verdict is Up marks the upstream Down; `Prefer`
      additionally falls back to a direct connection for that connection
- [ ] write tests with the upstream at a closed port: `Prefer` reaches the direct stub, `Require`
      returns `UpstreamDown`
- [ ] write a test asserting the flip back to Up once the stub upstream starts accepting
- [ ] write a test asserting a dial to a black-holed address fails within 3 s
- [ ] run `mise run check` - must pass before task 9

### Task 9: Structured logging and `nhop logs`

**Files:**
- Create: `nhop/src/logging.rs`
- Modify: `nhop/src/daemon/mod.rs`, `nhop/src/cli/mod.rs`

- [ ] initialise `tracing-subscriber` with the JSON formatter over
      `tracing_appender::rolling::daily(state_dir, "nhop.log")`, keeping 7 files - daily, because
      `tracing-appender` has no size-based rotation; the Filesystem contract says the same
- [ ] emit one event per connection decision whose fields are exactly `EventView` from the IPC
      contract; never log request bodies, headers or credentials
- [ ] `nhop logs` prints the current file and the kept rotations in chronological order; `-f`
      follows; `--since <dur>` accepts `humantime` durations (`15m`, `2h`, `3d`) and exits 4 on a
      malformed value; `--json` emits raw lines
- [ ] write tests for the `--since` filter and the malformed-duration exit code over a fixture file
- [ ] write a test parsing emitted lines into a `deny_unknown_fields` struct matching `EventView`
- [ ] run `mise run check` - must pass before task 10

### Task 10: `status`, `rules`, `test` and the system-proxy reader

**Files:**
- Create: `nhop/src/cli/status.rs`, `nhop/src/cli/explain.rs`, `nhop/src/cli/system_proxy.rs`

- [ ] create `system_proxy.rs` with `trait SystemProxyReader { fn read(&self, service: &str) -> Result<SystemProxy> }`
      and a real implementation shelling out to `networksetup -getwebproxy/-getsecurewebproxy/-getsocksfirewallproxy`,
      executed by the **daemon**. Task 13 extends this same module with the write path; do not add a
      second parser
- [ ] `status` returns `StatusView` exactly as defined in the IPC contract, built by a pure
      `status_json(state, proxy) -> serde_json::Value` so it can be tested without invoking
      `networksetup`
- [ ] `rules` returns `RuleView` in declaration order; `test <host:port>` returns `DecisionView`
      without opening any connection
- [ ] all three honour `--json`
- [ ] write tests for `test` covering a require match, a prefer match, a never match and no match,
      asserting the exact `DecisionView` including `rule_index`
- [ ] write a golden test comparing `status_json` over a fixed state and a fixed `SystemProxy`
      fixture against a checked-in `nhop/tests/golden/status.json`, byte for byte
- [ ] write tests parsing `networksetup` fixture strings into `SystemProxy`
- [ ] run `mise run check` - must pass before task 11

### Task 11: `nhop doctor`

**Files:**
- Create: `nhop/src/cli/doctor.rs`

- [ ] emit exactly seven `CheckView` objects, in this order, with these `name` values:
      `daemon_reachable`, `ports_bound`, `system_proxy`, `upstream_reachable`, `init_file`,
      `last_load`, `log_writable`
- [ ] the Local Network check is the subtle one: on `EHOSTUNREACH` when connecting to the upstream,
      report a probable Local Network permission denial with the remedy, because macOS reports that
      denial as a routing error
- [ ] exit codes: 0 when all pass; 3 when the only failures are upstream-reachability checks;
      otherwise 1
- [ ] write tests over the aggregation function with injected results: all pass, only upstream
      fails, several fail - asserting exit code, output order and the seven names
- [ ] run `mise run check` - must pass before task 12

### Task 12: `nhop tail`

**Files:**
- Create: `nhop/src/cli/tail.rs`
- Modify: `nhop/src/daemon/ipc_server.rs`, `nhop/src/proxy/mod.rs`

- [ ] `Command::Subscribe` switches that connection to stream mode - the only multi-response command
- [ ] each subscriber gets a bounded `mpsc::channel(256)`; publish with `try_send`; on `Full`
      increment a per-subscriber `dropped` counter and emit an `EventView` with `error` set to
      `"dropped <n>"` when the queue drains; a subscriber whose write fails is removed
- [ ] the front ends publish via `ctx.events` on every decision; a slow subscriber must never make a
      connection handler await
- [ ] write tests for subscribe and unsubscribe, and a test filling the queue with a non-reading
      subscriber that asserts the handler does not block and the drop count is reported
- [ ] run `mise run check` - must pass before task 13

### Task 13: `nhop proxy on|off`

**Files:**
- Modify: `nhop/src/cli/system_proxy.rs`

- [ ] `proxy on` sets HTTP and HTTPS proxies for the service to the HTTP listen address and the
      SOCKS proxy to the SOCKS listen address, then sets the bypass list to the named constant in
      Technical Details
- [ ] `proxy off` disables all three for that service
- [ ] both refuse to run without effective root and print the exact `sudo` invocation instead of
      prompting
- [ ] the service name is a parameter defaulting to `Wi-Fi`
- [ ] reuse the reader from Task 10 for `proxy status`; do not add a second parser
- [ ] write tests asserting the generated argv for `on` and `off`, including the bypass argv matching
      the constant verbatim
- [ ] run `mise run check` - must pass before task 14

### Task 14: Packaging - LaunchAgent, signing, install and uninstall

**Files:**
- Create: `scripts/build-signed.sh`, `packaging/com.pavel-karpovich.nhop.plist`,
  `packaging/nhop.init.example`
- Modify: `README.md`

- [ ] `build-signed.sh` builds release, codesigns with the Developer ID identity (team id passed as
      an argument, never hardcoded), verifies with `codesign --verify --strict`, prints the identifier
- [ ] the plist sets `RunAtLoad=true` and `KeepAlive=true` (restart-on-crash is launchd's
      responsibility; no timing is asserted) and points `StandardOutPath`/`StandardErrorPath` at the
      state directory
- [ ] `nhop.init.example` is a commented fish script using the canonical rule surface with **clearly
      marked placeholders** (`nhop upstream socks5://192.0.2.10:1080  # replace`, `example.com`
      hostnames). It is illustrative, not ready to run, and the file says so on its first line
- [ ] README documents install, the one-time `sudo nhop proxy on`, granting Local Network on first
      run, and the uninstall order (`proxy off` **before** removing the agent)
- [ ] write a test asserting the plist parses and contains the expected label, `KeepAlive` and
      program path shape
- [ ] run `mise run check` - must pass before task 15

### Task 15: Verify acceptance criteria

**Files:**
- Create: `nhop/tests/acceptance.rs`

- [ ] create exactly four `#[tokio::test]` cases named `require_reaches_upstream`,
      `prefer_reaches_upstream`, `prefer_falls_back_direct_when_upstream_closed`,
      `require_fails_when_upstream_closed`, using the Task 6 harness
- [ ] each case also asserts that `Command::Test` returns the same `DecisionView` variant and
      `rule_index` that the real connection then exercised (upstream stub vs direct stub)
- [ ] assert both listeners remain bound after `Off` and that a client on the SOCKS port then gets a
      direct connection rather than a refusal
- [ ] assert `doctor --json` emits the seven named checks
- [ ] `cargo test --test acceptance` passes 4/4
- [ ] run the full suite: `mise run check`

### Task 16: [Final] Documentation

- [ ] README contains H2 sections titled exactly `Commands`, `Init file`, `Rule classes`,
      `Filesystem contract`, `Install`, `Uninstall`; `Commands` lists every subcommand from Task 4,
      one line each; `Filesystem contract` reproduces the four paths from Technical Details
- [ ] record the three constraints a future reader will not guess: the SOCKS port pinning of an
      existing client, the Local Network signing requirement and its misleading `EHOSTUNREACH`, and
      why the daemon must keep listening when rules are cleared
- [ ] verify with `rg -c '^## (Commands|Init file|Rule classes|Filesystem contract|Install|Uninstall)$' README.md` returning 6
- [ ] move this plan to `docs/plans/completed/`
- [ ] run `mise run check`

## Post-Completion

**None of the items below are review criteria. They cannot be executed or verified by an automated
session and MUST NOT block marking the plan complete.**

**Operator verification on the target machine:**

- With the upstream VM running, drive the real workflow through the client pinned to the SOCKS port:
  an API request to a host that exists only behind the upstream must return the same response it
  returns when dialled through the upstream proxy directly.
- Open a public site in a browser with the system proxy pointing at nhop and confirm it loads.
- Power the upstream VM off and confirm the fallback: a `prefer` host still loads (direct), a
  `require` host fails immediately rather than after a long timeout.
- Confirm the Local Network permission holds for the signed binary **under launchd**, not only from
  a terminal. This is the single highest-risk unknown in the plan.
- Measure idle CPU by hand once the daemon runs under launchd - this is an operator observation, not
  an automated criterion.

**External system updates:**

- Grant Local Network permission in System Settings on first run if macOS does not prompt.
- Publish a formula to the operator's Homebrew tap once the binary is stable.
- Retire ClashX only after a full working day on nhop: quit it, confirm the ports are served by
  nhop, then remove the app and its privileged helper.
- The pinned API client needs no change as long as nhop occupies its SOCKS port; verify before
  uninstalling ClashX.
