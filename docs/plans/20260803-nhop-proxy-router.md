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
`Option<LoadId>` (see Task 5).

⚠️ **Envelope, settled in Task 1.** `Command` carries `#[serde(tag = "cmd", rename_all = "snake_case")]`
as specified. `Response` cannot: serde refuses to internally-tag a newtype variant holding a
sequence, which `Rules(Vec<RuleView>)` and `Doctor(Vec<CheckView>)` both are. `Response` therefore
uses adjacent tagging, `#[serde(tag = "resp", content = "data", rename_all = "snake_case")]`, which
keeps the variant shapes exactly as listed above and the wire form readable
(`{"resp":"rules","data":[...]}`, `{"resp":"ok"}`).

View structs, with JSON key names and types:

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

These four paths are exposed by `Paths` as `init_file()`, `socket_file()`, `pid_file()` and
`log_file()` (Task 1); later tasks use those accessors instead of repeating the file names.

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

- [x] create a two-member workspace (`nhop`, `nhop-ipc`) with shared `[workspace.package]` and
      `[workspace.dependencies]`
- [x] define `Command`, `Response`, `ErrKind` and the five view structs **exactly** as listed in
      the IPC contract section, with serde derives and `#[serde(tag = "cmd", rename_all = "snake_case")]`
      so the wire form is readable in logs (see the ⚠️ envelope note in the IPC contract for the
      `Response` tagging)
- [x] add `Paths { config_dir, state_dir }` with pure `Paths::from_home(&Path)` and
      `Paths::from_env()` (reads `$HOME` once, used only by `main`); every daemon and CLI entry
      point takes `Paths` as a parameter, so no test ever mutates the environment
- [x] `state_dir()` creates the directory with mode 0700 when missing, idempotently
- [x] add `#![warn(missing_docs)]` and rustdoc per the Code-Quality bar
- [x] `nhop/src/main.rs` compiles as a stub printing the version
- [x] write tests for `Paths::from_home` (creation, mode, idempotent second call) with `tempfile`
- [x] write tests round-tripping every `Command` and `Response` variant through `serde_json`, plus
      one unknown-variant case asserting a clean error
- [x] run `mise run check` - must pass before task 2

### Task 2: Rule model and the decision engine

**Files:**
- Create: `nhop/src/rules/mod.rs`, `nhop/src/rules/matcher.rs`, `nhop/src/rules/ruleset.rs`

- [x] define newtypes `Host`, `Port`, `RuleId(usize)` (index in declaration order within the
      current ruleset, invalidated by a reload), and enums `RuleKind`, `RuleClass`, and
      `Decision { Direct, Never{rule}, Upstream{class, rule} }` - `Never` and `Direct` both dial
      directly but render differently in `test`, `status` and the log event
- [x] implement each kind exactly as the Rule surface section defines it
- [x] implement `Ruleset::decide(&self, host: &Host, port: Port) -> Decision` with precedence:
      `never` rules first, then rules in declaration order, first match wins, default `Direct`
- [x] value parsers reject malformed input with `ErrKind::InvalidArgs`
- [x] write tests for suffix (exact, sub-domain, shared-tail non-match, case, trailing dot)
- [x] write tests for cidr (in range, out of range, hostname must not match), port, keyword
- [x] write tests for precedence and for each parser's rejection case
- [x] run `mise run check` - must pass before task 3

➕ `Host`, `Port`, `RuleClass` and `RuleKind` are re-exported from `nhop-ipc` by `rules/mod.rs`
rather than redefined, since Task 1 already defined them as the wire contract; redefining them in
`nhop` would be exactly the daemon/client drift the split crate exists to prevent. `RuleId` and
`Decision` are new here.

➕ `nhop/src/lib.rs` added: `nhop` is now a lib + bin crate. A binary-only crate reports every
routing type as `dead_code` until `main` calls it, which `cargo clippy -D warnings` turns into a
failed gate; the lib target also gives Tasks 6 and 15 a way to reach the daemon from
`nhop/tests/`. `main.rs` is unchanged.

### Task 3: Daemon skeleton, state ownership and the IPC server

**Files:**
- Create: `nhop/src/daemon/mod.rs`, `nhop/src/daemon/ipc_server.rs`, `nhop/src/daemon/state.rs`
- Modify: `nhop/src/main.rs`

- [x] **state ownership, one model only**: all mutation and query commands go to a single actor
      task via `mpsc::Sender<(Command, oneshot::Sender<Response>)>` (capacity 64, `send().await`
      for backpressure). The connection hot path never uses that channel: the live ruleset is
      published as `ArcSwap<Ruleset>` and each accepted connection loads **one snapshot** and uses
      it for its whole life - a swap therefore does not affect connections already accepted
- [x] single-instance guard: open the pid file `O_CREAT|O_RDWR` and take an exclusive advisory
      `flock` (`fs2`). Lock acquired = no live owner: unlink a stale socket, write the current pid.
      Lock refused = print the owning pid and exit **1**. The lock is held for the process lifetime
- [x] bind the unix socket, `chmod` it to 0600 before the accept loop starts, remove it and the pid
      file on clean shutdown; handle SIGINT/SIGTERM
- [x] accept loop reads one `Command` per line, forwards it to the actor, writes one `Response` line
- [x] write tests that start a daemon on a temp `Paths`, send `Command::Status` and assert
      `Response::Status` with `rules.require == 0`, `init_path == null` and both listeners reported
- [x] write tests for the guard: stale pid file with no live owner starts; a held lock refuses with
      exit code 1
- [x] write a test asserting a ruleset swap does not change the decision of an already-open connection
- [x] run `mise run check` - must pass before task 4

➕ `LiveRules` wraps the `ArcSwap<Ruleset>` and is the single publication point: the state task and
every connection hold the same handle, `snapshot()` is the per-connection read and `publish()` is
the swap Task 5 commits a staged ruleset through. `Status` derives its rule counts from that same
snapshot, so there is no second copy to drift.

➕ Only `Status` and `Rules` are served here; every other variant answers `ErrKind::Internal` with
"does not serve this command yet" until its owning task lands. The match lists all variants
explicitly, so adding a handler is a compiler-guided edit.

➕ Both listeners report `bound: false` until Task 6 spawns the front ends - nothing binds
7890/7891 yet. `main.rs` dispatches `start` by hand pending the `argh` tree in Task 4.

### Task 4: CLI client and subcommand plumbing

**Files:**
- Create: `nhop/src/cli/mod.rs`, `nhop/src/cli/client.rs`
- Modify: `nhop/src/main.rs`

- [x] declare the `argh` tree: `start`, `require`, `prefer`, `never`, `upstream`, `listen`,
      `reload`, `on`, `off`, `status`, `rules`, `test`, `logs`, `tail`, `doctor`, `proxy` - the
      rule verbs take `<kind> <value>` per the Rule surface section
- [x] every read command takes `--json`: with it, a single JSON document on stdout and nothing else
- [x] map `ErrKind` and transport failures onto the Exit codes table; a missing socket is exit 2
      with a one-line hint on stderr
- [x] no interactive prompting anywhere
- [x] write tests for parsing each subcommand, including an unknown rule kind (exit 4)
- [x] write tests asserting `--json` output parses as JSON and human text never leaks to stdout
- [x] write tests for the `ErrKind` -> exit code mapping, one case per row of the table
- [x] run `mise run check` - must pass before task 5

➕ `cli::Exit` is the single owner of the Exit codes table: one variant per row, `code()` renders
the number, and `of_err`/`of_unreachable`/`of_start` are the only mappings into it. Task 3's
`StartFailure::exit_code()` duplicated the last row and is removed, so the table cannot drift.

➕ `run(paths, arguments, out, err)` writes through `&mut dyn Write` rather than `println!`, which
is what lets the tests assert that `--json` puts one document on stdout and that error text never
leaves stderr. `main.rs` passes `io::stdout()`/`io::stderr()`. Nothing reads stdin anywhere.

➕ `logs`, `tail` and `proxy` parse fully - including `--json` and `proxy --service`, default
`Wi-Fi` - but answer "not implemented yet" on stderr with exit 1 until Tasks 9, 12 and 13 land,
mirroring how Task 3 left unserved daemon commands. Mutating commands send `load: None`; Task 5
adds the `NHOP_LOAD_ID` forwarding. Human rendering of `status`, `rules` and `test` is terse here;
Tasks 10 and 11 own the rich form and the `doctor` exit code.

➕ Beyond the listed files: `nhop/src/lib.rs` exports the new `cli` module, and `nhop/Cargo.toml`
gains `argh`, `serde` (the `Serialize` bound behind `--json`) and `humantime` (RFC3339 timestamps
in human `status`).

### Task 5: Init script execution and the atomic load protocol

**Files:**
- Create: `nhop/src/daemon/init_script.rs`, `nhop/src/daemon/staging.rs`
- Modify: `nhop/src/daemon/state.rs`

- [x] run `$HOME/.config/nhop/init` as a program (no explicit shell) so its shebang chooses the
      interpreter; set the working directory to the config directory and prepend the directory of
      the current executable to `PATH`
- [x] **load protocol**: the daemon generates a `LoadId(u64)` per run and passes it to the child as
      env `NHOP_LOAD_ID`; the CLI forwards it in the `load` field of every mutating command.
      Commands carrying the current id append to staging. Commands with no id or a stale id while a
      load is in progress are rejected with `ErrKind::LoadInProgress`, as is a second `Reload`.
      Commands with no id outside a load apply immediately as a one-command transaction
- [x] the run is bounded by a **30 s** timeout; on timeout the child is killed, staging is
      discarded and the previous ruleset stays live
- [x] on exit status zero, swap staging into the live `ArcSwap`; on non-zero or a failed command,
      discard staging and record which command failed
- [x] record `last_load { at, outcome: ok|failed|timed_out, command }`, returned by both `Reload`
      and `Status`
- [x] a missing init file is not an error: the ruleset stays empty. **Until the first load commits,
      the ruleset is empty and every connection is `Direct`** - state this in `status`
- [x] `Reload{path}` runs a different file and remembers it; `Off` clears the live ruleset without
      forgetting the path; `On` re-runs it
- [x] write tests with a generated init script: success applies rules; non-zero exit after adding
      rules leaves the previous set intact; missing file yields an empty set
- [x] write tests for a concurrent command rejected with `LoadInProgress` and for the timeout path
- [x] write a test asserting the child receives the executable's directory on `PATH` and `NHOP_LOAD_ID`
- [x] run `mise run check` - must pass before task 6

➕ The state task no longer blocks on a load. `Reload`/`On` stage the run, spawn the script as a
separate task and hold the caller's `oneshot` until it finishes, so the commands the script sends
back over the socket are served by the same actor while its own run is still in flight - awaiting
the child inside the actor would deadlock every init script that calls the CLI. Completion arrives
on a second channel the actor selects on.

➕ `Reload`/`On` answer `Response::Status` when the run commits (that is where `last_load` is
returned from) and `Response::Err{Internal}` when it fails or times out, so a scripted `nhop reload`
exits non-zero on a failed load instead of silently succeeding. A run whose script file does not
exist answers `ErrKind::NotFound` and touches no state; at daemon start that answer is discarded,
which is what keeps a missing init file from being an error.

➕ Staging starts empty rather than from the live ruleset - the init file is the whole profile - and
`SetUpstream`/`SetListen` inside a run are held until commit alongside the rules. Task 6 picks the
listen addresses up from there when it wires the rebinding.

➕ Beyond the listed files: `daemon/mod.rs` fires the startup load once the socket is served,
`cli/mod.rs` reads `NHOP_LOAD_ID` and forwards it on every mutating verb, `nhop-ipc` owns the
`LOAD_ID_ENV` name plus `Display`/`FromStr` for `LoadId` so daemon and client cannot spell the
handshake differently, and the workspace `tokio` gains the `process` feature.

➕ `nhop/tests/init_run.rs` added: the state-level tests drive the protocol with the daemon's own
handle, so nothing there proves the CLI forwards the id end to end. This integration test runs a
real init script that calls the built binary (`CARGO_BIN_EXE_nhop`, with the script exporting its
own `HOME`) and asserts both that a whole rule set arrives in declaration order and that a script
failing halfway leaves no rule behind.

### Task 6: Front-end wiring and the HTTP proxy

**Files:**
- Create: `nhop/src/proxy/mod.rs`, `nhop/src/proxy/http.rs`, `nhop/tests/support/mod.rs`
- Modify: `nhop/src/daemon/mod.rs`

- [x] in `proxy/mod.rs` define the single boundary the front ends use:
      `struct ConnCtx { rules: Arc<Ruleset>, health: HealthHandle, upstream: SocketAddr, events: EventTx }`
      and `trait NextHop { async fn dial(&self, host: &Host, port: Port, decision: Decision) -> io::Result<TcpStream> }`.
      Task 8 supplies the real implementation; this task uses a test double
- [x] in `daemon/mod.rs` add `spawn_frontends(state)`: bind `TcpListener` on the configured HTTP and
      SOCKS addresses (defaults `127.0.0.1:7890` and `127.0.0.1:7891`), **before** the init script
      runs, and spawn a task per accepted stream with a `ConnCtx` carrying the ruleset snapshot
- [x] `SetListen` inside a load takes effect only on commit; rebinding closes the old listener and
      keeps existing connections; if the new bind fails the old listener is retained and the load fails
- [x] parse the request head into a single `[u8; 8192]` stack buffer up to `\r\n\r\n`; no `Vec` or
      `String` for the head; exceeding it closes the connection
- [x] `CONNECT host:port` - reply `200 Connection established` only after the next hop is dialled,
      so a failed dial is a proper error response and not a dead tunnel
- [x] absolute-form plain HTTP (`GET http://host/path`): authority from the request target, falling
      back to the `Host` header, default port 80; forward the original bytes verbatim; **handle
      exactly one such request per client connection and close after relaying the response**, so a
      later request can never inherit the first request's next hop
- [x] failures: `UpstreamDown` rendering per Technical Details; a failed direct dial is `502` with a
      one-line body naming host:port; a malformed request line is `400`
- [x] relay with `tokio::io::copy_bidirectional`
- [x] create the shared harness in `nhop/tests/support/mod.rs`: `StubSocks5::start()` returning a
      handle whose `requests()` reports `{atyp, host, port}` and which echoes payload bytes;
      `StubOrigin::start()` echoing and counting connections; `TestDaemon::start(paths, upstream)`
      exposing ephemeral HTTP, SOCKS and IPC addresses. Tasks 7, 8 and 15 reuse this module
- [x] write tests for CONNECT through to the stub origin, for absolute-form GET, for the 8 KiB cap,
      for a malformed request line, for the 502-on-require-down case, and for a second pipelined
      request not being proxied
- [x] run `mise run check` - must pass before task 7

➕ `NextHop` returns `Pin<Box<dyn Future>>` rather than `async fn`: an `async fn` in a trait is not
dyn-compatible, and the front ends hold the dialer as `Arc<dyn NextHop>` so it can be swapped for
Task 8's without threading a type parameter through `DaemonState` and every test. One box per dial.

➕ `spawn_frontends(live, listen)` takes the published cells, not `StateHandle`: the listeners must
exist before the state task so the state task can own and rebind them. `daemon::start_on(paths,
listen)` is the same start path with explicit addresses - every test uses it with port 0, so no test
touches 7890/7891, and `Daemon::listen()` reports what the kernel actually handed out. `state::spawn`
now takes one `StateConfig` instead of the `spawn`/`spawn_with_timeout` pair.

➕ Until Task 8 lands, the dialer is `DirectHop`, which dials the destination directly whatever the
decision, and the SOCKS listener accepts and closes. Both are replaced in place (Tasks 8 and 7); the
`UpstreamDown` path is proven here with the `DownHop` double from the harness.

➕ `Upstream` (parsed in `proxy/mod.rs`) is validated when `set_upstream` is issued, not at commit:
`ConnCtx.upstream` is a `SocketAddr`, so `socks5://<ip>:<port>` is now the accepted form and a
hostname is rejected with `ErrKind::InvalidArgs`. `LiveUpstream` publishes it beside `LiveRules`,
both bundled in `Live` alongside `HealthHandle` and `EventTx`; `Live::accepted()` is the single place
a `ConnCtx` is built. Until an init script names one, the published address is `NO_UPSTREAM`
(`127.0.0.1:0`), which fails to dial at once. `staging::FailedCommand` gains `set_upstream` and
`set_listen` so a run rejected on either is reported by name, and `Listen` moved from `staging.rs` to
`proxy/mod.rs`. `BindState` in `status` is now derived from the front ends themselves.

➕ Beyond the listed files: `nhop/src/lib.rs` exports `proxy`, `daemon/state.rs` and
`daemon/staging.rs` are modified as above, `nhop/tests/http_proxy.rs` holds the socket-level tests,
and `nhop/tests/init_run.rs` plus the `cli` tests move to ephemeral front-end ports. The harness
carries `#![allow(dead_code)]` because each test binary compiles it separately and none uses all of
it, and it adds two `NextHop` doubles (`StubHop`, `DownHop`) that Tasks 7 and 8 reuse.

### Task 7: SOCKS5 front end

**Files:**
- Create: `nhop/src/proxy/socks5.rs`
- Modify: `nhop/src/proxy/mod.rs`

- [x] no-auth handshake and `CONNECT` for address types IPv4 (`0x01`), domain (`0x03`) and IPv6
      (`0x04`); reject `BIND` and `UDP ASSOCIATE`
- [x] reply codes: success `0x00`, general failure `0x01`, host unreachable `0x04`, command not
      supported `0x07`, address type not supported `0x08`. The success reply carries ATYP `0x01`
      with BND.ADDR `0.0.0.0` and BND.PORT `0` - deliberate, the tunnel is opaque
- [x] pass the **domain name** to the upstream when the client sent one - never resolve locally
      first, because internal names only resolve inside the upstream's network
- [x] `UpstreamDown` renders as reply code `0x04` per Technical Details
- [x] byte-layout notes are the one place `//` comments are allowed
- [x] write tests for the handshake and each address type against the shared stubs
- [x] write tests asserting the exact reply bytes for success and for `BIND`
- [x] write a test asserting a domain-type request reaches the stub upstream as a name, not an IP
- [x] run `mise run check` - must pass before task 8

➕ The name-not-an-IP assertion is made at the `NextHop` boundary, not against `StubSocks5`: the
dialer wired into the front ends is still Task 6's `DirectHop`, so nothing in this task can put
bytes on a SOCKS5 upstream. `a_domain_request_reaches_the_next_hop_as_a_name` asserts `StubHop`
was handed `Host("example.com")` verbatim, which is the same property one boundary earlier -
resolving locally would have turned it into an IP. Task 8 carries the name the rest of the way and
asserts it on `StubSocks5.requests()`.

➕ Parsing (`greet`, `request`) and reply writing (`answer`, `chosen`) are generic over
`AsyncRead`/`AsyncWrite` rather than taking `TcpStream`, so the byte-level cases are unit tests over
slices; `serve` keeps `TcpStream` because `copy_bidirectional` relays it. `Reply` owns the five
codes in one place, and a malformed domain (non-UTF-8 or zero length) answers `0x01` rather than
`0x08` - the address type was served, its content was not.

➕ A greeting that offers no supported method, or names another SOCKS version, is answered
`[0x05, 0xff]` and closed. `daemon/mod.rs` now hands `accept_socks` the same `Live` and
`Arc<dyn NextHop>` the HTTP front end gets, replacing the accept-and-close loop in place.

### Task 8: Upstream dialer and health state

**Files:**
- Create: `nhop/src/upstream/mod.rs`, `nhop/src/upstream/health.rs`
- Modify: `nhop/src/daemon/state.rs`

- [x] implement the `NextHop` trait from Task 6 over `tokio_socks`, honouring the constants in
      Technical Details; this replaces the test double, it does not introduce a new call path
- [x] `health.rs` owns the verdict as `{ state: Up|Down, changed_at: SystemTime }` - `SystemTime`,
      not `Instant`, because `status` and `doctor` must render it as RFC3339
- [x] transitions exactly as specified: one failure (real dial or probe) flips Down, one success
      flips Up, no probing while Up, probe interval injectable for tests
- [x] while Down, decisions are made without dialling: `Prefer` goes direct at once, `Require` fails
      at once with `UpstreamDown`
- [x] a `Require` or `Prefer` dial failure while the verdict is Up marks the upstream Down; `Prefer`
      additionally falls back to a direct connection for that connection
- [x] write tests with the upstream at a closed port: `Prefer` reaches the direct stub, `Require`
      returns `UpstreamDown`
- [x] write a test asserting the flip back to Up once the stub upstream starts accepting
- [x] write a test asserting a dial to a black-holed address fails within 3 s
- [x] run `mise run check` - must pass before task 9

➕ `HealthHandle` moved from `proxy/mod.rs` to `upstream/health.rs`, which is what "health.rs owns
the verdict" requires: the handle now publishes `Health { state, changed_at }` as one unit, so the
verdict and the instant it settled cannot drift apart. `changed_at` moves only when the verdict
turns over, via `ArcSwap::rcu` so concurrent dial failures cannot lose the transition. `state.rs`
drops its own `health_changed_at` field and renders both from that one snapshot.

➕ The probe is a single loop started with the dialer rather than a task spawned on each Down
transition: it wakes every interval and probes only while the verdict is Down. A daemon starts Down,
so without it nothing would ever discover an upstream that is up - a claim-a-flag-on-transition
design never probes before the first dial failure. `UpstreamHop` aborts the loop on drop.

➕ `UpstreamHop` reads the upstream address from `LiveUpstream` at dial time rather than from
`ConnCtx`: `NextHop::dial` takes no context (Task 6 fixed that signature) and the verdict must be
current at dial time, not at accept time. `DirectHop` is removed - `Decision::Direct` and
`Decision::Never` dial exactly as it did, and `Decision::Upstream { class: Never }` is served the
same way rather than by a wildcard arm.

➕ `nhop/tests/upstream_dialer.rs` added: the stub SOCKS5 upstream lives in the Task 6 harness, so
every case needing one is an integration test there rather than a unit test under `src/`. It also
carries the assertion Task 7 deferred - a domain request reaches `StubSocks5.requests()` as
`{atyp: 0x03, host: "example.com"}`, never resolved locally. `nhop/Cargo.toml` gains `tokio-socks`,
and the two front-end test files import `HealthHandle` from its new module.

### Task 9: Structured logging and `nhop logs`

**Files:**
- Create: `nhop/src/logging.rs`
- Modify: `nhop/src/daemon/mod.rs`, `nhop/src/cli/mod.rs`

- [x] initialise `tracing-subscriber` with the JSON formatter over
      `tracing_appender::rolling::daily(state_dir, "nhop.log")`, keeping 7 files - daily, because
      `tracing-appender` has no size-based rotation; the Filesystem contract says the same
- [x] emit one event per connection decision whose fields are exactly `EventView` from the IPC
      contract; never log request bodies, headers or credentials
- [x] `nhop logs` prints the current file and the kept rotations in chronological order; `-f`
      follows; `--since <dur>` accepts `humantime` durations (`15m`, `2h`, `3d`) and exits 4 on a
      malformed value; `--json` emits raw lines
- [x] write tests for the `--since` filter and the malformed-duration exit code over a fixture file
- [x] write a test parsing emitted lines into a `deny_unknown_fields` struct matching `EventView`
- [x] run `mise run check` - must pass before task 10

➕ `logging::start` is called from `daemon::run` only, not from `start`/`start_on`: installing a
process-wide subscriber is a one-shot, and every test starts several daemons in one process. Tests
build the same subscriber with `logging::subscriber(paths)` and scope it with
`tracing::subscriber::with_default`, so what they assert on is the daemon's real formatter and
appender. The filter is the constant `nhop=info`, read from no environment variable, so a log line
never depends on the shell a test ran in.

➕ Beyond the listed files: `proxy/mod.rs` gains `Routed`, and `proxy/http.rs` and
`proxy/socks5.rs` call it. A decision is only made in a front end, so that is the only place one
event per connection can be emitted. `Routed::begun` captures the verdict when the decision is
made, `Routed::ended` measures the connection and writes the line; Task 12 adds the
`ctx.events.publish` call to the same place. Both front ends now hand the relay to an inner `relay`
function so a refused dial is answered *and* reported as the connection's error - `serve` therefore
returns `Err` on a refusal where it returned `Ok` before, which nothing reads.

➕ tracing cannot record a null, so an absent `rule_index`, `class` or `error` is an absent field
rather than `"field":null`; the `deny_unknown_fields` test covers both shapes and `logged()` reads
either back into an `EventView`. The wire spellings the log uses are pinned to the serde spellings
by `the_logged_names_are_the_names_the_wire_uses`.

➕ `nhop/tests/decision_log.rs` added: nothing under `src/` can prove the front ends emit at all,
because that needs a real connection through a running daemon and a process-wide subscriber. Its
own test binary installs one and asserts that an HTTP tunnel and a SOCKS5 relay leave exactly one
line each, with the decision they were routed by.

⚠️ Pre-existing flake, not introduced here and not fixed here: the Task 5 state tests time out in
`await_load_id` (`PATIENCE` = 2 s) when the machine is loaded enough that the `/bin/sh` handshake
script does not reach its first write in time. Reproduced identically on the commit before this
task by running four `cargo test -p nhop --lib` processes at once; a single `mise run check` is
green.

### Task 10: `status`, `rules`, `test` and the system-proxy reader

**Files:**
- Create: `nhop/src/cli/status.rs`, `nhop/src/cli/explain.rs`, `nhop/src/cli/system_proxy.rs`

- [x] create `system_proxy.rs` with `trait SystemProxyReader { fn read(&self, service: &str) -> Result<SystemProxy> }`
      and a real implementation shelling out to `networksetup -getwebproxy/-getsecurewebproxy/-getsocksfirewallproxy`,
      executed by the **daemon**. Task 13 extends this same module with the write path; do not add a
      second parser
- [x] `status` returns `StatusView` exactly as defined in the IPC contract, built by a pure
      `status_json(state, proxy) -> serde_json::Value` so it can be tested without invoking
      `networksetup`
- [x] `rules` returns `RuleView` in declaration order; `test <host:port>` returns `DecisionView`
      without opening any connection
- [x] all three honour `--json`
- [x] write tests for `test` covering a require match, a prefer match, a never match and no match,
      asserting the exact `DecisionView` including `rule_index`
- [x] write a golden test comparing `status_json` over a fixed state and a fixed `SystemProxy`
      fixture against a checked-in `nhop/tests/golden/status.json`, byte for byte
- [x] write tests parsing `networksetup` fixture strings into `SystemProxy`
- [x] run `mise run check` - must pass before task 11

➕ The reader is injected rather than reached for: `StateConfig` carries
`proxy: Arc<dyn SystemProxyReader>`, `daemon::start_on` wires the real `Networksetup` and
`StateConfig::default()` wires `NoSystemProxy`, which answers "every setting off" without spawning
anything. Without that seam every unit test asserting a `StatusView` would depend on the proxy
settings of the machine running it - and on the operator's machine those are set. `NoSystemProxy` is
also the honest reader anywhere `networksetup` does not exist. A read that fails is reported as every
setting off, because the contract has no field for the failure; naming it is Task 11's
`system_proxy` check.

➕ `NetworkService` moved from `cli/mod.rs` into `system_proxy.rs`, where the rest of the macOS
surface lives, and gained `Default` (`Wi-Fi`) plus its own `EmptyService` rejection instead of
borrowing `InvalidDestination`. `ProxyKind::read_flag` is the single place the three `networksetup`
flags are spelled, so Task 13 adds `write_flag` beside it rather than a second table. The daemon
reads the default service; `--service` stays a Task 13 concern.

➕ `test` renders `Ruleset::decide` and never consults the health verdict: `DecisionView` carries no
health field, and the four cases this task pins are the four rule outcomes. A `prefer` match
therefore answers `upstream` even while the upstream is down - that is the ruleset's answer, and the
fallback belongs to the dialer. `next_hop` is the upstream as the init script wrote it for an
upstream decision, `host:port` otherwise, and `none` when no upstream has been named.

➕ `status_json` is `status_view` one step further, so the golden file carries the keys in the order
`serde_json::Map` holds them (alphabetical), not the order the contract lists them. `DaemonStatus` is
the pure input: everything `status` reports that the daemon knows without asking macOS.

➕ Beyond the listed files: `daemon/state.rs` takes the reader, serves `Command::Test` and delegates
both view builders to `cli/explain.rs`; `daemon/mod.rs` wires `Networksetup`; `cli/mod.rs` declares
the three modules and imports `NetworkService`; `BindState::is_bound` became public because
`status_view` renders it. The cli test that used `test` as a stand-in for an unserved command now
uses `doctor`, which Task 11 will take over in turn.

### Task 11: `nhop doctor`

**Files:**
- Create: `nhop/src/cli/doctor.rs`

- [x] emit exactly seven `CheckView` objects, in this order, with these `name` values:
      `daemon_reachable`, `ports_bound`, `system_proxy`, `upstream_reachable`, `init_file`,
      `last_load`, `log_writable`
- [x] the Local Network check is the subtle one: on `EHOSTUNREACH` when connecting to the upstream,
      report a probable Local Network permission denial with the remedy, because macOS reports that
      denial as a routing error
- [x] exit codes: 0 when all pass; 3 when the only failures are upstream-reachability checks;
      otherwise 1
- [x] write tests over the aggregation function with injected results: all pass, only upstream
      fails, several fail - asserting exit code, output order and the seven names
- [x] run `mise run check` - must pass before task 12

➕ `Check` owns the seven names and `CHECKS` their order, so `report(&[Finding])` renders the fixed
seven whatever order they were observed in. A check nothing observed renders failed with "not
checked" - which is exactly what `doctor` prints when the daemon never answered and only
`daemon_reachable` could be made. `exit_of` is the aggregation the plan asks for: it counts failures
and failures beyond `upstream_reachable`, so 0/3/1 fall out of the two counters.

➕ The daemon runs six checks synchronously in the state task and spawns the seventh: dialling the
upstream must not block the actor, and it is the only check that waits on the network. `Command::Doctor`
therefore holds its `oneshot` the way `Reload` does. `daemon_reachable` is answered by the daemon
having answered at all; when it does not answer, `cli::diagnose` builds the report locally from
`doctor::unreachable` and exits 1 per this task's own exit rule rather than the transport row of the
exit table - a doctor that prints nothing when the daemon is down would diagnose nothing.

➕ `upstream_reachable` dials TCP rather than completing a SOCKS5 handshake: `EHOSTUNREACH` is what
the Local Network denial surfaces as, and it surfaces at connect. `tokio_socks` would bury the
`ErrorKind` this check exists to name. `system_proxy` passes only when macOS points http and https at
the HTTP front end and socks at the SOCKS5 one - "some proxy is configured" would pass a machine
still pointing at ClashX - and it is the check that names a `networksetup` read failure Task 10
deliberately reported as "every setting off".

➕ `log_writable` reads the mode of the state directory instead of writing a probe file, so `doctor`
never leaves anything behind. Beyond the listed file: `cli/mod.rs` gains `diagnose` and the `doctor`
module, `daemon/state.rs` serves `Command::Doctor` and gains a `listen()` helper `status` shares.
The two tests that used `doctor` as a stand-in for an unserved command moved on - the state test to
`Command::Subscribe` (Task 12), the cli one to a `render` call, since no JSON-capable verb answers a
daemon error any more.

### Task 12: `nhop tail`

**Files:**
- Create: `nhop/src/cli/tail.rs`
- Modify: `nhop/src/daemon/ipc_server.rs`, `nhop/src/proxy/mod.rs`

- [x] `Command::Subscribe` switches that connection to stream mode - the only multi-response command
- [x] each subscriber gets a bounded `mpsc::channel(256)`; publish with `try_send`; on `Full`
      increment a per-subscriber `dropped` counter and emit an `EventView` with `error` set to
      `"dropped <n>"` when the queue drains; a subscriber whose write fails is removed
- [x] the front ends publish via `ctx.events` on every decision; a slow subscriber must never make a
      connection handler await
- [x] write tests for subscribe and unsubscribe, and a test filling the queue with a non-reading
      subscriber that asserts the handler does not block and the drop count is reported
- [x] run `mise run check` - must pass before task 13

➕ `EventTx` is now the fan-out itself: Task 6's `Discarded`/`Queued` pair collapses into a list of
subscribers behind a `std::sync::Mutex`, so `subscribe()` is the single way in and "nobody is
listening" is the same code path as a hundred readers. `publish` clones, `try_send`s and drops the
subscribers whose queue is closed - it contains no `await` at all, which makes "a slow subscriber
never makes a connection handler await" a property of the signature rather than of timing.

➕ The drop report rides the next event that reaches the subscriber instead of being an event of its
own: nothing is retained about what was lost, so a standalone report would have to invent a host and
a port. An event that carried its own failure keeps it - `dropped 2: reset by peer`.

➕ `Command::Subscribe` never reaches the state task. `ipc_server` intercepts it on the connection it
arrived on and holds that connection in `stream_events`, which selects on the subscriber queue and
on a read of the client half: a client that hangs up is noticed at once and unsubscribes, while one
that merely stops reading is noticed at the next publish. The state task keeps an explicit arm
answering `ErrKind::Internal` and naming where the command is served, so the match still lists every
variant. Task 3's `unserved()` is gone with it - the daemon now serves every command.

➕ `cli/tail.rs` keeps the whole `UnixStream` inside its `BufReader` rather than splitting it:
half-closing the write side is how a client says it is gone, so the writer must outlive the stream.
`client::connect` became public so `tail` reuses the same "no daemon is listening" mapping `ask`
uses. `Decisions::next` returns a `Response` rather than an `EventView`, so `follow` hands anything
that is not an event to the existing `render` and exits by the same table - a daemon error ends the
stream with its own code instead of being swallowed.

➕ Beyond the listed files: `daemon/state.rs` publishes the fan-out through `Live::events()`,
`cli/mod.rs` declares the module and dispatches `tail`, and `cli/client.rs` exports `connect`.
`nhop/tests/tail_stream.rs` added: a front end only publishes through a real connection, so nothing
under `src/` can prove `ctx.events` is where the decision goes. It runs `cli::run` and the traffic
concurrently in one task - `&mut dyn Write` is not `Send`, so the CLI future cannot be spawned - and
reads the printed documents out of a shared buffer.

### Task 13: `nhop proxy on|off`

**Files:**
- Modify: `nhop/src/cli/system_proxy.rs`

- [x] `proxy on` sets HTTP and HTTPS proxies for the service to the HTTP listen address and the
      SOCKS proxy to the SOCKS listen address, then sets the bypass list to the named constant in
      Technical Details
- [x] `proxy off` disables all three for that service
- [x] both refuse to run without effective root and print the exact `sudo` invocation instead of
      prompting
- [x] the service name is a parameter defaulting to `Wi-Fi`
- [x] reuse the reader from Task 10 for `proxy status`; do not add a second parser
- [x] write tests asserting the generated argv for `on` and `off`, including the bypass argv matching
      the constant verbatim
- [x] run `mise run check` - must pass before task 14

➕ The write path is a pure pair of builders - `enabling(listen, service)` and `disabling(service)`
returning `Vec<Invocation>`, where `Invocation { flag, arguments }` renders its own argv - plus one
`apply` that runs them in order and stops at the first refusal. That is what lets the tests assert
the argv verbatim without `networksetup` existing. `ProxyKind` now spells `write_flag` and
`state_flag` beside `read_flag`, so the three settings are still named in exactly one place: `on`
uses `-setwebproxy`/`-setsecurewebproxy`/`-setsocksfirewallproxy`, which turn a setting on as they
move it, and `off` the matching `-set*state ... off`.

➕ `proxy on` asks the running daemon for its `status` and points macOS at the addresses it reports
rather than at the 7890/7891 defaults: `nhop listen` can move the front ends, and Task 11's
`system_proxy` check compares the settings against those same addresses. With no daemon listening it
exits 2 by the transport row of the exit table. `sudo` keeps `HOME` on macOS, so root reaches the
operator's socket rather than root's own state directory.

➕ `Privilege::current()` reads the effective uid through `libc::geteuid` - std exposes no euid - so
`libc` joins the workspace dependencies. Both writes check it before asking the daemon anything,
which is also what keeps `cargo test` from touching the machine's real settings: the refusal test
returns early when it happens to run as root.

➕ Beyond the listed file: `cli/mod.rs` dispatches `proxy` and loses `unserved` - `proxy` was the
last verb answering "not implemented yet", so the CLI now serves every subcommand it declares.
`proxy status` renders the Task 10 reader's answer as three lines and takes no `--json`, because
Task 4 fixed that verb's flags to `--service`.

### Task 14: Packaging - LaunchAgent, signing, install and uninstall

**Files:**
- Create: `scripts/build-signed.sh`, `packaging/com.pavel-karpovich.nhop.plist`,
  `packaging/nhop.init.example`
- Modify: `README.md`

- [x] `build-signed.sh` builds release, codesigns with the Developer ID identity (team id passed as
      an argument, never hardcoded), verifies with `codesign --verify --strict`, prints the identifier
- [x] the plist sets `RunAtLoad=true` and `KeepAlive=true` (restart-on-crash is launchd's
      responsibility; no timing is asserted) and points `StandardOutPath`/`StandardErrorPath` at the
      state directory
- [x] `nhop.init.example` is a commented fish script using the canonical rule surface with **clearly
      marked placeholders** (`nhop upstream socks5://192.0.2.10:1080  # replace`, `example.com`
      hostnames). It is illustrative, not ready to run, and the file says so on its first line
- [x] README documents install, the one-time `sudo nhop proxy on`, granting Local Network on first
      run, and the uninstall order (`proxy off` **before** removing the agent)
- [x] write a test asserting the plist parses and contains the expected label, `KeepAlive` and
      program path shape
- [x] run `mise run check` - must pass before task 15

➕ The plist carries `{{HOME}}` where an absolute home directory has to go: launchd expands neither
`~` nor `$HOME`, so a checked-in LaunchAgent cannot name the operator's home and the install step
substitutes it with one `sed`. A third test asserts `{{HOME}}` is the *only* placeholder in the file,
so a token added later cannot silently survive that substitution.

➕ The plist also sets `EnvironmentVariables.PATH`. launchd's default PATH omits Homebrew, so
`#!/usr/bin/env fish` in the init script would not resolve under the agent even though it resolves
from a terminal - the same class of "works by hand, fails under launchd" failure the Local Network
permission has. The redirects are `launchd.out.log`/`launchd.err.log`, not `nhop.log*`, because
`logging::files` picks up everything named `nhop.log*` and `nhop logs` would otherwise print
launchd's stderr interleaved with the daemon's JSON lines.

➕ The example's shebang is on the second line: the first line is the "not ready to run" notice this
task requires, and a shebang that is not the first line is not a shebang. That is what makes the
file inert if copied unedited - the README's copy step says to delete that line so the shebang leads.

➕ `build-signed.sh` resolves the identity from the team id rather than taking an identity name:
`security find-identity -v -p codesigning` is filtered to the `Developer ID Application` line whose
name ends in `(<team id>)` and signs by its hash, so nothing about the operator's certificate is
written down here. The lookup pipeline ends in `|| true` because `set -euo pipefail` would otherwise
abort on the failing `grep` before the "no such identity" message could be printed. The signing run
itself is a Post-Completion step: `codesign --sign` needs keychain access, which this session must
not prompt for.

➕ Beyond the listed files: `nhop/tests/packaging.rs` holds the plist test - nothing under `src/`
reads the packaging directory. It parses with `plutil -convert json -o -` and asserts over the JSON,
rather than adding a plist dependency for one file; when `plutil` is absent the two parse tests
return early, as the Task 13 `proxy status` test already does for `networksetup`, while the
placeholder test still runs. The README's `## Status` section ("implementation not started") is
removed rather than updated - Task 16 owns the rest of the README, and `## Install`/`## Uninstall`
are added here under the exact headings it requires.

### Task 15: Verify acceptance criteria

**Files:**
- Create: `nhop/tests/acceptance.rs`

- [x] create exactly four `#[tokio::test]` cases named `require_reaches_upstream`,
      `prefer_reaches_upstream`, `prefer_falls_back_direct_when_upstream_closed`,
      `require_fails_when_upstream_closed`, using the Task 6 harness
- [x] each case also asserts that `Command::Test` returns the same `DecisionView` variant and
      `rule_index` that the real connection then exercised (upstream stub vs direct stub)
- [x] assert both listeners remain bound after `Off` and that a client on the SOCKS port then gets a
      direct connection rather than a refusal
- [x] assert `doctor --json` emits the seven named checks
- [x] `cargo test --test acceptance` passes 4/4
- [x] run the full suite: `mise run check`

➕ "the decision the real connection exercised" is read off the decision stream, not inferred from
which stub was reached: every case subscribes to `Live::events()` before it drives traffic and
asserts the published `EventView` carries the same `decision`, `rule_index` and `class` as
`Command::Test` answered. That is the same pairing for all four cases, including the one where the
two stubs disagree - `prefer_falls_back_direct_when_upstream_closed` is answered `upstream` by
`test` *and* routed as `upstream` by the connection, and still lands on the direct stub, because the
fallback belongs to the dialer and not to the ruleset (Task 10 settled that `test` never consults
the health verdict). The stub that was reached is asserted beside it, so the divergence is pinned
rather than papered over.

➕ All four cases use one rule shape - `port <ephemeral port of the origin stub>` - and one client
shape, an IPv4 `CONNECT` on the SOCKS5 front end. Only the class and the state of the upstream
differ between them, which is what makes "upstream stub vs direct stub" an exact comparison; the
domain-name path through a real upstream is already pinned by Task 8's `upstream_dialer.rs`.

➕ The two upstream-reachable cases set the verdict with `live().health().set(Up)` rather than
waiting for a probe: `daemon::start_on` wires the production `PROBE_INTERVAL` of 5 s and a daemon
starts Down, so waiting would add five seconds per case to prove what Task 8's
`the_verdict_flips_up_once_the_upstream_answers_a_probe` already proves. The two upstream-closed
cases leave the verdict at its Down default, which is the state they are about.

➕ The `Off` and `doctor --json` assertions live inside two of the four cases rather than in cases of
their own, because this task fixes the file at four tests. `Off` is asserted by
`require_fails_when_upstream_closed`, where clearing the rules turns the refusal into a direct
connection on the same port - the one place both halves of "the daemon must keep listening when
rules are cleared" are visible at once. `doctor --json` is asserted by `require_reaches_upstream`,
the only case with a live upstream, so `upstream_reachable` passes there rather than being reported
as a routine failure.

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
