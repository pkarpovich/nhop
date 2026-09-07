# `require` dials through a degraded upstream

## Overview

A `require` rule means "this destination must traverse the upstream, there is no direct fallback". Today it is gated by the health verdict: while the verdict is `Down`, `required()` returns `Dialled::Refused` without opening a socket (`nhop/src/upstream/mod.rs`, `required()`). That gate turns a *degraded* upstream into a *dead* one.

Observed in production on 3 September 2026. The upstream is a SOCKS5 proxy inside a Parallels VM on the same Mac. The host ran out of memory (54 GB taken by one audio job, 28 GB of swap in use) and 7.6 of 10 cores were burned by orphaned busy-loops, so the VM's pages were pushed into the compressor and its virtual CPU stalled on every touched page. The VM answered ICMP in 1-10 s. Successful SOCKS dials through it took 1386 ms, 2097 ms, 2233 ms, against a normal 30-300 ms - straddling `UPSTREAM_CONNECT_TIMEOUT`, which is 2 s.

The result: one dial past 2 s flipped the verdict `Down`, every `require` destination was then refused at 0 ms, two patrol probes 1 s apart flipped it back `Up`, the next real dial failed again. The verdict turned over about 40 times in 20 minutes and every work domain returned `502 Bad Gateway` for roughly three hours - while the upstream could have served all of them, slowly. `prefer` destinations (Teams, Slack, Zoom) silently fell back to direct and the user never noticed them.

The fix is to stop gating `require` on the verdict. A refusal only saves the user a dial timeout, and that is a win only when the upstream is genuinely dead; when it is merely slow, the refusal is strictly worse than the wait. `prefer` keeps its gate and its short timeout, because fast fallback to direct is its entire purpose.

This design was reviewed by an external model (`codex exec`, GPT-5.5, read-only over this repo) after being drafted here; four refinements below come from that review and are marked. Everything a task needs is written into this plan - the review is provenance, not a source to consult.

### Non-goals

- **No tri-state verdict.** `Up`/`Degraded`/`Down` was considered and rejected. "Degraded" is a policy judgment, not a health fact, and the policy is already expressed by the rule classes: `prefer` means "do not wait long", `require` means "no direct fallback". A third state would touch the IPC `HealthState` contract (`nhop-ipc/src/view.rs`), `status`, `doctor`, `logging`, `tail` and their tests, and would still hang off an arbitrary latency threshold.
- **No splitting of the SOCKS dial into phases.** The ideal model is a short budget for TCP-connect plus the SOCKS greeting and a longer one for the proxy's onward CONNECT (the part that depends on the VPN and the destination). `tokio_socks::Socks5Stream::connect` offers no phase boundary, so this would mean hand-rolling a no-auth SOCKS5 handshake. Revisit only if slow destinations are observed poisoning the verdict after this change.
- **No circuit breaker for `require`.** It would bound the descriptor cost of a dead upstream, but it reintroduces synthetic outages for the one class that has no fallback - the exact defect being fixed.
- **No change to `UpstreamDown`'s wording, to the HTTP 502 mapping (`nhop/src/proxy/http.rs`, the `UpstreamDown::carried_by` site) or to the SOCKS5 `0x04` mapping (`nhop/src/proxy/socks5.rs`, `refusal()`).** A `require` destination that cannot be served still fails the same way to the client.
- **No verdict events on the IPC wire.** Verdict transitions are written to the log file and rendered by `nhop logs`; `nhop tail`, `Command::Subscribe` and the `Response` vocabulary are untouched.
- **No configurability.** Both timeouts stay compile-time constants, like every other timing constant in this crate.

### Accepted trade-off

With the gate gone, a genuinely dead upstream costs one `require` dial per connection instead of an instant refusal. Measured on 7 September 2026 against the real upstream host, with `nc` and `curl` from the Mac (a `python3` socket inside an agent sandbox is refused the LAN and reports a false instant `EHOSTUNREACH` - do not measure with it):

| Upstream state | What the kernel does | Cost of one `require` dial |
|---|---|---|
| VM running, proxy not started | SYN answered late | about 1.0 s (3 of 3, and `curl` agrees at 1.007 s) |
| VM powered off, first ~50 s | SYN queued behind an ARP that never answers; the kernel never fails the connect on its own (a 40 s wait ran to the end) | the full `REQUIRE_CONNECT_TIMEOUT`, 10 s |
| VM powered off, afterwards | neighbour marked unreachable, connect fails at once | under 30 ms, until the kernel re-probes and the 10 s window briefly returns |

A browser opening a dozen parallel connections to a `require` domain during that first window will hold a dozen descriptors for 10 s each. This is affordable: the daemon raises `RLIMIT_NOFILE` to 16384 at startup (`nhop/src/daemon/open_files.rs`), and the descriptors are released on timeout rather than parked. The budget's value is the lever here: 10 s covers the deepest stalls seen in the incident (ICMP answered in up to 10 s), a smaller value would shorten the powered-off window at the cost of refusing the worst stalls.

It also contradicts the README's `require` description (`README.md`, "## Rule classes"), which this plan rewrites, and a comment in the user's own init file outside this repo, which is listed under Post-Completion. Failing instantly when the VM is off and serving when the VM is slow are not simultaneously achievable: without dialling, the two are indistinguishable.

## Skills to invoke

Load each skill below with the Skill tool and follow its conventions before implementing any task in this plan. The Code-Quality Rules section further down is the binding form of these conventions for this plan; on any disagreement the checklist wins.

- `rust-style` - every file this plan touches is Rust; its rules on `for` loops, `let ... else`, explicit destructuring, newtypes, enums-over-bools and no-wildcard matches are the house contract and a change that breaks one reads as foreign.
- `rustdoc` - every new public item (`UpstreamBudget`, `EffectiveHop`, `VerdictCause`, the new constants) needs a doc comment in RFC 1574 shape.
- `rust-analyzer-ssr` - for navigation when changing `HealthHandle::set` and `Dialled`, whose call sites span `nhop/src`, `nhop/tests` and the test support module. Without an LSP, `grep -rn 'health.set(\|\.set(HealthState\|Dialled::\|\.timed(' nhop/src nhop/tests` plus `cargo check --all-targets` enumerates the same sites.

## Context (from discovery)

Line numbers below are as of commit `fc9753b`, before Task 1. Tasks 1-5 all insert into `nhop/src/upstream/mod.rs`, so anchor by the named symbol when a number no longer lands on it.

- **The gate to remove** is `required()` in `nhop/src/upstream/mod.rs` (`:136-154`). Its sibling `preferred()` (`:156-173`) keeps its gate unchanged.
- **The single timeout** is `UPSTREAM_CONNECT_TIMEOUT` (`:22`), applied in `through()` (`:239-243`) around the whole of `Socks5Stream::connect`. Both `required()` and `preferred()` call `through()`; those are its only two production call sites.
- **`failed_dial()` (`:263`) already encodes the invariant this plan leans on**: every SOCKS reply *about the destination* becomes `DialFailure::Destination`, everything else `DialFailure::Upstream`. A `Destination` failure therefore proves the upstream is serving. The timeout path is blind and always becomes `DialFailure::Upstream` - correct for now, and the reason the phase split is a non-goal.
- **`NO_UPSTREAM`** (`nhop/src/proxy/mod.rs:36`) is `127.0.0.1:0`, published by `LiveUpstream::default()` (`nhop/src/daemon/state.rs:93`) until an init script names an upstream. Its own doc comment says port zero cannot be dialled, which is why the refusal must survive for this address alone - it is a configuration absence, not a health judgment. *(from the Codex review)*
- **`HealthHandle::set` (`nhop/src/upstream/health.rs:70`) is the only writer of the verdict** and the only place that can see a turnover: its `arc_swap::rcu` closure compares the settled state with the new one to decide whether `changed_at` moves, and `rcu` returns the replaced value, currently discarded as `_previous`. `rcu` retries its closure on contention, so the closure must stay pure. **Production call sites are exactly three**: `required()` (`:149`), `preferred()` (`:168`) and the patrol's `settle` (`:390`). **Test-only seeding sites**: the unit helper `hop()` in the same file (`:434`), `verdict()` in `nhop/tests/upstream_dialer.rs:30`, `nhop/tests/acceptance.rs:225` and `:256`, and the unit tests in `health.rs` - these seed a starting verdict and observe nothing.
- **`patrol` already guards its sequences by the probed address** (`:376-393`): a `Pending` records both the target state and the address it was made against, and a confirming probe must match both. Real dials have no such guard, so a slow result from a since-replaced upstream can move the verdict of the new one. *(from the Codex review)* Note also that **the patrol's first probe goes out immediately on start**, before any interval sleep; what stops a probe sequence from closing during a test is a long *confirm delay*, not a long interval.
- **`Dialled` (`nhop/src/proxy/mod.rs:421`) is where "what the dial did" belongs.** The CLAUDE.md invariant is explicit that this must be reported by the dial site and never re-derived afterwards from the error or from re-reading the verdict. The effective path of a `prefer` connection has exactly the same property, which is why it belongs on the same type rather than being inferred in the renderer. *(from the Codex review)*
- **`connect_ms` is wall-clock**: both front ends time the dial with `std::time::Instant` (`nhop/src/proxy/socks5.rs:129`, `nhop/src/proxy/http.rs:215`) and hand the elapsed time to `Dialled::timed`. A paused tokio clock does not move it, so no test may assert a `connect_ms` value under `tokio::time::pause`.
- **tokio's `test-util` feature is not enabled** anywhere in the workspace (`Cargo.toml` feature list: `rt-multi-thread, macros, net, io-util, process, signal, time, sync`), so `tokio::time::pause` and `#[tokio::test(start_paused = true)]` do not compile today. Task 1 adds it as a dev-dependency feature.
- **The log line renders the rule's decision, not the path taken.** `render_event` (`nhop/src/cli/mod.rs:911`) prints `decision_name` + `rule_name`, so a `prefer` connection that fell back to direct is logged as `upstream via rule 19 (prefer)`. During the incident this made it impossible to see from the log that Teams and Slack were working the whole time.
- **`EventView::upstream` is the verdict at the *start* of the connection** (`Routed::begun`, `nhop/src/proxy/mod.rs:358`). A two-minute connection therefore carries a two-minute-old verdict, and reading the log naively shows flapping that never happened. Diagnosis during the incident required filtering to connections under 2 s.
- **`logging::logged()` (`nhop/src/logging.rs:189`) is how a log line becomes a decision again**: it parses the line as JSON, takes the `fields` object and deserializes it as `EventView`. A line whose fields are not an `EventView` yields `None`; `render_log` (`nhop/src/cli/mod.rs:714`) then echoes the raw line. A verdict-transition line written today would come out as raw JSON in `nhop logs`.
- **`EventView` already has a precedent for an added field**: `connect_ms` carries `#[serde(default)]` with a doc comment naming lines written before the field existed (`nhop-ipc/src/view.rs:183`).
- **Golden renderings that must not change**: `logs_renders_a_decision_line_as_text_and_leaves_the_rest_alone` (`nhop/src/cli/mod.rs:1679`) expects `2026-08-03T10:00:00Z  api.example.com:443  upstream via rule 2 (require)  upstream up  9ms  -`; `logs_render_the_dial_time_of_a_line_that_carries_one` (`:1706`) expects the same with `1204ms (dial 37ms)`.
- **Test support**: `Answers` (`nhop/tests/support/mod.rs:215`) has `Always`, `Once`, `AfterOneDrop`, `Never`. `Never` accepts and holds the connection unanswered - a black hole. There is no variant that answers *late*, which is exactly the incident's shape. The accept loop is sequential and spawns one task per served connection. `StubSocks5::client_dials()` excludes patrol probes; `requests()` includes them. `DownHop` fabricates a dial through `Refusal::AfterDialling(Duration)` without waiting, which is how front-end tests already pin `connect_ms`.
- **Tests that pin the behaviour being removed**: `a_require_decision_fails_at_once_while_the_verdict_is_down` and `a_require_refusal_reports_that_nothing_was_dialled` (`nhop/src/upstream/mod.rs:568`, `:585`), `a_require_rule_is_refused_while_the_upstream_is_closed` (`nhop/tests/upstream_dialer.rs:106`) and `no_client_dial_reaches_the_upstream_while_the_verdict_is_down` (`:167`). *(named by the Codex review)*
- **A test that the budget split breaks on its own**: `a_dial_to_a_black_holed_upstream_fails_within_three_seconds` (`nhop/tests/upstream_dialer.rs:388`) dials `require(0)` into a black hole and asserts under 3 s - true only while `require` shares the 2 s budget.
- **`Refusal::BeforeDialling` (`nhop/tests/support/mod.rs:405`) stays**: front-end tests use it to drive the refusal path, and the `NO_UPSTREAM` case still produces it.

## Development Approach

- **testing approach**: Regular - implementation first, then tests for it, within the same task.
- complete each task fully before moving to the next
- make small, focused changes
- **CRITICAL: every task MUST include new/updated tests** for the code it changes. The test bullets listed inside each task are the complete required test set for that task; a task is complete when all of them exist and `mise run check` is green. Extra coverage is welcome but is not a review criterion.
- **CRITICAL: `mise run check` must pass before starting the next task** - no exceptions
- **CRITICAL: update this plan file when scope changes during implementation**

## Code-Quality Rules (verify before marking each task complete)

The `rust-style` and `rustdoc` skills carry no `## Hard rules` block, so the rules below are their section headings distilled into a checklist, merged with this repo's own style contract in `CLAUDE.md`.

### Rust

- no `//` comments anywhere; `///` on public items, `//!` for module docs. The only sanctioned exceptions in this tree are the protocol byte layouts in `proxy/socks5.rs` and `proxy/http.rs`
- no `matches!`, and no wildcard `_ =>` outside `std::io::ErrorKind` - adding an enum variant must break the build
- explicit destructuring always (`let Health { state, changed_at } = ...`), never field-by-field access through a value
- `let ... else` for early returns; `for` loops rather than iterator chains
- newtypes over bare `String`; enums over `bool` parameters - this is why the dial budget is `UpstreamBudget`, not a `Duration` argument or a flag
- shadow rather than rename when narrowing a value
- every new public item (`UpstreamBudget`, `EffectiveHop`, `VerdictCause`, `PREFER_CONNECT_TIMEOUT`, `REQUIRE_CONNECT_TIMEOUT`, `HealthHandle::seed`, `Logged`, `LoggedVerdict`) carries a `///` doc comment whose first line is one sentence; the two timeout constants additionally carry one sentence saying why that value

### Per-task gate

- `mise run check` green: `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`
- `grep -rn '^\s*//[^/!]' nhop/src nhop-ipc/src | wc -l` prints `5` - the baseline, all in `nhop/src/proxy/socks5.rs` byte layouts; the count must not grow
- `grep -rn 'matches!\|_ =>' nhop/src nhop-ipc/src | wc -l` prints `4` - the baseline (`cli/client.rs:59`, `:81`, `cli/doctor.rs:301`, `daemon/mod.rs:138`, all `io::ErrorKind`); the count must not grow

## Testing Strategy

- **unit tests** live beside the code in `#[cfg(test)] mod tests`, as `nhop/src/upstream/mod.rs` and `health.rs` already do; the module already has `destination()`, `closed_port()` and `upstream_answering(reply)` helpers plus the `GRANTED`/`REFUSED`/`GENERAL_FAILURE` reply constants
- **integration tests** go in `nhop/tests/`, sharing `nhop/tests/support/mod.rs` - no new stub types; extend the existing ones
- **paused time**: tests that measure a budget use `#[tokio::test(start_paused = true)]` (current-thread runtime). With the clock paused and every task blocked on socket readiness, tokio advances the clock to the next pending timer, so a 10 s budget elapses in milliseconds of wall time; elapsed time is asserted with `tokio::time::Instant`, never with `std::time::Instant` and never through `connect_ms`
- **real time**: the two `Answers::Slow` tests in Task 4 deliberately run in real time, 3 s each - the only slow tests this plan adds
- bind port 0 everywhere; nothing may touch 7890 or 7891
- scope the logging subscriber with `tracing::subscriber::with_default`, since several daemons run in one test process
- the project has no e2e/UI suite; `mise run check` is the whole gate

## Progress Tracking

- mark completed items with `[x]` immediately when done
- add newly discovered tasks with a leading `+`
- document blockers with a leading `!`
- keep this file in sync with the work actually done

## Solution Overview

Four behavioural changes and two diagnostic ones.

**The dial budget becomes a property of the rule class.** `UpstreamBudget` is an enum with `Prefer` and `Require`, passed into `through()`. `PREFER_CONNECT_TIMEOUT` keeps today's 2 s; `REQUIRE_CONNECT_TIMEOUT` is 10 s. The asymmetry is the whole point: `prefer` is measuring how long to wait before taking the direct route it already has, `require` is measuring how long a user is willing to wait for the only route there is.

**`require` stops consulting the verdict.** `required()` refuses before the network only when the published upstream is `NO_UPSTREAM`; for any configured address it always dials. The verdict is then something `require` *writes*, never something it reads.

**A real dial moves the verdict in both directions.** Today only a failure does and only the patrol can move it up. With `require` dialling unconditionally, its dials are the most direct evidence available: a connection, or a SOCKS reply about the destination, proves the upstream is serving, and both set `Up` immediately without waiting out the patrol's two-probe hysteresis. This is the symmetric half of the existing invariant that one real failure flips `Down` because it is evidence a user already paid for.

**Verdict writes from real dials are guarded by the address they were made against**, matching what `patrol` already does for probe sequences. A dial that started before a reload and lands after it must not move the verdict of an upstream it never touched.

**The log gains the effective path and the verdict transitions.** `EffectiveHop` records which way the bytes actually went, produced at the dial site and carried out on `Dialled` for the same reason `Connect` is. Verdict transitions are logged where the turnover is detected, with the cause that produced them, and `nhop logs` learns to render lines that are not decisions.

## Technical Details

### New vocabulary

```rust
pub enum UpstreamBudget { Prefer, Require }

pub enum EffectiveHop { Direct, Upstream, FallbackDirect }

pub enum VerdictCause { Probe, Dial }
```

`UpstreamBudget` and `VerdictCause` live in the daemon crate (`nhop/src/upstream/`); `EffectiveHop` lives in `nhop-ipc/src/view.rs` beside `DecisionKind` because it is on the wire. `EffectiveHop` has no `Refused` variant: `Connect::Refused` already says no dial was made, and a second spelling of the same fact would let the two disagree.

### Constants

| Constant | Value | Applies to |
|---|---|---|
| `PREFER_CONNECT_TIMEOUT` | 2 s (today's `UPSTREAM_CONNECT_TIMEOUT`, renamed) | `prefer` dials |
| `REQUIRE_CONNECT_TIMEOUT` | 10 s | `require` dials |
| `PROBE_TIMEOUT` | 2 s, unchanged | patrol probes |

### `required()` after the change

Its decision table, given a published upstream address and a rule id:

| Published upstream | Dial outcome | `Dialled` | Verdict write |
|---|---|---|---|
| `NO_UPSTREAM` | not dialled | `Refused(UpstreamDown)` | none |
| configured | connection | `Attempted { hop: Upstream, next: Ok }` | `Up`, cause `Dial` |
| configured | `DialFailure::Destination` | `Attempted { hop: Upstream, next: Err(that failure) }` | `Up`, cause `Dial` |
| configured | `DialFailure::Upstream` | `Attempted { hop: Upstream, next: Err(UpstreamDown) }` | `Down`, cause `Dial` |

`preferred()` keeps its verdict gate and gains the same `Up`-on-success and `Up`-on-`Destination` writes, since the evidence is identical.

### Address guard

Both real-dial writes go through one private method on `UpstreamHop`, `observed(&self, dialled: SocketAddr, state: HealthState)` (gaining a `VerdictCause` argument in Task 6), which re-reads `self.upstream.snapshot()` and writes the verdict only when it still equals the address the dial was made against. `patrol` needs no change: its `Pending` already carries `addr` and compares it.

### The dial reports its path

The shape, fixed here so every task builds the same thing:

- `Dialled::Attempted { hop: EffectiveHop, next: io::Result<TcpStream> }` replaces the tuple variant; `Dialled::Refused(io::Error)` is unchanged.
- `Connect::Attempted { took: Duration, hop: EffectiveHop }` replaces `Connect::Attempted(Duration)`; `Connect::Refused` is unchanged. `Dialled::timed(self, took) -> (Connect, io::Result<TcpStream>)` keeps its signature and moves `hop` across.
- `Routed` gains `hop: Option<EffectiveHop>`, set by `Routed::dialled(&mut self, connect: Connect)` (signature unchanged) and copied into `EventView.hop` by `ended`. The two self-address guards that call `dialled(Connect::Refused)` in `http.rs` and `socks5.rs` are untouched.
- `preferred()` returns `(EffectiveHop, io::Result<TcpStream>)`: `Upstream` when `through()` succeeded, `FallbackDirect` on each of its three paths that end in `direct()` (verdict `Down`, `Destination` failure, `Upstream` failure). `routed()` wraps that pair into `Dialled::Attempted`. `required()` always reports `Upstream`. The `Decision::Direct` and `Decision::Never` arms of `dial()` report `Direct`.
- Test support: `StubHop` reports `Direct` (it dials its target itself); `DownHop` reports `Upstream` for `Refusal::AfterDialling` and stays `Refused` for `Refusal::BeforeDialling`.

### Event and log shape

`EventView` gains `hop: Option<EffectiveHop>` with `#[serde(default)]`, absent when no dial was made and on lines written before the field existed - the same treatment `connect_ms` already documents. On the wire the field is `hop` with values `direct`, `upstream`, `fallback_direct` (`#[serde(rename_all = "snake_case")]`, matching `DecisionKind`); `logging::decision` emits it as `hop = hop.map(hop_name)`, where `hop_name` returns those same three strings and is covered by the serde-parity test.

`render_event` appends ` -> direct` immediately after the rule when the hop is `FallbackDirect`, and prints nothing extra otherwise, so the two golden lines above are byte-unchanged and only the previously invisible case gains text:

```
2026-09-03T19:53:11Z  teams.microsoft.com:443  upstream via rule 19 (prefer) -> direct  upstream down  431ms (dial 12ms)  -
```

A verdict transition is a log record of its own, written from `HealthHandle::set` with exactly three fields, `verdict_from`, `verdict_to` and `cause`, whose values are the `snake_case` names (`up`, `down`, `probe`, `dial`). `logging` gains `LoggedVerdict { at: Timestamp, from: HealthState, to: HealthState, cause: VerdictCause }` and `Logged { Decision(LoggedDecision), Verdict(LoggedVerdict) }`; `logged()` returns `Option<Logged>`, trying `EventView` first (its required fields make a verdict line fail to parse as one), then the verdict shape, else `None`. `render_log` keeps echoing the raw line for `None` and renders a verdict as:

```
2026-09-03T19:28:46Z  verdict up -> down  (dial)
```

That is the timestamp column exactly as decision lines print it, two spaces, the literal word `verdict`, the two state names around ` -> `, two spaces, the cause in parentheses. No padding, no placeholder columns.

## What Goes Where

- **Implementation Steps** (`[ ]` checkboxes): everything achievable in this repo - code, tests, README and CLAUDE.md updates.
- **Post-Completion** (no checkboxes): the user's own `~/.config/nhop/init` comment, re-timing the dead-upstream figures on the finished build, the release, and live verification against the real VM.

## Implementation Steps

### Task 1: Give the dial budget a type and split the two timeouts

**Files:**
- Modify: `nhop/Cargo.toml`
- Modify: `nhop/src/upstream/mod.rs`
- Modify: `nhop/tests/upstream_dialer.rs`

- [x] add `tokio = { workspace = true, features = ["test-util"] }` under `[dev-dependencies]` in `nhop/Cargo.toml` - `test-util` is not in the workspace feature list, so `tokio::time::pause` does not compile without it; dev-only keeps the paused clock out of the shipped binary
- [x] rename `UPSTREAM_CONNECT_TIMEOUT` to `PREFER_CONNECT_TIMEOUT`, keeping 2 s, and document that it is the budget for a dial that has a direct route waiting behind it
- [x] add `REQUIRE_CONNECT_TIMEOUT` at 10 s, documenting why a class with no fallback is given a longer one, that it caps the powered-off-upstream window measured in the Accepted trade-off, and why it is not configurable
- [x] add the `UpstreamBudget` enum with `Prefer` and `Require`, and a private method turning it into its `Duration`
- [x] give `through()` a fourth parameter of type `UpstreamBudget` and apply the matching duration in its `tokio::time::timeout`; the timeout error text names the budget's seconds as it does today. `required()` passes `Require`, `preferred()` passes `Prefer`. This changes the `require` dial budget to 10 s in this task; the verdict gate on `require` stays until Task 2
- [x] re-aim `a_dial_to_a_black_holed_upstream_fails_within_three_seconds` (`nhop/tests/upstream_dialer.rs:388`) at `prefer(0)` so it keeps pinning the 2 s budget - its `require` counterpart is written in Task 4
- [x] update the existing `through()` unit test (`an_upstream_socket_carries_keepalive_through_into_inner`) to pass a budget
- [x] add a unit helper `black_hole()` beside `closed_port()` that binds a `TcpListener` on port 0, spawns a task holding every accepted stream unanswered, and returns the address
- [x] write the unit test `a_prefer_budget_gives_up_at_the_prefer_timeout`: `#[tokio::test(start_paused = true)]`, `through()` against `black_hole()` with `UpstreamBudget::Prefer` returns `DialFailure::Upstream` and `tokio::time::Instant` advanced by exactly `PREFER_CONNECT_TIMEOUT`
- [x] write the unit test `a_require_budget_gives_up_at_the_require_timeout`: same shape with `UpstreamBudget::Require`, advanced by exactly `REQUIRE_CONNECT_TIMEOUT`
- [x] run `mise run check` - must pass before task 2

### Task 2: `require` dials whenever an upstream is configured

**Files:**
- Modify: `nhop/src/upstream/mod.rs`
- Modify: `nhop/tests/upstream_dialer.rs`

- [x] rewrite `required()` so the pre-network refusal happens only when the published upstream equals `NO_UPSTREAM`, and every configured address is dialled through `through()` with `UpstreamBudget::Require` regardless of the verdict
- [x] keep the outcome mapping as it is today for a dial that was made: `Destination` failures surface as themselves, `Upstream` failures surface as `UpstreamDown` and set the verdict `Down`
- [x] update the doc comments on `required()` and on the `UpstreamHop` struct, which currently state that nothing is dialled while the verdict is down
- [x] replace `a_require_decision_fails_at_once_while_the_verdict_is_down` with `a_require_decision_dials_a_configured_upstream_while_the_verdict_is_down`: a `require` decision against `closed_port()` with the verdict seeded `Down` returns `Dialled::Attempted` whose error carries the `UpstreamDown` surface
- [x] rewrite `a_require_refusal_reports_that_nothing_was_dialled` to build the hop on `NO_UPSTREAM` instead of `closed_port()`, so the surviving refusal path stays pinned as `Dialled::Refused`
- [x] rewrite `no_client_dial_reaches_the_upstream_while_the_verdict_is_down` (`nhop/tests/upstream_dialer.rs:167`) into `a_require_dial_reaches_the_upstream_while_the_verdict_is_down`: verdict seeded `Down`, a `require` dial to a live `StubSocks5` succeeds and appears in `client_dials()`, while a `prefer` dial still reaches the `StubOrigin` directly and does not appear there
- [x] revisit `a_require_rule_is_refused_while_the_upstream_is_closed` (`:106`): it asserts only the `UpstreamDown` error surface, so it stayed as is; if it asserts `Dialled::Refused`, rename it to say the dial was attempted and assert `Dialled::Attempted`
- [x] run `mise run check` - must pass before task 3

### Task 3: A real dial moves the verdict, guarded by the address it was made against

**Files:**
- Modify: `nhop/src/upstream/mod.rs`

- [x] add the private method `observed(&self, dialled: SocketAddr, state: HealthState)` on `UpstreamHop`, writing through `HealthHandle::set` only when `self.upstream.snapshot()` equals `dialled`
- [x] route both existing `self.health.set(HealthState::Down)` calls in `required()` and `preferred()` through it
- [x] call it with `Up` on a successful dial and on a `DialFailure::Destination`, in both `required()` and `preferred()`, documenting on the method that a SOCKS reply about a destination proves the upstream is serving - the invariant `failed_dial` already encodes
- [x] write the unit test `a_require_dial_that_connects_flips_the_verdict_up`: hop built with `PATIENT` for both interval and confirm delay (the first patrol probe still goes out immediately, so the stub will see it - isolation comes from the confirm delay, which keeps any probe sequence from closing), verdict seeded `Down`, a `require` dial through `upstream_answering(GRANTED)` succeeds, then `health.state()` is `Up` and `changed_at` moved
- [x] write the unit test `a_destination_refusal_flips_the_verdict_up`: same construction, upstream answering `REFUSED`; the dial fails with a non-`UpstreamDown` error and the verdict is `Up`
- [x] write the unit test `a_dial_landing_after_a_reload_leaves_the_new_verdict_alone`, exercising `observed()` directly: publish address A, seed `Down`, publish address B, call `observed(A, Up)` - still `Down`; call `observed(B, Up)` - now `Up`
- [x] run `mise run check` - must pass before task 4
+ [x] reorder the two dials in `a_require_dial_reaches_the_upstream_while_the_verdict_is_down` (`nhop/tests/upstream_dialer.rs`) so the `prefer` leg goes first: the `require` dial now flips the verdict `Up`, so a `prefer` dial issued after it would travel through the upstream instead of taking the direct route the test pins

### Task 4: Pin the incident with a stub that answers late

**Files:**
- Modify: `nhop/tests/support/mod.rs`
- Modify: `nhop/tests/upstream_dialer.rs`

- [x] add a `Slow(Duration)` variant to `Answers`, documented as the degraded-upstream shape: alive and serving, but past the `prefer` budget. In the accept loop it spawns one task per accepted connection that awaits `tokio::time::sleep` for the duration and then runs the existing `socks5` handshake, so connections are delayed independently and the loop never blocks; the delay applies to patrol probes too, which is faithful to the incident. Keep the match exhaustive, no wildcard arm
- [x] write the integration test `a_require_dial_is_served_by_a_slow_upstream` (real time): stub `Slow(3 s)`, hop built with `PATIENT` for interval and confirm delay so no probe sequence can close, verdict seeded `Down`; a `require` dial succeeds, the request appears in `client_dials()`, and the verdict is `Up` afterwards - the case that produced three hours of 502s
- [x] write the integration test `a_prefer_dial_leaves_a_slow_upstream_for_the_direct_route` (real time): same stub, verdict seeded `Up`; a `prefer` dial reaches the `StubOrigin` directly, the elapsed `std::time::Instant` is at least `PREFER_CONNECT_TIMEOUT` and under 3 s, and the verdict is `Down` afterwards
- [x] write the integration test `a_require_dial_into_a_black_hole_costs_the_require_budget`: `#[tokio::test(start_paused = true)]`, stub `Answers::Never`, hop with `PATIENT` twice, verdict seeded `Down`; the dial returns `Dialled::Attempted` whose error carries the `UpstreamDown` surface, `tokio::time::Instant` advanced by exactly `REQUIRE_CONNECT_TIMEOUT`, verdict `Down`. `connect_ms` is not asserted here - it is wall-clock and already pinned by the front-end tests that use `DownHop::AfterDialling`
- [x] run `mise run check` - must pass before task 5

### Task 5: Carry the effective path out of the dial site into the event

**Files:**
- Modify: `nhop-ipc/src/view.rs`
- Modify: `nhop/src/proxy/mod.rs`
- Modify: `nhop/src/proxy/http.rs`
- Modify: `nhop/src/proxy/socks5.rs`
- Modify: `nhop/src/upstream/mod.rs`
- Modify: `nhop/src/logging.rs`
- Modify: `nhop/src/cli/mod.rs`
- Modify: `nhop/tests/support/mod.rs`
- Modify: `nhop/tests/upstream_dialer.rs`

- [x] add `EffectiveHop` to `nhop-ipc/src/view.rs` beside `DecisionKind`, deriving the same traits and `#[serde(rename_all = "snake_case")]`
- [x] reshape `Dialled::Attempted` and `Connect::Attempted` exactly as "The dial reports its path" specifies, add `hop` to `Routed`, and fill `EventView.hop` in `ended`
- [x] change `preferred()` to return `(EffectiveHop, io::Result<TcpStream>)` and wrap it in `routed()`; `required()` reports `Upstream`, the `Direct`/`Never` arms of `dial()` report `Direct`
- [x] update every construction and pattern of the changed shapes: the `.timed(..)` callers in `http.rs` and `socks5.rs`, the `Connect::Attempted` construction in the `proxy/mod.rs` unit tests, `StubHop` and `DownHop` in the support module, the `dial` helper and the refusal test in `nhop/tests/upstream_dialer.rs`, the unit tests in `nhop/src/upstream/mod.rs` that match on `Dialled::`, and the tests Tasks 2-4 added - asserting the hop where it is the point and ignoring it elsewhere
- [x] add `hop: Option<EffectiveHop>` to `EventView` with `#[serde(default)]` and a doc comment naming both absences: no dial was made, and a line written before the field existed
- [x] emit it in `logging::decision` via a `hop_name` helper, and in `render_event` as the ` -> direct` suffix after the rule when the hop is `FallbackDirect` only
- [x] write the unit test `a_prefer_fallback_reports_fallback_direct`: a `prefer` decision with the verdict seeded `Down` returns `Dialled::Attempted { hop: FallbackDirect, .. }`; and `a_require_dial_reports_upstream` for a `require` decision through `upstream_answering(GRANTED)`
- [x] write the rendering test `a_fallback_direct_line_renders_the_suffix` in `nhop/src/cli/mod.rs`, asserting the full expected line for an event with `decision: Upstream`, `class: Prefer`, `hop: Some(FallbackDirect)` in the shape of the example under "Event and log shape"; confirm `logs_renders_a_decision_line_as_text_and_leaves_the_rest_alone` and `logs_render_the_dial_time_of_a_line_that_carries_one` still pass with their expected strings byte-unchanged
- [x] extend the serde-parity test in `nhop/src/logging.rs` (the one iterating `DecisionKind`, `RuleClass`, `HealthState`) to cover every `EffectiveHop` variant against `hop_name`
- [x] run `mise run check` - must pass before task 6

### Task 6: Log verdict transitions with their cause and render them

**Files:**
- Modify: `nhop/src/upstream/health.rs`
- Modify: `nhop/src/upstream/mod.rs`
- Modify: `nhop/src/logging.rs`
- Modify: `nhop/src/cli/mod.rs`
- Modify: `nhop/tests/upstream_dialer.rs`
- Modify: `nhop/tests/acceptance.rs`

- [x] add `VerdictCause` with `Probe` and `Dial` in `nhop/src/upstream/health.rs`, deriving `Serialize`/`Deserialize` with `#[serde(rename_all = "snake_case")]` alongside the usual traits
- [x] give `HealthHandle::set` a second parameter of type `VerdictCause`. Keep the `rcu` closure pure - no logging inside it, it may be retried and its result discarded. Bind the value `rcu` returns (`let previous = ...`), and after it commits compare the previous state with `state`; on a turnover emit exactly one `tracing::info!` record with the three fields `verdict_from`, `verdict_to`, `cause` as `snake_case` names
- [x] add `HealthHandle::seed(state)` that sets the verdict with no cause and no log line, for tests that establish a starting verdict rather than observe one
- [x] give `observed()` (Task 3) a `VerdictCause` argument; the three production `set` callers pass `Dial` from `required()`/`preferred()` and `Probe` from the patrol's `settle`. Point the seeding sites at `seed`: the unit helper `hop()` in `nhop/src/upstream/mod.rs`, `verdict()` in `nhop/tests/upstream_dialer.rs`, both calls in `nhop/tests/acceptance.rs`, and the unit tests in `health.rs`
- [x] add `LoggedVerdict` and the `Logged` enum to `logging.rs`, turn `logged()` into `Option<Logged>` with the parse order fixed under "Event and log shape", and update `render_log` in `nhop/src/cli/mod.rs` to keep echoing the raw line for `None` and to render a verdict as the literal format given there
- [x] write the unit test `a_repeated_verdict_emits_no_line` and `a_turnover_emits_one_line_with_its_cause` in `health.rs`, capturing records with a subscriber scoped by `tracing::subscriber::with_default`; the second asserts exactly one record with `verdict_from`, `verdict_to`, `cause`
- [x] write the unit test `logged_tells_a_decision_a_verdict_and_noise_apart` in `logging.rs`: one line of each kind, the right variant for the first two, `None` for the third
- [x] write the rendering test `logs_renders_a_verdict_line` in `nhop/src/cli/mod.rs` asserting `2026-09-03T19:28:46Z  verdict up -> down  (dial)` byte for byte, and extend the serde-parity test to `VerdictCause`
- [x] run `mise run check` - must pass before task 7

### Task 7: Verify acceptance criteria

- [x] `cargo test -p nhop a_require_dial_is_served_by_a_slow_upstream` passes - a `require` destination is served through an upstream slower than the `prefer` budget, from a `Down` verdict
- [x] `cargo test -p nhop a_require_refusal_reports_that_nothing_was_dialled` passes - `NO_UPSTREAM` is still refused before the network
- [x] `cargo test -p nhop a_prefer_dial_leaves_a_slow_upstream_for_the_direct_route` and `a_dial_to_a_black_holed_upstream_fails_within_three_seconds` pass - `prefer` still gives up on the upstream at its 2 s budget
- [x] `cargo test -p nhop a_dial_landing_after_a_reload_leaves_the_new_verdict_alone` passes - a dial landing after a reload cannot move the new upstream's verdict
- [x] `cargo test -p nhop a_require_dial_into_a_black_hole_costs_the_require_budget` passes - a dead upstream costs exactly the require budget and reports `Attempted`
- [x] `cargo test -p nhop a_fallback_direct_line_renders_the_suffix` and `a_prefer_fallback_reports_fallback_direct` pass - the log distinguishes a `prefer` connection that went direct
- [x] `cargo test -p nhop logs_renders_a_verdict_line` and `a_turnover_emits_one_line_with_its_cause` pass - verdict transitions are logged with their cause and rendered by `nhop logs`
- [x] run the full gate: `mise run check`

### Task 8: Update documentation

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `docs/plans/20260907-require-dials-through-degradation.md`

- [ ] in `README.md` "## Rule classes", rewrite the `require` bullet that says the connection fails at once when the upstream is down: it now dials and fails after the require budget, except with no upstream configured; state both budgets by name and value
- [ ] in `README.md` "## Commands" (the `nhop require` / `nhop prefer` table rows) and "## Shape" (the three-class summary), align the one-line descriptions with the same change
- [ ] in `README.md` "## The upstream verdict", add what the verdict now governs - `prefer` reads it, `require` only writes it - that a real dial moves it in both directions while probes still need the two-probe hysteresis, the measured dead-upstream costs from the Accepted trade-off table, and the verdict line `nhop logs` prints with its literal format
- [ ] in `README.md` "## Rule classes", under `prefer`, document the ` -> direct` suffix with the example line from "Event and log shape"
- [ ] in `CLAUDE.md`, update the invariant "Only an upstream failure flips the health verdict down" to state the symmetric half (a connection or a destination reply from a real dial flips it up at once, address-guarded), and the `Dialled` invariant to say the effective path travels with it
- [ ] in `CLAUDE.md`, add an invariant that `require` is gated only by the absence of an upstream, with one line on why the verdict gate was removed, so a future change does not restore it
- [ ] move this plan to `docs/plans/completed/`

## Post-Completion

*Items requiring manual intervention or external systems - no checkboxes, informational only*

**User-owned configuration**

`~/.config/nhop/init` line 23 carries the comment "Only reachable through the upstream. With the VM off these fail at once". After this change they fail after the require budget instead. The file is the user's, outside this repo, so the wording is theirs to update.

**Re-timing the dead-upstream figures on the finished build**

The Accepted trade-off table was measured on the raw socket. With the daemon built from this plan and the VM's proxy stopped, one `nc`-timed `require` dial through `127.0.0.1:7890` should cost about 1 s plus nothing (the daemon adds only its own budget on top, which does not fire when the kernel answers first); with the VM powered off it should cost 10 s for the first minute and under 30 ms afterwards. A human with the LAN does this; no test can.

**Live verification against the real upstream**

The incident is reproducible on the Mac: put the host under memory pressure with the VM running, then open a `require` domain. Before this change it returns 502 immediately; after it should load, slowly. Worth doing once before the release, because no unit test can reproduce a stalled virtual CPU.

**Release**

Per `docs/releasing.md` the workspace version bump belongs in the pull request being released. The workspace is at 0.1.4; if this PR ships as a release, bump it and tag `v0.1.5` on `main` after merge.
