# Ordered upstreams with fallback

## Overview

nhop has exactly one SOCKS5 upstream. When it is off, `require` destinations fail and `prefer` destinations go direct, even when a second machine could carry the same traffic into the same remote network. The common shape is a primary upstream that is sometimes off and a fallback that is always on, both offering an equivalent SOCKS5 proxy.

This plan turns the single upstream into an ordered list. Each entry is patrolled and judged on its own with the existing `HealthState` machinery, new connections go through the first entry that is up, and traffic returns to a higher-ranked entry only after it has stayed up for a hold period, so a flapping primary cannot bounce traffic back and forth. Connections already open are never touched by a switch: an accepted connection keeps the upstream it dialled until it ends.

A one-entry list behaves exactly as nhop behaves today, and every existing init script keeps working unchanged.

### Non-goals

- **No load balancing.** The list is an order of preference, not a pool. Spreading connections over several healthy upstreams would split long-lived sessions across exits and make every log line harder to read.
- **No per-rule upstream pinning.** A rule chooses a class (`require`, `prefer`, `never`), never an upstream. Pinning would turn the list into a routing table and multiply the rule vocabulary.
- **No authentication per upstream.** nhop speaks no-auth SOCKS5 today; credentials are a separate feature with its own storage question.
- **No retry of one connection on the next upstream.** A dial that fails on the active entry fails that connection exactly as today and flips that entry's verdict; the next connection selects the next entry. Retrying inside one connection would stack budgets (a `require` dial into a powered-off host already costs the full 10 s `REQUIRE_CONNECT_TIMEOUT`), and the client would see a hang that no single budget explains.
- **No switch events on the IPC wire.** 20260907 kept verdict transitions out of `Command::Subscribe` and the `Response` vocabulary on purpose; switches follow the same rule and are written to the log file only. `tail` still shows which upstream carried each connection (see "Event and log shape"), which is what a person watching it needs.
- **No hostnames in upstream addresses.** An entry stays an IP literal for the same reason the single upstream is one: it is dialled without a resolver.
- **Health means the proxy answers, not the network behind it.** `probe` asks an upstream to CONNECT to its own address and counts any reply about that destination as `Up`, and a real dial that fails at the destination does not flip the verdict either (`DialFailure::Destination`). An upstream whose SOCKS server is alive but whose own path into the remote network is down therefore stays `Up`, its dials fail at the destination, and no failover happens even though the fallback would serve them. Detecting that needs a probe through each upstream to a destination the operator chooses, which is new init vocabulary and a new judgment about what a failed destination means; it is listed under Post-Completion as a possible follow-up plan.
- **No configurability of the hold.** `RETURN_HOLD` is a compile-time constant, like every other timing constant in this crate; tests inject it the same way they inject the probe interval.

### Decisions made while drafting

These were open in the request and are settled here; the reasoning is kept so implementation does not reopen them.

- **One command, several addresses.** `nhop upstream <addr> [<addr>...]` takes the whole list in order. A separate `nhop fallback` command was rejected: the order would then depend on the order of statements in the script, and the existing "the last `upstream` wins" staging rule would need a second rule for how the two commands combine. With one command the list is stated once, and a second `nhop upstream` line replaces it, exactly as a second line replaces the single upstream today.
- **The hold is derived from the verdict's own `changed_at`, not from a second clock.** An entry has "held" when its verdict is `Up` and `changed_at` is at least `RETURN_HOLD` ago. Selection is therefore a pure function of the published list, each entry's `Health` and the current time, with no selection state to keep consistent. The only state kept is the last selection, and only for logging switches.
- **`require` with no entry up dials the first entry.** Today a `require` dial is made whatever the verdict says (20260907). With a list, "whatever the verdict says" needs a target; the first entry is the one the operator ranked first, and a successful dial flips its verdict up at once, which makes it the selected entry for the connections after it. Trying every entry in turn was rejected for the same budget-stacking reason as the non-goal above. "Fail fast" is not today's `require` behaviour and is not restored: since 20260907 `require` waits up to `REQUIRE_CONNECT_TIMEOUT` for the only route there is.
- **`doctor` keeps one `upstream_reachable` check.** It fails only when no entry is reachable and names every entry with its outcome in the detail. Failing whenever any entry is unreachable would turn `doctor` red for the normal state of this feature, a primary that is sometimes off. The seven stable check names stay unchanged.

## Skills to invoke

Load each skill below with the Skill tool and follow its conventions before implementing any task in this plan. The Code-Quality Rules section further down is the binding form of these conventions for this plan; on any disagreement the checklist wins.

- `rust-style` - every file this plan touches is Rust; its rules on `for` loops, `let ... else`, explicit destructuring, newtypes, enums-over-bools and no-wildcard matches are the house contract.
- `rustdoc` - every new public item (`Upstreams`, `UpstreamEntry`, `Selection`, `SwitchCause`, `RETURN_HOLD`, `UpstreamView`) needs a doc comment in RFC 1574 shape.
- `rust-analyzer-ssr` - for navigation when replacing `LiveUpstream`'s single address and the shared `HealthHandle`, whose call sites span `nhop/src`, `nhop/tests` and the test support module. Without an LSP, `grep -rn 'LiveUpstream\|live.health()\|\.health()\|NO_UPSTREAM\|SetUpstream' nhop/src nhop-ipc/src nhop/tests` plus `cargo check --all-targets` enumerates the same sites.

## Context (from discovery)

Line numbers below are as of commit `1b75da9` (v0.1.6). Anchor by the named symbol when a number no longer lands on it.

- **The single address** is `LiveUpstream(Arc<ArcSwap<SocketAddr>>)` (`nhop/src/daemon/state.rs:92`), defaulting to `NO_UPSTREAM` (`nhop/src/proxy/mod.rs:129`, `127.0.0.1:0`). It is published by `adopt_upstream` (`state.rs:755`) on commit and read by `UpstreamHop` (`snapshot()` in `routed()`, `observed()` and the patrol).
- **The single verdict** is one `HealthHandle` held by `Live` (`state.rs:116`) and handed to `UpstreamHop::start` at both spawn sites (`nhop/src/daemon/mod.rs:447`, `:709`). It is not reset by a reload; the address guard in `observed()` (`nhop/src/upstream/mod.rs:231`) and the `addr` in the patrol's `Pending` (`:436`) are what keep a stale observation from judging a replaced upstream.
- **The patrol** (`patrol`, `advance`, `probe` in `nhop/src/upstream/mod.rs:455-533`) probes one address in both verdict states, first probe at once, and moves the verdict only on two agreeing probes `confirm_delay` apart. A real dial moves it at once in either direction (20260907).
- **`required()` and `preferred()`** (`:190`, `:243`) are the only dial sites that read the upstream. `required()` refuses before the network only for `NO_UPSTREAM`; `preferred()` goes direct at once while the verdict is `Down`.
- **`Upstream`** (`nhop/src/proxy/mod.rs:142`) pairs the written form (`UpstreamAddr`) with the parsed `SocketAddr`. `Staging::set_upstream` (`nhop/src/daemon/staging.rs:84`) replaces the staged upstream, so the last `nhop upstream` line of a run wins.
- **`Command::SetUpstream { addr: UpstreamAddr, load }`** (`nhop-ipc/src/command.rs:110`) carries one address. `Command` is internally tagged (`#[serde(tag = "cmd")]`) and does not deny unknown fields.
- **`StatusView`** (`nhop-ipc/src/view.rs:150`) carries `upstream`, `health`, `health_changed_at` for the one upstream. `forwards` is the precedent for an added list field: `#[serde(default)]` with a doc comment naming older daemons. The golden file is `nhop/tests/golden/status.json`.
- **`EventView.upstream`** is the verdict at the start of the connection, taken in `Routed::begun` (`nhop/src/proxy/mod.rs:449`) from `ctx.health`. `EventView.hop` (`EffectiveHop`) is the effective path, reported by the dial site and carried on `Dialled` - the CLAUDE.md invariant that what a dial did is reported by the dial site and never re-derived applies to "which upstream" exactly as it does to "which path".
- **`ConnCtx.upstream: SocketAddr`** (`nhop/src/proxy/mod.rs:415`) is filled by `Live::accepted` and has no reader in `nhop/src` at `1b75da9` (`grep -rn 'ctx.upstream' nhop/src` prints nothing). It goes with the type change rather than being given a list.
- **Verdict log lines** are written by `HealthHandle::set` with `verdict_from`, `verdict_to`, `cause` and parsed back by `logging::logged()` into `LoggedVerdict`; `render_log` prints `<ts>  verdict up -> down  (dial)`. They carry no address, which is unambiguous only while there is one upstream.
- **`doctor::upstream_reachable`** (`nhop/src/cli/doctor.rs:275`) TCP-connects the one upstream within `PREFER_CONNECT_TIMEOUT` and reports the verdict.
- **`explain::decision_view`** (`nhop/src/cli/explain.rs`) renders `next_hop` from the written upstream for `Upstream` decisions, without consulting the verdict.
- **Test support** (`nhop/tests/support/mod.rs`): `StubSocks5::answering(Answers)` with `Always`, `Once`, `AfterOneDrop`, `Never`, `Slow(Duration)`; `client_dials()` excludes patrol probes, `requests()` includes them. `TestDaemon::start(&paths, upstream)` takes one address. There is no stub that can be stopped and started again on the same port.

## Development Approach

- **testing approach**: Regular - implementation first, then tests for it, within the same task.
- complete each task fully before moving to the next
- make small, focused changes
- **CRITICAL: every task MUST include new/updated tests** for the code it changes. The test bullets listed inside each task are the complete required test set for that task; a task is complete when all of them exist and `mise run check` is green.
- **CRITICAL: `mise run check` must pass before starting the next task** - no exceptions
- **CRITICAL: update this plan file when scope changes during implementation**
- a one-entry list must behave byte-for-byte as today: existing tests are changed only where a type they construct changed shape, never to accept different behaviour

## Code-Quality Rules (verify before marking each task complete)

### Rust

- no `//` comments anywhere; `///` on public items, `//!` for module docs. The only sanctioned exceptions in this tree are the protocol byte layouts in `proxy/socks5.rs` and `proxy/http.rs`
- no `matches!`, and no wildcard `_ =>` outside `std::io::ErrorKind` - adding an enum variant must break the build
- explicit destructuring always, never field-by-field access through a value
- `let ... else` for early returns; `for` loops rather than iterator chains
- newtypes over bare `String`; enums over `bool` parameters - this is why the switch reason is `SwitchCause` and "is this entry active" is reported through `Selection`, not a flag argument
- shadow rather than rename when narrowing a value
- every new public item carries a `///` doc comment whose first line is one sentence; `RETURN_HOLD` additionally carries one sentence saying why that value

### Per-task gate

- `mise run check` green: `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`
- `grep -rn '^\s*//[^/!]' nhop/src nhop-ipc/src | wc -l` must not grow from its value at the start of Task 1 (record it in this file before starting)
- `grep -rn 'matches!\|_ =>' nhop/src nhop-ipc/src | wc -l` must not grow from its value at the start of Task 1 (record it the same way)

## Testing Strategy

- **unit tests** live beside the code in `#[cfg(test)] mod tests`
- **selection is tested without sockets or clocks**: `select` takes the entries' `Health` values and a `now: SystemTime`, so every hysteresis case is a table of hand-built `Health { state, changed_at }` values against a fixed `now`
- **integration tests** go in `nhop/tests/`, sharing `nhop/tests/support/mod.rs` - extend the existing stubs, no new stub types
- the hold, like the probe interval and confirm delay, is a start parameter of `UpstreamHop`, so integration tests run with a hold of a few hundred milliseconds in real time. Paused tokio time does not help here: `changed_at` is a `SystemTime`
- these tests run on a shared, loaded machine: every "after the hold" and "after a probe cycle" assertion polls for its condition with a support helper and a deadline of several seconds, never a fixed sleep. The only fixed-time assertion allowed is the negative one in Task 6 ("before the hold elapses"), made immediately after the primary is restarted and well inside the hold
- bind port 0 everywhere; nothing may touch 7890 or 7891
- scope the logging subscriber with `tracing::subscriber::with_default`, since several daemons run in one test process
- the project has no e2e/UI suite; `mise run check` is the whole gate

## Progress Tracking

- mark completed items with `[x]` immediately when done
- add newly discovered tasks with a leading `+`
- document blockers with a leading `!`
- keep this file in sync with the work actually done

## Solution Overview

**The upstream becomes an ordered list of entries, each with its own verdict.** `Upstreams` is the published value: a vector of `UpstreamEntry { upstream: Upstream, health: HealthHandle }` in operator order, empty when no init script has named one (replacing `NO_UPSTREAM` as the published "absent" value). `LiveUpstream` publishes `Arc<Upstreams>` the way it publishes an address today.

**A reload keeps the verdict of every address it keeps.** When a commit publishes a new list, an entry whose `SocketAddr` was in the previous list reuses that entry's `HealthHandle`; a new address gets a fresh one (`Down`, as a cold daemon does). Without this, every reload would drop every verdict to `Down` and send all `prefer` traffic direct until the patrol confirmed again. The address guard falls out of this design: a dial holds a clone of the handle of the entry it dialled, so a dial landing after its address was removed writes to a handle nobody reads, and an address removed and added back gets a fresh handle the stale dial cannot reach.

**Selection is a pure function.** Given the list, each entry's `Health` and `now`, `select` returns the entry new connections use:

1. the first entry that is `Up` and has held (`now - changed_at >= RETURN_HOLD`);
2. otherwise the `Up` entry that has been up longest (earliest `changed_at`), ties broken by list order;
3. otherwise nothing.

Step 1 is the hysteresis: a primary that has just come back does not take traffic from a fallback that is serving until it has stayed up for `RETURN_HOLD`. Step 2 keeps the cold-start and only-one-alive cases immediate - at cold start the entries leave `Down` in the same patrol round, and the patrol stamps every verdict write of one round with the round's start instant (see "Same-round ties" below), so the tie goes to list order and the primary serves at once - without letting an unheld higher-ranked entry preempt an unheld lower-ranked one that came up first. Demotion is immediate in every case, because a `Down` entry is never selected. A one-entry list selects that entry whenever it is `Up`, exactly as the single upstream is used today.

Step 2 must not be "the first `Up` entry". With [P, F] and a 60 s hold, F up at t=0 and P up at t=10: "first `Up`" moves traffic F -> P at t=10 (P not held), back P -> F at t=60 (F held, P not) and F -> P again at t=70 - three switches in 70 s, the bounce the hold exists to prevent, and it happens whenever the fallback comes up shortly before the primary, both hosts booting for one. With "up longest", F keeps traffic until P has held at t=70: one switch, cause `held`.

The property that keeps the cause table complete: **a selected `Up` entry is never displaced by a lower-ranked one.** If it was selected by step 1 it stays held while it stays `Up`, and no lower-ranked entry can win step 1 ahead of it. If it was selected by step 2 its `changed_at` is the earliest of all `Up` entries and can move only through a turnover, which passes through `Down` and demotes it; any lower-ranked entry that holds later has a later `changed_at`, so the selected entry holds first and wins step 1 by rank. A `changed_at` in the future of `now` (the wall clock moved back) counts as not held and still orders by its value in step 2.

**The dial sites consult selection instead of one verdict.**

| Class | Selected entry | Nothing selected |
|---|---|---|
| `require` | dial it with the require budget | dial the first entry with the require budget; empty list refused before the network as `NO_UPSTREAM` is today |
| `prefer` | dial it with the prefer budget, direct on failure as today | direct at once (`EffectiveHop::FallbackDirect`) |
| `never` / no rule | direct | direct |

Forward ports route through the same `NextHop`, so they follow selection with no change of their own. Every verdict write from a dial goes to the handle of the entry that was dialled.

**Existing connections are untouched by construction.** A connection dials once, at accept time, through the entry selected then; nothing in this plan closes, re-dials or migrates an accepted connection. The integration test in Task 6 pins it.

**The patrol probes every entry.** One patrol task, as today, probes all entries of the current list concurrently each round, keeping one `Pending` per address. It sleeps `confirm_delay` while any sequence is pending and `interval` otherwise. A round costs at most one `PROBE_TIMEOUT` regardless of the list's length.

**Switches are logged, once each, where they are seen.** `Selection` remembers the last selected address and the list it was selected from (logging only - routing always recomputes). Every dial and every patrol round calls `Selection::observe(new)`; on a change it writes one log record with the old and new address and a `SwitchCause`. The patrol round matters because a hold expiring is a switch that no verdict write announces.

## Technical Details

### New vocabulary

```rust
pub struct UpstreamEntry { upstream: Upstream, health: HealthHandle }

pub struct Upstreams(Vec<UpstreamEntry>);

pub enum SwitchCause { Down, Held, Recovered, Reload }

pub const RETURN_HOLD: Duration = Duration::from_secs(60);
```

`Upstreams` and `UpstreamEntry` live in `nhop/src/upstream/`; `SwitchCause` beside `VerdictCause` in `nhop/src/upstream/health.rs`, serialized `snake_case`.

### Same-round ties

`HealthHandle::set` stamps a turnover with `SystemTime::now()`. With step 2 ordering by `changed_at`, that would make cold start depend on which probe of one round happened to return first: a fallback answering a few milliseconds faster than the primary would get the earlier `changed_at`, win step 2, and keep traffic for a whole `RETURN_HOLD`. The patrol therefore records one `SystemTime` when a round starts and writes every verdict of that round with it, through a new `HealthHandle::set_at(state, cause, at)`; `set` stays for dial-driven writes and is `set_at` with `now`. Entries whose sequences close in the same round tie exactly, and the tie goes to list order. An entry that needs an extra round to confirm (a slower or later-booting primary) is judged later and waits out the hold, which is the hold doing its job.

### `RETURN_HOLD`

60 s. The upstream flapping documented in 20260907 turned the verdict over about every 30 s; a hold of twice that keeps a primary in that state from ever winning traffic back, while a primary that is genuinely back takes over within a minute plus one probe cycle. It applies only to winning traffic back: losing it is immediate.

### Switch causes

Derived when `Selection::observe` sees a change, from the previous and new selection, the list published at the previous observation and the current list. `Selection` keeps the previous list as the `Arc<Upstreams>` it was given, so "the list changed" is a pointer comparison, not a content one:

| Condition, checked in this order | Cause |
|---|---|
| the current list is not the list of the previous observation | `reload` |
| previous `Some(a)`, `a` now `Down` | `down` |
| previous `Some(a)`, new `Some(b)` with `b` ranked above `a` | `held` |
| previous `None`, new `Some(b)` | `recovered` |

`reload` is checked first because a reload can reorder or replace entries, after which rank comparisons against the old selection mean nothing. With the list unchanged, the property under "Solution Overview" rules out the remaining shape - previous `Some(a)` with `a` still `Up` and new `Some(b)` ranked below `a` - so every change matches exactly one row; the unit test in Task 3 checks that exhaustively.

### Command and init-script shape

```
nhop upstream socks5://<primary-ip>:<port> socks5://<fallback-ip>:<port>
```

- argh positional `Vec<UpstreamAddr>` with at least one element; zero addresses is a usage error.
- On the wire `Command::SetUpstream` keeps `addr` (the first entry) and gains `fallbacks: Vec<UpstreamAddr>` with `#[serde(default)]`. A one-address command serializes byte-identically to today's, and a command without the field reads as a one-entry list.
- Each address is parsed with `Upstream::parse`; a duplicate `SocketAddr` in one command is rejected with a new `DuplicateUpstream` error (staged command fails, the load fails, the previous list keeps serving), mirroring `DuplicateForward`.
- Staging keeps "last wins": a second `nhop upstream` replaces the whole list.

### Status shape

`StatusView` gains `upstreams: Vec<UpstreamView>` with `#[serde(default)]` and a doc comment naming daemons older than the field:

```rust
pub struct UpstreamView {
    pub addr: UpstreamAddr,
    pub health: HealthState,
    pub health_changed_at: Timestamp,
    pub selected: bool,
}
```

The existing `upstream`, `health`, `health_changed_at` keep their meaning for the first entry, so a consumer reading only them sees the primary as before. `nhop status` prints one line per entry in list order, the first under the existing `upstream` label and the rest under `fallback`, each suffixed ` (selected)` when it is the selected one:

```
upstream      socks5://192.0.2.10:1080 down since 2026-02-02T02:40:00Z
fallback      socks5://192.0.2.11:1080 up since 2026-02-02T02:41:00Z (selected)
```

A one-entry list prints exactly today's line, with no ` (selected)` suffix: there is nothing to choose between, and a one-entry list must behave byte-for-byte as today. The suffix appears only when the list has two or more entries.

### Event and log shape

- `EventView` gains `via: Option<UpstreamAddr>` with `#[serde(default)]`: the written form of the entry that carried the connection, present only when `hop` is `Upstream`, absent on older lines. It is reported by the dial site on `Dialled` and `Connect`, never re-derived from selection afterwards.
- `render_event` appends ` @ <via>` after the rule when `via` is present. Existing golden lines have no `via`, so they stay byte-unchanged.
- `EventView.upstream` (verdict at the start) becomes the verdict of the selected entry, or `Down` when nothing is selected.
- Verdict records gain an `upstream` field (the entry's written address); `LoggedVerdict` reads it with `#[serde(default)]`, and `render_log` prints it when present: `<ts>  verdict socks5://192.0.2.11:1080 up -> down  (dial)`. A verdict line without the field renders exactly as today.
- Switch records carry `upstream_from`, `upstream_to` (written addresses, empty for none) and `switch_cause`. `logging` gains `LoggedSwitch` and a `Logged::Switch` variant, parsed after the decision and verdict shapes. Rendered as `<ts>  switch socks5://192.0.2.10:1080 -> socks5://192.0.2.11:1080  (down)`, with `none` for an absent side.

### `doctor`

`upstream_reachable` takes the list. It TCP-connects every entry concurrently within `PREFER_CONNECT_TIMEOUT`, passes when at least one answers, and its detail names each entry in order with `reachable`/`unreachable` and its verdict. An empty list keeps today's "no upstream is configured" failure.

### `test` / `explain`

`decision_view` gains the current selection. For an `Upstream` decision `next_hop` is the written address the dial would use now: the selected entry, or the first entry when nothing is selected (what `require` would dial). It still does not apply the `prefer` fallback, which is today's behaviour: `test` reports the route the rules choose, and the live verdict is shown by `status`.

## What Goes Where

- **Implementation Steps** (`[ ]` checkboxes): everything achievable in this repo - code, tests, README and CLAUDE.md updates.
- **Post-Completion** (no checkboxes): adding the fallback to a real init file, live verification with a real primary turned off and on, the release.

## Implementation Steps

### Task 1: Parse and stage an ordered upstream list

**Files:**
- Modify: `nhop-ipc/src/command.rs`
- Modify: `nhop/src/proxy/mod.rs`
- Modify: `nhop/src/daemon/staging.rs`
- Modify: `nhop/src/daemon/state.rs`
- Modify: `nhop/src/cli/mod.rs`

- [ ] add `fallbacks: Vec<UpstreamAddr>` with `#[serde(default)]` to `Command::SetUpstream`, documented as the entries after `addr`, in order
- [ ] make the `upstream` subcommand take one or more positional addresses; the CLI sends the first as `addr` and the rest as `fallbacks`
- [ ] add `Upstreams` (ordered, non-empty when parsed from a command) with a constructor that parses every address with `Upstream::parse` and rejects a repeated `SocketAddr` with `DuplicateUpstream`; staging stores `Option<Upstreams>` and `set_upstream` replaces it whole
- [ ] map `DuplicateUpstream` to a failed staged command the way `DuplicateForward` is mapped
- [ ] keep publishing only the first entry's address through the existing `LiveUpstream` in this task, so routing is unchanged until Task 2
- [ ] write the wire test `a_single_upstream_command_serializes_as_before`: a `SetUpstream` with empty `fallbacks` produces the exact JSON today's command produces, and that JSON without `fallbacks` deserializes to empty `fallbacks`
- [ ] write the CLI parse tests `upstream_takes_several_addresses_in_order` and `upstream_without_an_address_is_a_usage_error`
- [ ] write the staging tests `a_repeated_upstream_address_fails_the_command` and `a_second_upstream_line_replaces_the_whole_list`
- [ ] run `mise run check` - must pass before task 2

### Task 2: Publish the list with a verdict per entry

**Files:**
- Modify: `nhop/src/daemon/state.rs`
- Modify: `nhop/src/daemon/mod.rs`
- Modify: `nhop/src/proxy/mod.rs`
- Modify: `nhop/src/upstream/mod.rs`
- Modify: `nhop/tests/support/mod.rs`
- Modify: every test that constructs `LiveUpstream`, `Live` or `UpstreamHop` (enumerate with the grep in "Skills to invoke")

- [ ] change `LiveUpstream` to publish `Arc<Upstreams>`, empty by default; remove the shared `HealthHandle` from `Live` and from both `UpstreamHop::start` call sites
- [ ] in `adopt_upstream`, build the published entries by reusing the `HealthHandle` of any entry whose `SocketAddr` is in the currently published list and creating a fresh one otherwise
- [ ] remove `ConnCtx.upstream` (no reader) and take `ConnCtx.health` from the selected entry - until Task 3 lands selection, the first entry's handle, or a fresh `Down` handle for an empty list
- [ ] keep `NO_UPSTREAM` only where it is still meaningful (the empty-list refusal and the `test` rendering); delete the constant if no reader is left and say so in this plan
- [ ] make `required()`, `preferred()` and `observed()` take the entry they dial: in this task the first entry, so routing for a one-entry list is unchanged; verdict writes go to that entry's handle
- [ ] give `TestDaemon::start` a list of upstream addresses; existing callers pass one
- [ ] write the unit test `a_reload_keeps_the_verdict_of_an_address_it_keeps`: publish [A, B], seed A `Up`, publish [B, A, C] - A is still `Up` with its `changed_at` unchanged, C is `Down`
- [ ] write the unit test `an_address_removed_and_added_back_starts_down`: publish [A], seed `Up`, publish [B], publish [A] - A is `Down`
- [ ] rewrite `a_dial_landing_after_a_reload_leaves_the_new_verdict_alone` against the new model: a write to the handle of an entry no longer published does not change the verdict of the entry that replaced it
- [ ] confirm every test in `nhop/tests/upstream_dialer.rs` and `nhop/tests/acceptance.rs` passes with only constructor changes
- [ ] run `mise run check` - must pass before task 3

### Task 3: Selection with a return hold

**Files:**
- Create: `nhop/src/upstream/select.rs`
- Modify: `nhop/src/upstream/mod.rs`
- Modify: `nhop/src/upstream/health.rs`
- Modify: `nhop/src/logging.rs`

- [ ] add `RETURN_HOLD` with its doc comment and the reasoning from "`RETURN_HOLD`"
- [ ] add the pure function `select(entries, now, hold) -> Option<usize>` implementing the three steps in "Solution Overview"; a `changed_at` in the future of `now` (wall clock moved back) counts as not held
- [ ] add `SwitchCause` and `Selection` (`observe(&self, list: &Arc<Upstreams>, new)`), keeping the previous selection and the previous list's `Arc`, deriving the cause from the table in "Switch causes" and writing one log record with `upstream_from`, `upstream_to`, `switch_cause` on a change only; `rcu`-style as `HealthHandle::set`, with the closure kept pure and the log written after the swap
- [ ] add `hold: Duration` to `UpstreamHop::start` beside `interval` and `confirm_delay`; production passes `RETURN_HOLD`
- [ ] write the table-driven unit test `selection_follows_the_list_order_and_the_hold` covering at least: one entry up; one entry down; primary up and held; primary up but not held with fallback up and held - fallback; primary up but not held with fallback down - primary; both up with equal `changed_at` (cold start) - primary; both up, neither held, fallback up first - fallback; primary down and fallback up - fallback; everything down - none; a `changed_at` after `now` - not held
- [ ] in the same test, the trace from "Solution Overview" as consecutive rows with list [P, F] and a 60 s hold: F up at t=0, P up at t=10; the selection is F at t=0, t=10 and t=60, and P at t=70
- [ ] write the unit test `every_switch_has_exactly_one_cause`, exhaustive over a three-entry list: every combination of each entry's verdict and `changed_at` drawn from a small set of instants (including equal ones and ones on either side of the hold) at two consecutive `now` values, with the list unchanged; assert that whenever the selection changes it derives exactly one `SwitchCause`, that no change ever has a still-`Up` previous entry replaced by a lower-ranked one, and that an unchanged selection logs nothing. Add the case of a reloaded list (a new `Arc`) yielding `reload` whatever else changed
- [ ] add the trace from "Solution Overview" to that test as a sequence of observations, asserting exactly one switch, F -> P, cause `held`
- [ ] write the unit test `a_switch_is_logged_once`, capturing records with a scoped subscriber: two `observe` calls with the same new selection produce one record
- [ ] run `mise run check` - must pass before task 4

### Task 4: Dial through the selected entry

**Files:**
- Modify: `nhop/src/upstream/mod.rs`
- Modify: `nhop/src/proxy/mod.rs`
- Modify: `nhop/src/proxy/http.rs`
- Modify: `nhop/src/proxy/socks5.rs`
- Modify: `nhop-ipc/src/view.rs`
- Modify: `nhop/src/logging.rs`
- Modify: `nhop/src/cli/mod.rs`
- Modify: `nhop/tests/support/mod.rs`

- [ ] make `routed()` compute `select` once per connection and dial per the class table in "Solution Overview"; call `Selection::observe` with the result
- [ ] report the carrying entry on `Dialled::Attempted` and `Connect::Attempted` as `via: Option<UpstreamAddr>`, set only when the hop is `Upstream`; fill `EventView.via` in `Routed::ended`
- [ ] take `EventView.upstream` from the selected entry's verdict (`Down` when none is selected)
- [ ] emit `via` in `logging::decision` and render ` @ <via>` in `render_event` when present
- [ ] update `StubHop` and `DownHop` in the support module for the new field
- [ ] write the unit tests `a_require_dial_uses_the_selected_fallback`, `a_require_dial_with_nothing_up_dials_the_first_entry`, `a_prefer_dial_with_nothing_up_goes_direct_at_once` and `a_prefer_dial_uses_the_selected_fallback`, each asserting the dialled stub, `hop` and `via`
- [ ] write the unit test `a_dial_failure_flips_only_the_entry_it_dialled`: two entries both seeded `Up`, the selected one closed; after a `require` dial the selected one is `Down` and the other is still `Up`
- [ ] write the rendering test `a_line_carried_by_an_upstream_names_it` and confirm the existing decision goldens are byte-unchanged
- [ ] run `mise run check` - must pass before task 5

### Task 5: Patrol every entry

**Files:**
- Modify: `nhop/src/upstream/mod.rs`

- [ ] make `patrol` probe every entry of the current list concurrently each round, keep one `Pending` per address (a sequence for an address no longer published is dropped), and sleep `confirm_delay` while any sequence is pending, `interval` otherwise
- [ ] add `HealthHandle::set_at(state, cause, at: SystemTime)` as specified in "Same-round ties", make `set` delegate to it with `SystemTime::now()`, and have the patrol stamp every write of one round with the instant the round started
- [ ] after each round call `Selection::observe` so a hold expiring is logged without waiting for traffic
- [ ] write the unit test `entries_confirmed_in_one_round_tie_and_the_primary_wins`: two upstreams answering `GRANTED`, the fallback's stub answering faster; after the round that confirms both, their `changed_at` are equal and `select` picks the primary
- [ ] keep the empty-list behaviour of today's `NO_UPSTREAM` branch: the fast tick for `NO_UPSTREAM_EAGER`, then the interval
- [ ] write the unit test `a_round_probes_every_entry`: two upstreams answering `GRANTED`, both start `Down`, both are `Up` after two rounds
- [ ] write the unit test `a_sequence_for_a_removed_address_cannot_close`: one contradicting probe banked for A, A removed from the list, a later probe of the same address added back does not close it
- [ ] write the unit test `a_dead_entry_does_not_slow_the_round`: one entry `Answers::Never`, one `GRANTED`; the live entry is judged `Up` within one `PROBE_TIMEOUT` plus `confirm_delay` of the round starting (paused time)
- [ ] run `mise run check` - must pass before task 6

### Task 6: Pin failover and return end to end

**Files:**
- Modify: `nhop/tests/support/mod.rs`
- Create: `nhop/tests/upstream_fallback.rs`

- [ ] give `StubSocks5` a way to stop accepting and start again on the same port (`stop()` closing the listener, `restart()` rebinding the recorded address), documented as the shape of an upstream host that is turned off and on
- [ ] write `a_down_primary_hands_new_connections_to_the_fallback`: daemon with [P, F], short interval/confirm/hold, P stopped; a `require` connection is carried by F (`F.client_dials()`), its event has `via` F
- [ ] write `a_primary_back_takes_new_connections_only_after_the_hold`: from the previous state restart P; a connection made before the hold elapses still goes to F; after the hold plus one probe cycle a new connection goes to P
- [ ] write `an_open_connection_survives_a_switch`: open a relayed connection through F, let P come back and win selection, then exchange bytes over the open connection and assert the echo; assert F still holds it
- [ ] write `the_log_records_each_switch_with_its_cause`: read the daemon's log after the scenario above and assert the switch records `P -> F (down)` and `F -> P (held)` in order
- [ ] write `a_forward_port_follows_selection`: a `forward` port whose destination matches a `require` rule is carried by F while P is down
- [ ] run `mise run check` - must pass before task 7

### Task 7: Status, doctor, test and logs

**Files:**
- Modify: `nhop-ipc/src/view.rs`
- Modify: `nhop/src/cli/status.rs`
- Modify: `nhop/src/cli/doctor.rs`
- Modify: `nhop/src/cli/explain.rs`
- Modify: `nhop/src/daemon/state.rs`
- Modify: `nhop/src/upstream/health.rs`
- Modify: `nhop/src/logging.rs`
- Modify: `nhop/src/cli/mod.rs`
- Modify: `nhop/tests/golden/status.json`

- [ ] add `UpstreamView` and `StatusView.upstreams` as specified in "Status shape"; fill them in the state task from the published list and `select`
- [ ] render the per-entry status lines as specified in "Status shape", with no suffix for a one-entry list
- [ ] change `doctor::upstream_reachable` as specified in "`doctor`"
- [ ] change `decision_view` as specified in "`test` / `explain`"
- [ ] add the `upstream` field to verdict records, `LoggedSwitch` and `Logged::Switch`, and both renderings from "Event and log shape"
- [ ] write the status tests `status_lists_every_upstream_in_order`, `status_marks_the_selected_upstream` and `a_single_upstream_status_line_is_unchanged` (byte-for-byte today's line), and update the golden file
- [ ] write the doctor tests `doctor_passes_while_any_upstream_answers` and `doctor_fails_when_no_upstream_answers`, both asserting the detail names every entry; confirm the acceptance test's seven check names are unchanged
- [ ] write the test `test_reports_the_selected_upstream`
- [ ] write the rendering tests `logs_renders_a_verdict_line_with_its_upstream`, `logs_renders_a_switch_line` and confirm `logs_renders_a_verdict_line` (no address) is byte-unchanged; extend the serde-parity test to `SwitchCause`
- [ ] run `mise run check` - must pass before task 8

### Task 8: Verify acceptance criteria

- [ ] a one-entry list behaves as before: every pre-existing test in `nhop/tests/` passes with constructor-only changes, and the decision and verdict goldens are byte-unchanged
- [ ] `cargo test -p nhop --test upstream_fallback` passes - failover, return after the hold, an open connection surviving the switch, forwards following selection
- [ ] `cargo test -p nhop selection_follows_the_list_order_and_the_hold every_switch_has_exactly_one_cause` passes
- [ ] `cargo test -p nhop a_require_dial_with_nothing_up_dials_the_first_entry a_prefer_dial_with_nothing_up_goes_direct_at_once` passes - rule semantics across the list
- [ ] run the full gate: `mise run check`

### Task 9: Update documentation

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `packaging/nhop.init.example`
- Modify: `docs/plans/20261007-fallback-upstreams.md`

- [ ] in `README.md`, document the list form of `nhop upstream`, selection, `RETURN_HOLD` and why it exists, that open connections are never moved, the class table from "Solution Overview", and the new status, log and doctor output
- [ ] in `README.md`, state the cold-start window: right after the daemon starts, and after a reload that adds addresses, the new entries are `Down` until two agreeing probes (about `confirm_delay` plus the probe time, around a second); during that window `require` dials the first entry, so with the primary off a connection made then can cost the full `REQUIRE_CONNECT_TIMEOUT`
- [ ] in `README.md`, state the health non-goal: an entry is `Up` when its proxy answers, not when the network behind it works
- [ ] in `packaging/nhop.init.example`, show a commented two-entry `nhop upstream` line with documentation addresses
- [ ] in `CLAUDE.md`, add the invariants: each upstream has its own verdict, kept across reloads by address; selection is a pure function of the list, the verdicts and the time, and the selected entry is reported by the dial site (`via`), never re-derived; a switch never touches an accepted connection
- [ ] move this plan to `docs/plans/completed/`

## Post-Completion

*Items requiring manual intervention or external systems - no checkboxes, informational only*

**Configuration**

The operator adds the fallback to their own init file as a second address on the existing `nhop upstream` line. Entries may be different machines or different network paths to one machine, for example two addresses of the same host on two networks; each gets its own verdict either way. An init script that today chooses between such addresses with a reachability check can list them instead.

**Possible follow-up: probing the network behind an upstream**

Probe through each upstream to a destination the operator chooses, so an upstream whose proxy answers but whose path into the remote network is down is judged `Down` and fails over. Out of scope here (see Non-goals); whether it becomes its own plan is the maintainer's call.

**Live verification**

With a real primary and fallback: turn the primary off and confirm new connections move to the fallback within one dial or one probe confirmation, that a long-lived connection through the fallback survives the primary coming back, and that traffic returns about `RETURN_HOLD` after the primary is up. `nhop logs` should show one switch line per move. No test can reproduce a real host being powered off, so this is worth doing once before the release.

**Release**

Per `docs/releasing.md` the workspace version bump belongs in the pull request being released; tag on `main` after merge.
