# Relay keepalive and upstream patrol

## Overview

Three defects found during live investigation (2026-08-15), one release (0.1.3):

1. **Relayed connections silently die behind NAT.** The home router drops idle
   established TCP after ~25 minutes (violating RFC 5382 REQ-5's 2h4m minimum).
   Chrome keeps its *direct* sockets alive with TCP keepalive (45s); Go's dialer
   (= ClashX's core) does the same at 15s. nhop sets no keepalive at all, so
   every idle tunnel through it dies in the NAT kill zone. Evidence: 353
   ETIMEDOUT deaths in 24h with heartbeat-shaped lifetimes repeating per host
   (`mtalk.google.com` at exactly 28.3 min ~110 times, `node.windy.com` at 30.3,
   `raw.githubusercontent.com` at 60.1), Chrome black-page hangs of ~10s when it
   pulls a dead tunnel from its pool, and 88 fds parked in dying states.
2. **The upstream verdict goes stale and flaps.** `probe_while_down` probes only
   while the verdict is Down, so a dead VM is discovered by the first user dial
   (2.135s measured), not by the prober; the first probe also waits out a full
   interval before running, and a single stray answer during VM boot flips the
   verdict Up (observed: six flips in 11 seconds).
3. **The log cannot separate "dialled slowly" from "lived long".** `duration_ms`
   is the whole connection lifetime, so this entire investigation needed live
   probes instead of one `nhop logs` read.

## Context (from discovery)

- Both dial sites live in `nhop/src/upstream/mod.rs`: `direct()` (TcpStream::connect)
  and `through()` (Socks5Stream + `UPSTREAM_CONNECT_TIMEOUT` 2s, unwrapped via
  `into_inner()`). The prober loop `probe_while_down` and `probe()` are in the
  same file; verdict lives in `upstream/health.rs` (`HealthHandle`, ArcSwap).
- `UpstreamHop::start(upstream, health, interval)` is the only spawn seam, with
  five call sites: `nhop/src/daemon/mod.rs:322`, `nhop/src/upstream/mod.rs:271`,
  `nhop/tests/upstream_dialer.rs:32`, `:163`, `:186`.
- **Five** existing tests in `nhop/tests/upstream_dialer.rs` assert behaviour a
  probing-while-up patrol reverses. Two name the retired invariant directly:
  `:184` `no_probe_is_sent_while_the_verdict_is_up` and `:160`
  `the_verdict_flips_up_once_the_upstream_answers_a_probe` (exactly one probe
  expected). Three more break because `StubSocks5` records *every* CONNECT
  (`nhop/tests/support/mod.rs:210`, `:256-291`) while the local `hop()` helper
  (`upstream_dialer.rs:31`) publishes the stub address before spawning, so the
  startup probe lands in the same recording: `:102`
  `a_require_rule_travels_through_the_upstream_as_the_name_the_client_wrote`
  and `:124` `a_prefer_rule_travels_through_the_upstream_while_the_verdict_is_up`
  both assert a single recorded request, and `:144`
  `a_down_verdict_reaches_no_upstream_at_all` asserts `requests() == Vec::new()`
  - a premise patrol removes outright, since a Down verdict now legitimately
  reaches the upstream. Distinguishing a probe from a user dial needs a seam in
  the stub, because a probe is exactly a self-addressed CONNECT.
- `nhop/src/daemon/mod.rs:395-396` builds `Live::default()` and spawns the front
  ends before any init script runs; `LiveUpstream::default()` is `NO_UPSTREAM` =
  `127.0.0.1:0` (`daemon/state.rs:91-94`, `proxy/mod.rs:36`). The real upstream
  is published later by the `Command::Reload` spawned at `:410-415`, and nothing
  wakes the prober on publish - it re-reads `upstream.snapshot()` only at the
  top of each loop iteration.
- The per-connection object is `Routed` (`nhop/src/proxy/mod.rs:237`), which
  already holds `started: Instant` and owns `ended()` (`:263`). `ConnCtx` (`:225`)
  is an immutable `Clone` snapshot with no methods; `accepted()` belongs to
  `Live` (`nhop/src/daemon/state.rs:122`). Front ends dial through the `NextHop`
  trait's `dial()` (`proxy/mod.rs:302`), called inside `relay(..)`
  (`http.rs:181`, `socks5.rs:99`); `UpstreamHop::routed` is private and
  unreachable from a front end.
- `EventView` (`nhop-ipc/src/view.rs:164`) is constructed or destructured in ten
  files (grep `EventView {`): `nhop-ipc/src/{view,command}.rs`,
  `nhop/src/{logging.rs, proxy/mod.rs, cli/mod.rs, cli/tail.rs, daemon/mod.rs}`,
  `nhop/tests/{acceptance,decision_log,tail_stream}.rs`. The house rule
  "always destructure explicitly, never `..`" makes every one of them a compile
  error when a field is added. `nhop/src/logging.rs:256` has a test-side
  `#[serde(deny_unknown_fields)]` struct that will reject the new field.
- `socket2` 0.6.5 is already in `Cargo.lock:481` transitively. Verified against
  its docs: the **setters** (`TcpKeepalive::with_time/with_interval/with_retries`)
  need no feature and support macOS; the **getters**
  (`tcp_keepalive_interval`, `tcp_keepalive_retries`) require the `all` feature
  and list macOS. Values are expressed in whole seconds on this platform, so a
  round-trip of sub-second durations is lossy - the constants below are integral
  seconds for that reason.
- The upstream is `socks5://192.168.198.144:1080`, a **LAN address**: the socket
  `through()` returns never crosses the home NAT.
- Style contract (CLAUDE.md): no `//` comments, `let..else`, explicit
  destructuring, newtypes, no `matches!`; wire vocabulary only in `nhop-ipc`.

## Development Approach

- **testing approach**: Regular (code + tests in the same task, repo convention)
- complete each task fully before moving to the next
- every task ends with `mise run check` green (fmt + clippy -D warnings + tests)
- wire changes are additive only: old log lines must still parse
- version bump 0.1.2 -> 0.1.3 rides this PR (docs/releasing.md: the tag must
  match the crate version, so the bump belongs in the PR being released)

## Testing Strategy

- unit and integration tests per task as listed; no e2e infrastructure here
- keepalive is verified by reading the options back off a live socket through
  `SockRef`, never by waiting out a timer
- the patrol state machine is driven by short injected delays against the
  existing SOCKS stubs, the way `EAGER`/`PATIENT` already work in
  `nhop/tests/upstream_dialer.rs`

## Solution Overview

- **Keepalive.** Every outbound relay socket gets TCP keepalive: idle 15s,
  interval 15s, 4 lost probes = dead. 15s matches Go's dialer default, proven
  for years on this exact network by ClashX, and sits inside RFC 6202 §5.5's
  safe band. The benefit differs per dial site and the plan states both halves
  rather than one blanket claim:
  - `direct()` - the socket crosses the home NAT, so probes refresh the mapping
    and idle tunnels stop dying at all. This is the half that removes the
    `mtalk.google.com`-shaped deaths and the Chrome black pages.
  - `through()` - the socket terminates on the LAN at the VM, so it refreshes
    no NAT mapping; what it buys is bounded dead-peer detection (a powered-off
    VM surfaces within ~75s instead of hanging until the OS gives up), which is
    the zombie-fd half. The onward hop from the VM is beyond our reach.
  The client (loopback) half gets nothing: loopback cannot die silently.
- **Patrol prober.** The prober runs in both verdict states, first probe
  immediately at startup. A probe whose outcome contradicts the live verdict
  opens a **pending sequence** that records the state it is trying to reach and
  the verdict it started from, and schedules a confirming probe after
  `confirm_delay`; the verdict moves only when a second probe agrees with that
  recorded target. Any probe agreeing with the current verdict discards the
  sequence, and so does **any verdict change arriving by another path** - a real
  dial failure, an operator command. Anchoring on a recorded target rather than
  on "contradicts whatever the verdict is right now" is load-bearing: without it
  a banked contradiction against Up, followed by a dial failure flipping Down,
  followed by a *successful* confirming probe, reads as a second contradiction
  and declares the upstream alive on one good probe - the exact outcome the
  hysteresis exists to prevent.
  A real dial failure keeps flipping Down immediately and unconditionally,
  exactly as today - that path is evidence a user already paid for, while a
  self-generated timeout is not. The symmetry is deliberate: a single 2s
  `PROBE_TIMEOUT` miss against a momentarily loaded VM, a transient loss, or the
  instant after the Mac wakes must not hard-refuse `require` traffic with 502,
  and a single stray answer during VM boot must not declare the upstream alive
  (both observed).
  **Timing, stated honestly.** Each observation can itself consume up to
  `PROBE_TIMEOUT` (2s), so a verdict change costs `interval + confirm_delay +
  2 * PROBE_TIMEOUT` in the worst case and `interval + confirm_delay` when the
  peer refuses fast. The two paths differ in practice: a dropped listener answers
  RST in microseconds, while a powered-off VM black-holes and burns the full
  timeout - the plan's own evidence is a 2.135s dial against exactly that. So a
  dead VM is discovered by the patrol in ~10s rather than 6, still fixing the
  defect (no user pays for the discovery) but not at the number a naive reading
  gives.
  **Cold start needs the daemon's own startup order to be handled**, not just the
  test harness's: the daemon spawns the hop against `NO_UPSTREAM` and publishes
  the real address later, so an immediate first probe hits `127.0.0.1:0`, fails,
  agrees with the default Down verdict, and the real upstream is not seen until
  the next tick. Left alone, cold start becomes ~6s - a second *worse* than
  today. The patrol therefore must not sleep a full interval while the snapshot
  is `NO_UPSTREAM`: it re-checks on a short tick until a real address appears,
  then probes it promptly.
- **connect_ms.** The dial phase is timed around the `hop.dial(..)` await inside
  `relay(..)`, recorded on `Routed` (the object that already owns `started` and
  `ended()`), and lands in `EventView` as an optional field. `None` means no
  dial was attempted (a `require` refusal while the verdict is Down);
  `Some(ms)` covers both a successful and a failed attempt, so a slow failing
  dial stays visible.

## Technical Details

- New direct dependency: `socket2 = { version = "0.6", features = ["all"] }`
  (the `all` feature is required by the getters the tests read back), used only
  inside `nhop/src/upstream/mod.rs`.
- New constants beside `UPSTREAM_CONNECT_TIMEOUT`: `KEEPALIVE_IDLE` = 15s,
  `KEEPALIVE_INTERVAL` = 15s, `KEEPALIVE_RETRIES` = 4, `PROBE_CONFIRM_DELAY` = 1s.
- Contract signatures (bodies are born during execution):
  - `fn keep_alive(stream: &TcpStream) -> io::Result<()>` - builds a
    `TcpKeepalive` from the three constants and applies it via `SockRef`.
    Callers log a warning and continue: a failed setsockopt must never fail a
    dial that otherwise succeeded.
  - `async fn patrol(upstream: LiveUpstream, health: HealthHandle, interval: Duration, confirm_delay: Duration)`
    replaces `probe_while_down` at the same spawn site.
  - `UpstreamHop::start` gains a fourth parameter `confirm_delay: Duration`, so
    the hysteresis is drivable from integration tests without waiting out real
    seconds. All five call sites change; production passes
    `PROBE_CONFIRM_DELAY`.
  - `EventView.connect_ms: Option<u64>` with `#[serde(default)]`.
  - `Routed` gains a recorder for the dial duration, consumed by `ended()`.
    **The refused-versus-attempted distinction originates in `NextHop::dial`'s
    result**, not in timing: from inside `relay(..)` the await is opaque and
    always yields a duration, so a returned duration or an out-parameter can
    only ever report `Some(~0)` for a refusal. `dial` therefore hands back an
    outcome distinguishing `Refused` (the `require`-while-Down path in
    `upstream/mod.rs:92-93`, which never touched the network) from
    `Attempted(Duration)` (success or failure after a real attempt). How that
    value travels from `relay(..)` to `Routed` stays the executor's choice.
    Two shortcuts are banned because both destroy the number this defect is
    about: mapping `UpstreamDown` to `None` (`required` returns the same error
    for a pre-dial refusal and for a dial that was attempted and failed, so the
    measured 2.135s failing dial would report `None`), and re-sampling the health
    verdict outside the call (it races the new patrol).
  - Test helpers pin their own `confirm_delay`: both `upstream/mod.rs:266` and
    `nhop/tests/upstream_dialer.rs:31` pass a long one (`PATIENT`-scale), so no
    confirming probe fires inside a test body that is not about hysteresis.
    Tests that *are* about hysteresis pass a short one explicitly.
  - `StubSocks5` (`nhop/tests/support/mod.rs`) gains a way to read only the
    client dials - probes are self-addressed CONNECTs to the stub's own address,
    so they are filterable - leaving the existing "a require rule must not reach
    the destination itself" guarantees assertable.
- Human `tail`/`logs` line (`cli/mod.rs:930`) shows the dial time when present;
  `logging::logged` keeps parsing old lines (missing field -> `None`).
- CLAUDE.md invariant updates: the prober patrols both states with two-probe
  hysteresis while a real dial failure still flips Down on one failure; relay
  sockets carry keepalive as part of the transport contract.

## What Goes Where

- **Implementation Steps**: code, tests, docs, version bump.
- **Post-Completion**: merge/tag/release mechanics, live verification on this
  machine, vault note update.

## Progress Tracking

- mark completed items with `[x]` immediately when done
- add newly discovered tasks with ➕ prefix, blockers with ⚠️ prefix
- update this file if implementation deviates

## Implementation Steps

### Task 1: TCP keepalive on every outbound relay socket

**Files:**
- Modify: `Cargo.toml` (workspace deps), `nhop/Cargo.toml`
- Modify: `nhop/src/upstream/mod.rs`

- [x] add `socket2` with the `all` feature to the workspace and crate manifests
- [x] add the three keepalive constants and `keep_alive(&TcpStream)` with a doc
      comment carrying the why: NAT-mapping refresh for `direct()` (RFC 6202
      §5.5 band; Chrome 45s / Go 15s precedent) and bounded dead-peer detection
      for `through()`, whose socket stays on the LAN
- [x] apply it in `direct()` and `through()` before the stream is returned,
      warning without failing the dial when the syscall errors; leave `probe()`
      untouched (probe connections live milliseconds)
- [x] write a test: a stream from `direct()` against a local listener reads back
      `keepalive() == true`, `tcp_keepalive_interval() == KEEPALIVE_INTERVAL`
      and `tcp_keepalive_retries() == KEEPALIVE_RETRIES` through `SockRef`
      (`a_direct_socket_carries_keepalive`)
- [x] write a test: the same four-value read-back on the stream returned by
      `through()` against the in-module SOCKS stub, proving `into_inner()` does
      not drop the options
      (`an_upstream_socket_carries_keepalive_through_into_inner`, against a new
      `GRANTED` reply constant)
- [x] cover the idle time too: assert `tcp_keepalive_time() == KEEPALIVE_IDLE`
      where the getter exists on macOS; if it does not, state that in this file
      and assert the two available timers instead - do not silently skip it
      - the getter **does** exist on macOS: socket2 0.6.5 gates
        `Socket::tcp_keepalive_time` on `all(feature = "all", not(any(windows,
        haiku, openbsd, vita)))`, so all four values are asserted
- [x] run `mise run check` - must pass before task 2
      - ➕ `set_tcp_keepalive` does **not** set `SO_KEEPALIVE` on unix (checked
        against socket2 0.6.5 `sys/unix.rs`), so `keep_alive` calls
        `set_keepalive(true)` first - without it `keepalive()` reads back false
        and no probe is ever sent
      - ⚠️ three pre-existing failures in this Linux dev container, unrelated to
        this task and present on the base commit as well:
        `cli::client::tests::a_daemon_that_hangs_up_reports_a_closed_connection`,
        `cli::tail::tests::every_published_decision_is_printed_until_the_daemon_hangs_up`,
        `cli::tail::tests::the_human_form_prints_one_text_line_per_decision`
        (unix-socket hang-up surfaces as ECONNRESET rather than EOF). fmt,
        clippy and every other target are green; 246 pass here against 244 on
        the base commit

### Task 2: patrol prober with immediate start and two-probe hysteresis

**Files:**
- Modify: `nhop/src/upstream/mod.rs`
- Modify: `nhop/src/daemon/mod.rs` (spawn site gains `PROBE_CONFIRM_DELAY`)
- Modify: `nhop/tests/upstream_dialer.rs` (five tests assert retired behaviour;
  three call sites gain the fourth argument)
- Modify: `nhop/tests/support/mod.rs` (`StubSocks5` gains the client-dial view)

- [ ] replace `probe_while_down` with `patrol`: probe first, sleep after, probe
      in both verdict states every `interval`
- [ ] implement the pending-sequence rule: a contradicting probe records the
      target state and the baseline verdict and schedules a confirming probe
      after `confirm_delay`; the verdict moves only on a second probe agreeing
      with that target; an agreeing probe or any verdict change from another
      path discards the sequence
- [ ] do not sleep a full interval while the snapshot is `NO_UPSTREAM` -
      re-check on a short tick so the address published by the first init load
      is probed promptly
- [ ] keep the dial-failure path flipping Down on one failure, and keep the
      "any SOCKS reply counts as serving" classification in `probe()` untouched
- [ ] thread `confirm_delay` through `UpstreamHop::start` and update all five
      call sites; production passes `PROBE_CONFIRM_DELAY`, test helpers pass a
      long delay by default
- [ ] add a client-dial view to `StubSocks5` that excludes self-addressed probe
      CONNECTs
- [ ] replace `no_probe_is_sent_while_the_verdict_is_up` with its inverse: a
      probe IS sent while the verdict is Up
- [ ] relax `the_verdict_flips_up_once_the_upstream_answers_a_probe` to expect
      at least two probes, all aimed at the upstream's own address
- [ ] rework the three request-counting tests onto the client-dial view:
      `a_require_rule_travels_through_the_upstream_as_the_name_the_client_wrote`
      and `a_prefer_rule_travels_through_the_upstream_while_the_verdict_is_up`
      assert the user dial is present without asserting it is the only request;
      restate `a_down_verdict_reaches_no_upstream_at_all` as "no client dial
      reaches the upstream while Down" - keeping, in all three, the guarantee
      that a require rule never reaches the destination directly
- [ ] write a test: cold start against a healthy stub reaches Up shortly after
      `confirm_delay`, without waiting out an interval
- [ ] write a test: starting from `LiveUpstream::default()` and publishing the
      stub afterwards still reaches Up well inside `PROBE_INTERVAL` (this is the
      daemon's real startup order; the test must be able to fail if the
      `NO_UPSTREAM` tick is missing)
- [ ] write a test: a stub answering exactly once never flips the verdict Up
- [ ] write a test: verdict Up, stub gone, verdict reaches Down within
      `interval + confirm_delay + 2 * PROBE_TIMEOUT`
- [ ] write a test: a live stub that misses one probe and answers the next
      leaves the verdict Up, so no `require` connection is refused
- [ ] write a test for the baseline rule: bank a contradicting probe against Up,
      flip the verdict Down through a dial failure mid-sequence, then let a
      *successful* confirming probe land - the verdict must stay Down until a
      second agreeing probe
- [ ] add a stub that accepts and withholds its SOCKS reply, so the
      `PROBE_TIMEOUT` path is exercised rather than only the fast-RST one
- [ ] leave the in-module closed-port hops (`upstream/mod.rs:337-346`) asserting
      Up: one failing probe no longer flips anything, and their helper passes a
      long `confirm_delay`, so no confirming probe fires inside the test body
- [ ] run `mise run check` - must pass before task 3

### Task 3: connect_ms in the decision event

**Files:**
- Modify: `nhop-ipc/src/view.rs`, `nhop-ipc/src/command.rs`
- Modify: `nhop/src/proxy/mod.rs`, `nhop/src/proxy/http.rs`, `nhop/src/proxy/socks5.rs`
- Modify: `nhop/src/logging.rs`, `nhop/src/cli/mod.rs`, `nhop/src/cli/tail.rs`
- Modify: `nhop/src/daemon/mod.rs`
- Modify: `nhop/tests/acceptance.rs`, `nhop/tests/decision_log.rs`, `nhop/tests/tail_stream.rs`
- Modify: `nhop/tests/support/mod.rs` (`StubHop` and `DownHop` implement
  `NextHop`, so they move with the dial-result shape)

- [ ] add `connect_ms: Option<u64>` (`#[serde(default)]`, doc comment) to
      `EventView`
- [ ] give `NextHop::dial` a result that distinguishes `Refused` from
      `Attempted(Duration)`, time the await inside `relay(..)` in both serve
      paths, and carry the outcome to `Routed`; record in this plan how it
      travels across the `relay` boundary
- [ ] update **every** `EventView` literal and destructure in the tree - all ten
      files above - without introducing `..` rest patterns
- [ ] add the field to the test-side `deny_unknown_fields` struct in
      `logging.rs` so the emitted line still parses
- [ ] render the dial time in the human `tail`/`logs` line when present
- [ ] write tests: JSON round-trip with and without `connect_ms`, proving an old
      log line still parses
- [ ] write a test that separates the two timings: hold an established tunnel
      open well past a quick dial, then assert `duration_ms` covers the hold
      while `connect_ms` does not
- [ ] write tests for the two absent/present cases: a `require` refusal while
      the verdict is Down reports `None`; an attempted dial that fails
      **upstream-side** (so it surfaces as `UpstreamDown`, the same error the
      refusal produces) reports `Some` - this is the test that catches the
      banned `UpstreamDown`-means-`None` shortcut
- [ ] run `mise run check` - must pass before task 4

### Task 4: version bump and documentation

**Files:**
- Modify: `Cargo.toml` (+ `Cargo.lock` via cargo)
- Modify: `README.md`, `CLAUDE.md`

- [ ] bump the workspace version 0.1.2 -> 0.1.3
- [ ] README: document keepalive on relayed sockets with the split benefit
      (NAT refresh for direct, dead-peer detection for upstream), the patrol
      lifecycle (immediate first probe, two-probe hysteresis both ways, dial
      failures still immediate), and `connect_ms` in the log-fields list of
      "Agent-friendly by design"
- [ ] CLAUDE.md: update the upstream invariant and add the relay-keepalive
      transport contract to the invariants list
- [ ] run `mise run check` - must pass before task 5

### Task 5: verify acceptance criteria

- [ ] all three Overview defects addressed: keepalive options readable off both
      dial sites' sockets, patrol probing both states with hysteresis,
      `connect_ms` present in JSON and human output
- [ ] wire compat verified: old log lines parse, `--json` consumers see only an
      added optional field
- [ ] no test in the tree still asserts a retired invariant
- [ ] full gate: `mise run check`

### Task 6: [Final] close out the plan

- [ ] re-read the README/CLAUDE.md deltas against the final code
- [ ] move this plan to `docs/plans/completed/`

## Post-Completion

**Release mechanics** (docs/releasing.md): PR -> CI green -> squash-merge ->
annotated tag `v0.1.3` on main -> release workflow builds, signs, publishes and
rewrites the tap formula -> `brew upgrade nhop && brew services restart nhop`.

**Live verification on this machine** (the real acceptance test):
- keepalive is actually set on a live relay socket (read it back off the running
  daemon rather than trusting the unit test)
- within a day, the zombie census for **direct** traffic collapses:
  `nhop logs --since 24h --json` filtered to `decision == "direct"` should lose
  the `mtalk.google.com` deaths at 28.3 min and drop from ~350 ETIMEDOUT/day
  toward zero. Upstream-routed hosts are explicitly NOT expected to follow -
  their NAT-crossing hop belongs to the VM
- fd census stays low: dying-state sockets (FIN_WAIT_2 / CLOSED / CLOSE_WAIT)
  no longer accumulate during ordinary browsing
- VM off/on cycle: the verdict reaches Down without any user dial - expect
  ~`interval + confirm_delay + 2 * PROBE_TIMEOUT` (~10s), not the fast-refusal
  ~6s, because a powered-off VM black-holes rather than refuses - returns Up
  shortly after boot, and does not flap during boot
- daemon cold start: the verdict reaches Up well inside `PROBE_INTERVAL` of the
  first init load, confirming the `NO_UPSTREAM` tick works in production and not
  only in the harness
- the Chrome symptom: no multi-second black pages on kagi after a long idle

**Vault note** (`nhop proxy router.md` in PK Workspace): add the NAT/keepalive
item to "Грабли" and refresh the version reference to 0.1.3.
