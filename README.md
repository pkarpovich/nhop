# nhop

Rule-based local proxy router for macOS.

Decides, per connection, what the next hop is: a corporate SOCKS5 proxy or the
destination itself. Runs as a background daemon with no GUI and no menu bar
presence; everything is driven from the CLI.

## Shape

- single binary: `nhop start` runs the daemon, every other subcommand is a client
  talking to it over a unix socket
- config is an executable script at `~/.config/nhop/init` that calls the CLI,
  so it can be fish, loops and all
- three rule classes: `require` (must go through the upstream, error if it is
  down), `prefer` (try the upstream, fall back to a direct connection) and
  `never` (always direct, matched before every other rule)
- listens for HTTP CONNECT and SOCKS5 on the ports the previous setup used, so
  clients pinned to them need no reconfiguration

## Commands

`nhop start` is the daemon. Everything else connects to its socket, sends one
command and exits. The rule verbs and `upstream`, `listen`, `on`, `off` and
`reload` mutate the ruleset; `status`, `rules`, `test`, `logs`, `tail` and
`doctor` read. Each of those six takes `--json` and then prints one JSON
document on stdout and nothing else. `nhop proxy status` is the exception: it
reads macOS rather than the daemon and prints three fixed lines.

| Command | What it does |
|---|---|
| `nhop start` | runs the daemon in the foreground until it is signalled |
| `nhop require <kind> <value>` | adds a rule that must traverse the upstream |
| `nhop prefer <kind> <value>` | adds a rule that tries the upstream, direct when it is down |
| `nhop never <kind> <value>` | adds a rule that is always dialled directly |
| `nhop upstream socks5://<ip>:<port>` | points the router at its one SOCKS5 upstream |
| `nhop listen <http addr> <socks addr>` | moves the two front ends |
| `nhop reload [path]` | re-runs the init script, or a different file and remembers it |
| `nhop on` | re-runs the remembered init script |
| `nhop off` | clears the live ruleset while both front ends keep listening |
| `nhop status` | reports uptime, listeners, upstream health, last load, rule counts, system proxy |
| `nhop rules` | lists the live ruleset in declaration order |
| `nhop test <host>:<port>` | reports where a destination would be routed, without dialling it |
| `nhop logs` | prints the daemon log; `-f` follows, `--since 15m` limits the window |
| `nhop tail` | follows routing decisions as they are made |
| `nhop doctor` | runs the seven diagnostic checks |
| `nhop proxy on\|off\|status` | reads or sets the macOS proxy settings; `--service`, default `Wi-Fi` |

Exit codes: 0 success, 2 nothing there (no socket, no daemon, unknown thing), 3
upstream down, 4 malformed arguments, 1 everything else.

`nhop doctor` aggregates its own code from the checks - `daemon_reachable`,
`ports_bound`, `system_proxy`, `upstream_reachable`, `init_file`, `last_load`,
`log_writable` - rather than following that table: 0 when all seven pass, 3 when
`upstream_reachable` is the only failure, 1 otherwise. With no daemon answering
it still prints all seven, the unmade ones failed, and exits 1.

`--service` belongs to `nhop proxy` alone. The daemon always reads the `Wi-Fi`
service, so on a machine set up on another service `nhop status` reports the
system proxy as off and the `system_proxy` check of `nhop doctor` keeps failing.

## Rule classes

One canonical form, used on the command line and in the init file:

```
nhop <require|prefer|never> <suffix|cidr|port|keyword> <value>
```

The three classes differ only in what happens when the upstream is down:

- `require` - must traverse the upstream. With the upstream down the connection
  fails at once: `502 Bad Gateway` on the HTTP front end, reply `0x04` on the
  SOCKS5 one, exit 3 from the CLI. For what only exists behind the upstream.
- `prefer` - tries the upstream and falls back to a direct connection when it is
  down. For public services routed through the upstream only for traffic volume.
- `never` - always dialled directly, and matched before every other rule.

That split is why nothing has to be toggled when the upstream goes away: bulk
traffic self-heals to direct and internal traffic fails honestly.

The four kinds:

- `suffix` - exact or dot-boundary match, case-insensitive, trailing dot stripped
- `cidr` - matches only hosts that are IP literals; a hostname never matches one
- `port` - exact equality, no ranges
- `keyword` - case-insensitive substring of the host, never of the port

Precedence: `never` rules first, then the rest in declaration order, first match
wins, no match is direct.

## Limits

The router carries TCP and nothing else. SOCKS5 `BIND` and `UDP ASSOCIATE` are
refused with reply `0x07`, so QUIC and every other UDP flow leaves the machine
without ever being routed; there is no DNS server and no TUN interception, so
only clients that use the system proxy or dial the two ports are covered at all.

The HTTP front end serves one request per connection: a `CONNECT` tunnel, or one
absolute-form plain-HTTP request with its body. Anything the client pipelines
behind that body is discarded rather than sent to the first request's next hop.
A request head over 8 KiB closes the connection without an answer.

## Init file

`~/.config/nhop/init` is the profile. The daemon runs it as a program at start
and on `reload`, so its shebang picks the interpreter - fish, loops and all. It
runs with the working directory set to `~/.config/nhop` and the directory of the
running `nhop` binary prepended to `PATH`, so a plain `nhop` inside it reaches
the daemon whose run it belongs to.

Loads are atomic. The daemon stamps each run with an id, passes it to the script
as `NHOP_LOAD_ID`, and the CLI hands it back on every mutating command, so those
commands accumulate in a staging ruleset instead of touching live traffic. The
staged set goes live only when the script exits zero; a failed command, a
non-zero exit or a run exceeding 30 seconds leaves the previous ruleset serving
traffic and records which command failed in `nhop status`. A half-applied rule
set on a router means traffic silently taking the wrong path, which is why there
is no incremental mode. Anything the script spawns has to inherit that variable:
a command reaching the daemon without it while a run is in flight is refused.

A missing init file is not an error. Until the first load commits the ruleset is
empty and every connection is direct - `nhop status` says so.

`packaging/nhop.init.example` is a commented starting point with placeholders.

## Filesystem contract

| Path | Purpose |
|---|---|
| `~/.config/nhop/init` | executable rule script, run at daemon start and on `reload` |
| `~/.local/state/nhop/nhop.sock` | IPC socket, mode 0600 |
| `~/.local/state/nhop/nhop.pid` | single-instance guard, held under an advisory `flock` |
| `~/.local/state/nhop/nhop.log.<date>` | JSON-lines log, one file per day, 7 kept; `nhop logs` reads them all |
| `~/.local/state/nhop/launchd.{out,err}.log` | what launchd caught of stdout and stderr, startup failures only |

The socket deliberately does not live in `/tmp`: a world-writable socket would
let any local process rewrite this machine's traffic routing.

## Install

Everything below is one-time setup. Commands are written for fish. Building
needs the pinned toolchain (`mise install`, Rust 1.97) and a `Developer ID
Application` identity in the login keychain; `mise run check` is the full gate -
`cargo fmt --check`, `cargo clippy --all-targets -D warnings`, `cargo test`.

**1. Build and sign.** macOS denies local-subnet access to binaries that are not
properly signed and reports the denial as `No route to host`, so a Developer ID
signature is not optional here. The team id is the parenthesised suffix of the
identity, never a literal in this repo:

```
security find-identity -v -p codesigning
./scripts/build-signed.sh <TEAM_ID>
```

The script builds release, signs with the hardened runtime, verifies with
`codesign --verify --strict` and prints the identifier it signed under.

**2. Install the binary and the directories.**

```
mkdir -p ~/.local/bin ~/.config/nhop ~/.local/state/nhop
install -m 755 target/release/nhop ~/.local/bin/nhop
```

**3. Write the init file.** It is the profile: the rule set is whatever this
script declares, and it is re-run on `nhop reload`.

```
cp packaging/nhop.init.example ~/.config/nhop/init
$EDITOR ~/.config/nhop/init
chmod +x ~/.config/nhop/init
```

The example ships with placeholders and its own first line is a notice rather
than a shebang - replace every line marked `# replace` and delete that first
line so the shebang leads. A missing init file is not an error; until the first
load commits, the ruleset is empty and every connection is direct.

**4. Load the LaunchAgent.** The plist carries `{{HOME}}` where an absolute home
directory has to go, because launchd expands neither `~` nor `$HOME`:

```
sed "s|{{HOME}}|$HOME|g" packaging/com.pavel-karpovich.nhop.plist \
    > ~/Library/LaunchAgents/com.pavel-karpovich.nhop.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.pavel-karpovich.nhop.plist
```

It sets `RunAtLoad` and `KeepAlive`, so launchd starts the daemon at login and
restarts it when it dies, and points stdout and stderr at
`~/.local/state/nhop/launchd.out.log` and `launchd.err.log`. Those two catch
startup failures only; the daemon's own JSON log is
`~/.local/state/nhop/nhop.log.<date>`, read with `nhop logs`. `PATH` is set in the
plist because launchd's default does not include Homebrew and
`#!/usr/bin/env fish` has to resolve.

**5. Point macOS at the daemon, once.** The daemon never touches the system
proxy itself:

```
sudo nhop proxy on
```

This asks the running daemon for its listen addresses and sets the HTTP, HTTPS
and SOCKS proxies of the Wi-Fi service to them, plus the bypass list
(`localhost`, `127.0.0.1`, `*.local`, `169.254/16`). Another service takes
`--service '<name>'`. Without root it refuses and prints the exact `sudo`
invocation instead of prompting. `sudo` keeps `HOME` on macOS, so root reaches
the operator's socket rather than root's own state directory.

**6. Grant Local Network access on first run.** macOS should prompt the first
time the daemon dials the upstream. If it does not, enable `nhop` by hand under
System Settings -> Privacy & Security -> Local Network. A denial surfaces as
`No route to host` rather than as a permission error, which is what `nhop
doctor` reports as a probable Local Network denial.

**7. Check the result.**

```
nhop doctor
nhop status
```

## Uninstall

The order matters. `sudo nhop proxy off` goes **first**: removing the agent
before it leaves macOS pointing every app at ports nothing listens on.

```
sudo nhop proxy off
launchctl bootout gui/$(id -u)/com.pavel-karpovich.nhop
rm ~/Library/LaunchAgents/com.pavel-karpovich.nhop.plist
rm ~/.local/bin/nhop
rm -r ~/.config/nhop ~/.local/state/nhop
```

Confirm with `nhop proxy status` before removing the binary - all three settings
must read `off`.

## Three constraints behind the design

Each of these looks like an arbitrary choice and is not.

**The default ports are not a preference.** An API client on the target machine
is pinned to `127.0.0.1:7891` SOCKS5 by hand and ignores the macOS system proxy
entirely. That is why the front ends default to `127.0.0.1:7890` (HTTP) and
`127.0.0.1:7891` (SOCKS5), and why moving the SOCKS port with `nhop listen`
breaks that client silently - it will keep dialling 7891.

**The binary must be signed, and the failure does not look like a permission
problem.** macOS Local Network privacy denies local-subnet access to binaries
that are not properly signed and reports the denial as `EHOSTUNREACH`, "No route
to host" - never as a permission error. An ad-hoc-signed build therefore looks
like a broken upstream. `nhop doctor` names this: on `EHOSTUNREACH` while
dialling the upstream it reports a probable Local Network denial and the remedy.
The permission has to be confirmed under launchd, not only from a terminal.

**`nhop off` clears the rules but keeps both listeners bound, on purpose.** For
the pinned client above, a closed port is not "no proxying" - it is
`connection refused`, i.e. no connectivity at all. With the listeners up and the
ruleset empty every connection is served and dialled directly, which is what
"off" has to mean here. The same reasoning applies to stopping the daemon: don't,
unless the system proxy is off and the pinned client is expected to fail.
