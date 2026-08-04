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

### A worked example

Nothing below is real. It is the Scranton branch of the Dunder Mifflin Paper
Company, working from home after the Sabre acquisition, and it exists to show
what pushes a destination into one class rather than another.

The setup: a VM on the home LAN runs the corporate VPN client and exposes a
SOCKS5 proxy on `192.168.7.20:1080`. Everything Dunder Mifflin lives behind it.

```fish
#!/usr/bin/env fish

nhop upstream socks5://192.168.7.20:1080

# Home LAN and the branch printer. Matched before every other rule, so nothing
# below can accidentally drag them into the tunnel.
nhop never cidr 192.168.7.0/24
nhop never suffix pyramid.local

# Only reachable through the VPN, so a direct attempt cannot succeed - better a
# clear 502 than a minute of silence.
nhop require suffix corp.dundermifflin.com
nhop require keyword sabre   # sabre-erp, sabre-sso, whatever it is called this quarter

# Public, and routed through the VPN for policy rather than reachability. When
# the VM is off these keep working over the ordinary connection.
nhop prefer suffix dundermifflin.com
nhop prefer suffix wuphf.com

# The init file is a program, so the branch subnets are a loop. A cidr rule only
# ever catches a client that already dials an IP literal - nothing here resolves
# a hostname to an address to see whether it lands in one of these.
for subnet in 10.15.0.0/16 10.20.0.0/16 10.30.0.0/16 10.99.0.0/16
    nhop require cidr $subnet   # Scranton, Utica, Stamford, corporate NYC
end
```

The split is the whole point. `warehouse.corp.dundermifflin.com` is `require`
because it does not exist outside the VPN; `dundermifflin.com` is `prefer`
because it is a public website that merely ought to be reached from a corporate
address. With the VM shut down for the weekend the first fails immediately and
the second still loads, and no rule had to be edited to get there.

Check any of it without opening a connection. Rules are numbered from zero in
declaration order:

```
$ nhop test warehouse.corp.dundermifflin.com:443
upstream via rule 2 (require) to socks5://192.168.7.20:1080

$ nhop test pyramid.local:9100
never via rule 1 (never) to pyramid.local:9100

$ nhop test 10.15.4.9:445
upstream via rule 6 (require) to socks5://192.168.7.20:1080

$ nhop test example.net:443
direct via no rule to example.net:443
```

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
sed "s|{{HOME}}|$HOME|g" packaging/dev.pkarpovich.nhop.plist \
    > ~/Library/LaunchAgents/dev.pkarpovich.nhop.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.pkarpovich.nhop.plist
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
launchctl bootout gui/$(id -u)/dev.pkarpovich.nhop
rm ~/Library/LaunchAgents/dev.pkarpovich.nhop.plist
rm ~/.local/bin/nhop
rm -r ~/.config/nhop ~/.local/state/nhop
```

Confirm with `nhop proxy status` before removing the binary - all three settings
must read `off`.

## Agent-friendly by design

A router that decides where every connection goes is only as good as your ability
to ask it what it did. Everything it reports is machine-readable, so a coding
agent asked to work out why something is slow or unreachable can do it without
guessing:

- **`--json` on every read command** - `status`, `rules`, `test`, `logs`, `tail`,
  `doctor`. With the flag they print one JSON document on stdout and nothing
  else, so no output has to be scraped out of prose that changes wording later.
- **Exit codes carry meaning** - 0 success, 2 nothing there, 3 upstream down, 4
  malformed arguments, 1 everything else. A script can branch without reading a
  message.
- **The log is JSON lines**, one object per routing decision, so `jq` answers
  questions the tool has no command for.
- **No interactive prompts anywhere.** Every command either acts or fails with a
  message. Nothing waits on a human.

### Is it my proxy?

`nhop doctor` runs seven checks and exits non-zero if any fails. It is the first
thing to run and usually the last:

```
$ nhop doctor
ok    daemon_reachable  the daemon answered on ~/.local/state/nhop/nhop.sock
ok    ports_bound       http on 127.0.0.1:7890, socks5 on 127.0.0.1:7891
ok    system_proxy      Wi-Fi sends http and https to 127.0.0.1:7890 and socks to 127.0.0.1:7891
ok    upstream_reachable  socks5://… answered, the verdict is up
```

It knows one macOS trap by name: a denied Local Network permission surfaces as
`No route to host`, not as a permission error, so the `upstream_reachable` check
says so and names the remedy rather than reporting a routing fault.

### Why did this host go there?

`nhop test` answers without opening a connection, so it is safe to run against
production hostnames:

```
$ nhop test warehouse.internal.example:443 --json
{"decision":"upstream","rule_index":5,"class":"require","next_hop":"socks5://…"}
```

`rule_index` is the position in `nhop rules`, so the answer points at the exact
line of the init file that decided it. A destination that matches nothing comes
back as `direct` with a null rule.

### What actually happened to that request?

`nhop tail` follows decisions live; `nhop logs --since 15m` reads back. With
`--json` both feed `jq`. Which upstream hosts are slow:

```
nhop logs --since 1h --json |
  jq -rs '[.[] | select(.fields.decision=="upstream")]
          | group_by(.fields.host)
          | map({host: .[0].fields.host, worst: (map(.fields.duration_ms) | max)})
          | sort_by(-.worst) | .[:5][] | "\(.host)  \(.worst)ms"'
```

Only the connections that failed, with the reason:

```
nhop logs --since 1h --json |
  jq -r 'select(.fields.error) | "\(.fields.host):\(.fields.port)  \(.fields.error)"'
```

Every decision event carries `host`, `port`, `decision`, `rule_index`, `class`,
`upstream` (the health verdict at the time), `duration_ms` and `error`. Hostnames
and ports only - no request bodies, headers or credentials are ever logged.

### Did my rule change land?

`nhop reload` re-runs the init script and either commits the whole new ruleset or
keeps the old one. `nhop status` then reports the outcome:

```
$ nhop status --json | jq '{last_load, rules}'
{"last_load":{"at":"…","outcome":"ok","command":null},"rules":{"require":9,"prefer":20,"never":5}}
```

An `outcome` of `failed` carries the command that broke in `command`, and the
previous ruleset is still the one serving traffic.

### Health gate in a script

```fish
if nhop doctor >/dev/null
    echo "routing is healthy"
else if test $status -eq 3
    echo "the upstream is down - require rules will fail, prefer rules go direct"
end
```

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
