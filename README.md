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
- two rule classes: `require` (must go through the upstream, error if it is down)
  and `prefer` (try the upstream, fall back to a direct connection)
- listens for HTTP CONNECT and SOCKS5 on the ports the previous setup used, so
  clients pinned to them need no reconfiguration

## Install

Everything below is one-time setup. Commands are written for fish.

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
`~/.local/state/nhop/nhop.log`, read with `nhop logs`. `PATH` is set in the
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

The order matters. `sudo nhop proxy off` goes **first**, while the daemon is
still running: it needs the daemon to answer, and removing the agent first
leaves macOS pointing every app at ports nothing listens on.

```
sudo nhop proxy off
launchctl bootout gui/$(id -u)/com.pavel-karpovich.nhop
rm ~/Library/LaunchAgents/com.pavel-karpovich.nhop.plist
rm ~/.local/bin/nhop
rm -r ~/.config/nhop ~/.local/state/nhop
```

Confirm with `nhop proxy status` before removing the binary - all three settings
must read `off`.
