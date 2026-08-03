# nhop

Rule-based local proxy router for macOS.

Decides, per connection, what the next hop is: a corporate SOCKS5 proxy or the
destination itself. Runs as a background daemon with no GUI and no menu bar
presence; everything is driven from the CLI.

## Status

Design settled, implementation not started.

## Shape

- single binary: `nhop start` runs the daemon, every other subcommand is a client
  talking to it over a unix socket
- config is an executable script at `~/.config/nhop/init` that calls the CLI,
  so it can be fish, loops and all
- two rule classes: `require` (must go through the upstream, error if it is down)
  and `prefer` (try the upstream, fall back to a direct connection)
- listens for HTTP CONNECT and SOCKS5 on the ports the previous setup used, so
  clients pinned to them need no reconfiguration
