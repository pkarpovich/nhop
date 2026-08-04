#!/usr/bin/env bash
set -euo pipefail

IDENTIFIER="dev.pkarpovich.nhop"

if [ $# -ne 1 ]; then
	echo "usage: ${0##*/} <team-id>" >&2
	echo "the team id is the parenthesised suffix of a Developer ID Application identity:" >&2
	echo "  security find-identity -v -p codesigning" >&2
	exit 2
fi

team_id=$1
root=$(cd "$(dirname "$0")/.." && pwd)
binary="$root/target/release/nhop"

identity=$(security find-identity -v -p codesigning |
	grep "Developer ID Application" |
	grep "($team_id)" |
	head -n 1 |
	awk '{print $2}' || true)

if [ -z "$identity" ]; then
	echo "no Developer ID Application identity for team $team_id in the login keychain" >&2
	exit 1
fi

cargo build --release --manifest-path "$root/Cargo.toml"

codesign \
	--force \
	--timestamp \
	--options runtime \
	--identifier "$IDENTIFIER" \
	--sign "$identity" \
	"$binary"

codesign --verify --strict --verbose=2 "$binary"

codesign --display "$binary" 2>&1 | grep '^Identifier='
