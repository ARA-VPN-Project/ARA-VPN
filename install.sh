#!/bin/sh
# ARA VPN 0.1.1: pinned GitHub bootstrap. No user data is embedded here.
set -eu
die() { printf 'ARA VPN: %s\n' "$*" >&2; exit 1; }
[ "$#" -le 2 ] || die 'usage: install.sh [server|control|edge|client] [--check]'
role=${1:-server}
case "$role" in server|control) mode=--setup-panel;; edge|client) mode=--apply;; *) die 'choose server, control, edge or client';; esac
if [ "$#" -eq 2 ]; then [ "$2" = --check ] || die 'second argument must be --check'; mode=--check; fi
if [ "$mode" != --check ]; then [ "$(id -u)" = 0 ] || die 'run through sudo sh (or sh as root)'; fi
command -v dpkg >/dev/null 2>&1 || die 'Debian with dpkg is required'
command -v curl >/dev/null 2>&1 || die 'install curl first'
command -v sha256sum >/dev/null 2>&1 || die 'sha256sum is required'
arch=$(dpkg --print-architecture)
case "$arch" in
    amd64) manifest=d72b8bf8696dab1b334cb089898732dcb460c51ec4bd11bbb564287cb3244130 ;;
    armhf) manifest=fed4ef1eee34f37a381865e957de3bbe4ca854fb22343f58bc40267c15fa4f62 ;;
    *) die 'this release contains amd64 and armhf packages only' ;;
esac
# curl | sudo sh leaves stdin at EOF. Use the controlling terminal for the
# interactive wizard, and reject non-interactive setup before installing.
if [ "$mode" = --setup-panel ]; then
    ( : </dev/tty ) 2>/dev/null || die 'interactive setup requires a terminal; use --check for unattended verification'
fi
base=https://github.com/ARA-VPN-Project/ARA-VPN/releases/download/v0.1.1
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
trap 'exit 1' HUP INT TERM
curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 10 --max-time 300 "$base/install.sh" -o "$stage/install.sh"
printf '%s  %s\n' 'be9f5db5ccb3283bb59920815e03a33963516380c56c07d8992768aa77cf33fc' "$stage/install.sh" | sha256sum -c - >/dev/null || die 'installer checksum mismatch'
if [ "$mode" = --setup-panel ]; then
    sh "$stage/install.sh" "$base" 0.1.1 "$manifest" "$role" "$mode" </dev/tty
else
    sh "$stage/install.sh" "$base" 0.1.1 "$manifest" "$role" "$mode"
fi
