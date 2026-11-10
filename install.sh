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
    amd64) manifest=1f46ba72afddbb1792e64d6efaedbc81dfe228495beea3478209c1526a6113b2 ;;
    armhf) manifest=f0a11b29a593e766bb7bd04bdfb7c0afa98f061d2f6d407d3e819d7771aee9e8 ;;
    *) die 'this release contains amd64 and armhf packages only' ;;
esac
base=https://github.com/ARA-VPN-Project/ARA-VPN/releases/download/v0.1.1
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
trap 'exit 1' HUP INT TERM
curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 10 --max-time 300 "$base/install.sh" -o "$stage/install.sh"
printf '%s  %s\n' 'bb122aa3f3a437fe90770a18acba39672039b4381f73cc3401d6eb88b08d9ced' "$stage/install.sh" | sha256sum -c - >/dev/null || die 'installer checksum mismatch'
sh "$stage/install.sh" "$base" 0.1.1 "$manifest" "$role" "$mode"
