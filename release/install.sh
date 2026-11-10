#!/bin/sh
# Debian bootstrap. Run as root only for the explicit --apply step.
set -eu

die() { printf 'ARA: %s\n' "$*" >&2; exit 1; }

[ "$#" -ge 4 ] && [ "$#" -le 5 ] ||
    die 'usage: install.sh RELEASE_HTTPS_BASE VERSION MANIFEST_SHA256 client|edge|control|server [--apply|--setup-panel]'
base=${1%/}
version=$2
expected=$3
role=$4
mode=${5:---check}
case "$base" in https://?*) ;; *) die 'release URL must use HTTPS' ;; esac
case "$base" in *[!a-zA-Z0-9./:_-]*) die 'invalid release URL' ;; esac
case "$version" in ''|*[!0-9.a-z-]*) die 'invalid release version' ;; esac
case "$expected" in ''|*[!0-9a-f]*) die 'invalid SHA-256' ;; esac
[ "${#expected}" = 64 ] || die 'expected a 64-character manifest SHA-256'
case "$role" in
    client) packages='ara-engine ara' ;;
    edge) packages='ara-engine ara ara-edge' ;;
    control) packages='ara-control' ;;
    server) packages='ara-engine ara-edge ara-control' ;;
    *) die 'choose client, edge, control or server' ;;
esac
case "$mode" in --check|--apply|--setup-panel) ;; *) die 'use --apply or --setup-panel to install' ;; esac
if [ "$mode" = --setup-panel ]; then
    case "$role" in
        control) packages='ara-engine ara ara-control' ;;
        server) packages='ara-engine ara ara-edge ara-control' ;;
        *) die '--setup-panel requires the control or server role' ;;
    esac
fi
[ "$mode" = --check ] || [ "$(id -u)" = 0 ] || die '--apply requires root'
[ -r /etc/os-release ] && [ "$(sed -n 's/^ID=//p' /etc/os-release)" = debian ] ||
    die 'this installer supports Debian'
arch=$(dpkg --print-architecture)
case "$arch" in amd64|arm64|armhf) ;; *) die "unsupported architecture: $arch" ;; esac

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
trap 'exit 1' HUP INT TERM
download() {
    curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 10 --max-time 300 --output "$2" "$base/$1"
}
verify() {
    actual=$(sha256sum "$2")
    [ "${actual%% *}" = "$1" ] || die "SHA-256 mismatch: ${2##*/}"
}
manifest="SHA256SUMS-$arch"
download "$manifest" "$stage/$manifest"
verify "$expected" "$stage/$manifest"
manifest_digest() {
    digest=$(awk -v file="$1" '$2 == file { digest = $1; count++ } END { if (count == 1) print digest }' "$stage/$manifest")
    case "$digest" in ''|*[!0-9a-f]*) die "invalid or missing digest for $1" ;; esac
    [ "${#digest}" = 64 ] || die "invalid digest for $1"
    printf '%s\n' "$digest"
}
if [ "$mode" = --setup-panel ]; then
    download configure-panel.sh "$stage/configure-panel.sh"
    digest=$(manifest_digest configure-panel.sh)
    verify "$digest" "$stage/configure-panel.sh"
fi
set --
for package in $packages; do
    current=$(dpkg-query -W -f='${db:Status-Abbrev} ${Version}' "$package" 2>/dev/null || true)
    case "$current" in
        "ii  $version"|'') ;;
        'ii '*) die "installed $package has a different version; use the signed ARA updater" ;;
        'rc '*) ;;
        *) die "package $package is in a partial state; inspect dpkg before continuing" ;;
    esac
    file="${package}_${version}_${arch}.deb"
    digest=$(manifest_digest "$file")
    download "$file" "$stage/$file"
    verify "$digest" "$stage/$file"
    [ "$(dpkg-deb -f "$stage/$file" Package)" = "$package" ] &&
        [ "$(dpkg-deb -f "$stage/$file" Version)" = "$version" ] &&
        [ "$(dpkg-deb -f "$stage/$file" Architecture)" = "$arch" ] ||
        die "package identity mismatch: $file"
    set -- "$@" "$stage/$file"
done
apt-get --simulate --no-remove --no-install-recommends install "$@"
if [ "$mode" != --check ]; then
    apt-get --assume-yes --no-remove --no-install-recommends install "$@" </dev/null
    if [ "$mode" = --setup-panel ]; then sh "$stage/configure-panel.sh"; fi
else
    printf '%s\n' 'Packages verified. Add --apply to install.'
fi
