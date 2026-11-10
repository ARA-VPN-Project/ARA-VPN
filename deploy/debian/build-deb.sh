#!/bin/sh
# build-deb.sh — build .deb packages for ara components on a Debian host.
# Requires: go (pinned, see go.mod), dpkg-deb, fakeroot optional.
# This script never enables system routing and never starts services:
# postinst only creates users/dirs; activation happens via an explicit
# `ara setup apply` of a reviewed plan (docs/OPERATIONS.md).
set -eu
# Package payloads contain public binaries; dpkg requires traversable metadata.
# Do not inherit a caller's private-data umask for DEBIAN and payload directories.
umask 022

cd "$(dirname "$0")/../.."
VERSION="${ARA_VERSION:-$(cat VERSION)}"
ARCH="${ARA_ARCH:-$(dpkg --print-architecture)}"
case "$ARCH" in
    amd64|arm64) GOARCH="$ARCH"; unset GOARM ;;
    armhf) GOARCH=arm; export GOARM=7 ;;
    *) echo "FATAL: unsupported Debian architecture: $ARCH (expected amd64, arm64 or armhf)" >&2; exit 1 ;;
esac
export GOOS=linux GOARCH CGO_ENABLED=0
OUT="${ARA_OUT:-dist}"
mkdir -p "$OUT"

# GO may be overridden (ARA_GO=/path/to/pinned/go) when the system go is
# older than the module's toolchain directive.
GO="${ARA_GO:-go}"

build_bin() {
    "$GO" build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o "$2" "./cmd/$1"
}

# Legal materials are mandatory payload, not optional release attachments.
install_legal_docs() {
    legal_dir="$1/usr/share/doc/$2"
    mkdir -p "$legal_dir"
    install -m 0644 LICENSE NOTICE TRADEMARKS.md SOURCES.md "$legal_dir/"
    cp -R licenses "$legal_dir/licenses"
    cp NOTICE "$legal_dir/copyright"
}

# --- ara-cli (client CLI + agent) -------------------------------------
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
build_bin ara "$STAGE/ara"
build_bin ara-agent "$STAGE/ara-agent"

# D03: the client runtime launches sing-box (TUN/proxy mode) — the SAME
# pinned engine travels in the client package under /usr/lib/ara with a
# recorded sha256; a build without the pinned engine fails.
if [ -n "${ARA_SINGBOX:-}" ] && [ -x "$ARA_SINGBOX" ]; then
    install -m 0755 "$ARA_SINGBOX" "$STAGE/sing-box"
else
    echo "FATAL: ARA_SINGBOX must point at the pinned sing-box build for the ara client package" >&2
    exit 1
fi
# E03: the engine input is verified against the TRUSTED digest lock
# (ARA_SINGBOX_SHA256) BEFORE anything is staged — computing and recording
# the sha256 of untrusted bytes proves nothing. A wrong/absent lock fails
# the build.
if [ -z "${ARA_SINGBOX_SHA256:-}" ]; then
    echo "FATAL: ARA_SINGBOX_SHA256 (trusted engine digest lock) is required — an unverifiable input is never packaged" >&2
    exit 1
fi
GOT_SHA=$(sha256sum "$STAGE/sing-box" | cut -d" " -f1)
if [ "$GOT_SHA" != "$ARA_SINGBOX_SHA256" ]; then
    echo "FATAL: engine digest mismatch: lock=$ARA_SINGBOX_SHA256 input=$GOT_SHA — refusing to package untrusted bytes" >&2
    exit 1
fi
if [ "$ARCH" = armhf ]; then
    if ! "$GO" version -m "$STAGE/sing-box" | awk '
        $2 == "GOOS=linux" { os=1 }
        $2 == "GOARCH=arm" { arch=1 }
        $2 ~ /^GOARM=7(,hardfloat)?$/ { variant=1 }
        END { exit !(os && arch && variant) }'; then
        echo "FATAL: armhf requires the Linux ARMv7 sing-box binary" >&2
        exit 1
    fi
fi
mkdir -p "$STAGE/deb/DEBIAN" "$STAGE/deb/usr/bin" "$STAGE/deb/usr/share/doc/ara" \
         "$STAGE/deb/lib/systemd/system" "$STAGE/deb/var/lib/ara-agent"
install -m 0755 "$STAGE/ara" "$STAGE/deb/usr/bin/ara"
install -m 0755 "$STAGE/ara-agent" "$STAGE/deb/usr/bin/ara-agent"
install -m 0644 deploy/debian/systemd/ara-agent.service deploy/debian/systemd/ara-node-access.service deploy/debian/systemd/ara-node-access.socket "$STAGE/deb/lib/systemd/system/"
install -m 0644 README.md "$STAGE/deb/usr/share/doc/ara/"
install_legal_docs "$STAGE/deb" ara

cat > "$STAGE/deb/DEBIAN/control" <<EOF
Package: ara
Version: $VERSION
Architecture: $ARCH
Maintainer: ARA VPN project <ara@invalid>
Depends: libc6 (>= 2.34), ara-engine (= $VERSION)
Section: net
Priority: optional
Description: ARA VPN client CLI and local agent
 Typed policy/routing/limits engine with plan-based management.
 Data plane activation requires an explicit reviewed setup plan.
Homepage: https://invalid.example/ara
EOF

cat > "$STAGE/deb/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
# create the service user; never touch routing/DNS/firewall here
if ! id ara-agent >/dev/null 2>&1; then
    adduser --system --group --home /var/lib/ara-agent --no-create-home ara-agent
fi
chown ara-agent:ara-agent /var/lib/ara-agent
chmod 0700 /var/lib/ara-agent
# NOTE: no systemctl enable/start — activation is explicit operator work
# with a reviewed plan; see /usr/share/doc/ara/README.md.
# deluser on purge handled in postrm (review R15)
# Refresh unit definitions without enabling or starting any service.
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi
exit 0
EOF
cat > "$STAGE/deb/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
# stop only the ARA unit if it is running; never other services
if [ "$1" = remove ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop ara-agent.service ara-node-access.socket ara-node-access.service 2>/dev/null || true
fi
exit 0
EOF
cat > "$STAGE/deb/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
# remove keeps state (usage history must survive upgrades); purge removes
# only ARA-owned state directories and the package-created system users
# (review R15).
if [ "$1" = purge ]; then
    rm -rf /var/lib/ara-agent
    deluser --system ara-agent 2>/dev/null || true
fi
exit 0
EOF
chmod 0755 "$STAGE/deb/DEBIAN/postinst" "$STAGE/deb/DEBIAN/prerm" "$STAGE/deb/DEBIAN/postrm"

dpkg-deb --root-owner-group --build "$STAGE/deb" "$OUT/ara_${VERSION}_${ARCH}.deb"
echo "built $OUT/ara_${VERSION}_${ARCH}.deb"

# --- ara-control (server) ---------------------------------------------
STAGE2="$STAGE/control"
mkdir "$STAGE2"
build_bin ara-control "$STAGE2/ara-control"
mkdir -p "$STAGE2/deb/DEBIAN" "$STAGE2/deb/usr/bin" "$STAGE2/deb/usr/share/doc/ara-control" \
         "$STAGE2/deb/lib/systemd/system" "$STAGE2/deb/var/lib/ara-control"
install -m 0755 "$STAGE2/ara-control" "$STAGE2/deb/usr/bin/ara-control"
install -m 0644 deploy/debian/systemd/ara-control.service "$STAGE2/deb/lib/systemd/system/"
install -m 0644 README.md "$STAGE2/deb/usr/share/doc/ara-control/"
install_legal_docs "$STAGE2/deb" ara-control

cat > "$STAGE2/deb/DEBIAN/control" <<EOF
Package: ara-control
Version: $VERSION
Architecture: $ARCH
Maintainer: ARA VPN project <ara@invalid>
Depends: libc6 (>= 2.34)
Conflicts: ara (<< 0.1.0)
Section: net
Priority: optional
Description: ARA VPN control plane (loopback management API)
 Local registry of devices, nodes, policies and audit. Management binds
 loopback only; remote access requires an authenticated TLS proxy.
Homepage: https://invalid.example/ara
EOF

cat > "$STAGE2/deb/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if ! id ara-control >/dev/null 2>&1; then
    adduser --system --group --home /var/lib/ara-control --no-create-home ara-control
fi
chown ara-control:ara-control /var/lib/ara-control
chmod 0700 /var/lib/ara-control
runuser -u ara-control -- /usr/bin/ara-control --state-dir /var/lib/ara-control --init-admin
# Refresh unit definitions without enabling or starting any service.
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi
exit 0
EOF
cat > "$STAGE2/deb/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
# review R15: stop ONLY the ARA control unit on remove, so remove/purge
# never leaves a running old process whose binary is being deleted, and
# purge never removes state under a live service. Other services are
# never touched.
if [ "$1" = remove ] || [ "$1" = deconfigure ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop ara-control.service 2>/dev/null || true
fi
exit 0
EOF
cat > "$STAGE2/deb/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = purge ]; then
    rm -rf /var/lib/ara-control
    deluser --system ara-control 2>/dev/null || true
fi
exit 0
EOF
chmod 0755 "$STAGE2/deb/DEBIAN/postinst" "$STAGE2/deb/DEBIAN/prerm" "$STAGE2/deb/DEBIAN/postrm"

dpkg-deb --root-owner-group --build "$STAGE2/deb" "$OUT/ara-control_${VERSION}_${ARCH}.deb"
echo "built $OUT/ara-control_${VERSION}_${ARCH}.deb"

# --- ara-edge (data plane) ---------------------------------------------
# C06: the package is a COMPLETE data plane — the pinned engine (sing-box,
# ARA_SINGBOX or ARA_ENGINE_DIR), the testpoint binary and the edge itself;
# the serving config ships group-readable to the service (root:ara-edge
# 0640), not a 0600 root-only file the unit cannot read.
STAGE3="$STAGE/edge"
mkdir "$STAGE3"
build_bin ara-edge "$STAGE3/ara-edge"
build_bin ara-testpoint "$STAGE3/ara-testpoint"
# D03: the engine is a PINNED build artifact (ARA_SINGBOX) — a random
# system binary is never accepted; a build without it FAILS.
if [ -n "${ARA_SINGBOX:-}" ] && [ -x "$ARA_SINGBOX" ]; then
    install -m 0755 "$ARA_SINGBOX" "$STAGE3/sing-box"
else
    echo "FATAL: ARA_SINGBOX must point at the pinned sing-box build for the ara-edge package" >&2
    exit 1
fi
GOT_SHA3=$(sha256sum "$STAGE3/sing-box" | cut -d" " -f1)
if [ "$GOT_SHA3" != "$ARA_SINGBOX_SHA256" ]; then
    echo "FATAL: engine digest mismatch for ara-edge: lock=$ARA_SINGBOX_SHA256 input=$GOT_SHA3" >&2
    exit 1
fi
mkdir -p "$STAGE3/deb/DEBIAN" "$STAGE3/deb/usr/bin" "$STAGE3/deb/usr/lib/ara" "$STAGE3/deb/usr/share/doc/ara-edge" \
         "$STAGE3/deb/lib/systemd/system" "$STAGE3/deb/var/lib/ara-edge" "$STAGE3/deb/etc/ara-edge"
install -m 0755 "$STAGE3/ara-edge" "$STAGE3/deb/usr/bin/ara-edge"
install -m 0755 "$STAGE3/ara-testpoint" "$STAGE3/deb/usr/bin/ara-testpoint"
# E03: the engine binary is NOT shipped here — the dedicated ara-engine
# package is the SINGLE OWNER of /usr/lib/ara/sing-box; ara and ara-edge
# declare versioned Depends on it.
install -m 0644 deploy/debian/systemd/ara-edge.service \
    deploy/debian/systemd/ara-openvpn@.service deploy/debian/systemd/ara-wireguard@.service \
    "$STAGE3/deb/lib/systemd/system/"
install -m 0755 deploy/debian/wireguard-backbone "$STAGE3/deb/usr/lib/ara/"
install -m 0644 README.md "$STAGE3/deb/usr/share/doc/ara-edge/"
install_legal_docs "$STAGE3/deb" ara-edge
# the serving config is operator-owned; postinst chowns it to
# root:ara-edge 0640 once the group exists (build host has no ara users)
install -m 0640 /dev/null "$STAGE3/deb/etc/ara-edge/edge.json"
# D03: the serving config is a conffile — dpkg upgrade never overwrites
# an operator-applied config
printf "/etc/ara-edge/edge.json\n" > "$STAGE3/deb/DEBIAN/conffiles"

cat > "$STAGE3/deb/DEBIAN/control" <<EOF
Package: ara-edge
Version: $VERSION
Architecture: $ARCH
Maintainer: ARA VPN project <ara@invalid>
Depends: libc6 (>= 2.34), ara-engine (= $VERSION)
Suggests: openvpn, wireguard-tools, iputils-ping
Section: net
Priority: optional
Description: ARA VPN edge data plane
 VLESS/TLS access termination with pinned route listeners, per-subscription
 quota ledgers and exit selection. Config is delivered by the owner panel
 (edge-config plan/apply), never edited in place.
Homepage: https://invalid.example/ara
EOF

cat > "$STAGE3/deb/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if ! id ara-edge >/dev/null 2>&1; then
    adduser --system --group --home /var/lib/ara-edge --no-create-home ara-edge
fi
chown ara-edge:ara-edge /var/lib/ara-edge
chmod 0700 /var/lib/ara-edge
# C06: the unit (User=ara-edge) must READ the serving config
chown root:ara-edge /etc/ara-edge/edge.json 2>/dev/null || true
chmod 0640 /etc/ara-edge/edge.json 2>/dev/null || true
install -d -m 0700 /etc/ara-edge/backbones/openvpn /etc/ara-edge/backbones/wireguard
# Refresh unit definitions without enabling or starting any service.
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi
exit 0
EOF
cat > "$STAGE3/deb/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop ara-edge.service 'ara-openvpn@*.service' 'ara-wireguard@*.service' 2>/dev/null || true
fi
exit 0
EOF
cat > "$STAGE3/deb/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = purge ]; then
    rm -rf /var/lib/ara-edge
    deluser --system ara-edge 2>/dev/null || true
fi
exit 0
EOF
chmod 0755 "$STAGE3/deb/DEBIAN/postinst" "$STAGE3/deb/DEBIAN/prerm" "$STAGE3/deb/DEBIAN/postrm"

dpkg-deb --root-owner-group --build "$STAGE3/deb" "$OUT/ara-edge_${VERSION}_${ARCH}.deb"
echo "built $OUT/ara-edge_${VERSION}_${ARCH}.deb"

# --- ara-engine (SINGLE OWNER of the pinned engine) ---------------------
# E03: exactly one package owns /usr/lib/ara/sing-box; ara and ara-edge
# declare versioned Depends on it — a co-owned path cannot diverge or be
# silently overwritten by a concurrent upgrade.
STAGE4="$STAGE/engine"
mkdir "$STAGE4"
mkdir -p "$STAGE4/deb/DEBIAN" "$STAGE4/deb/usr/lib/ara" "$STAGE4/deb/usr/share/doc/ara-engine"
install -m 0755 "$STAGE3/sing-box" "$STAGE4/deb/usr/lib/ara/sing-box"
( cd "$STAGE3" && sha256sum sing-box | cut -d" " -f1 > "$STAGE4/deb/usr/lib/ara/sing-box.sha256" )
install -m 0644 README.md "$STAGE4/deb/usr/share/doc/ara-engine/"
install_legal_docs "$STAGE4/deb" ara-engine

cat > "$STAGE4/deb/DEBIAN/control" <<EOF
Package: ara-engine
Version: $VERSION
Architecture: $ARCH
Maintainer: ARA VPN project <ara@invalid>
Depends: libc6 (>= 2.34)
Section: net
Priority: optional
Description: ARA VPN pinned transport engine
 The single owner of /usr/lib/ara/sing-box (digest-locked at build time:
 $GOT_SHA3). ara and ara-edge depend on this exact version.
Homepage: https://invalid.example/ara
EOF

dpkg-deb --root-owner-group --build "$STAGE4/deb" "$OUT/ara-engine_${VERSION}_${ARCH}.deb"
echo "built $OUT/ara-engine_${VERSION}_${ARCH}.deb"
