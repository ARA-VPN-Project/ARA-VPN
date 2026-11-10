#!/bin/sh
# C07/D04 edge entrypoint: pull the owner-delivered config on start (edge
# sync with the installed path inside the container), optionally start the
# sing-box transit adapter when an adapter config is mounted, then exec
# the data plane. Without a config the container exits with a clear error
# instead of serving a stale/empty one.
set -e
if [ ! -s /etc/ara-edge/edge.json ]; then
  if [ -s /reviewed/edge.json ]; then
    # a REVIEWED config was mounted read-only: seed the writable volume
    install -m 0640 /reviewed/edge.json /etc/ara-edge/edge.json
  elif [ -n "${OWNER_BASE}" ]; then
    ara edge sync --base "${OWNER_BASE}" --install-path /etc/ara-edge/edge.json
  fi
fi
if [ ! -s /etc/ara-edge/edge.json ]; then
  echo "edge: no serving config at /etc/ara-edge/edge.json; set OWNER_BASE for edge sync or mount a reviewed config" >&2
  exit 78
fi
if [ -s /etc/ara-edge/adapter.json ]; then
  # transit adapter (Edge→Exit hop): the pinned engine runs it as the same
  # unprivileged user; TUN adapters additionally need the compose
  # cap_add/devices (explicit configuration)
  setsid /usr/local/lib/ara/sing-box run -c /etc/ara-edge/adapter.json \
    > /var/lib/ara-edge/state/adapter.log 2>&1 &
fi
# E04: the authenticated testpoint starts when its token file is provided
if [ -n "${ARA_TESTPOINT_TOKENS:-}" ] && [ -s "${ARA_TESTPOINT_TOKENS}" ]; then
  setsid ara-testpoint -listen "${ARA_TESTPOINT_LISTEN:-0.0.0.0:18490}" \
    -tokens "${ARA_TESTPOINT_TOKENS}" \
    > /var/lib/ara-edge/state/testpoint.log 2>&1 &
fi
exec ara-edge --config /etc/ara-edge/edge.json
