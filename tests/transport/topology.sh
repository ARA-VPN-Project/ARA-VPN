#!/bin/bash
# topology.sh — disposable 5-namespace topology for the ARA transport E2E.
# Owns ONLY the ara-tf-* resources listed in $WORK/owned.list; cleanup
# never touches other namespaces, links, routes or processes.
#   client 10.60.0.2 <-> edge 10.60.0.1
#   edge    10.61.0.1 <-> exit-ru 10.61.0.2
#   edge    10.62.0.1 <-> exit-fa 10.62.0.2
#   edge    10.63.0.1 <-> exit-fb 10.63.0.2
#   canary loopbacks: 10.71.1.1 (RU), 10.72.1.1 (foreign, on fa/fb/ru)
set -u
WORK="${WORK:-/var/tmp/ara-transport-run}"
OWNED="$WORK/owned.list"
NSES="ara-tf-cl ara-tf-ed ara-tf-ru ara-tf-fa ara-tf-fb"
LINKS="ara-tf-v0 ara-tf-v1 ara-tf-v2 ara-tf-v3 ara-tf-v4 ara-tf-v5 ara-tf-v6 ara-tf-v7"

mkdir -p "$WORK"
touch "$OWNED"

own() { grep -qxF "$1" "$OWNED" || echo "$1" >> "$OWNED"; }

owned_ok() { case "$1" in ara-tf-*) return 0;; *) return 1;; esac; }

cleanup() {
  while read -r name; do
    owned_ok "$name" || continue
    case "$name" in
      ara-tf-cl|ara-tf-ed|ara-tf-ru|ara-tf-fa|ara-tf-fb)
        for p in $(ip netns pids "$name" 2>/dev/null); do kill "$p" 2>/dev/null; done
        ip netns del "$name" 2>/dev/null
        ;;
      ara-tf-v[0-7]) ip link del "$name" 2>/dev/null ;;
    esac
  done < "$OWNED"
  : > "$OWNED"
}

if [ "${1:-}" = "cleanup" ]; then cleanup; echo "topology: owned ara-tf-* cleaned"; exit 0; fi

# a namespace with our name that is NOT in the ledger is not ours: abort
for ns in $NSES; do
  if ip netns list | grep -q "^$ns" && ! grep -qxF "$ns" "$OWNED"; then
    echo "ABORT: $ns exists but is not in the ownership ledger $OWNED" >&2
    exit 1
  fi
done
cleanup

mklink() { # ns_a if_a addr_a ns_b if_b addr_b
  ip link add "$2" type veth peer name "$5" || return 1
  ip link set "$2" netns "$1"; ip link set "$5" netns "$4"
  ip -n "$1" addr add "$3" dev "$2"; ip -n "$4" addr add "$6" dev "$5"
  ip -n "$1" link set "$2" up; ip -n "$4" link set "$5" up
  own "$2"; own "$5"; return 0
}

rc=0
for ns in $NSES; do ip netns add "$ns" || rc=1; own "$ns"; done
mklink ara-tf-cl ara-tf-v0 10.60.0.2/24 ara-tf-ed ara-tf-v1 10.60.0.1/24 || rc=1
mklink ara-tf-ed ara-tf-v2 10.61.0.1/24 ara-tf-ru ara-tf-v3 10.61.0.2/24 || rc=1
mklink ara-tf-ed ara-tf-v4 10.62.0.1/24 ara-tf-fa ara-tf-v5 10.62.0.2/24 || rc=1
mklink ara-tf-ed ara-tf-v6 10.63.0.1/24 ara-tf-fb ara-tf-v7 10.63.0.2/24 || rc=1
for ns in $NSES; do ip -n "$ns" link set lo up; done
ip -n ara-tf-ru addr add 10.71.1.1/32 dev lo
ip -n ara-tf-ru addr add 10.72.1.1/32 dev lo
ip -n ara-tf-fa addr add 10.72.1.1/32 dev lo
ip -n ara-tf-fb addr add 10.72.1.1/32 dev lo
# IPv6: ULA transport links + global-class canary loopbacks (2000::/3 is
# NOT in the non-global ACL set, so the canary is a legal egress target;
# ULA fd00::/8 stays denied — used by the leak/negative tests)
ip -n ara-tf-cl -6 addr add fd00:60::2/64 dev ara-tf-v0
ip -n ara-tf-ed -6 addr add fd00:60::1/64 dev ara-tf-v1
ip -n ara-tf-ed -6 addr add fd00:61::1/64 dev ara-tf-v2
ip -n ara-tf-ru -6 addr add fd00:61::2/64 dev ara-tf-v3
ip -n ara-tf-ed -6 addr add fd00:62::1/64 dev ara-tf-v4
ip -n ara-tf-fa -6 addr add fd00:62::2/64 dev ara-tf-v5
ip -n ara-tf-ed -6 addr add fd00:63::1/64 dev ara-tf-v6
ip -n ara-tf-fb -6 addr add fd00:63::2/64 dev ara-tf-v7
ip -n ara-tf-ru -6 addr add 2001:678:230::1/128 dev lo
ip -n ara-tf-fa -6 addr add 2001:678:230::1/128 dev lo
ip -n ara-tf-fb -6 addr add 2001:678:230::1/128 dev lo
if [ "$rc" = "0" ]; then echo "PASS topo:up"; else echo "FAIL topo:up"; exit 1; fi
