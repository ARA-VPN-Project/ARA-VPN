#!/bin/bash
# federation_e2e.sh — acceptance for linked panels, shared multi-profile
# subscriptions, direct (no-RU-transit) profiles and the shared quota
# ledger (docs/FEDERATION.md). Two ara-control panels (ru-1, de-1) are
# linked through a one-time invite with signed federation requests; a
# single subscription carries «Германия напрямую», «Нидерланды напрямую»,
# «Германия через Россию», «Нидерланды через Россию»; traffic runs BOTH
# through the RU transit and DIRECTLY through the DE ingress (no RU in
# path), both edges drawing ONE shared budget; then ownership transfer
# (usage preserved), revocation and link teardown.
set -u
cd "$(dirname "$0")"
WORK="${WORK:-/opt/ara-vpn-lab/proto-profiles-20261030/fed-run}"
ARA_BIN="${ARA_BIN:?set ARA_BIN}"
ARA_CA="$WORK/ca"
S="$WORK/slice"; R="$WORK/results"
rm -rf "$R" "$S"; mkdir -p "$S" "$R" "$ARA_CA"
PASS=0; FAIL=0
check() { if [ "$2" = "0" ]; then PASS=$((PASS+1)); echo "PASS $1"; else FAIL=$((FAIL+1)); echo "FAIL $1"; fi }
UUID_D="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
KEEP="${KEEP:-}"
finish() {
  if [ "$KEEP" = "1" ]; then echo "KEEP=1: resources left";
  else bash ./topology.sh cleanup >/dev/null 2>&1; pkill -f "ara-control -state-dir $S/panel-ru" 2>/dev/null; pkill -f "ara-control -state-dir $S/panel-de" 2>/dev/null; echo cleanup; fi
}
trap finish EXIT

for f in "$ARA_BIN/ara" "$ARA_BIN/ara-control" "$ARA_BIN/ara-edge" "$ARA_BIN/sing-box" "$ARA_BIN/fileserver"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done
if [ ! -f "$ARA_CA/ca.crt" ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out "$ARA_CA/ca.key" 2>/dev/null
  openssl req -x509 -new -key "$ARA_CA/ca.key" -subj "/CN=ara-lab-test-ca" -days 30 -out "$ARA_CA/ca.crt" 2>/dev/null
  openssl ecparam -name prime256v1 -genkey -noout -out "$ARA_CA/srv.key" 2>/dev/null
  openssl req -new -key "$ARA_CA/srv.key" -subj "/CN=edge.ara.lab" -out "$WORK/srv.csr" 2>/dev/null
  printf "subjectAltName=DNS:edge.ara.lab,IP:127.0.0.1,IP:10.69.0.1\n" > "$WORK/srv.ext"
  openssl x509 -req -in "$WORK/srv.csr" -CA "$ARA_CA/ca.crt" -CAkey "$ARA_CA/ca.key" \
    -CAcreateserial -days 30 -extfile "$WORK/srv.ext" -out "$ARA_CA/srv.crt" 2>/dev/null
fi

export SSL_CERT_FILE="$ARA_CA/ca.crt" CURL_CA_BUNDLE="$ARA_CA/ca.crt"

bash ./topology.sh 2>&1 | tail -1
ip netns list | grep -q "^ara-tf-ed" || { echo "topology down"; exit 1; }
for pair in "ru 10.61.0.1" "fa 10.62.0.1" "fb 10.63.0.1"; do
  set -- $pair
  ip -n "ara-tf-$1" route add default via "$2" 2>/dev/null
  ip -n "ara-tf-$1" -6 route add default via "fd00:6${1:0:1}::1" 2>/dev/null
done
ip -n ara-tf-cl route add default via 10.60.0.1 2>/dev/null
# the DIRECT profile client dials the DE ingress THROUGH the edge netns:
# kernel forwarding inside the disposable lab namespace only
ip netns exec ara-tf-ed sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
# host-facing link so NETNS edges can reach the OWNER PANEL on the host
# (owned ara-tf-* resources, cleaned by the topology ledger)
ip link add ara-tf-v8 type veth peer name ara-tf-v9 2>/dev/null
ip link set ara-tf-v8 netns ara-tf-ed 2>/dev/null
ip addr add 10.69.0.1/24 dev ara-tf-v9 2>/dev/null; ip link set ara-tf-v9 up 2>/dev/null
ip -n ara-tf-ed addr add 10.69.0.2/24 dev ara-tf-v8 2>/dev/null; ip -n ara-tf-ed link set ara-tf-v8 up 2>/dev/null
ip -n ara-tf-fa route add 10.69.0.0/24 via 10.62.0.1 2>/dev/null
ip route add 10.62.0.0/24 via 10.69.0.2 dev ara-tf-v9 2>/dev/null
grep -qxF "ara-tf-v8" "$WORK/owned.list" 2>/dev/null || { echo ara-tf-v8 >> "$WORK/owned.list"; echo ara-tf-v9 >> "$WORK/owned.list"; }

# ---- panels ----
A_STATE="$S/panel-ru"; B_STATE="$S/panel-de"
ARA="env ARA_STATE_DIR=$A_STATE $ARA_BIN/ara"; ARB="env ARA_STATE_DIR=$B_STATE $ARA_BIN/ara"
$ARA panel init --id ru-1 >/dev/null 2>&1; check "panel-ru-init" $?
$ARB panel init --id de-1 >/dev/null 2>&1; check "panel-de-init" $?
(ARA_STATE_DIR=$A_STATE ARA_SUB_CA="$ARA_CA/ca.crt" ARA_SUB_SNI=edge.ara.lab $ARA_BIN/ara-control -state-dir "$A_STATE" -listen 0.0.0.0:18451 -allow-non-loopback --tls-cert "$ARA_CA/srv.crt" --tls-key "$ARA_CA/srv.key" >"$R/ctl-ru.log" 2>&1 &)
(ARA_STATE_DIR=$B_STATE ARA_SUB_CA="$ARA_CA/ca.crt" ARA_SUB_SNI=edge.ara.lab $ARA_BIN/ara-control -state-dir "$B_STATE" -listen 0.0.0.0:18452 -allow-non-loopback --tls-cert "$ARA_CA/srv.crt" --tls-key "$ARA_CA/srv.key" >"$R/ctl-de.log" 2>&1 &)
sleep 1.5
UA="https://127.0.0.1:18451"; UB="https://127.0.0.1:18452"

# ---- secure linking: one-time invite, mutual Ed25519 auth ----
TOK_B=$($ARA panel invite --for de-1 --json | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['token'])")
$ARB panel redeem --base $UA --token "$TOK_B" >/dev/null 2>&1; check "panel-link-redeem" $?
$ARA panel links --json | grep -q '"de-1"'; check "panel-link-visible-on-ru" $?
$ARB panel links --json | grep -q '"de-1"'; check "panel-self-visible" $?

# ---- topology: roles/countries/ingress separated ----
# RU panel: transit hub edge-ru (ingress) + logical exits de-exit/nl-exit
$ARA node add --id edge-ru --country RU --role ru --priority 0 >/dev/null 2>&1
$ARA node set-ingress --id edge-ru --addr 10.60.0.1:443 --sni edge.ara.lab >/dev/null 2>&1
$ARA node add --id de-exit --country DE --role foreign --priority 1 >/dev/null 2>&1
$ARA node add --id nl-exit --country NL --role foreign --priority 2 >/dev/null 2>&1
$ARA node transport add-profile --json --node de-exit --protocol trojan --server-name edge.ara.lab \
  --ca-path "$ARA_CA/ca.crt" --password-stdin <<< "fed-trojan-pw" >/dev/null 2>&1
TP_DE=$($ARA node transport list --json --node de-exit | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['profiles'][0]['id'])")
$ARA link add --edge edge-ru --exit de-exit --transport tcp --priority 1 --profile-id "$TP_DE" >/dev/null 2>&1
$ARA link add --edge edge-ru --exit nl-exit --transport tcp --priority 2 >/dev/null 2>&1
check "ru-topology" $?
# DE panel: ingress nodes de-1/nl-1 (role foreign + ingress)
$ARB node add --id de-1 --country DE --role foreign --priority 0 >/dev/null 2>&1
$ARB node add --id nl-1 --country NL --role foreign --priority 1 >/dev/null 2>&1
$ARB node set-ingress --id de-1 --addr 10.62.0.2:8443 --sni edge.ara.lab >/dev/null 2>&1
$ARB node set-ingress --id nl-1 --addr 10.63.0.2:8443 --sni edge.ara.lab >/dev/null 2>&1
check "de-topology" $?

# exchange allowed nodes (signed, scope nodes)
$ARA panel share --to de-1 --base $UB >/dev/null 2>&1; check "share-de-to-ru" $?
$ARB panel share --to ru-1 --base $UA >/dev/null 2>&1; check "share-ru-to-de" $?
$ARA node list --json >/dev/null 2>&1 || true

# ---- account/device (the subscription's client identity) ----
CTOKA=$(cat "$A_STATE/control.token")
curl -s -H "Authorization: Bearer $CTOKA" -X POST -H "Content-Type: application/json" \
  -d '{"id":"user1"}' $UA/api/v1/accounts >/dev/null
DEV=$(curl -s -H "Authorization: Bearer $CTOKA" -X POST -H "Content-Type: application/json" \
  -d '{"account_id":"user1","name":"phone"}' $UA/api/v1/devices)
UUID=$(echo "$DEV" | python3 -c "import json,sys;print(json.load(sys.stdin)['device']['vless_uuid'])")
[ -n "$UUID" ]; check "device-enrolled" $?

# ---- ONE subscription, FOUR profiles: 2 direct + 2 transit ----
SUB=$($ARA subscription create --json --account user1 --name "user1-all" --limit-bytes 20971520 \
  --profile direct:de-1 --profile direct:nl-1 --profile transit:de-exit --profile transit:nl-exit 2>"$R/sub-create.err")
echo "$SUB" > "$R/sub.json"
SUBID=$(echo "$SUB" | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['subscription']['id'])")
SUBTOK=$(echo "$SUB" | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['token'])")
[ -n "$SUBID" ] && [ -n "$SUBTOK" ]; check "subscription-created" $?
# A second independently issued key belongs to the SAME subscription.
$ARA subscription set-device-slots --id "$SUBID" --max-devices 2 > "$R/slots.out" 2>&1
SECOND=$($ARA subscription device-add --json --id "$SUBID" --name tablet --base "$UA" 2>"$R/device-add.err")
echo "$SECOND" > "$R/device-second.json"
SECOND_ID=$(echo "$SECOND" | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['device_id'])")
SECOND_URL=$(echo "$SECOND" | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['url'])")
[ -n "$SECOND_ID" ] && [ -n "$SECOND_URL" ]; check "second-device-own-link" $?
curl -fsS "$SECOND_URL" > "$R/catalog-second.json"
$ARA subscription device-add --json --id "$SUBID" --name excess --base "$UA" > "$R/device-excess.json" 2>&1
[ "$?" != 0 ]; check "third-device-slot-refused" $?
# AUTHORITATIVE shared rate: 3 mbit/s down for the WHOLE subscription
$ARA subscription set-rate --id "$SUBID" --download-bps 3000000 >/dev/null 2>&1
check "subscription-rate-set" $?

curl -s $UA/sub/$SUBTOK > "$R/catalog.json"
FED_R="$R" python3 - <<'PYEOF'
import json,sys
d=json.load(open(__import__('os').environ['FED_R']+'/catalog.json'))
labels=[p['label_ru'] for p in d['profiles']]
need={'Германия напрямую','Нидерланды напрямую','Германия через Россию','Нидерланды через Россию'}
kinds={p['kind'] for p in d['profiles']}
cfg_ok=all('client_config' in p and p['client_config'].get('outbounds') for p in d['profiles'])
sys.exit(0 if need <= set(labels) and kinds=={'direct','transit'} and cfg_ok and len(d['profiles'])==4 else 1)
PYEOF
check "catalog-4-profiles-real-configs" $?

# the catalog's DIRECT config is a runnable client config (used below)
FED_R="$R" S="$S" python3 - <<'PYEOF'
import json,os
d=json.load(open(os.environ['FED_R']+'/catalog.json'))
S=os.environ['S']
direct=[p for p in d['profiles'] if p['kind']=='direct' and p['node_id']=='de-1'][0]
json.dump(direct['client_config'], open(S+'/client-direct.json','w'))
transit=[p for p in d['profiles'] if p['kind']=='transit' and p['node_id']=='de-exit'][0]
json.dump(transit['client_config'], open(S+'/client-transit.json','w'))
second=json.load(open(os.environ['FED_R']+'/catalog-second.json'))
c=[p for p in second['profiles'] if p['kind']=='transit' and p['node_id']=='de-exit'][0]['client_config']
assert c['outbounds'][0]['uuid'] != transit['client_config']['outbounds'][0]['uuid']
c['inbounds']=[{'type':'mixed','tag':'test-device','listen':'127.0.0.1','listen_port':19080}]
c['route']['auto_detect_interface']=False
json.dump(c,open(S+'/client-second.json','w'))
PYEOF
"$ARA_BIN/sing-box" check -c "$S/client-direct.json" >"$R/direct-check.log" 2>&1; check "direct-config-singbox-check" $?

# ---- issue from the OTHER panel too (de-1 issues its own subscription) ----
curl -s -H "Authorization: Bearer $(cat $B_STATE/control.token)" -X POST -H "Content-Type: application/json" \
  -d '{"id":"user2"}' $UB/api/v1/accounts >/dev/null
SUB2=$($ARB subscription create --json --account user2 --name "de-issued" --profile direct:de-1)
SUB2ID=$(echo "$SUB2" | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['subscription']['id'])")
[ -n "$SUB2ID" ]; check "subscription-issued-from-de-panel" $?

# ---- data plane: RU edge + DE direct ingress, BOTH with quota_remote ----
printf '%s\n' "fed-trojan-pw" > "$S/trojan.pw"
# canaries: RU canary (ru netns), foreign canary on fa/fb/ru; the
# de-exit ENGINE lives in the ru netns so its egress scope sees 10.72.1.1
ip netns exec ara-tf-ru sh -c 'mkdir -p /tmp/c-ru /tmp/c-f && echo RU-CANARY-PAYLOAD > /tmp/c-ru/canary.txt && echo FOREIGN-CANARY-PAYLOAD > /tmp/c-f/canary.txt'
ip netns exec ara-tf-fa sh -c 'mkdir -p /tmp/c-f && echo FOREIGN-CANARY-PAYLOAD > /tmp/c-f/canary.txt'
ip netns exec ara-tf-ru setsid nohup "$ARA_BIN/fileserver" 10.71.1.1:8000 /tmp/c-ru </dev/null >/dev/null 2>&1 &
ip netns exec ara-tf-ru setsid nohup "$ARA_BIN/fileserver" 10.72.1.1:8000 /tmp/c-f </dev/null >/dev/null 2>&1 &
ip netns exec ara-tf-fa setsid nohup "$ARA_BIN/fileserver" 10.72.1.1:8000 /tmp/c-f </dev/null >/dev/null 2>&1 &
ip netns exec ara-tf-fb setsid nohup "$ARA_BIN/fileserver" 10.72.1.1:8000 /tmp/c-f </dev/null >/dev/null 2>&1 &
# a big synthetic file for the shared-rate measurement (no user data)
dd if=/dev/zero of="$S/big.bin" bs=1M count=32 2>/dev/null
ip netns exec ara-tf-fa cp "$S/big.bin" /tmp/c-f/big.bin
sleep 0.5

# RU exit engines (vless for de-exit... one trojan profile on de-exit link + vless default on nl-exit)
# DE-exit trojan inbound lives in the RU netns (the transit hop target)
cat > "$S/exit-de.json" <<EOFX
{"log":{"level":"warn"},"inbounds":[{"type":"trojan","tag":"ti","listen":"10.61.0.2","listen_port":443,"users":[{"password":"fed-trojan-pw"}],"tls":{"enabled":true,"certificate_path":"$ARA_CA/srv.crt","key_path":"$ARA_CA/srv.key"}}],"outbounds":[{"type":"direct"}]}
EOFX
ip netns exec ara-tf-ru setsid nohup "$ARA_BIN/sing-box" run -c "$S/exit-de.json" </dev/null >"$R/exit-ru.log" 2>&1 &
cat > "$S/exit-nl.json" <<EOFX
{"log":{"level":"warn"},"inbounds":[{"type":"vless","tag":"vi","listen":"10.63.0.2","listen_port":443,"users":[{"uuid":"$UUID"}],"tls":{"enabled":true,"certificate_path":"$ARA_CA/srv.crt","key_path":"$ARA_CA/srv.key"}}],"outbounds":[{"type":"direct"}]}
EOFX
ip netns exec ara-tf-fb setsid nohup "$ARA_BIN/sing-box" run -c "$S/exit-nl.json" </dev/null >"$R/exit-fb.log" 2>&1 &
sleep 1.5

# RU edge config: AUTO-APPLIED (no hand-written JSON) — devices from the
# subscription account, exits from the declared topology, quota_remote to
# the owner; plan → apply (registered for dispatch) → signed sync on the
# edge state dir
TOK_E1=$($ARA panel invite --for edge-ru-1 --scopes quota,nodes --json | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['token'])")
ESTATE="$S/state-ru-edge"
python3 - "$SUBID" "$ARA_CA" "$ESTATE" "$R" <<'PLANINPUT'
import json,sys
sub,ca,state,out=sys.argv[1:]
json.dump({'edge_node_id':'edge-ru','edge_panel_id':'edge-ru-1','subscription_id':sub,'exit_dns_addr':'10.72.1.1:53','owner_url':'https://10.69.0.1:18451','access_listen':'10.60.0.1:443','tls_cert':ca+'/srv.crt','tls_key':ca+'/srv.key','ca_cert':ca+'/ca.crt','state_dir':state,'status_file':out+'/edge-ru-status.json'},open(out+'/edge-plan-request.json','w'))
PLANINPUT
curl -fsS -H "Authorization: Bearer $CTOKA" -H 'Content-Type: application/json' --data-binary @"$R/edge-plan-request.json" "$UA/api/v1/edge-config/plan" > "$R/ec-plan.json" 2> "$R/ec-plan.out"
check "edge-config-plan" $?
ECHASH=$(python3 -c "import json;print(json.load(open('$R/ec-plan.json'))['plan_hash'])" 2>/dev/null)
EPLAN=$R/ec-plan.json
EPID=$(python3 -c "import json;print(json.load(open('$R/ec-plan.json'))['plan_id'])")
# Wrong hash is refused before publishing a new config.
curl -s -o "$R/edge-bad-hash.json" -w '%{http_code}' -H "Authorization: Bearer $CTOKA" -H 'Content-Type: application/json' -d "{\"plan_id\":\"$EPID\",\"plan_hash\":\"wrong\"}" "$UA/api/v1/edge-config/apply" > "$R/edge-bad-hash.status"
[ "$(cat "$R/edge-bad-hash.status")" != 200 ]; check "edge-publication-wrong-hash-refused" $?
curl -fsS -H "Authorization: Bearer $CTOKA" -H 'Content-Type: application/json' -d "{\"plan_id\":\"$EPID\",\"plan_hash\":\"$ECHASH\"}" "$UA/api/v1/edge-config/apply" > "$R/ec-apply.out" 2>&1
check "edge-config-apply" $?
(ARA_STATE_DIR="$ESTATE" $ARA_BIN/ara panel init --id edge-ru-1 >/dev/null 2>&1)
(ARA_STATE_DIR="$ESTATE" $ARA_BIN/ara panel redeem --base $UA --token "$TOK_E1" >/dev/null 2>&1)
ARA_STATE_DIR="$ESTATE" $ARA_BIN/ara edge sync --base $UA > "$R/ec-sync.out" 2>&1
check "edge-config-sync" $?
SYNCPATH="$ESTATE/edge-config/edge.json"
[ -f "$SYNCPATH" ]; check "synced-config-exists" $?
python3 -c "
import json,sys
d=json.load(open('$SYNCPATH'))
sys.exit(0 if d.get('quota_remote',{}).get('subscription_id') and d.get('devices') and len(d.get('exits',[]))>=2 else 1)"
check "synced-config-content" $?
# Runtime fixture extension: isolate private canaries from production ACL policy.
# This copy is NOT evidence that the compiler publishes lab exceptions.
python3 - "$SYNCPATH" "$S/edge-ru-lab.json" <<'LABCFG'
import json,sys
cfg=json.load(open(sys.argv[1])); cfg['allow_lab_lan_exceptions']=True
json.dump(cfg,open(sys.argv[2],'w'))
LABCFG
ip netns exec ara-tf-ed setsid nohup "$ARA_BIN/ara-edge" -config "$S/edge-ru-lab.json" </dev/null >"$R/edge-ru.log" 2>&1 &

# transit adapters: rendered by the PRODUCT renderer, ports taken from
# the auto-applied plan (de-exit → trojan profile; nl-exit → explicit
# vless profile; both created through the CLI earlier in this script)
for spec in "de-exit 10.61.0.2 trojan" "nl-exit 10.63.0.2 vless"; do
  set -- $spec
  PORT=$(python3 -c "
import json
d=json.load(open('$SYNCPATH'))
print([e['socks_addr'].split(':')[1] for e in d['exits'] if e['id']=='$1'][0])")
  LID=$(ARA_STATE_DIR="$A_STATE" $ARA_BIN/ara link list --json | python3 -c "
import json,sys
ls=json.load(sys.stdin)['data']['links']
print([l['id'] for l in ls if l['exit_id']=='$1'][0])")
  if [ "$3" = "trojan" ]; then
    TPID=$(ARA_STATE_DIR="$A_STATE" $ARA_BIN/ara node transport list --json --node $1 | python3 -c "import json,sys;ps=json.load(sys.stdin)['data']['profiles'];print([p['id'] for p in ps if p['protocol']=='trojan'][0])")
    ARA_STATE_DIR="$A_STATE" $ARA_BIN/ara link set-profile --id "$LID" --profile-id "$TPID" >/dev/null 2>&1
  else
    VP=$(ARA_STATE_DIR="$A_STATE" $ARA_BIN/ara node transport add-profile --json --node $1 --protocol vless \
      --server-name edge.ara.lab --ca-path "$ARA_CA/ca.crt" --password-stdin <<< "$UUID" | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['profile']['id'])")
    ARA_STATE_DIR="$A_STATE" $ARA_BIN/ara link set-profile --id "$LID" --profile-id "$VP" >/dev/null 2>&1
  fi
  ARA_STATE_DIR="$A_STATE" $ARA_BIN/ara node transport render --link "$LID" --endpoint $2:443 \
    --socks-host 127.0.0.1 --socks-port "$PORT" --server-cert "$ARA_CA/srv.crt" --server-key "$ARA_CA/srv.key" --out "$S" >/dev/null 2>&1
  check "render-adapter-$1" $?
  ip netns exec ara-tf-ed setsid nohup "$ARA_BIN/sing-box" run -c "$S/exitch-$LID.json" </dev/null >"$R/exitch-$1.log" 2>&1 &
done
sleep 1.5

# DE DIRECT ingress edge (fa netns): client→DE→internet, NO RU in path
# the DE edge draws from the SAME shared subscription: link its identity to panel ru-1 (the owner)
TOK_E2A=$($ARA panel invite --for edge-de-1 --scopes quota --json | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['token'])")
DEV_ID=$(echo "$DEV" | python3 -c "import json,sys;print(json.load(sys.stdin)['device']['id'])")
# Register this serving edge through the owner's reviewed plan/apply path.
# A federation quota scope alone grants no access to an arbitrary subscription.
$ARA link add --edge de-1 --exit de-exit --transport tcp --priority 1 --profile-id "$TP_DE" > "$R/de-link.out" 2>&1
$ARA node edge-config plan --json --edge-node de-1 --panel-id edge-de-1 --subscription "$SUBID" \
  --owner-url https://10.69.0.1:18451 --access-listen 10.62.0.2:8443 \
  --tls-cert "$ARA_CA/srv.crt" --tls-key "$ARA_CA/srv.key" --ca-cert "$ARA_CA/ca.crt" \
  --exit-dns-addr 10.72.1.1:53 --edge-state-dir "$S/state-de" --output "$R/de-plan.json" > "$R/de-plan.out" 2>&1
check "direct-edge-delegation-plan" $?
DEHASH=$(python3 -c "import json;print(json.load(open('$R/de-plan.json'))['plan_hash'])" 2>/dev/null)
$ARA node edge-config apply --expected-hash "$DEHASH" --plan "$R/de-plan.json" > "$R/de-apply.out" 2>&1
check "direct-edge-delegation-apply" $?

# the DE edge enforces the SUBSCRIPTION's device identity (the same UUID
# the catalog serves) — a fixture UUID would be an unknown identity
DEV_UUID=$(python3 -c "import json;d=json.load(open('$R/catalog.json'));print([p for p in d['profiles'] if p['kind']=='direct'][0]['client_config']['outbounds'][0]['uuid'])")
cat > "$S/direct-adapter.json" <<EOFX
{"log":{"level":"warn"},"inbounds":[{"type":"socks","tag":"si","listen":"127.0.0.1","listen_port":1179}],"outbounds":[{"type":"direct","tag":"exit-out"}],"route":{"final":"exit-out"}}
EOFX
ip netns exec ara-tf-fa setsid nohup "$ARA_BIN/sing-box" run -c "$S/direct-adapter.json" </dev/null >"$R/direct-adapter.log" 2>&1 &
sleep 0.5
printf '{"allow_lab_lan_exceptions":true,"access_listen":"10.62.0.2:8443","tls_cert":"%s","tls_key":"%s","ca_cert":"%s","devices":[{"uuid":"%s","device_id":"%s","socks_user":"dev-user1","socks_pass":"p1"}],"state_dir":"%s","status_file":"%s","current_foreign_id":"direct-local","quota_bytes":100000000,"probe_interval_s":2,"probe_timeout_ms":3000,"exits":[{"id":"direct-local","country":"DE","role":"foreign","priority":0,"socks_addr":"127.0.0.1:1179"}],"quota_remote":{"subscription_id":"%s","owner_url":"https://10.69.0.1:18451","panel_id":"edge-de-1","invite_token":"%s"}}\n' \
  "$ARA_CA/srv.crt" "$ARA_CA/srv.key" "$ARA_CA/ca.crt" "$DEV_UUID" "$DEV_ID" "$S/state-de" "$R/edge-de-status.json" "$SUBID" "$TOK_E2A" > "$S/edge-de.json"
# Keep the product-generated subscription/identity/budget context. Only
# the isolated test's local egress adapter and private-canary ACL differ.
python3 - "$R/de-plan.json" "$S/edge-de.json" <<'DIRECTCTX'
import json,sys
plan=json.load(open(sys.argv[1])); fixture=json.load(open(sys.argv[2]))
fixture['subscriptions']=plan['plan']['changes']['config']['subscriptions']
json.dump(fixture,open(sys.argv[2],'w'))
DIRECTCTX
ip netns exec ara-tf-fa setsid nohup "$ARA_BIN/ara-edge" -config "$S/edge-de.json" </dev/null >"$R/edge-de.log" 2>&1 &
# health convergence BEFORE traffic (probes every 2s)
CONV_OK=1
for i in $(seq 1 45); do
  R1=$(python3 -c "
import json,sys
try:
    d=json.load(open('$R/edge-ru-status.json'))
    st={n['id']:n['state'] for n in d.get('nodes',[])}
    sys.exit(0 if st.get('de-exit')=='healthy' and st.get('nl-exit')=='healthy' else 1)
except Exception: sys.exit(1)" 2>/dev/null && echo OK || echo NO)
  R2=$(python3 -c "
import json,sys
try:
    d=json.load(open('$R/edge-de-status.json'))
    st={n['id']:n['state'] for n in d.get('nodes',[])}
    sys.exit(0 if st.get('direct-local')=='healthy' else 1)
except Exception: sys.exit(1)" 2>/dev/null && echo OK || echo NO)
  if [ "$R1" = "OK" ] && [ "$R2" = "OK" ]; then CONV_OK=0; break; fi
  sleep 1
done
check "edges-health-converged" $CONV_OK

# Configure an independent volume cap through the public CLI service path.
python3 - "$R/catalog.json" "$S/profile-limits.json" <<'CAPS'
import json,sys
catalog=json.load(open(sys.argv[1]));inputs=[]
for p in catalog['profiles']:
 v={'kind':p['kind'],'node_id':p['node_id']}
 if p['kind']=='direct' and p['node_id']=='de-1':v.update(limit_bytes=131072,name='Personal direct')
 inputs.append(v)
json.dump(inputs,open(sys.argv[2],'w'))
CAPS
$ARA subscription set-profiles --id "$SUBID" --profiles-file "$S/profile-limits.json" > "$R/profile-limits.out" 2>&1
check "profile-limits-configured-via-cli" $?
curl -s "$UA/sub/$SUBTOK" | python3 -c "import json,sys;d=json.load(sys.stdin);sys.exit(0 if any(p['label_en']=='Personal direct' for p in d['profiles']) else 1)"
check "custom-client-profile-name-exported" $?
# DIRECT traffic: catalog's own client config → DE ingress, no RU
ip netns exec ara-tf-cl setsid nohup "$ARA_BIN/sing-box" run -c "$S/client-direct.json" </dev/null >"$R/client-direct.log" 2>&1 &
sleep 2.5
ip netns exec ara-tf-cl ip addr show ara-tun | grep -q "10.99.0.1"; check "direct-client-tun-up" $?
ip netns exec ara-tf-cl curl -s -m 10 -o "$R/direct.txt" http://10.72.1.1:8000/canary.txt
grep -q "FOREIGN-CANARY-PAYLOAD" "$R/direct.txt"; check "direct-traffic-no-ru" $?

ip netns exec ara-tf-cl curl -s -m 8 -o "$R/profile-capped.bin" http://10.72.1.1:8000/big.bin
CAP_BYTES=$(stat -c%s "$R/profile-capped.bin" 2>/dev/null || echo 0)
[ "$CAP_BYTES" -gt 1000 ] && [ "$CAP_BYTES" -le 131072 ]; check "direct-profile-volume-enforced" $?
ip netns exec ara-tf-cl curl -fsS -m 5 -o /dev/null http://10.72.1.1:8000/canary.txt
[ "$?" != 0 ]; check "direct-profile-exhaustion-blocks" $?
# TRANSIT traffic: switch the client to the catalog's transit config (RU hub + trojan)
pkill -f "client-direct.json" 2>/dev/null; sleep 0.5
ip netns exec ara-tf-cl setsid nohup "$ARA_BIN/sing-box" run -c "$S/client-transit.json" </dev/null >"$R/client-transit.log" 2>&1 &
sleep 2.5
TRANSIT_OK=1
for attempt in $(seq 1 40); do
  ip netns exec ara-tf-cl curl -fsS -m 3 -o "$R/transit.txt" http://10.72.1.1:8000/canary.txt 2>> "$R/transit-retries.log"
  if grep -q "FOREIGN-CANARY-PAYLOAD" "$R/transit.txt" 2>/dev/null; then TRANSIT_OK=0; break; fi
  sleep 1
done
check "transit-traffic-trojan" "$TRANSIT_OK"
pkill -f "client-transit.json" 2>/dev/null; sleep 0.3

# Independent second device really carries traffic, then only its key is revoked.
ip netns exec ara-tf-cl setsid nohup "$ARA_BIN/sing-box" run -c "$S/client-second.json" </dev/null >"$R/client-second.log" 2>&1 &
sleep 1
# Shared rate rights may still belong to the other edge until its 30s
# lease expires. Bound convergence explicitly; never treat a failed probe
# or zero rate as successful payload delivery.
SECOND_OK=1
for attempt in $(seq 1 40); do
  ip netns exec ara-tf-cl curl -fsS --proxy socks5h://127.0.0.1:19080 -m 3 http://10.72.1.1:8000/canary.txt > "$R/second-before.txt" 2>> "$R/second-retries.log"
  if grep -q FOREIGN-CANARY-PAYLOAD "$R/second-before.txt"; then SECOND_OK=0; break; fi
  sleep 1
done
check "second-device-wire-traffic" "$SECOND_OK"
$ARA subscription device-revoke --id "$SUBID" --device "$SECOND_ID" > "$R/second-revoke.out" 2>&1
check "second-device-revoked" $?
[ "$(curl -s -o /dev/null -w '%{http_code}' "$SECOND_URL")" = 401 ]; check "revoked-device-link-denied" $?
[ "$(curl -s -o /dev/null -w '%{http_code}' "$UA/sub/$SUBTOK")" = 200 ]; check "primary-device-link-survives" $?
ip netns exec ara-tf-cl curl -fsS --proxy socks5h://127.0.0.1:19080 -m 8 http://10.72.1.1:8000/canary.txt > "$R/second-after.txt"
[ "$?" != 0 ]; check "revoked-device-wire-blocked" $?
pkill -f "client-second.json" 2>/dev/null

# shared rate: the transit client is still the enforcement path; measure
# a throttled download through the RU edge (share = 3 mbit/s, 1 holder)
# Shared rate with ACKNOWLEDGED redistribution (review FED05): the first
# window primes the rights registry; the joining edge's full share expires
# by TTL; after convergence the measured window is bounded by the share.
ip netns exec ara-tf-cl setsid nohup "$ARA_BIN/sing-box" run -c "$S/client-transit.json" </dev/null >"$R/client-rate.log" 2>&1 &
sleep 2.5
ip netns exec ara-tf-cl curl -s -m 6 -o /dev/null http://10.72.1.1:8000/big.bin
sleep 33   # rate right TTL (30s) + margin: the stale full right expires
ip netns exec ara-tf-cl curl -s -m 6 -o "$R/rate.bin" http://10.72.1.1:8000/big.bin
BYTES=$(stat -c%s "$R/rate.bin" 2>/dev/null || echo 0)
echo "rate window bytes: $BYTES"
[ "${BYTES:-0}" -ge 250000 ] && [ "${BYTES:-0}" -le 3200000 ]; check "shared-rate-throttles" $?
pkill -f "client-transit.json" 2>/dev/null; sleep 0.3
# the consumption crossed the lease → the edge reported; the owner ledger
# reflects REAL shared usage
USED=$($ARA subscription quota --json --id "$SUBID" | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['used_bytes'])")
[ "${USED:-0}" -ge 1000000 ]; check "shared-quota-consumed" $?

# ---- shared quota: both edges drew ONE budget ----
grep -q "edge-de-1" "$A_STATE/audit.jsonl" 2>/dev/null; check "de-edge-reports-to-owner" $?

# Optional bounded stability window using the same real, authenticated path.
# No new fixture or parallel namespace owner; never more than five minutes.
SOAK_SECONDS=${SOAK_SECONDS:-0}
if ! [[ "$SOAK_SECONDS" =~ ^[0-9]+$ ]] || [ "$SOAK_SECONDS" -gt 300 ]; then
  echo "invalid SOAK_SECONDS (0..300)"; exit 1
fi
if [ "$SOAK_SECONDS" -gt 0 ]; then
  ip netns exec ara-tf-cl setsid nohup "$ARA_BIN/sing-box" run -c "$S/client-transit.json" </dev/null >"$R/client-soak.log" 2>&1 &
  sleep 1
  SOAK_END=$((SECONDS+SOAK_SECONDS)); SOAK_OK=0; SOAK_FAIL=0
  while [ "$SECONDS" -lt "$SOAK_END" ]; do
    if ip netns exec ara-tf-cl curl -fsS -m 5 http://10.72.1.1:8000/canary.txt 2>>"$R/soak-errors.log" | grep -q FOREIGN-CANARY-PAYLOAD; then
      SOAK_OK=$((SOAK_OK+1))
    else SOAK_FAIL=$((SOAK_FAIL+1)); fi
    sleep 1
  done
  echo "soak seconds=$SOAK_SECONDS success=$SOAK_OK failed=$SOAK_FAIL"
  [ "$SOAK_OK" -ge 1 ] && [ "$SOAK_FAIL" -eq 0 ]; check "bounded-soak-payload" $?
  pkill -f "client-transit.json" 2>/dev/null; sleep 0.3
fi

# ---- ownership transfer preserves the spend ----
$ARA subscription transfer --id "$SUBID" --to-panel de-1 --base $UB > "$R/transfer.out" 2>&1
# the protocol is resumable: a second run completes a pending activation
$ARA subscription transfer --id "$SUBID" --to-panel de-1 --base $UB >> "$R/transfer.out" 2>&1
$ARB subscription quota --json --id "$SUBID" >/dev/null 2>&1
check "transfer-applied" $?
$ARB subscription quota --json --id "$SUBID" > "$R/quota-after.json" 2>/dev/null
USED_B=$(python3 -c "import json;print(json.load(open('$R/quota-after.json'))['data']['used_bytes'])" 2>/dev/null || echo 0)
[ "${USED_B:-0}" -ge 1000000 ]; check "transfer-preserves-usage" $?
$ARA subscription list --json | grep -q '"transferred_to":"de-1"'; check "old-panel-shows-transfer" $?
# the serving edge learns the authority move on its next report: STICKY
# stop (no cached-credit continuation). Drive the report with a download
# that exhausts the outstanding lease, then verify traffic blocks.
ip netns exec ara-tf-cl setsid nohup "$ARA_BIN/sing-box" run -c "$S/client-transit.json" </dev/null >"$R/client-after.log" 2>&1 &
sleep 2.5
ip netns exec ara-tf-cl curl -s -m 10 -o /dev/null http://10.72.1.1:8000/big.bin
for i in $(seq 1 10); do
  ip netns exec ara-tf-cl curl -s -m 5 -o /dev/null http://10.72.1.1:8000/big.bin && sleep 1 || break
done
grep -q "NOT_OWNER" "$R/edge-ru.log"; check "edge-stops-on-not-owner" $?
ip netns exec ara-tf-cl curl -s -m 8 -o /dev/null http://10.72.1.1:8000/canary.txt
RC=$?
[ "$RC" != "0" ]; check "post-transfer-traffic-blocked" $?
pkill -f "client-transit.json" 2>/dev/null; sleep 0.3
# the old fetch URL serves a MOVED notice, never a second authority
curl -s $UA/sub/$SUBTOK | python3 -c "import json,sys;d=json.load(sys.stdin);sys.exit(0 if d.get('moved') and d.get('transferred_to')=='de-1' else 1)"
check "old-url-moved-notice" $?

# ---- client auto-follow after the transfer (the agreed user scenario) ----
# the installed client follows the moved pointer to the new owner,
# validates the destination against its OWN enrolled identity, keeps LKG
# lab http panels are EXPLICITLY allow-listed (origin policy is on by default)
ARA_STATE_DIR="$S/cl" $ARA_BIN/ara follow --json --token "$SUBTOK" --base $UA \
  --allow-http-base $UA --allow-http-base $UB \
  --device-uuid "$DEV_UUID" > "$R/follow.json" 2>&1
check "client-follow-ran" $?
python3 -c "
import json,sys
d=json.load(open('$R/follow.json'))
data=d.get('data',{})
sys.exit(0 if data.get('followed') and data.get('catalog_ok') else 1)"
check "client-followed-and-catalog-valid" $?
[ -f "$S/cl/subscription/catalog.json" ]; check "client-catalog-stored" $?

# a foreign-identity catalog is refused (scope check)
ARA_STATE_DIR="$S/cl" $ARA_BIN/ara follow --json --token "$SUBTOK" --base $UA \
  --allow-http-base $UA --allow-http-base $UB \
  --device-uuid "00000000-0000-0000-0000-000000000000" > "$R/follow-foreign.json" 2>&1
python3 -c "
import json,sys
d=json.load(open('$R/follow-foreign.json'))
data=d.get('data',{})
sys.exit(0 if 'scope' in (data.get('error') or '') and not data.get('catalog_ok') else 1)"
check "follow-refuses-foreign-identity" $?

# ---- token rotation (GLM_REMAINING A) ----
NEW_TOK_FILE="$S/rot.token"
$ARB subscription rotate --json --id "$SUBID" --grace-seconds 30 --out "$NEW_TOK_FILE" > "$R/rotate.json" 2>&1
check "rotate-issued" $?
NEW_TOK=$(cat "$NEW_TOK_FILE")
[ -n "$NEW_TOK" ] && [ "$NEW_TOK" != "$SUBTOK" ]; check "rotate-new-secret" $?
# during grace BOTH tokens resolve
C1=$(curl -s -o /dev/null -w "%{http_code}" $UB/sub/$SUBTOK)
C2=$(curl -s -o /dev/null -w "%{http_code}" $UB/sub/$NEW_TOK)
[ "$C1" = "200" ] && [ "$C2" = "200" ]; check "rotate-grace-dual" $?
sleep 31
C1b=$(curl -s -o /dev/null -w "%{http_code}" $UB/sub/$SUBTOK)
[ "$C1b" = "401" ]; check "rotate-grace-expired" $?
# identity/usage untouched by rotation
Q2=$($ARB subscription quota --json --id "$SUBID" | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['used_bytes'])")
[ "${Q2:-0}" = "${USED_B:-0}" ]; check "rotate-usage-unchanged" $?
SUBTOK="$NEW_TOK"

# ---- client follow A→B→C: the installed client's token survives the transfer ----
# (already followed A→B above; re-point the follow at the new owner with the ROTATED token)
ARA_STATE_DIR="$S/cl" $ARA_BIN/ara follow --json --token "$SUBTOK" --base $UB \
  --allow-http-base $UA --allow-http-base $UB \
  --device-uuid "$DEV_UUID" > "$R/follow-rot.json" 2>&1
check "client-follow-after-rotate" $?
[ -f "$S/cl/subscription/catalog.json" ]; check "client-catalog-after-rotate" $?
# the pre-rotate catalog became the LKG on the re-follow
[ -f "$S/cl/subscription/lkg.json" ]; check "client-lkg-kept" $?

# ---- revocation on the new owner kills the token ----
$ARB subscription revoke --id "$SUBID" >/dev/null 2>&1
CODE=$(curl -s -o /dev/null -w "%{http_code}" $UB/sub/$SUBTOK)
[ "$CODE" = "401" ]; check "revoked-token-401" $?

# ---- link teardown ----
$ARA panel revoke --id de-1 --base $UB >/dev/null 2>&1; check "link-revoked" $?
$ARB panel share --to ru-1 --base $UA >/dev/null 2>&1
$ARA panel links --json | python3 -c "
import json,sys
d=json.load(sys.stdin)
links={l['panel_id']:l for l in d['data']['links']}
sys.exit(0 if links.get('de-1',{}).get('revoked_at') else 1)"
check "link-revocation-visible" $?

echo "=== FEDERATION E2E: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = "0" ]
