#!/bin/sh
# First-time direct HTTPS setup for the native ara-control package.
set -eu
die() { printf 'ARA: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die 'run as root'
if [ "$#" -eq 0 ]; then
    printf 'Имя панели или IP / Panel hostname or IP [127.0.0.1]: ' >&2
    IFS= read -r answer_host || die 'no input'
    printf 'Порт / Port [29445]: ' >&2
    IFS= read -r answer_port || die 'no input'
    set -- "${answer_host:-127.0.0.1}" --port "${answer_port:-29445}"
    if [ "${answer_host:-127.0.0.1}" != 127.0.0.1 ] && [ "$answer_host" != localhost ]; then
        printf 'Принимать подключения извне / Listen publicly? [y/N]: ' >&2
        IFS= read -r answer_public || die 'no input'
        case "$answer_public" in y|Y) set -- "$@" --bind 0.0.0.0 ;; esac
    fi
    printf '%s\n' '1. Локальный сертификат / Local certificate'         '2. Let’s Encrypt для домена / Let’s Encrypt for a domain (TCP 80)'         '3. Свой сертификат / Existing certificate' >&2
    printf 'Способ / Method [1]: ' >&2
    IFS= read -r answer_tls || die 'no input'
    case "$answer_tls" in
        ''|1) set -- "$@" --self-signed ;;
        2) set -- "$@" --acme ;;
        3)
            printf 'Сертификат PEM / Certificate PEM path: ' >&2
            IFS= read -r answer_cert || die 'no input'
            printf 'Ключ PEM / Private key PEM path: ' >&2
            IFS= read -r answer_key || die 'no input'
            set -- "$@" --cert "$answer_cert" --key "$answer_key"
            ;;
        *) die 'choose certificate method 1, 2 or 3' ;;
    esac
fi
host=$1
shift
port=29445 bind=127.0.0.1 cert= key= self_signed=no acme=no
while [ "$#" -gt 0 ]; do
    case "$1" in
        --port|--bind|--cert|--key)
            [ "$#" -ge 2 ] || die "missing value for $1"
            case "$1" in
                --port) port=$2 ;;
                --bind) bind=$2 ;;
                --cert) cert=$2 ;;
                --key) key=$2 ;;
            esac
            shift 2 ;;
        --acme) acme=yes; shift ;;
        --self-signed) self_signed=yes; shift ;;
        *) die "unknown option: $1" ;;
    esac
done
case "$host" in ''|*[!a-zA-Z0-9.-]*|[-.]*|*[-.]) die 'enter a DNS name or IPv4 address, without scheme or port' ;; esac
case "$host" in invalid|*.invalid) die 'choose a usable DNS name or IP' ;; esac
case "$bind" in ''|*[!0-9.]*) die 'bind address must be IPv4' ;; esac
case "$port" in ''|*[!0-9]*|0*) die 'invalid panel port' ;; esac
[ "${#port}" -le 5 ] && [ "$port" -ge 1024 ] && [ "$port" -le 65535 ] ||
    die 'choose a panel port between 1024 and 65535'
command -v ara-control >/dev/null || die 'install ara-control first'
command -v openssl >/dev/null || die 'openssl is required'
command -v curl >/dev/null || die 'curl is required'
command -v ss >/dev/null || die 'iproute2 is required'
if [ "$acme" = yes ]; then
    [ "$self_signed" = no ] && [ -z "$cert$key" ] || die 'choose one certificate method'
    printf '%s\n' "$host" | grep -Eq '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z][A-Za-z0-9-]*$' ||
        die 'ACME mode requires a public DNS name'
    command -v ara >/dev/null || die 'ACME requires the ara CLI package'
fi
state=/var/lib/ara-control
settings=/etc/default/ara-control
tls="$state/setup-tls"
[ ! -e "$settings" ] && [ ! -e "$state/admin.origin" ] && [ ! -e "$state/control.db" ] ||
    die 'panel state or settings already exist; use the existing installation workflow'
if systemctl is-active --quiet ara-control.service || systemctl is-enabled --quiet ara-control.service; then
    die 'ara-control.service is already active or enabled'
fi
if ss -H -ltn "sport = :$port" | grep -q .; then die "port $port is already in use"; fi
umask 077
mkdir -m 0750 -- "$tls" || die 'panel TLS directory already exists'
published=no started=no committed=no temp_settings= temp_origin=
cleanup() {
    if [ -n "$temp_settings" ]; then rm -f -- "$temp_settings"; fi
    if [ -n "$temp_origin" ]; then rm -f -- "$temp_origin"; fi
    if [ "$committed" = no ]; then
        if [ "$started" = yes ]; then systemctl stop ara-control.service || true; fi
        if [ "$published" = yes ]; then rm -f -- "$settings" "$state/admin.origin"; fi
        rm -f -- "$tls/fullchain.pem" "$tls/key.pem"
        if [ "$acme" = yes ]; then rm -rf -- "$tls/acme"; fi
        rmdir -- "$tls" || true
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
chgrp ara-control "$tls"

if [ "$self_signed" = yes ]; then
    [ -z "$cert$key" ] || die 'choose an imported certificate or self-signed'
    case "$host" in *[!0-9.]*) san="DNS:$host" ;; *) san="IP:$host" ;; esac
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
        -subj "/CN=$host" -addext "subjectAltName=$san" \
        -keyout "$tls/key.pem" -out "$tls/fullchain.pem"
    set -- --cacert "$tls/fullchain.pem"
else
    if [ "$acme" = yes ]; then
        ara --state-dir "$tls/acme" tls renew --trust system \
            --hostname "$host" --acme-dir https://acme-v02.api.letsencrypt.org/directory
        cert="$tls/acme/tls/active/cert.pem"
        key="$tls/acme/tls/active/key.pem"
    fi
    [ -n "$cert" ] && [ -n "$key" ] || die 'provide --cert and --key, or use --self-signed'
    install -m 0600 -- "$cert" "$tls/fullchain.pem"
    install -m 0600 -- "$key" "$tls/key.pem"
    set --
fi
chgrp ara-control "$tls/fullchain.pem" "$tls/key.pem"
chmod 0640 "$tls/fullchain.pem" "$tls/key.pem"

origin="https://$host:$port"
probe_addr=$bind
[ "$bind" != 0.0.0.0 ] || probe_addr=127.0.0.1
temp_settings=$(mktemp /etc/default/.ara-control.XXXXXX)
cat >"$temp_settings" <<SETTINGS
ARA_CONTROL_LISTEN=$bind:$port
ARA_HTTPS_CERT=$tls/fullchain.pem
ARA_HTTPS_KEY=$tls/key.pem
ARA_PANEL_ID=panel-$(openssl rand -hex 8)
ARA_MONITOR_CLOUDFLARE=1
ARA_SUB_CA=system
SETTINGS
ln -- "$temp_settings" "$settings" || die 'could not publish panel settings'
published=yes
# Publish the origin before the first process starts: subscription endpoint
# initialization runs at startup and must see the selected host and port.
temp_origin=$(mktemp "$state/.admin.origin.XXXXXX")
printf '%s\n' "$origin" >"$temp_origin"
chgrp ara-control "$temp_origin"
chmod 0640 "$temp_origin"
ln -- "$temp_origin" "$state/admin.origin" || { rm -f -- "$temp_origin"; die 'could not publish panel origin'; }
rm -f -- "$temp_origin"
started=yes
systemctl start ara-control.service
attempt=0
until curl -q -fsS --noproxy '*' --connect-timeout 1 --max-time 2 "$@" \
    --resolve "$host:$port:$probe_addr" "$origin/" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 10 ] || die 'HTTPS probe failed. Check service logs, hostname and certificate trust.'
    sleep 1
done
systemctl enable ara-control.service >/dev/null
committed=yes
if [ "$bind" = 127.0.0.1 ]; then
    printf '%s\n' 'Panel binds to loopback. Use an SSH tunnel or a separately configured reverse proxy.' >&2
fi
if [ "$self_signed" = yes ]; then
    printf 'Trust this certificate on your client: %s\n' "$tls/fullchain.pem" >&2
fi
runuser -u ara-control -- ara-control --state-dir "$state" --admin-credentials
