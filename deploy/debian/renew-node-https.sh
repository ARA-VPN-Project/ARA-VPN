#!/bin/sh
# Renew and publish the shared panel/ingress chain for a dedicated Debian node.
set -eu
umask 077
: "${ARA_BIN:?}" "${ARA_ACME_STATE:?}" "${ARA_TLS_LINK:?}" "${ARA_TLS_GROUP:?}"
: "${ARA_TLS_HOST:?}" "${ARA_TLS_IP:?}" "${ARA_PANEL_PORT:?}" "${ARA_PANEL_UNIT:?}" "${ARA_EDGE_UNIT:?}"
renew_before=2592000
published="$ARA_TLS_LINK/cert.pem"
if openssl x509 -in "$published" -checkend "$renew_before" -noout >/dev/null; then
    exit 0
fi
cached="$ARA_ACME_STATE/tls/active"
if ! openssl x509 -in "$cached/cert.pem" -checkend "$renew_before" -noout >/dev/null 2>&1; then
    "$ARA_BIN" --state-dir "$ARA_ACME_STATE" tls renew \
      --acme-dir https://acme-v02.api.letsencrypt.org/directory \
      --hostname "$ARA_TLS_HOST" --challenge-listen "$ARA_TLS_IP:80" --trust system
fi
openssl verify -CApath /etc/ssl/certs -untrusted "$cached/cert.pem" \
    -verify_hostname "$ARA_TLS_HOST" "$cached/cert.pem"
old=$(readlink "$ARA_TLS_LINK")
parent=$(dirname "$ARA_TLS_LINK")
next=$(mktemp -d "$parent/public-renewed.XXXXXX")
chown "root:$ARA_TLS_GROUP" "$next"
chmod 0750 "$next"
install -o root -g "$ARA_TLS_GROUP" -m 0640 "$cached/cert.pem" "$cached/key.pem" "$next/"
publish() {
    ln -s "$1" "$next/pointer"
    mv -Tf "$next/pointer" "$ARA_TLS_LINK"
}
publish "$(basename "$next")"
if systemctl restart "$ARA_PANEL_UNIT" "$ARA_EDGE_UNIT" &&
    systemctl is-active --quiet "$ARA_PANEL_UNIT" "$ARA_EDGE_UNIT" &&
    curl --noproxy '*' --retry 4 --retry-connrefused --max-time 6 -fsS -o /dev/null \
       --resolve "$ARA_TLS_HOST:$ARA_PANEL_PORT:$ARA_TLS_IP" "https://$ARA_TLS_HOST:$ARA_PANEL_PORT/"; then
    exit 0
fi
publish "$old"
systemctl restart "$ARA_PANEL_UNIT" "$ARA_EDGE_UNIT"
exit 1
