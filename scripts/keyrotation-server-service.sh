#!/usr/bin/env bash
set -euo pipefail
: "${KEYROTATION_BINARY:=/usr/local/bin/keyrotation-server}"
: "${KEYROTATION_DATA_DIR:=/var/lib/keyrotation-server}"
: "${KEYROTATION_LISTEN:=0.0.0.0:4233}"
: "${KEYROTATION_PUBLIC_URL:?Set KEYROTATION_PUBLIC_URL to the client API URL}"
args=(serve --data-dir "$KEYROTATION_DATA_DIR" --listen "$KEYROTATION_LISTEN"
      --public-url "$KEYROTATION_PUBLIC_URL")
if [[ -n ${KEYROTATION_TLS_CERT:-} || -n ${KEYROTATION_TLS_KEY:-} ]]; then
  : "${KEYROTATION_TLS_CERT:?Set both TLS certificate and key}"
  : "${KEYROTATION_TLS_KEY:?Set both TLS certificate and key}"
  args+=(--tls-cert "$KEYROTATION_TLS_CERT" --tls-key "$KEYROTATION_TLS_KEY")
fi
# exec makes the API server systemd's MainPID; no nohup or background fork.
exec "$KEYROTATION_BINARY" "${args[@]}"
