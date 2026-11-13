#!/usr/bin/env bash
# Root only. Use already built Linux binaries; all service state is synthetic.
# Usage: sudo bash scripts/test-systemd.sh SERVER_BINARY PROBE_BINARY NORMAL_USER
set -euo pipefail
umask 077
[[ $EUID == 0 ]] || { echo 'Run with sudo/root'; exit 2; }
bin=$(realpath "${1:?server binary}")
probe=$(realpath "${2:?e2e binary}")
test_user=${3:?normal non-root test user}
[[ $(id -u "$test_user") != 0 ]] || { echo 'Test service must run as a non-root user'; exit 2; }
test_group=$(id -gn "$test_user")
repo=$(cd "$(dirname "$0")/.." && pwd)
[[ $(ps -p 1 -o comm=) == systemd ]] || { echo 'PID 1 must be systemd'; exit 2; }
for tool in systemctl systemd-analyze openssl runuser sha256sum timeout; do command -v "$tool" >/dev/null; done
work=$(mktemp -d /var/lib/keyrotation-e2e.XXXXXX)
name=${work##*/}
unit=$name.service
target=$name.target
report=${KEYROTATION_REPORT_DIR:-$repo/.local/systemd-reports/$name}
mkdir -p "$report" "$work/bin" "$work/creds" "$work/data" "$work/imported"
import_pid=
checks=0
pass() { checks=$((checks + 1)); printf '[PASS] %s\n' "$*" | tee -a "$report/checks.txt"; }
cleanup() {
  local result=$?
  trap - EXIT
  systemctl stop "$target" "$unit" >/dev/null 2>&1 || true
  systemctl disable --runtime "$unit" >/dev/null 2>&1 || true
  if [[ -n $import_pid ]]; then kill "$import_pid" 2>/dev/null || true; wait "$import_pid" 2>/dev/null || true; fi
  journalctl -u "$unit" --no-pager > "$report/journal.txt" 2>/dev/null || true
  rm -f "/run/systemd/system/$unit" "/run/systemd/system/$target" "/run/systemd/system/multi-user.target.wants/$unit" "/run/systemd/system/$target.wants/$unit"
  rmdir "/run/systemd/system/$target.wants" 2>/dev/null || true
  systemctl daemon-reload
  systemctl reset-failed "$unit" >/dev/null 2>&1 || true
  # Never remove a caller-supplied directory; work is generated above.
  [[ $work == /var/lib/keyrotation-e2e.* && $(dirname "$work") == /var/lib ]] || exit 90
  rm -rf -- "$work"
  printf 'result=%s checks=%s cleanup=complete\n' "$result" "$checks" | tee -a "$report/checks.txt"
  chmod -R go-rwx "$report"
  printf 'Report: %s\n' "$report"
  exit "$result"
}
trap cleanup EXIT
install -m 755 "$bin" "$work/bin/keyrotation-server"
install -m 755 "$repo/scripts/keyrotation-server-service.sh" "$work/bin/service"
bin=$work/bin/keyrotation-server
for secret in admin content new-content new-admin; do openssl rand -hex 24 > "$work/creds/$secret"; done
chown -R "$test_user:$test_group" "$work"
export RK_USER=admin RK_PASS_FILE=$work/creds/admin RK_CONTENT_PASS_FILE=$work/creds/content
export RK_NEW_PASS_FILE=$work/creds/new-content RK_RESUME_FILE=$work/resume.json RK_LEGACY_DB=$work/legacy.db
port=$("$probe" port)
import_port=$("$probe" port)
[[ $port != "$import_port" ]] || { echo 'Port selection collided; rerun'; exit 1; }
export RK_URL=http://127.0.0.1:$port/
export RK_PUBKEY=
write_env() {
  cat > "$work/server.env" <<EOF
KEYROTATION_BINARY=$bin
KEYROTATION_DATA_DIR=$work/data
KEYROTATION_LISTEN=127.0.0.1:$port
KEYROTATION_PUBLIC_URL=$RK_URL
EOF
  chown "$test_user:$test_group" "$work/server.env"
}
write_env
sed -e "s/^User=.*/User=$test_user/" -e "s/^Group=.*/Group=$test_group/" \
    -e "s|^StateDirectory=.*|StateDirectory=$name|" \
    -e "s|^WorkingDirectory=.*|WorkingDirectory=$work|" \
    -e "s|^Environment=.*|Environment=KEYROTATION_DATA_DIR=$work/data|" \
    -e "s|^EnvironmentFile=.*|EnvironmentFile=$work/server.env|" \
    -e "s|^ExecStart=.*|ExecStart=$work/bin/service|" \
    "$repo/deploy/systemd/keyrotation-server.service" > "/run/systemd/system/$unit"
cat > "/run/systemd/system/$target" <<EOF
[Unit]
Description=Isolated keyrotation boot dependency test
EOF
systemd-analyze verify "/run/systemd/system/$unit" "/run/systemd/system/$target" > "$report/verify.txt" 2>&1
pass 'unit syntax and executable paths verified'
runuser -u "$test_user" -- "$bin" init --data-dir "$work/data" --username admin --password-stdin < "$RK_PASS_FILE" > "$report/init.txt"
runuser -u "$test_user" -- "$bin" check --data-dir "$work/data" >> "$report/init.txt"
RK_PUBKEY=$(runuser -u "$test_user" -- "$bin" public-key --data-dir "$work/data")
export RK_PUBKEY
[[ $(stat -c %a "$work/data") == 700 && $(stat -c %a "$work/data/ptoolkit_keys.db") == 600 && $(stat -c %a "$work/data/identity.key") == 600 ]]
pass 'explicit init/check/public-key and Unix 700/600 permissions'
before=$(sha256sum "$work/data/ptoolkit_keys.db" | cut -d' ' -f1)
if runuser -u "$test_user" -- "$bin" init --data-dir "$work/data" --username admin --password-stdin < "$RK_PASS_FILE" > "$report/duplicate-init.txt" 2>&1; then exit 1; fi
[[ $(sha256sum "$work/data/ptoolkit_keys.db" | cut -d' ' -f1) == "$before" ]]
if "$bin" serve --data-dir "$work/data" --unknown value > "$report/bad-cli.txt" 2>&1; then exit 1; fi
pass 'duplicate init is non-destructive; unknown CLI option is rejected'
wait_ready() {
  local host=$1 target_port=$2
  for ((i=0;i<100;i++)); do
    if (echo >/dev/tcp/"$host"/"$target_port") 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  echo 'Listener did not become ready'; return 1
}
scenario() {
  local scenario_name=$1
  timeout 180 "$probe" "$scenario_name" > "$report/$scenario_name.txt" 2>&1 || { tail -15 "$report/$scenario_name.txt"; return 1; }
  pass "protocol scenario $scenario_name ($(tail -1 "$report/$scenario_name.txt"))"
}
systemctl daemon-reload
systemctl enable --runtime "$unit" > "$report/enable.txt" 2>&1
[[ $(systemctl is-enabled "$unit") == enabled-runtime ]]
[[ -L /run/systemd/system/multi-user.target.wants/$unit ]]
pass 'enable creates boot target dependency (runtime-isolated test)'
systemctl add-wants --runtime "$target" "$unit"
systemctl start "$target"
wait_ready 127.0.0.1 "$port"
[[ $(systemctl is-active "$unit") == active ]]
pid=$(systemctl show "$unit" -p MainPID --value)
[[ $(readlink -f "/proc/$pid/exe") == "$bin" ]]
[[ $(stat -c %U "/proc/$pid") == "$test_user" ]]
pass 'isolated boot target starts service; MainPID is actual non-root server'
old_pid=$pid
systemctl restart "$unit"
wait_ready 127.0.0.1 "$port"
pid=$(systemctl show "$unit" -p MainPID --value)
[[ $pid != "$old_pid" && $pid != 0 ]]
pass 'manual restart replaces MainPID and returns a working listener'
scenario sandbox
# Kill the real MainPID, not a shell wrapper. Preserve the same DB and identity.
restarts=$(systemctl show "$unit" -p NRestarts --value)
systemctl kill --kill-whom=main --signal=SIGKILL "$unit"
for ((i=0;i<100;i++)); do
  next=$(systemctl show "$unit" -p MainPID --value)
  if [[ $next != 0 && $next != "$pid" ]] && systemctl is-active --quiet "$unit"; then break; fi
  sleep 0.1
 done
wait_ready 127.0.0.1 "$port"
[[ $next != "$pid" && $next != 0 ]]
[[ $(systemctl show "$unit" -p NRestarts --value) -gt $restarts ]]
pass 'SIGKILL triggers automatic restart with new MainPID'
scenario resume
# Verify stop is graceful (exit 0) and never triggers Restart=on-failure.
systemctl stop "$unit"
sleep 2.5
[[ $(systemctl show "$unit" -p MainPID --value) == 0 ]]
[[ $(systemctl show "$unit" -p ExecMainStatus --value) == 0 ]]
[[ $(systemctl show "$unit" -p ActiveState --value) == inactive ]]
pass 'SIGTERM stop exits successfully and remains stopped past RestartSec'
# Legacy import on a second synthetic instance, byte-for-byte non-destructive.
scenario fixture
chown "$test_user:$test_group" "$RK_LEGACY_DB"
legacy_before=$(sha256sum "$RK_LEGACY_DB" | cut -d' ' -f1)
runuser -u "$test_user" -- "$bin" import --data-dir "$work/imported" --source "$RK_LEGACY_DB" --username admin --password-stdin < "$RK_PASS_FILE" > "$report/import.txt"
foreign=$(runuser -u "$test_user" -- "$bin" public-key --data-dir "$work/imported")
"$bin" serve --data-dir "$work/imported" --listen "127.0.0.1:$import_port" --public-url "http://127.0.0.1:$import_port/" > "$report/import-server.txt" 2>&1 &
import_pid=$!
wait_ready 127.0.0.1 "$import_port"
sandbox_public=$RK_PUBKEY
RK_URL=http://127.0.0.1:$import_port/ RK_PUBKEY=$foreign RK_FOREIGN_PUBKEY=$sandbox_public scenario real
kill "$import_pid"; wait "$import_pid"; import_pid=
[[ $(sha256sum "$RK_LEGACY_DB" | cut -d' ' -f1) == "$legacy_before" ]]
pass 'synthetic legacy import leaves source bytes unchanged'
# Same systemd unit switched to real TLS with a one-use local CA.
mkdir "$work/tls"
openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes -keyout "$work/tls/ca.key" -out "$work/tls/ca.pem" -subj /CN=keyrotation-e2e-ca >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$work/tls/server.key" -out "$work/tls/server.csr" -subj /CN=127.0.0.1 >/dev/null 2>&1
printf 'subjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' > "$work/tls/san.cnf"
openssl x509 -req -in "$work/tls/server.csr" -CA "$work/tls/ca.pem" -CAkey "$work/tls/ca.key" -CAcreateserial -days 1 -sha256 -out "$work/tls/server.pem" -extfile "$work/tls/san.cnf" >/dev/null 2>&1
chown -R "$test_user:$test_group" "$work/tls"
RK_URL=https://127.0.0.1:$port/
export RK_URL RK_CA_FILE=$work/tls/ca.pem
write_env
printf 'KEYROTATION_TLS_CERT=%s\nKEYROTATION_TLS_KEY=%s\n' "$work/tls/server.pem" "$work/tls/server.key" >> "$work/server.env"
systemctl start "$unit"
wait_ready 127.0.0.1 "$port"
RK_CONTENT_PASS_FILE=$RK_NEW_PASS_FILE scenario https
systemctl stop "$unit"
[[ $(systemctl show "$unit" -p ExecMainStatus --value) == 0 ]]
pass 'HTTPS unit startup, trusted CA RPC and graceful SIGTERM shutdown'
# Offline admin reset invalidates existing persisted sessions.
runuser -u "$test_user" -- "$bin" reset-password --data-dir "$work/data" --username admin --password-stdin < "$work/creds/new-admin" > "$report/reset.txt"
RK_URL=http://127.0.0.1:$port/
export RK_URL
write_env
systemctl start "$unit"
wait_ready 127.0.0.1 "$port"
RK_PASS_FILE=$work/creds/new-admin scenario admin
systemctl stop "$unit"
runuser -u "$test_user" -- "$bin" check --data-dir "$work/data" > "$report/final-check.txt"
runuser -u "$test_user" -- "$bin" check --data-dir "$work/imported" >> "$report/final-check.txt"
pass 'both test databases pass offline integrity checks after all operations'
# Permanent configuration failure must be rate-limited, then explicitly recoverable.
printf 'KEYROTATION_PUBLIC_URL=invalid-url\n' >> "$work/server.env"
systemctl reset-failed "$unit"
systemctl start "$unit" || true
for ((i=0;i<200;i++)); do
  [[ $(systemctl show "$unit" -p ActiveState --value) == failed && $(systemctl show "$unit" -p NRestarts --value) -ge 5 ]] && break
  sleep 0.1
 done
[[ $(systemctl show "$unit" -p ActiveState --value) == failed ]]
limited_restarts=$(systemctl show "$unit" -p NRestarts --value)
sleep 2.5
[[ $(systemctl show "$unit" -p NRestarts --value) == "$limited_restarts" ]]
[[ $(systemctl show "$unit" -p MainPID --value) == 0 ]]
journalctl -u "$unit" --no-pager > "$report/rate-limit.txt"
grep -q 'Start request repeated too quickly' "$report/rate-limit.txt"
pass 'permanent startup failure hits restart rate limit rather than looping forever'
write_env
systemctl reset-failed "$unit"
systemctl start "$unit"
wait_ready 127.0.0.1 "$port"
systemctl stop "$unit"
pass 'fixed configuration plus reset-failed restores normal startup'
systemctl disable --runtime "$unit" > "$report/disable.txt" 2>&1
[[ $(systemctl is-enabled "$unit" || true) == disabled ]]
pass 'disable removes autostart dependency'
journalctl -u "$unit" --no-pager > "$report/journal.txt"
grep -q 'listening on' "$report/journal.txt"
grep -q 'stopped' "$report/journal.txt"
if grep -F -f "$work/creds/admin" -f "$work/creds/content" -f "$work/creds/new-content" -f "$work/creds/new-admin" "$report/journal.txt"; then echo 'Secret leaked to journal'; exit 1; fi
pass 'journal records lifecycle and excludes generated passwords/content passphrases'
