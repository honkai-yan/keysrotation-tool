#!/usr/bin/env bash
# Integration test for the installer, using real systemd with isolated paths/user.
set -euo pipefail
umask 077
[[ $EUID == 0 ]] || { echo 'Run as root'; exit 2; }
binary=$(realpath "${1:?Linux server binary}")
probe=$(realpath "${2:?Linux e2e binary}")
repo=$(cd "$(dirname "$0")/.." && pwd)
[[ -z $(ss -H -lnt 'sport = :4233') ]] || { echo 'Test requires free default port 4233'; exit 2; }
work=$(mktemp -d /var/lib/keyrotation-installer.XXXXXX)
chmod 755 "$work"
suffix=$(openssl rand -hex 3)
service=keyrotation-install-$suffix
account=kri-$suffix
unit=$service.service
! getent passwd "$account" >/dev/null
report=${KEYROTATION_REPORT_DIR:-$repo/.local/installer-reports/$service}
mkdir -p "$report" "$work/creds"
chmod 700 "$work/creds"
openssl rand -hex 24 > "$work/creds/admin"
openssl rand -hex 24 > "$work/creds/content"
openssl rand -hex 24 > "$work/creds/new-content"
blocker= checks=0 private=
pass() { checks=$((checks + 1)); printf '[PASS] %s\n' "$*" | tee -a "$report/checks.txt"; }
cleanup() {
  local result=$?
  trap - EXIT
  systemctl disable --now "$unit" >/dev/null 2>&1 || true
  [[ -z $blocker ]] || { kill "$blocker" 2>/dev/null || true; wait "$blocker" 2>/dev/null || true; }
  journalctl -u "$unit" --no-pager > "$report/journal.txt" 2>/dev/null || true
  rm -f "/etc/systemd/system/$unit" "/etc/systemd/system/multi-user.target.wants/$unit" "/run/lock/$service.install.lock"
  systemctl daemon-reload
  systemctl reset-failed "$unit" >/dev/null 2>&1 || true
  if getent passwd "$account" >/dev/null; then userdel "$account"; fi
  if getent group "$account" >/dev/null; then groupdel "$account"; fi
  [[ $work == /var/lib/keyrotation-installer.* && $(dirname "$work") == /var/lib ]] || exit 90
  rm -rf -- "$work"
  if [[ -n $private ]]; then
    [[ $private == /root/keyrotation-existing.* && $(dirname "$private") == /root ]] || exit 91
    rm -rf -- "$private"
  fi
  printf 'result=%s checks=%s cleanup=complete\n' "$result" "$checks" | tee -a "$report/checks.txt"
  printf 'Report: %s\n' "$report"
  exit "$result"
}
trap cleanup EXIT
common=(--install-root "$work" --service-name "$service" --user "$account")
if [[ ${3:-} != --auto-build ]]; then common+=(--binary "$binary"); fi
installer=$repo/scripts/install-service.sh
runtime_data=$work/var/lib/keyrotation-server
data=$runtime_data
adoption=()
if [[ ${3:-} == --existing-data ]]; then
  private=$(mktemp -d /root/keyrotation-existing.XXXXXX)
  data=$private/'existing data%vault'
  mkdir "$data"
  "$binary" init --data-dir "$data" --username admin --password-stdin < "$work/creds/admin" > "$report/existing-init.txt"
  original_db=$(sha256sum "$data/ptoolkit_keys.db" | cut -d' ' -f1)
  original_identity=$(sha256sum "$data/identity.key" | cut -d' ' -f1)
  adoption=(--data-dir "$data")
fi
config=$work/etc/keyrotation-server/server.env
installed=$work/usr/local/bin/keyrotation-server
if bash "$installer" "${common[@]}" --port 0 --public-url http://127.0.0.1:4233/ > "$report/invalid-port.txt" 2>&1; then exit 1; fi
if bash "$installer" "${common[@]}" --public-url http://0.0.0.0:4233/ > "$report/invalid-url.txt" 2>&1; then exit 1; fi
[[ ! -e /etc/systemd/system/$unit && ! -e $runtime_data ]]
! getent passwd "$account" >/dev/null
pass 'invalid input rejected before account/data/service creation'
if [[ -n $private ]]; then
  if bash "$installer" "${common[@]}" --data-dir "$private/not-found" --public-url http://127.0.0.1:4233/ < /dev/null > "$report/missing-data.txt" 2>&1; then exit 1; fi
  mkdir "$private/incomplete"
  if bash "$installer" "${common[@]}" --data-dir "$private/incomplete" --public-url http://127.0.0.1:4233/ < /dev/null > "$report/incomplete-data.txt" 2>&1; then exit 1; fi
  ! getent passwd "$account" >/dev/null
  pass 'missing/incomplete explicit data directories rejected without initialization or account creation'
fi
if [[ -n $private ]]; then
  bash "$installer" "${common[@]}" "${adoption[@]}" --public-url http://127.0.0.1:4233/ < /dev/null > "$report/install.txt" 2>&1
else
  bash "$installer" "${common[@]}" --public-url http://127.0.0.1:4233/ --password-stdin < "$work/creds/admin" > "$report/install.txt" 2>&1
fi
systemctl is-enabled --quiet "$unit"
systemctl is-active --quiet "$unit"
pid=$(systemctl show "$unit" -p MainPID --value)
[[ $(stat -c %U "/proc/$pid") == "$account" ]]
ss -H -lntp 'sport = :4233' | grep -q "0.0.0.0:4233.*pid=$pid,"
[[ $(getent passwd "$account" | cut -d: -f7) == /usr/sbin/nologin ]]
[[ $(stat -c %a "$data") == 700 && $(stat -c %a "$data/ptoolkit_keys.db") == 600 && $(stat -c %a "$data/identity.key") == 600 && $(stat -c %a "$config") == 600 ]]
pass 'first install creates dedicated system account, all-IPv4 :4233 service, permissions and enable link'
if [[ -n $private ]]; then
  [[ $(sha256sum "$data/ptoolkit_keys.db" | cut -d' ' -f1) == "$original_db" ]]
  [[ $(sha256sum "$data/identity.key" | cut -d' ' -f1) == "$original_identity" ]]
  [[ ! -e $runtime_data/ptoolkit_keys.db ]]
  [[ $(stat -c %a "$private") == 700 && $(stat -c %U "$private") == root ]]
  [[ $(stat -c %d:%i "$data/ptoolkit_keys.db") == $(nsenter -t "$pid" -m -- stat -c %d:%i "$runtime_data/ptoolkit_keys.db") ]]
  pass 'existing private path with space/percent is bound directly: same inode, unchanged DB/identity, no parent permission change'
fi
if [[ ${3:-} == --auto-build ]]; then
  [[ -x $repo/target/release/keyrotation-server ]]
  [[ $(stat -c %U "$repo/target/release/keyrotation-server") == "${SUDO_USER:-root}" ]]
  pass 'release artifact is available and owned by the invoking user'
fi
export RK_USER=admin RK_URL=http://127.0.0.1:4233/
export RK_PASS_FILE=$work/creds/admin RK_CONTENT_PASS_FILE=$work/creds/content
export RK_NEW_PASS_FILE=$work/creds/new-content RK_RESUME_FILE=$work/resume.json
RK_PUBKEY=$("$installed" public-key --data-dir "$data")
export RK_PUBKEY
scenario() {
  local kind=$1 label=$2
  timeout 180 "$probe" "$kind" > "$report/$label.txt" 2>&1 || { tail -10 "$report/$label.txt"; return 1; }
  pass "$label ($(tail -1 "$report/$label.txt"))"
}
scenario sandbox installed-business
sha_db=$(sha256sum "$data/ptoolkit_keys.db" | cut -d' ' -f1)
sha_key=$(sha256sum "$data/identity.key" | cut -d' ' -f1)
uid=$(id -u "$account")
bash "$installer" "${common[@]}" < /dev/null > "$report/reinstall.txt" 2>&1
[[ $(sha256sum "$data/ptoolkit_keys.db" | cut -d' ' -f1) == "$sha_db" ]]
[[ $(sha256sum "$data/identity.key" | cut -d' ' -f1) == "$sha_key" ]]
[[ $(id -u "$account") == "$uid" ]]
pass 'repeat install without password or URL preserves existing database, identity, account and configuration'
if [[ -n $private ]]; then
  grep -Fq "KEYROTATION_HOST_DATA_DIR=\"$data\"" "$config"
  pid=$(systemctl show "$unit" -p MainPID --value)
  [[ $(stat -c %d:%i "$data/ptoolkit_keys.db") == $(nsenter -t "$pid" -m -- stat -c %d:%i "$runtime_data/ptoolkit_keys.db") ]]
  pass 'reinstall without --data-dir retains the recorded external directory and binding'
  old_env=$(sha256sum "$config" | cut -d' ' -f1)
  mkdir "$private/corrupt"
  cp "$data/identity.key" "$private/corrupt/identity.key"
  printf corrupt > "$private/corrupt/ptoolkit_keys.db"
  if bash "$installer" "${common[@]}" --data-dir "$private/corrupt" < /dev/null > "$report/corrupt-data.txt" 2>&1; then exit 1; fi
  [[ $(systemctl show "$unit" -p MainPID --value) == "$pid" ]]
  [[ $(sha256sum "$config" | cut -d' ' -f1) == "$old_env" ]]
  pass 'corrupt replacement directory rejected before stopping the current service or changing config'
fi
scenario resume after-reinstall
next_port=$("$probe" port)
bash "$installer" "${common[@]}" --port "$next_port" --public-url "http://127.0.0.1:$next_port/" < /dev/null > "$report/change-port.txt" 2>&1
grep -q "^KEYROTATION_LISTEN=0.0.0.0:$next_port$" "$config"
sed -i "s#http://127[.]0[.]0[.]1:4233/#http://127.0.0.1:$next_port/#g" "$RK_RESUME_FILE"
RK_URL=http://127.0.0.1:$next_port/
export RK_URL
scenario resume after-port-change
pid=$(systemctl show "$unit" -p MainPID --value)
systemctl kill --kill-whom=main --signal=SIGKILL "$unit"
for ((i=0;i<100;i++)); do
  new_pid=$(systemctl show "$unit" -p MainPID --value)
  if [[ $new_pid != 0 && $new_pid != "$pid" ]] && ss -H -lntp "sport = :$next_port" | grep -q "pid=$new_pid,"; then break; fi
  sleep 0.1
 done
[[ $new_pid != 0 && $new_pid != "$pid" ]]
pass 'installed unit automatically restarts after SIGKILL'
scenario resume after-crash
# An occupied target port must roll back to the previous working installation.
busy_port=$("$probe" port)
"$binary" init --data-dir "$work/blocker" --username admin --password-stdin < "$work/creds/admin" > "$report/blocker.txt"
"$binary" serve --data-dir "$work/blocker" --listen "127.0.0.1:$busy_port" --public-url "http://127.0.0.1:$busy_port/" >> "$report/blocker.txt" 2>&1 &
blocker=$!
for ((i=0;i<100;i++)); do
  ss -H -lntp "sport = :$busy_port" | grep -q "pid=$blocker," && break
  sleep 0.1
 done
old_env=$(sha256sum "$config" | cut -d' ' -f1)
if bash "$installer" "${common[@]}" --port "$busy_port" --public-url "http://127.0.0.1:$busy_port/" < /dev/null > "$report/rollback.txt" 2>&1; then exit 1; fi
[[ $(sha256sum "$config" | cut -d' ' -f1) == "$old_env" ]]
systemctl is-active --quiet "$unit"
systemctl is-enabled --quiet "$unit"
pass 'occupied port fails installation and restores previous enabled/running service and config'
scenario resume after-rollback
# TLS installation must copy readable cert/key files and survive a plain reinstall.
mkdir "$work/tls"
openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes -keyout "$work/tls/ca.key" -out "$work/tls/ca.pem" -subj /CN=keyrotation-installer-ca >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$work/tls/server.key" -out "$work/tls/server.csr" -subj /CN=127.0.0.1 >/dev/null 2>&1
printf 'subjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' > "$work/tls/san.cnf"
openssl x509 -req -in "$work/tls/server.csr" -CA "$work/tls/ca.pem" -CAkey "$work/tls/ca.key" -CAcreateserial -days 1 -sha256 -out "$work/tls/server.pem" -extfile "$work/tls/san.cnf" >/dev/null 2>&1
bash "$installer" "${common[@]}" --public-url "https://127.0.0.1:$next_port/" --tls-cert "$work/tls/server.pem" --tls-key "$work/tls/server.key" < /dev/null > "$report/https-install.txt" 2>&1
[[ $(stat -c %U "$work/etc/keyrotation-server/server.key") == root && $(stat -c %G "$work/etc/keyrotation-server/server.key") == "$account" && $(stat -c %a "$work/etc/keyrotation-server/server.key") == 640 ]]
RK_URL=https://127.0.0.1:$next_port/ RK_CA_FILE=$work/tls/ca.pem RK_CONTENT_PASS_FILE=$RK_NEW_PASS_FILE scenario https installer-https
old_env=$(sha256sum "$config" | cut -d' ' -f1)
bash "$installer" "${common[@]}" < /dev/null > "$report/https-reinstall.txt" 2>&1
[[ $(sha256sum "$config" | cut -d' ' -f1) == "$old_env" ]]
pass 'HTTPS reinstall preserves URL, TLS paths and root-owned group-readable private key'
RK_URL=https://127.0.0.1:$next_port/ RK_CA_FILE=$work/tls/ca.pem RK_CONTENT_PASS_FILE=$RK_NEW_PASS_FILE scenario https after-https-reinstall
systemctl stop "$unit"
"$installed" check --data-dir "$data" > "$report/final-check.txt"
if grep -rF -f "$work/creds/admin" -f "$work/creds/content" -f "$work/creds/new-content" "$report"; then echo 'Secret leaked to report'; exit 1; fi
pass 'final integrity check passes and generated passwords are absent from reports'
