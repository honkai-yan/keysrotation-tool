#!/usr/bin/env bash
# One-command systemd installation. No administrator password is stored.
set -euo pipefail
umask 077
repo=$(cd "$(dirname "$0")/.." && pwd)
script=$repo/scripts/install-service.sh
original=("$@")
public_url= port= binary= username=admin password_stdin=0
service=keyrotation-server account=keyrotation prefix= cert= key=
usage() {
  cat <<'EOF'
Usage: bash scripts/install-service.sh [--public-url http://HOST:4233/] [--port 4233]
       [--binary PATH] [--username admin] [--password-stdin]
       [--tls-cert PEM --tls-key PEM]

Defaults: dedicated user keyrotation, IPv4 0.0.0.0:4233, service keyrotation-server.
Without --binary, build the release server if needed (before sudo when possible).
First installation prompts for the API URL and administrator password.
Existing databases, identity keys and configuration are retained on reinstall.
--password-stdin reads one password line only when initializing a new database.

Isolation/advanced: --install-root ABSOLUTE_PATH --service-name NAME --user NAME
A nonempty install root requires an explicit nondefault service name and user.
EOF
}
fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }
while (($#)); do
  case $1 in
    -h|--help) usage; exit 0 ;;
    --password-stdin) password_stdin=1; shift ;;
    --public-url|--port|--binary|--username|--tls-cert|--tls-key|--install-root|--service-name|--user)
      (($# >= 2)) || fail "$1 needs a value"
      case $1 in
        --public-url) public_url=$2 ;; --port) port=$2 ;; --binary) binary=$2 ;;
        --username) username=$2 ;; --tls-cert) cert=$2 ;; --tls-key) key=$2 ;;
        --install-root) prefix=$2 ;; --service-name) service=$2 ;; --user) account=$2 ;;
      esac
      shift 2 ;;
    *) fail "Unknown option: $1" ;;
  esac
done
[[ $(uname -s) == Linux ]] || fail 'Run this script on the Linux server (or inside WSL Debian).'
[[ $service =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,60}$ ]] || fail 'Invalid service name'
[[ $account =~ ^[a-z_][a-z0-9_-]{0,30}$ ]] || fail 'Invalid service user'
if [[ -n $prefix ]]; then
  [[ $prefix =~ ^/[a-zA-Z0-9_./-]+$ && $prefix != / && $prefix != *..* ]] || fail 'Invalid install root'
  [[ $service != keyrotation-server && $account != keyrotation ]] || fail 'Isolated root requires separate service name and user'
  prefix=${prefix%/}
fi
[[ ${cert:+yes} == ${key:+yes} ]] || fail 'Supply both --tls-cert and --tls-key'
if [[ -n $port ]]; then
  [[ $port =~ ^[0-9]{1,5}$ ]] && ((10#$port >= 1 && 10#$port <= 65535)) || fail 'Port must be 1..65535'
  port=$((10#$port))
fi
if [[ -z $binary ]]; then
  target_dir=$(realpath -m "${CARGO_TARGET_DIR:-$repo/target}")
  binary=$target_dir/release/keyrotation-server
  if [[ ! -x $binary ]]; then
    printf 'Building release server as the invoking user...\n'
    if [[ $EUID == 0 && -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
      build_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
      runuser -u "$SUDO_USER" -- env CARGO_TARGET_DIR="$target_dir" "$build_home/.cargo/bin/cargo" build --release --locked --manifest-path "$repo/Cargo.toml" -p keyrotation-server
    else
      export PATH="$HOME/.cargo/bin:$PATH"
      command -v cargo >/dev/null || fail 'Install Rust/Cargo or pass --binary /path/to/keyrotation-server'
      CARGO_TARGET_DIR="$target_dir" cargo build --release --locked --manifest-path "$repo/Cargo.toml" -p keyrotation-server
    fi
  fi
fi
binary=$(realpath "$binary")
[[ -f $binary && -x $binary ]] || fail "Missing executable: $binary"
if [[ $EUID != 0 ]]; then
  exec sudo bash "$script" "${original[@]}" --binary "$binary"
fi
[[ $(ps -p 1 -o comm=) == systemd ]] || fail 'PID 1 is not systemd; enable systemd before installing.'
for tool in systemctl systemd-analyze useradd groupadd runuser flock ss; do
  command -v "$tool" >/dev/null || fail "Missing required command: $tool"
done
exec 9>"/run/lock/$service.install.lock"
flock -n 9 || fail 'Another installer is already running for this service'
unit=$service.service
dest=$prefix/usr/local/bin/keyrotation-server
launcher=$prefix/usr/local/libexec/keyrotation-server-service
config_dir=$prefix/etc/keyrotation-server
config=$config_dir/server.env
data=$prefix/var/lib/keyrotation-server
unit_file=/etc/systemd/system/$unit
for path in "$prefix/usr" "$prefix/usr/local" "$prefix/usr/local/bin" "$prefix/usr/local/libexec" "$prefix/etc" "$config_dir" "$config" "$prefix/var" "$prefix/var/lib" "$data" "$unit_file" "$dest" "$launcher" "$data/ptoolkit_keys.db" "$data/identity.key"; do
  [[ ! -L $path ]] || fail "Refusing symbolic-link installation target: $path"
done
read_env() { sed -n "s/^$1=//p" "$config" | tail -1; }
if [[ -f $config ]]; then
  saved_data=$(read_env KEYROTATION_DATA_DIR)
  [[ -z $saved_data || $saved_data == "$data" ]] || fail 'Existing config uses another data directory; keep using the manual deployment path.'
  [[ -n $public_url ]] || public_url=$(read_env KEYROTATION_PUBLIC_URL)
  if [[ -z $port ]]; then
    saved_listen=$(read_env KEYROTATION_LISTEN)
    port=${saved_listen##*:}
  fi
fi
port=${port:-4233}
[[ $port =~ ^[0-9]{1,5}$ ]] && ((10#$port >= 1 && 10#$port <= 65535)) || fail 'Invalid saved port'
port=$((10#$port))
if [[ -z $public_url ]]; then
  [[ -r /dev/tty && $password_stdin == 0 ]] || fail 'Noninteractive installation needs --public-url'
  read -rp "Client API URL (for example http://192.168.1.100:$port/): " public_url </dev/tty
fi
# Keep EnvironmentFile values literal, never source them as root shell code.
[[ $public_url =~ ^https?://[^[:space:]\"\'\\?#@]+$ ]] || fail 'Use an HTTP(S) URL without whitespace, credentials, query or fragment'
authority=${public_url#*://}; authority=${authority%%/*}
[[ $authority =~ ^([a-zA-Z0-9][a-zA-Z0-9.-]*|\[[a-fA-F0-9:]+\])(:[0-9]{1,5})?$ ]] || fail 'Invalid API host or port'
if [[ $authority =~ :([0-9]+)$ ]]; then
  url_port=${BASH_REMATCH[1]}
  ((10#$url_port >= 1 && 10#$url_port <= 65535)) || fail 'Invalid public URL port'
fi
[[ $authority != 0.0.0.0 && $authority != 0.0.0.0:* && $authority != '[::]' && $authority != '[::]:'* ]] || fail 'Public URL must use a reachable IP or hostname, not a wildcard address'
if [[ $public_url == https://* && -z $cert ]]; then
  [[ -f $config && -n $(read_env KEYROTATION_TLS_CERT) && -n $(read_env KEYROTATION_TLS_KEY) ]] || fail 'HTTPS needs --tls-cert and --tls-key'
fi
[[ $public_url == https://* || -z $cert ]] || fail 'TLS files require an https:// public URL'
if [[ -n $cert ]]; then
  cert=$(realpath "$cert"); key=$(realpath "$key")
  [[ -f $cert && -r $cert && -f $key && -r $key ]] || fail 'Cannot read TLS files'
fi
fresh=0
[[ -e $data/ptoolkit_keys.db ]] || fresh=1
if [[ $fresh == 1 ]]; then
  [[ ! -e $data/identity.key ]] || fail 'Identity exists without a database; refusing automatic replacement'
  if [[ $password_stdin == 1 ]]; then
    password=
    IFS= read -r password || [[ -n $password ]] || fail 'No administrator password on stdin'
  else
    [[ -r /dev/tty ]] || fail 'First install needs an administrator password; use --password-stdin in automation'
    read -rsp 'New administrator password: ' password </dev/tty; printf '\n' >/dev/tty
    read -rsp 'Repeat administrator password: ' repeated </dev/tty; printf '\n' >/dev/tty
    [[ $password == "$repeated" ]] || fail 'Passwords do not match'
    unset repeated
  fi
  [[ -n $password ]] || fail 'Administrator password cannot be empty'
else
  [[ -f $data/ptoolkit_keys.db && -f $data/identity.key ]] || fail 'Existing database or identity is incomplete'
fi
if id "$account" >/dev/null 2>&1; then
  [[ $(id -u "$account") != 0 ]] || fail 'Service user cannot be root'
  entry=$(getent passwd "$account")
  [[ $(cut -d: -f6 <<<"$entry") == "$data" && $(cut -d: -f7 <<<"$entry") =~ /(nologin|false)$ ]] || fail 'Existing account is not the expected dedicated service user'
fi
stage=$(mktemp -d /var/tmp/keyrotation-install.XXXXXX)
targets=("$dest" "$launcher" "$config" "$unit_file")
if [[ -n $cert ]]; then targets+=("$config_dir/server.pem" "$config_dir/server.key"); fi
for i in "${!targets[@]}"; do
  [[ ! -L ${targets[i]} ]] || fail 'Refusing a symbolic-link deployment file'
  if [[ -e ${targets[i]} ]]; then cp -p "${targets[i]}" "$stage/old-$i"; fi
done
was_active=0; was_enabled=0; deploying=0
systemctl is-active --quiet "$unit" && was_active=1
systemctl is-enabled --quiet "$unit" 2>/dev/null && was_enabled=1
finish() {
  local result=$?
  trap - EXIT
  unset password repeated
  if ((result != 0 && deploying)); then
    systemctl stop "$unit" >/dev/null 2>&1 || true
    systemctl disable "$unit" >/dev/null 2>&1 || true
    for i in "${!targets[@]}"; do
      if [[ -f $stage/old-$i ]]; then cp -p "$stage/old-$i" "${targets[i]}"; else rm -f "${targets[i]}"; fi
    done
    systemctl daemon-reload
    systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    ((was_enabled == 0)) || systemctl enable "$unit" >/dev/null 2>&1 || true
    ((was_active == 0)) || systemctl start "$unit" >/dev/null 2>&1 || true
    printf 'Installation failed; original service files restored. Database and identity were retained.\n' >&2
  fi
  rm -rf -- "$stage"
  exit "$result"
}
trap finish EXIT
# Stage binary before stopping: --binary may be the currently installed path.
cp "$binary" "$stage/server"
deploying=1
if ((was_active)); then systemctl stop "$unit"; else systemctl stop "$unit" >/dev/null 2>&1 || true; fi
if ! id "$account" >/dev/null 2>&1; then
  getent group "$account" >/dev/null || groupadd --system "$account"
  useradd --system --gid "$account" --home-dir "$data" --no-create-home --shell /usr/sbin/nologin "$account"
fi
group=$(id -gn "$account")
install -d -o root -g root -m 755 "$prefix/usr/local/bin" "$prefix/usr/local/libexec"
install -d -o root -g "$group" -m 750 "$config_dir"
install -d -o "$account" -g "$group" -m 700 "$data"
atomic_install() {
  local source=$1 target=$2 mode=$3 owner=${4:-root} target_group=${5:-root} temporary
  temporary=$(mktemp "$target.install.XXXXXX")
  install -o "$owner" -g "$target_group" -m "$mode" "$source" "$temporary"
  mv -fT "$temporary" "$target"
}
atomic_install "$stage/server" "$dest" 755
atomic_install "$repo/scripts/keyrotation-server-service.sh" "$launcher" 755
if [[ $fresh == 1 ]]; then
  printf '%s' "$password" | runuser -u "$account" -- "$dest" init --data-dir "$data" --username "$username" --password-stdin
  unset password
else
  chown "$account:$group" "$data/ptoolkit_keys.db" "$data/identity.key"
  chmod 600 "$data/ptoolkit_keys.db" "$data/identity.key"
fi
runuser -u "$account" -- "$dest" check --data-dir "$data"
runuser -u "$account" -- "$dest" public-key --data-dir "$data" > "$stage/public-key"
if [[ -f $config ]]; then
  grep -vE '^KEYROTATION_(BINARY|DATA_DIR|LISTEN|PUBLIC_URL)=' "$config" > "$stage/env" || true
else
  : > "$stage/env"
fi
if [[ -n $cert ]]; then
  grep -vE '^KEYROTATION_TLS_(CERT|KEY)=' "$stage/env" > "$stage/env-tls" || true
  mv "$stage/env-tls" "$stage/env"
  atomic_install "$cert" "$config_dir/server.pem" 640 root "$group"
  atomic_install "$key" "$config_dir/server.key" 640 root "$group"
  printf 'KEYROTATION_TLS_CERT=%s\nKEYROTATION_TLS_KEY=%s\n' "$config_dir/server.pem" "$config_dir/server.key" >> "$stage/env"
fi
printf 'KEYROTATION_BINARY=%s\nKEYROTATION_DATA_DIR=%s\nKEYROTATION_LISTEN=0.0.0.0:%s\nKEYROTATION_PUBLIC_URL=%s\n' "$dest" "$data" "$port" "$public_url" >> "$stage/env"
atomic_install "$stage/env" "$config" 600
sed -e "s|^User=.*|User=$account|" -e "s|^Group=.*|Group=$group|" \
    -e "s|^WorkingDirectory=.*|WorkingDirectory=$data|" \
    -e "s|^Environment=.*|Environment=KEYROTATION_DATA_DIR=$data|" \
    -e "s|^EnvironmentFile=.*|EnvironmentFile=$config|" \
    -e "s|^ExecStart=.*|ExecStart=$launcher|" \
    "$repo/deploy/systemd/keyrotation-server.service" > "$stage/$unit"
if [[ -n $prefix ]]; then
  sed -i '/^StateDirectory=/d; /^StateDirectoryMode=/d' "$stage/$unit"
  sed -i "/^ProtectSystem=/a ReadWritePaths=$data" "$stage/$unit"
fi
atomic_install "$stage/$unit" "$unit_file" 644
systemd-analyze verify "$unit_file"
systemctl daemon-reload
systemctl reset-failed "$unit" >/dev/null 2>&1 || true
systemctl enable --now "$unit"
ready=0
for ((i=0;i<100;i++)); do
  pid=$(systemctl show "$unit" -p MainPID --value)
  if [[ $pid != 0 ]] && systemctl is-active --quiet "$unit" \
      && ss -H -lntp "sport = :$port" | grep -q "pid=$pid,"; then ready=1; break; fi
  sleep 0.1
done
[[ $ready == 1 ]] || fail "Service did not become ready; inspect journalctl -u $unit"
printf '\nInstalled %s as user %s\nListening: 0.0.0.0:%s\nClient API URL: %s\nData: %s\nServer public key: ' "$unit" "$account" "$port" "$public_url" "$data"
cat "$stage/public-key"
printf 'Manage: sudo systemctl {status|restart|stop} %s\nLogs: sudo journalctl -u %s -f\n' "$unit" "$unit"
