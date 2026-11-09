#!/usr/bin/env bash
# 真实旧库端到端验证：导入真实 ptoolkit_keys.db 后跑通四条链路。
#   1) real    —— 导入保真与只读校验（绝不写入该实例）
#   2) sandbox —— 独立空实例上的全部写路径（限额、幂等、后提交覆盖、轮换）
#   3) resume  —— 服务端重启后的会话与 operation 恢复
#   4) https   —— TLS 明文 RPC 通道与 CA 信任校验
#
# 用法：scripts/real-run.sh [场景名...]，不带参数时依次跑完四个场景。
# 所有数据目录、口令和证书都落在被 gitignore 的目录里，可安全重复执行。

set -uo pipefail
cd "$(dirname "$0")/.."

REAL_DIR=server-data/real
SANDBOX_DIR=server-data/sandbox
LEGACY_DB=.local/ptoolkit_keys.db
WORK_DIR=.local/e2e
CRED_DIR=.local/creds
REAL_URL=http://127.0.0.1:8080/
SANDBOX_URL=http://127.0.0.1:8081/
HTTPS_URL=https://127.0.0.1:8443/
BIN=target/debug/keyrotation-server
EXAMPLE=target/debug/examples/real_run

mkdir -p "$WORK_DIR" "$CRED_DIR"

log() { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }

fail_all=0
results=()

gen_pass() {
  local file=$1
  if [[ ! -s $file ]]; then
    (umask 077; openssl rand -hex 16 > "$file"; echo >> "$file")
    chmod 600 "$file"
    note "已生成口令 $file"
  fi
}

wait_port() {
  local host=$1 port=$2 tries=0
  while (( tries < 100 )); do
    if nc -z -w1 "$host" "$port" 2>/dev/null; then return 0; fi
    if [[ -n ${3:-} ]] && ! kill -0 "$3" 2>/dev/null; then
      echo "  服务进程 $3 已退出，见日志"; return 1
    fi
    sleep 0.1; (( tries += 1 ))
  done
  echo "  端口 $host:$port 未就绪"; return 1
}

start_server() {
  local name=$1 dir=$2 listen=$3 public_url=$4
  shift 4
  local logfile="$WORK_DIR/serve-$name.log"
  : > "$logfile"
  nohup "$BIN" serve --data-dir "$dir" --listen "$listen" --public-url "$public_url" \
    "$@" >> "$logfile" 2>&1 &
  echo $! > "$WORK_DIR/serve-$name.pid"
  disown 2>/dev/null || true
  local host=${listen%%:*} port=${listen##*:}
  wait_port "$host" "$port" "$!" || { tail -5 "$logfile"; return 1; }
  note "$name 已监听 $listen ($public_url)，pid $(cat "$WORK_DIR/serve-$name.pid")"
}

stop_server() {
  local name=$1
  local pidfile="$WORK_DIR/serve-$name.pid"
  [[ -f $pidfile ]] || return 0
  local pid
  pid=$(cat "$pidfile")
  if kill -0 "$pid" 2>/dev/null; then kill "$pid" 2>/dev/null; fi
  local tries=0
  while kill -0 "$pid" 2>/dev/null && (( tries < 50 )); do sleep 0.1; (( tries += 1 )); done
  rm -f "$pidfile"
  note "$name 已停止"
}

run_scenario() {
  local name=$1
  shift
  log "场景 $name"
  if env "$@" "$EXAMPLE" "$name" 2>&1 | tee "$WORK_DIR/$name.txt"; then
    results+=("$name 通过")
  else
    results+=("$name 失败（见 $WORK_DIR/$name.txt）")
    fail_all=1
  fi
}

log "构建"
cargo build --locked -p keyrotation-server 2>&1 | tail -2
cargo build --locked --example real_run 2>&1 | tail -2
[[ -x $BIN && -x $EXAMPLE ]] || { echo "  构建产物缺失"; exit 1; }

if [[ ! -f $LEGACY_DB ]]; then
  echo "  未找到旧库 $LEGACY_DB"; exit 1
fi
LEGACY_BEFORE=$(shasum -a 256 "$LEGACY_DB" | cut -d' ' -f1)
note "旧库摘要 $LEGACY_BEFORE"

# 已存在的数据目录先归档，保证每次从干净的库开始。
STAMP=$(date +%Y%m%d-%H%M%S)
for dir in "$REAL_DIR" "$SANDBOX_DIR"; do
  if compgen -G "$dir/*.db" > /dev/null; then
    archive="$WORK_DIR/archive-$STAMP-$(basename "$dir")"
    mv "$dir" "$archive"
    note "旧数据目录已归档到 $archive"
  fi
done

REAL_PASS=$CRED_DIR/real-admin.pass
SANDBOX_PASS=$CRED_DIR/sandbox-admin.pass
KEY_A=$CRED_DIR/sandbox-content.pass
KEY_B=$CRED_DIR/sandbox-new.pass
for file in "$REAL_PASS" "$SANDBOX_PASS" "$KEY_A" "$KEY_B"; do gen_pass "$file"; done

stop_server real
stop_server sandbox
stop_server sandbox-https

log "初始化真实实例（导入旧库）与沙箱实例"
"$BIN" import --data-dir "$REAL_DIR" --source "$LEGACY_DB" \
  --username admin --password-stdin < "$REAL_PASS" | tee "$WORK_DIR/import.txt" || exit 1
"$BIN" init --data-dir "$SANDBOX_DIR" --username admin --password-stdin \
  < "$SANDBOX_PASS" | tee -a "$WORK_DIR/import.txt" || exit 1
"$BIN" check --data-dir "$REAL_DIR"
"$BIN" check --data-dir "$SANDBOX_DIR"

REAL_KEY=$("$BIN" public-key --data-dir "$REAL_DIR")
SANDBOX_KEY=$("$BIN" public-key --data-dir "$SANDBOX_DIR")
note "真实实例公钥 $REAL_KEY"
note "沙箱实例公钥 $SANDBOX_KEY"

start_server real "$REAL_DIR" 127.0.0.1:8080 "$REAL_URL" || exit 1
start_server sandbox "$SANDBOX_DIR" 127.0.0.1:8081 "$SANDBOX_URL" || exit 1

if (( $# > 0 )); then WANT=("$@"); else WANT=(real sandbox resume https); fi

for scenario in "${WANT[@]}"; do
  case $scenario in
    real)
      run_scenario real RK_URL=$REAL_URL RK_PUBKEY=$REAL_KEY \
        RK_FOREIGN_PUBKEY=$SANDBOX_KEY RK_USER=admin RK_PASS_FILE=$REAL_PASS \
        RK_LEGACY_DB=$LEGACY_DB
      ;;
    sandbox)
      run_scenario sandbox RK_URL=$SANDBOX_URL RK_PUBKEY=$SANDBOX_KEY \
        RK_USER=admin RK_PASS_FILE=$SANDBOX_PASS RK_CONTENT_PASS_FILE=$KEY_A \
        RK_NEW_PASS_FILE=$KEY_B RK_RESUME_FILE=$WORK_DIR/resume.json
      ;;
    resume)
      stop_server sandbox
      start_server sandbox "$SANDBOX_DIR" 127.0.0.1:8081 "$SANDBOX_URL" || continue
      run_scenario resume RK_URL=$SANDBOX_URL RK_PUBKEY=$SANDBOX_KEY \
        RK_USER=admin RK_RESUME_FILE=$WORK_DIR/resume.json
      ;;
    https)
      tls="$WORK_DIR/tls"
      mkdir -p "$tls"
      if [[ ! -s "$tls/ca.pem" ]]; then
        (umask 077
         cd "$tls"
         openssl req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes \
           -keyout ca.key -out ca.pem -subj "/CN=rust-keyrotation-e2e-ca" 2>/dev/null
         openssl req -newkey rsa:2048 -nodes -keyout server.key \
           -out server.csr -subj "/CN=127.0.0.1" 2>/dev/null
         printf 'subjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' > san.cnf
         openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -days 2 \
           -sha256 -out server.pem -extfile san.cnf 2>/dev/null)
        note "已生成一次性 CA 与服务端证书"
      fi
      stop_server sandbox
      start_server sandbox-https "$SANDBOX_DIR" 127.0.0.1:8443 "$HTTPS_URL" \
        --tls-cert "$tls/server.pem" --tls-key "$tls/server.key" || continue
      run_scenario https RK_URL=$HTTPS_URL RK_CA_FILE="$tls/ca.pem" \
        RK_USER=admin RK_PASS_FILE=$SANDBOX_PASS RK_CONTENT_PASS_FILE=$KEY_B
      ;;
    *)
      echo "  未知场景 $scenario"; fail_all=1 ;;
  esac
done

log "收尾检查"
stop_server real
stop_server sandbox
stop_server sandbox-https
"$BIN" check --data-dir "$REAL_DIR"
"$BIN" check --data-dir "$SANDBOX_DIR"
LEGACY_AFTER=$(shasum -a 256 "$LEGACY_DB" | cut -d' ' -f1)
if [[ $LEGACY_BEFORE == "$LEGACY_AFTER" ]]; then
  note "旧库摘要未变化，导入确实是非破坏性的"
else
  note "旧库摘要发生变化：$LEGACY_AFTER"; fail_all=1
fi

log "汇总"
for line in ${results[@]+"${results[@]}"}; do note "$line"; done
note "口令文件：${CRED_DIR}/（600 权限）"
note "服务日志：$WORK_DIR/serve-*.log"
exit $fail_all
