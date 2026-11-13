# 密钥轮换小工具

Rust / gpui-kit 桌面客户端，加独立 Rust API 服务端。服务端直接持有单个 `ptoolkit_keys.db`；客户端只获取描述列表和按需请求的单条内容密文，不下载、保存或上传整库。

条目内容由客户端使用 Argon2id + AES-256-GCM 加解密，内容口令及明文不发送给服务端。HTTP 使用预先导入服务端公钥的 Noise 通道；HTTPS 使用正常校验证书的 TLS，不再额外使用 Noise。描述在服务端数据库中为明文。

桌面客户端以 macOS 为交付目标，构建为普通二进制；客户端状态与 GUI 也在 Windows 本机回归。服务端增加 Linux/systemd 启动示例，并在 WSL2 Debian 隔离验收；备份与其它部署方式仍未实现。原「桌面客户端经 WebDAV 同步整库」的实现已于 2026-11-10 从仓库中删除，包括 WebDAV 协议代码、内存 SQLite、v1 配置迁移兼容层与 OpenList 凭据模板 `.env.example`；仓库内只剩新 API 这一套客户端。

## 构建与检查

使用 Rust stable（本机验证 1.96.0）、macOS 的 Xcode Command Line Tools，运行：

```sh
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all --check
```

日常 `cargo run` 运行桌面程序。构建缓存继续保留在 `target/`，使用 Cargo 默认增量编译；不例行执行 `cargo clean`，不再通过 `dist/` 交付。

## 启动本机服务

先显式创建服务端数据目录、schema 与管理员。以下命令从已有环境变量取登录密码，经 stdin 提供给程序；请通过受控输入或密码管理工具设置该变量，不把真实密码写入命令参数或提交到仓库。

```sh
printf '%s' "$KEYROTATION_ADMIN_PASSWORD" | cargo run -p keyrotation-server -- init --data-dir ./server-data --username admin --password-stdin
cargo run -p keyrotation-server -- check --data-dir ./server-data
cargo run -p keyrotation-server -- public-key --data-dir ./server-data
cargo run -p keyrotation-server -- serve --data-dir ./server-data --listen 127.0.0.1:8080 --public-url http://127.0.0.1:8080/
```

`init` 不覆盖已有库，不创建默认密码。账号密码与内容加密口令相互独立。`public-key` 输出可通过可信途径交给客户端的服务端公钥；对应的 `identity.key` 保存在服务端数据目录内，限制为 600 权限，不应删除或重新生成来绕过公钥不匹配。

`--public-url` 必须与客户端填写的规范化 API 基础地址一致，包含非根基础路径时也必须一致。HTTP listener 只开放加密通道，不提供明文登录或明文 RPC。HTTPS 入口使用相同业务实现，需显式提供 `--tls-cert CERT.pem --tls-key KEY.pem`，并把公开地址设为 `https://.../`；systemd 用法见下文。

修改管理员密码使用 `reset-password --data-dir PATH --username NAME --password-stdin`，仍从重定向 stdin 输入；会撤销现有会话。管理初始化、导入及密码重置应在服务停止时操作，避免引入第二个数据库写入口。

## Linux / WSL Debian：systemd 自启动与崩溃恢复

推荐直接在 Linux 服务器的项目根目录运行 [一键安装脚本](scripts/install-service.sh)：

```bash
bash scripts/install-service.sh
```

脚本在缺少二进制时先构建 release 服务端，随后通过 sudo 安装。首次提示输入客户端使用的 API URL、管理员密码和确认密码；管理员密码只经 stdin 传给 `init`，不写入配置或日志。也可以直接指定地址：

```bash
bash scripts/install-service.sh --public-url http://192.168.1.100:4233/
```

把示例 IP 换成客户端能访问的真实地址。已有 Linux 二进制时用 `--binary ./keyrotation-server` 跳过构建；改变本机监听端口用 `--port 5233`，同时填写对应 public URL。普通用户运行时先以本人构建，再 sudo；通过 sudo 运行时尽量以原用户构建，直接 root 运行则需要该账号可用的 Cargo 或提供 `--binary`。

安装器自动创建专用非登录用户 **keyrotation**、配置 **0.0.0.0:4233**、设置目录/文件权限，安装并启用 `keyrotation-server.service`，等待真实服务 PID 监听成功，最后打印公钥及管理命令。首次数据库初始化后，内容加密库仍由客户端登录后明确初始化。

已有服务端数据目录时直接指定 `--data-dir`，例如：

```bash
bash scripts/install-service.sh --data-dir /srv/keys-data --public-url http://192.168.1.100:4233/
# 相对路径也可以，例如 --data-dir ./server-data
```

目录内必须已有 **ptoolkit_keys.db 和 identity.key**，是新 API 服务端的数据目录；旧版单客户端只有 SQLite 的旧库仍需先 import。接管前先停止原来的手动/nohup 服务进程。安装器原地使用该目录，不复制或搬迁数据、不执行 init、不重置管理员密码或生成新身份；会将数据目录权限设为 700、库和身份文件设为 600，并交给 keyrotation 用户。数据目录缺失、不完整或校验失败会直接拒绝，不会创建空库替代。

自定义路径会记录在配置里，后续再次运行安装器不必重复 `--data-dir`；未指定的地址和端口也继续沿用。`/root/...`、用户主目录下的专用子目录和带空格的路径可用（有空格时用引号），不需要放宽父目录权限。systemd 只把选定的数据目录绑定到服务内部固定路径，`KEYROTATION_HOST_DATA_DIR` 记录宿主真实路径，`KEYROTATION_DATA_DIR` 是进程内的挂载路径；二者指向同一份文件，没有整库副本。离线管理命令应在停服后由管理员针对宿主真实目录执行（例如 `sudo /usr/local/bin/keyrotation-server check --data-dir /srv/keys-data`）。

不指定数据目录的首次安装仍默认使用 `/var/lib/keyrotation-server/` 并提示创建管理员；重复安装保留数据库、身份私钥和账号。更新文件前停服并备份原部署文件，启动失败会恢复原文件及此前启用/运行状态，数据始终保留。防火墙仍需自行放行端口。

HTTPS 一次配置示例：

```bash
bash scripts/install-service.sh --public-url https://keys.example.com:4233/ --tls-cert ./server.pem --tls-key ./server.key
```

证书及私钥复制到 root 管理、keyrotation 组可读的位置。自动化首次安装可使用 `--password-stdin --username admin` 从受保护的密码文件重定向输入，不能把密码放进命令参数；`--help` 显示全部选项。

<details>
<summary>手动安装步骤（可选）</summary>

使用 [服务单元](deploy/systemd/keyrotation-server.service)、[启动脚本](scripts/keyrotation-server-service.sh) 和 [环境配置示例](deploy/systemd/server.env.example)。以 Bash 执行以下命令，从项目根目录安装；服务以专用非 root 用户运行，默认监听所有 IPv4 接口的 **4233** 端口，数据在 `/var/lib/keyrotation-server/ptoolkit_keys.db`。

```bash
cargo build --release --locked -p keyrotation-server
id keyrotation >/dev/null 2>&1 || sudo useradd --system --user-group --home-dir /var/lib/keyrotation-server --no-create-home --shell /usr/sbin/nologin keyrotation
sudo install -d -o root -g root -m 755 /usr/local/libexec
sudo install -m 755 target/release/keyrotation-server /usr/local/bin/keyrotation-server
sudo install -m 755 scripts/keyrotation-server-service.sh /usr/local/libexec/keyrotation-server-service
sudo install -d -o root -g keyrotation -m 750 /etc/keyrotation-server
sudo install -d -o keyrotation -g keyrotation -m 700 /var/lib/keyrotation-server
sudo install -m 600 deploy/systemd/server.env.example /etc/keyrotation-server/server.env
sudo install -m 644 deploy/systemd/keyrotation-server.service /etc/systemd/system/keyrotation-server.service
sudoedit /etc/keyrotation-server/server.env
```

把 `KEYROTATION_PUBLIC_URL` 的占位地址改成客户端实际填写的 URL，例如 `http://192.168.1.100:4233/`。`KEYROTATION_LISTEN=0.0.0.0:4233` 决定绑定接口；public URL 决定服务地址约定及 Noise 握手上下文，不能填 `0.0.0.0`。环境文件使用 systemd `EnvironmentFile` 语法，不是 shell 脚本，不存管理员密码或内容口令。

**首次安装且目标没有数据库时**显式初始化；已有库不要重复 init，迁移使用下文的 import，并在停服时操作：

```bash
read -rsp '管理员密码: ' KEYROTATION_ADMIN_PASSWORD
printf '\n'
printf '%s' "$KEYROTATION_ADMIN_PASSWORD" | sudo -u keyrotation /usr/local/bin/keyrotation-server init --data-dir /var/lib/keyrotation-server --username admin --password-stdin
unset KEYROTATION_ADMIN_PASSWORD
sudo -u keyrotation /usr/local/bin/keyrotation-server check --data-dir /var/lib/keyrotation-server
sudo -u keyrotation /usr/local/bin/keyrotation-server public-key --data-dir /var/lib/keyrotation-server
sudo systemctl daemon-reload
sudo systemctl enable --now keyrotation-server.service
```

将最后输出的公钥经可信途径录入 HTTP 客户端。初始化失败时先检查错误，不继续启动；服务运行时不会自动新建或覆盖数据库。远程访问还需放行 TCP 4233。服务文件与可执行文件由 root 管理，数据目录 700、数据库和身份私钥 600。

</details>

安装后用标准 systemctl 管理：

```bash
systemctl status keyrotation-server.service --no-pager
sudo journalctl -u keyrotation-server.service -f
sudo systemctl restart keyrotation-server.service
sudo systemctl stop keyrotation-server.service
sudo systemctl disable --now keyrotation-server.service
```

`Restart=on-failure` 在异常退出/崩溃后等待 2 秒重启；手动 stop 不重启。60 秒内最多启动 5 次，持续配置错误会停止重试；修复配置后用 `sudo systemctl reset-failed keyrotation-server.service`，再 start。HTTP 和 HTTPS 都处理 SIGTERM/SIGINT，正常停服会等待在途请求退出。启动脚本用 `exec`，systemd 管理的是服务端自身的 PID，无需 nohup。

HTTPS 时在同一环境文件中设置 `KEYROTATION_PUBLIC_URL=https://.../`、`KEYROTATION_TLS_CERT` 和 `KEYROTATION_TLS_KEY`，证书和私钥必须对 `keyrotation` 用户可读，例如 `/etc/keyrotation-server/` 内 root:keyrotation、640 权限。自签 CA 在客户端配置。修改环境文件后 restart；替换 unit 后先 daemon-reload。

WSL 中先确认 `ps -p 1 -o comm=` 为 systemd。Debian 的 `/etc/wsl.conf` 应含 `[boot]` 与 `systemd=true`；修改后需自行重启实例。`enable` 表示 **Debian 实例启动时**启动服务，不等于 Windows 开机自动启动 Debian；Windows 任务计划程序需另行配置。systemd 服务本身也不保证 WSL 实例持续存活，参见 [Microsoft WSL systemd 说明](https://learn.microsoft.com/en-us/windows/wsl/systemd)。本项目不自动修改 Windows 启动任务，也不在测试中终止整个 Debian。

## 隔离自动测试与本机实测

[测试覆盖表与边界](docs/systemd-test-coverage.md) 先列明用例；[实施记录](docs/server-implementation-validation.md) 保存结果。需要 Rust/Cargo、C 编译器、CMake、OpenSSL 命令及正在运行的 systemd。服务端不需要构建 Linux GUI：

```bash
cargo build --locked -p keyrotation-server -p keyrotation-e2e
cargo test --locked -p keyrotation-protocol -p keyrotation-transport -p keyrotation-server
sudo bash scripts/test-systemd.sh "$PWD/target/debug/keyrotation-server" "$PWD/target/debug/keyrotation-e2e" "$(id -un)"
```

脚本为每次执行建立 `/var/lib/keyrotation-e2e.*` 临时目录、随机口令、合成旧库和空库，使用回环临时端口及 `/run/systemd/system/` 的临时单元。结束时停服、禁用、删除单元与测试配置/数据库，只保留 `.local/systemd-reports/` 下的报告；不会读取真实 `.local/ptoolkit_keys.db`、生产服务目录或 `~/.rust-keyrotation`。需要 root 仅用于临时 systemd 安装/信号/清理，服务进程使用传入的普通用户。不要把生产用户名或生产实例目录作为测试参数。

从 Windows 项目目录启动本机 Debian 构建/测试，可执行：

```powershell
wsl -d Debian -- bash /mnt/e/Projects_2026/General/keysrotation-tool/scripts/wsl-build-test.sh
```

该入口只复制源码到 Debian 用户的 `~/projects/keyrotation-systemd-validation/`，不复制 `.local`、`.env`、数据库或 Windows 构建产物，并保留 Linux Cargo 缓存。随后用上述 root 测试命令指定该目录的两个构建产物。客户端和 GUI 留在 Windows 执行 `cargo test --locked --bin rust_keyrotation`。

2026-11-12 实测：WSL2 Debian 13.5 / systemd 257 / Rust 1.99.1 下服务端、协议和传输层 **29 项通过，零跳过**；Windows 客户端/GUI **25 项通过**。systemd 脚本 **21 个检查点通过**，其六个协议场景共 **120 项检查通过**（包含在流程检查点的业务汇总中，不重复累计）；覆盖启动、崩溃恢复、HTTP/HTTPS、CRUD、轮换、幂等、合成旧库导入和密码重置。自启动验证使用真实 enable 链接及独立 target 事务，没有进行 Debian 冷启动或 Windows 重启；macOS 原生实机、断电/磁盘满及 100,000 条极限负载未在此轮实测。

## 桌面使用

```sh
cargo run
```

向导中填写新服务的 API 基础地址与内容加密口令。HTTP 还须输入通过可信途径取得的服务端公钥；HTTPS 可选填受信任 CA 的 PEM 文件路径，证书错误不会被忽略。不要将旧 OpenList 的 `/dav/` 地址当作 API 地址。

登录采用单管理员、多客户端模式。客户端保存用户名和 48 小时会话 token，不保存登录密码；有效 token 自动登录，失效后要求重新登录。管理员/schema 建立后，加密库仍需由登录后的客户端明确点击“初始化”，才会创建空内容库。

| 操作 | 行为 |
| --- | --- |
| 点击遮蔽内容 | 行内加载，成功取回该条密文后在本地解密；60 秒后遮蔽并清理明文 |
| 双击描述或已解密内容 | 编辑；Enter 保存，Esc 取消；内容编辑期间冻结计时，确认后重新计时 |
| 右键已解密内容 | 复制，状态栏“复制成功”闪烁两次后保留 |
| 右键描述 | 二次确认删除；正文仍为“确定删除该密钥吗？” |
| 新增 | 成功后进入描述编辑；新增的空内容也先加密 |
| 修改内容口令 | 分批取密文、逐条重加密、服务端原子提交；确认后才更新本地口令；最终提交前可取消 |
| 修改服务器地址/端口 | 双向同步，确认地址变化后清理旧会话和界面状态，不跨地址复用公钥或会话 |
| 退出登录 | 清理本地 token、内容口令、派生密钥及查看状态，尽力撤销服务器会话 |

主页不定时轮询，启动/重连、本客户端写入及轮换成功后加载同一版本的描述快照。读取内容发现版本过时或条目已删除时清理查看/编辑/对话框并按需刷新。其他客户端的改动不主动同步。

HTTP Noise 通道在每次请求前检查寿命并按需重新握手，保留原登录 token；读取遇到通道丢失时最多自动恢复一次。写入结果未知仍查询原 `operation_id`，只有明确会话失效才要求重新登录；挂机期间不发送保活请求。

普通编辑按服务器事务的成功提交顺序覆盖指定字段：描述修改只覆盖描述，内容修改只覆盖内容。普通编辑不使用旧条目 revision 拒绝后提交覆盖；读取一致性、数据世代、key epoch 和轮换整体基线仍校验。

查看只在行内加载，写入使用全局遮罩。临时断网保留配置并清理显示明文；写请求结果未知时查询原操作编号，阻塞后续修改。结果记录过期后不会盲目重做，需明确重新加载服务器数据。轮换提交已确认但本地配置保存失败时，界面保留错误提示并提供重试保存；请保管新口令。服务器数据库缺失/损坏不会由客户端创建空库或上传本地库修复。

## 配置与限额

客户端配置为 `~/.rust-keyrotation/config.json`，版本 2；Unix 目录 700、文件 600，原子写入。内容口令和 token 仍明文保存，按已确认需求依赖本地文件权限保护；服务端只存登录密码哈希和 token 摘要。

配置只接受版本 2，不提供 v1（WebDAV 时代）配置的迁移兼容层。版本不符或字段缺失时程序报错并保持原文件不动，提示重新填写 API 地址与内容口令；旧 OpenList 账号、密码和 token 从不发给新服务。历史版本写入的 `legacy_endpoint` 键在加载时被忽略，不会再被保存。新服务公钥与可选 CA 文件按规范化 API 地址保存。

| 限额 | 数值 |
| --- | --- |
| 单条内容明文 | 32 KiB（UTF-8 字节） |
| 描述 | 4 KiB（UTF-8 字节） |
| 条目数 | 100,000 |
| 完整 RPC 明文 | 60 KiB，包括 JSON 封装、escaping 等；请求和响应均限制 |

分页和轮换按实际序列化字节处理，超限不截断。当前轮换客户端每批处理一个条目，避免持有大量明文；服务端支持多个条目的合规批次。

2026-11-13 一键安装器补充验收：独立账号/单元/数据库下 **14 个流程检查点、115 项协议业务检查通过**，覆盖默认 4233 全 IPv4、重复安装保留、端口修改、SIGKILL 恢复、端口占用回滚，以及 HTTPS 安装/重复安装。另一次缺少 release 产物的实测验证了以 sudo 原用户自动构建。服务端 29 项回归仍全通过；测试用户、服务和数据均已清理。覆盖及报告位置见 [安装器测试记录](docs/systemd-test-coverage.md#一键安装脚本覆盖2026-11-13)。

## 旧库导入

先停止仍在运行的旧版单客户端写入（该版本的代码已不在本仓库，需从历史发布或用户环境取得），由管理员通过安全途径取得旧 `ptoolkit_keys.db` 文件，再导入到尚不存在数据库的新数据目录：

```sh
printf '%s' "$KEYROTATION_ADMIN_PASSWORD" | cargo run -p keyrotation-server -- import --data-dir ./server-data --source PATH_TO_LEGACY_DB --username admin --password-stdin
```

导入只读打开源文件，验证完整性、表结构、盐/verifier、密文格式与限额，保留 ID、描述、密文和加密元数据。已有目标库不会被覆盖；超限明确列出 ID 并拒绝导入。服务端不知道内容口令，结构检查不能替代客户端实际解密验证。

仓库不再提供 `.env.example`，也没有任何代码读取 `TEST_SERVER`、`TEST_ACCOUNT`、`TEST_PASSWORD`；这些变量只属于已退役的旧 OpenList 测试环境，本机残留的 `.env` 可以自行删除。当前测试使用本机临时服务和合成数据，真实旧库端到端验证的凭据只放在被 gitignore 的 `.local/creds/`。

## 端到端自检

`scripts/real-run.sh` 用真实旧库跑通四条链路：导入后的只读保真校验、空沙箱实例上的全部写路径（限额、幂等、字段级后提交覆盖、完整轮换与冲突）、服务端重启后的会话与操作恢复、HTTPS 明文 RPC。工装是 `cargo run --example real_run --locked -- <real|sandbox|resume|https>`，由脚本注入环境变量并管理进程与证书。

```sh
./scripts/real-run.sh            # 依次跑完四个场景
./scripts/real-run.sh real https # 只跑指定场景
```

脚本每次把已有 `server-data/` 归档到 `.local/e2e/`，用 `.local/creds/` 下的口令（缺失则随机生成，600 权限）重建实例，结束停服并对两个库执行 `check`，同时校验旧库摘要未变。真实导入实例只读，所有写入都落在沙箱实例。测试秘密与日志只出现在被 gitignore 的 `.local/` 和 `server-data/`，不涉及 `~/.rust-keyrotation`。

## 代码与验证记录

- `src/`：gpui-kit UI、API 状态、内容加密、版本化配置及串行 API worker。
- `crates/protocol/`：DTO、错误码、格式限额及规范化业务请求摘要。
- `crates/transport/`：固定 Noise NK profile 和 HTTP/HTTPS 客户端。
- `crates/server/`：HTTP/TLS 入口、认证、文件 SQLite worker、幂等操作、轮换和管理 CLI。
- [M0 合同](docs/m0-contract.md)、[路线图](docs/server-migration-roadmap.md)、[实施与验证](docs/server-implementation-validation.md)。

内置中文字体和 Claude 配色继续保留；macOS 关闭窗口即退出，支持 Cmd+Q。`vendor/gpui-pre-macos` 继续保留上游许可证及 stable Rust 兼容补丁说明。
