# 服务端改造实施与验证

日期：2026-11-03，2026-11-10 补充真实旧库端到端验证。M0 合同已冻结，M1–M5 软件功能已实施；M6 已完成本机合成迁移与功能验证，并已用真实旧库 `ptoolkit_keys.db` 跑通 HTTP 与 HTTPS 两条服务端链路，桌面 GUI 原生回归与故障注入仍未验收。用户已明确延后备份、部署和其他平台交付。

本轮使用临时目录、合成账号和内容密钥；没有读取 `.env`，没有读取或改写 `~/.rust-keyrotation`、真实 WebDAV 或真实密钥库。Rust stable 1.96.0 / macOS ARM64。

## 结果

| 检查 | 结果 |
| --- | --- |
| `cargo fmt --all --check` | 通过 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 通过 |
| `cargo test --workspace --locked` | 40 passed，0 failed（含 2026-11-10 删除旧客户端兼容层后新增的配置回归） |
| `cargo build --workspace --locked` | 通过；桌面、服务端均为普通 Mach-O ARM64 二进制 |
| `git diff --check` | 通过 |
| 服务端普通依赖树 | 无 gpui-kit / egui / GUI 依赖 |
| 桌面普通依赖树 | 无 rusqlite / libsqlite3；SQLite 仅在服务端及测试 fixture 中使用 |
| 管理 CLI 冒烟 | init、check、public-key、reset-password、serve、SIGINT 停止均通过 |
| 私有数据入口 | HTTP listener 拒绝静态下载数据库及伪造代理头的明文 RPC |
| 真实旧库导入 | `import` 前后旧库 SHA-256 一致；条目 ID/描述/密文逐字节相同，salt/verifier 与旧 `meta` 一致 |
| 真实库端到端 | `scripts/real-run.sh` 四场景共 117 项断言全部通过 |

另已构建默认桌面目标，供日常 `cargo run` 复用对应的 Cargo 特性与增量缓存。保留 `target/` 和默认增量缓存；开始约 5.7 GB，本轮依赖、普通构建、测试及预览构建后约 15 GB。未执行 `cargo clean`，未删除用户缓存，未复制到 dist。暂时的预览源码与 App 包已移除，产品仍为普通二进制。旧版遗留的 dist 不作为本轮交付位置；运行使用 `cargo run` / `target/debug/`。

上游 `block 0.1.6` 仍有 Cargo future-incompatibility 提示，本轮 stable 构建和检查通过。新增直接依赖的锁定版本已按本地 Cargo 源码核对许可证和 Rust 版本；未为本轮升级 GUI 或修改全局依赖源码。

## 阶段实现

| 阶段 | 已实施内容 |
| --- | --- |
| M0 | 五组回复写回 AGENTS.md；[合同](m0-contract.md)冻结后提交覆盖、48 小时 token、断网保留配置、限额及本轮范围 |
| M1 | 根 package + workspace；协议 DTO/错误码/格式验证；独立服务端、文件 SQLite、schema v1、受限权限、有界 DB worker、显式 init、管理员管理、旧库结构导入 |
| M2 | 固定 Noise NK over HTTP、可信公钥、URL/prologue 绑定、双向顺序状态；HTTPS TLS/JSON；入口隔离、通道寿命/并发/大小限制、禁重定向 |
| M3 | 管理员登录、会话摘要和到期/撤销；meta/分页列表/按需密文/CRUD；字段补丁后提交覆盖；SQL 事务、generation/key epoch、持久操作结果和过期墓碑 |
| M4 | 配置 v2、旧 OpenList 凭据隔离、向导公钥/CA、自动 token 登录、描述列表、单条密文查看、API 写入/轮询/结果未知恢复；移除桌面内存 SQLite、WebDAV 与整库修复；2026-11-10 追加删除 v1 配置兼容层、`legacy_endpoint` 与 `.env.example`（见“旧单客户端残留清理”） |
| M5 | 逐条分批重加密、暂存、基线检查、一次原子提交、提交结果查询；提交前取消；确认后才更新本地口令，配置保存失败可重试 |
| M6 本轮部分 | 合成旧库只读导入与解密/轮换演练、本机 HTTP/HTTPS 合同与桌面 worker 验证、真实旧库导入与四条链路的脚本化端到端验证（见“真实旧库端到端验证”一节）、原生预览、CLI 和运行说明 |

当前首版技术资源限制：32 个有效登录会话、128 个 Noise 通道、16 个并发握手、64 个服务请求/DB 队列容量；通道空闲 5 分钟、绝对 1 小时；轮换空闲 1 小时、绝对 24 小时。实现常量不通过不可信网络协商降级。

## 验证覆盖

40 项测试分别为协议 4、服务端存储/worker/入口 12、真实网络业务合同 3、通道 4、桌面状态/配置/加密/GPUI 17。组件测试与真实网络测试分开执行，不把离线 fixture 当作真实服务器证明。

- **存储**：显式初始化、重启读取、schema/权限、缺失/损坏/过新库不覆盖、运行中删除/替换/头部损坏、已有条目但加密元数据缺失时禁止重新初始化、事务回滚、并发调用都落在同一 DB 线程。
- **通道**：错误公钥/基础路径、双向认证加密、篡改、重放、乱序、错方向/会话、请求编号/版本、大小和通道寿命边界；HTTP 不开放明文 RPC，HTTPS 不开放 Noise 路由。
- **真实网络**：临时 listener 上的 Noise HTTP 和校验证书 HTTPS 使用同一合同；不可信证书拒绝。两个独立客户端分别登录、普通同字段后提交覆盖、单客户端退出不撤销另一会话、按需读取、幂等写入、旧 epoch 拒绝。
- **结果恢复**：已提交响应视为丢失后，关闭/重开 repository 能查询和重试原操作；改变参数拒绝、结果到期拒绝重做；客户端保留原编号并清理明文，丢弃旧 epoch 返回值；本地提交后的刷新若还观察到远端变化，也会清理旧查看和编辑状态。
- **轮换**：暂存时正式库不变，半批失败回滚、不完整提交拒绝、并发普通写入使轮换冲突、全部提交后同编号重试仍返回原结果；空库、多批和 Unicode 内容；确认前取消保持旧密钥；本地配置保存失败保留已确认密钥并能重新保存。
- **桌面 worker**：真实本机服务完成登录、显式初始化、按需查看、描述/内容编辑、新增删除、轮换及退出；测试配置目录只产生 config.json，不产生数据库。
- **迁移**：合成旧 meta/entries 数据库保留 ID 42/99、描述、密文、salt/verifier；源字节不变；新客户端能解密，取消一次轮换后仍是旧口令，再完成多批轮换后两条内容仍可解密。超限/结构不符拒绝安装目标库。
- **GPUI**：真实组件事件覆盖 Enter/Esc、复制前置条件、独立倒计时、明文清理、远端替换、hover 重绘、遮罩及 Cmd+Q。

## 原生预览

临时 example 使用同一份 UI 与 `App::test_vault`，从不调用 `App::new` 或真实配置 load/save；cfg_path 为 None，测试 fixture 轮询暂停。没有连接真实服务器。

已通过 computer use 核对：主页中文、两列表格、固定底部状态栏；点击遮蔽单元格显示合成明文、行高亮；双击进入原生输入框，Enter 保存合成修改，Esc 取消后恢复原值；HTTP 向导的可信服务端公钥字段完整可读。未操作系统剪贴板。

Cmd+Q 后通过仅匹配本次临时预览路径的进程检查确认退出，两次预览均无残留进程。窗口共享层后来未暴露原生关闭按钮，因此未完成直接点击该按钮的验收；关闭回调仍保留。临时源码和 App 包随后删除。

## 真实旧库端到端验证（2026-11-10）

用户把真实旧库放到 `.local/ptoolkit_keys.db`（20,480 字节，SHA-256 `627ed9f0771e14ddb41baa7a0b43370b8ec004319be5c20245dfabbdc80c1c7d`，8 条条目）后，本轮改为对真实数据做一次完整实跑。按用户确认：管理员口令由本次验证随机生成并告知；真实导入实例保持只读，所有写入测试落在另一个初始化为空的沙箱实例；入口先 HTTP+Noise 再 HTTPS；本轮不启动 GUI，用脚本驱动协议层。

工装为 [examples/real_run.rs](../examples/real_run.rs)（1,580 行）与 [scripts/real-run.sh](../scripts/real-run.sh)（203 行）。脚本自带生命周期：构建 → 归档旧数据目录 → `import` 真实库与 `init` 沙箱库 → 起 HTTP 服务 → 依次跑四个场景 → 停服并对两个库执行 `check`。场景口令、公钥、证书和日志分别落在被 gitignore 的 `.local/creds/`（600 权限）、`server-data/` 与 `.local/e2e/`，重复执行不留残余，也不写入 `~/.rust-keyrotation`。

- **real，37 项**：连接 `127.0.0.1:8080`，`initialized=true`，generation/server_id 为 32 位十六进制；`vault_meta` 的 salt、verifier 与旧库 `meta` 逐字节一致，KDF 为 argon2id/19/19456/2/1/32；分页取回 8 条，ID、描述、密文与旧库逐字节相同，revision/key_epoch 全为 1，翻页期间 vault_revision 不变。负例覆盖未登录 `Unauthenticated`、错口令 `InvalidCredentials`、过期 expected_revision `RevisionChanged`、不存在条目 `NotFound`、错世代 `GenerationChanged`、limit 0/101 `InvalidRequest`、超 60 KiB 整包在客户端即 `LimitExceeded` 且服务端零写入。通道侧确认缺公钥拒绝建连、拿别的实例公钥握手失败、非法 endpoint 被拒；HTTP 监听器对 `/api/v1/rpc` 返回 404 且伪造 `X-Forwarded-Proto/Host` 无效。场景全程只读，结束后 `entries` 计数与 vault_revision 未变，旧库文件摘要未变。
- **sandbox，63 项**：在空实例上完成 `vault.initialize` 及其幂等重放、参数不同复用编号 `OperationMismatch`、重复初始化 `AlreadyInitialized`；描述 4 KiB 边界通过、4 KiB+1 拒绝 `LimitExceeded`，32 KiB 明文加密后整包仍在 60 KiB 内且能解密；字段级后提交覆盖（只改描述不动密文、只改内容不动描述、同字段后者胜出）；删除后旧更新不复活、内容读取 `NotFound`，而已提交的删除操作仍可查询；错 key_epoch、错 generation、`valid_until` 过早或过晚分别给出 `KeyEpochChanged`、`GenerationChanged`、`OperationExpired`。轮换演练三段：部分暂存后 commit `RotationIncomplete` 并 abort 为 `aborted`；并发普通写入打破基线后读块/暂存/提交全部 `RotationConflict`，作业被持久改写为 `conflicted` 终态且 `rotation.status` 与重复 `rotation.abort` 都如实返回它、加密元数据未变；完整多步 begin→read_batch→stage→commit 使 key_epoch 加一、换成新 salt/verifier，全部条目可用新密钥解密、旧密钥失效、条目 key_epoch 同步、明文内容不变，旧 key_epoch 写入随后被拒。另有第二客户端独立会话、单客户端登出不影响另一会话。
- **resume，9 项**：对沙箱实例发 SIGTERM 后重启，旧会话 token 仍有效（48 小时持久化），generation、key_epoch、server_id 与条目全部保持，内容仍可用轮换后的密钥解密；已提交 operation 重启后仍可查询且不会重复执行；未知 job_id 返回 `NotFound`。
- **https，8 项**：用一次性自签 CA 与 `IP:127.0.0.1` SAN 服务端证书起 `https://127.0.0.1:8443/`；不导入该 CA 时握手失败，不静默降级；HTTPS 模式无需预导入 Noise 公钥，meta、分页列表、写入后解密、删除全部正常；TLS 端口上 Noise 路由不存在，明文 HTTP 打该端口被拒绝。

一处结论修正：先前阅读 `dispatch.rs` 时判断 `RotationState::Conflicted` 不可达，实跑证伪。真正落笔的是 `store.rs` 的 `advance_revision()`，它在每次推进 revision 的写入事务里把基线已变的 staging 作业改写为 `conflicted`。该语义已补写进 [M0 合同](m0-contract.md)的轮换限额条目。

## 旧单客户端残留清理（2026-11-10）

M4 之后仓库里只剩新 API 一套客户端，但仍留着当年为切换准备的兼容层。本轮把它们删干净，让代码与本文件描述的唯一口径一致：

- 删除 `Config::legacy_endpoint` 字段与 v1→v2 迁移路径。`load_at` 现在把配置读成 JSON 后先丢弃历史的 `legacy_endpoint` 键（用户机器上的 v2 文件里有这个键的 `null` 残留，不能因为 `deny_unknown_fields` 被判成坏配置），再校验 `config_version == 2`，否则报“不支持的配置版本，请重新填写 API 地址与内容口令”并原样保留文件。
- 删除 `App::new` 对旧 WebDAV 地址的分支、`start_connect` 的旧地址拦截、向导里的“不能继续使用旧 WebDAV 地址”拒绝以及 `wizard_confirm` 中的字段清空；这些判断在旧凭据无处可来之后已不可达。
- 删除 `.env.example` 模板，`.gitignore` 中只留 `.env` / `.env.*` 与注释，不再有 `!.env.example` 例外。本机 `.env` 保留在磁盘上但已无任何代码读取。
- 配置回归测试改为 4 项：v2 往返保留会话与公钥信任且从不落盘登录密码；含 `legacy_endpoint` 的 v2 文件可加载且保存后该键消失；v1（WebDAV）配置被拒绝且文件字节不变；版本过新或格式损坏的配置报错而不被覆盖。

清理只删兼容层与旧凭据入口，不动已验证的协议、服务端与桌面业务逻辑；同一轮把 `AGENTS.md` 的“使用描述/其他/补充”改写成现行网络 API 行为，并在 `README.md`、[M0 合同](m0-contract.md)、[路线图](server-migration-roadmap.md)、[P0 验证](ui-migration-validation.md) 中把“旧客户端仍在并行维护”的措辞改为历史来源说明。

## 尚未完成的完整验收

- 桌面 GUI 走真实服务的完整原生登录/故障/轮换流程；本轮按用户确认未启动 GUI，真实库与服务端链路已由上一节的脚本化端到端覆盖，桌面链路仍只有组件测试与原生预览证据。
- macOS 直接点击窗口关闭按钮、输入法及完整原生焦点/遮罩回归；目前有组件测试和上述原生交互证据。
- OS 磁盘满/权限故障、提交期间进程强杀/断电、通道大规模压力、100,000 条极限负载；已有 SQL 事务/回滚与提交后丢响应/重启测试，未把它们冒充这些故障注入。
- HTTPS 整条原生 UI 流程；HTTPS API 合同与证书拒绝已实测。

备份/恢复、部署样例、自动 WebDAV 备份和其他平台交付按用户确认延后，不列作本轮未交付的软件功能。

## 运行入口

桌面：`cargo run`。服务端：`cargo run -p keyrotation-server -- --help`。管理员初始化、HTTP 本机运行和旧库导入的完整命令见 [README](../README.md)。管理员操作使用受控 stdin 输入密码，当前 CLI 不接受密码参数；管理数据修改需停止服务后执行。


## 2026-11-12：取消轮询与 HTTP 通道自动恢复

- 删除主页 2 秒版本轮询、焦点调度、自动同步专用 500ms 遮罩及右侧提示；保留 UI 定时器处理后台结果、明文到期与未知写入恢复。启动/重连、普通写入和轮换成功仍加载快照；过时内容读取触发按需刷新，未决写入优先。
- 通道期限由客户端/服务端共享。客户端发送前按单调时钟检查空闲/绝对期限，提前 30 秒重建；不续期 token。安全读取遇到通道失败最多重试一次，使用新 request_id、原 token；登录/退出/业务写入不自动重发。
- 本机 Windows 执行 `cargo test --workspace --lib --bins --tests -- --skip store::tests::deleted_or_replaced_open_database_stops_requests`：**50 项通过**（协议 4、服务端库 11、真实 API 合同 4、传输层 9、客户端/GUI 22），1 项原有测试被显式过滤。该测试要求打开 SQLite 时可改名，Windows 在改名步骤返回共享冲突（OS error 32）；未把它算作通过。
- 通道寿命测试通过调整测试对象的单调时间戳跨越空闲 5 分钟和绝对 1 小时边界，再执行真实 TCP + Noise 交换，不以实际等待一小时验证。覆盖健康通道复用、自动重建、通道丢失读重试、新 request_id/原 token、持续失败停止重试、会话失效不重试、登录/退出/写入不盲目重发。
- 真实 API 测试使用临时目录中的合成 SQLite、独立 config.json 和回环随机端口：空闲 2.2 秒服务端请求计数不变；外部修改后旧内容读取触发快照刷新；写入事务提交后故意破坏响应 request_id，客户端查询原 operation_id，最终只有一条新增且 revision 只增一次；服务端关闭重启后原客户端自动重建通道并复用持久化 token。原有 HTTP+Noise/受信 HTTPS、CRUD、幂等、轮换与 GUI 状态测试同时通过。
- 测试未读取真实用户配置、`.local/ptoolkit_keys.db` 或真实凭据；临时服务正常停止，配置和数据库由 TempDir 管理。未做 macOS 原生实机验收。
- 配套修复：服务端数据库安装后的目录 fsync 仅 Unix 执行；原有编辑 GUI 测试在 Windows/Linux 用 Ctrl+A、macOS 用 Cmd+A。`cargo fmt --all --check` 与 `git diff --check` 通过。
- 原有 `examples/real_run.rs` 包含未加条件编译的 Unix 权限 API，Windows 上 `cargo test --workspace` 会先在示例编译处失败；本次明确选择库/二进制/集成测试目标，不修改真实旧库实跑脚本，也不将它计为已执行。


## 2026-11-12：systemd 与 Debian 隔离全链路

新增 `deploy/systemd/keyrotation-server.service`、`server.env.example` 和 `scripts/keyrotation-server-service.sh`：专用非 root 用户、4233 默认监听、独立 EnvironmentFile/StateDirectory、on-failure 每 2 秒恢复、60 秒五次启动限流、journal 与基本沙箱限制。服务端 HTTP/HTTPS 加入 SIGTERM/SIGINT 的正常停服处理及无秘密的生命周期日志。

为避免在 Debian 构建桌面 GUI，新增工作区 `tools/e2e` 包复用 `examples/real_run.rs`；增加合成旧库 fixture、随机端口及管理员重置验证入口，保持原真实旧库脚本及其数据不动。`scripts/wsl-build-test.sh` 只复制源码至独立 Linux 工作目录，`scripts/test-systemd.sh` 创建临时状态目录和单元并保证 EXIT 清理。

验收：WSL2 Debian 13.5 下 Rust 协议/服务端/传输 29 项全通过；Windows 客户端/GUI 25 项全通过。systemd 脚本 21 个检查点和其中六个协议场景 120 项全部通过；真实 SIGKILL 自动恢复、HTTP/HTTPS 正常 stop、持久 token/数据/操作、错误配置限流与修复恢复均有实测。临时资源清理完成。完整表、报告位置与边界见 [systemd 测试覆盖](systemd-test-coverage.md)。

本轮没有终止 Debian 或重启 Windows；自启动通过实际 enable 链接和独立 target 启动事务验证。没有声称完成 macOS 原生实机、断电/磁盘满或十万条极限负载验证。此前文档记载的 Windows-only 跳过项已由此次 Linux 全量服务端测试补齐；`real_run` 的 Unix 权限语句现有条件编译，Windows 示例编译不再因该句失败。


## 2026-11-13：一键 systemd 安装器

新增 `scripts/install-service.sh`，默认创建 keyrotation 非登录系统用户、监听 0.0.0.0:4233、显式首次 init、安装/启用/启动服务并等待真实 PID 的监听。支持普通用户自动构建后 sudo、--binary、端口和 HTTPS；既有默认数据/身份/账号不重置，重复安装保留未指定地址/端口/TLS。更新失败恢复原部署文件与服务启用/运行状态，保留数据库；不会自动接管其它路径的库。

新增真实 systemd 安装器隔离回归 `scripts/test-install-service.sh`：14 检查点及 115 业务检查通过（release 二进制），另有实际缺失 release 产物后的普通用户自动构建与 12 检查点通过记录。默认端口绑定、专用用户/权限、重复安装 SHA-256/UID 不变、token/operation 恢复、端口变更、崩溃重启、端口占用回滚、TLS 文件权限与重复安装全部实测。Linux 29 项协议/服务端/传输回归通过。详见 [安装覆盖表](systemd-test-coverage.md)。临时账号/单元/配置/数据库均清理；未安装正式实例。
