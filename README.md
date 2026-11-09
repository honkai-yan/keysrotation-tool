# 密钥轮换小工具

Rust / gpui-kit 桌面客户端，加独立 Rust API 服务端。服务端直接持有单个 `ptoolkit_keys.db`；客户端只获取描述列表和按需请求的单条内容密文，不下载、保存或上传整库。

条目内容由客户端使用 Argon2id + AES-256-GCM 加解密，内容口令及明文不发送给服务端。HTTP 使用预先导入服务端公钥的 Noise 通道；HTTPS 使用正常校验证书的 TLS，不再额外使用 Noise。描述在服务端数据库中为明文。

本轮先支持和验证 macOS，构建为普通二进制。备份、部署脚本及其他平台交付延后。原 WebDAV 客户端已被新 API 流程替代。

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

`--public-url` 必须与客户端填写的规范化 API 基础地址一致，包含非根基础路径时也必须一致。HTTP listener 只开放加密通道，不提供明文登录或明文 RPC。HTTPS 入口使用相同业务实现，需显式提供 `--tls-cert CERT.pem --tls-key KEY.pem`，并把公开地址设为 `https://.../`；本轮未交付部署脚本。

修改管理员密码使用 `reset-password --data-dir PATH --username NAME --password-stdin`，仍从重定向 stdin 输入；会撤销现有会话。管理初始化、导入及密码重置应在服务停止时操作，避免引入第二个数据库写入口。

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

主页有焦点时每 2 秒只查询库版本。远端变化后重新获取同一版本的描述列表，清理查看/编辑/对话框，应用时显示至少 500ms 遮罩，并保留右侧同步提示。

普通编辑按服务器事务的成功提交顺序覆盖指定字段：描述修改只覆盖描述，内容修改只覆盖内容。普通编辑不使用旧条目 revision 拒绝后提交覆盖；读取一致性、数据世代、key epoch 和轮换整体基线仍校验。

查看只在行内加载，写入使用全局遮罩。临时断网保留配置并清理显示明文；写请求结果未知时查询原操作编号，阻塞后续修改。结果记录过期后不会盲目重做，需明确重新加载服务器数据。轮换提交已确认但本地配置保存失败时，界面保留错误提示并提供重试保存；请保管新口令。服务器数据库缺失/损坏不会由客户端创建空库或上传本地库修复。

## 配置与限额

客户端配置为 `~/.rust-keyrotation/config.json`，版本 2；Unix 目录 700、文件 600，原子写入。内容口令和 token 仍明文保存，按已确认需求依赖本地文件权限保护；服务端只存登录密码哈希和 token 摘要。

旧配置仅保留地址和本地内容口令用于迁移提示，不把 OpenList 账号、密码或 token 发送给新服务。用户明确确认新 API 地址后保存新版配置，清除旧认证字段。新服务公钥与可选 CA 文件按规范化 API 地址保存。

| 限额 | 数值 |
| --- | --- |
| 单条内容明文 | 32 KiB（UTF-8 字节） |
| 描述 | 4 KiB（UTF-8 字节） |
| 条目数 | 100,000 |
| 完整 RPC 明文 | 60 KiB，包括 JSON 封装、escaping 等；请求和响应均限制 |

分页和轮换按实际序列化字节处理，超限不截断。当前轮换客户端每批处理一个条目，避免持有大量明文；服务端支持多个条目的合规批次。

## 旧库导入

先停止旧客户端写入，由管理员通过安全途径取得旧 `ptoolkit_keys.db` 文件，再导入到尚不存在数据库的新数据目录：

```sh
printf '%s' "$KEYROTATION_ADMIN_PASSWORD" | cargo run -p keyrotation-server -- import --data-dir ./server-data --source PATH_TO_LEGACY_DB --username admin --password-stdin
```

导入只读打开源文件，验证完整性、表结构、盐/verifier、密文格式与限额，保留 ID、描述、密文和加密元数据。已有目标库不会被覆盖；超限明确列出 ID 并拒绝导入。服务端不知道内容口令，结构检查不能替代客户端实际解密验证。

`.env` 的 `TEST_SERVER`、`TEST_ACCOUNT`、`TEST_PASSWORD` 仅适用于旧 OpenList 测试环境，不是新服务凭据；当前测试使用本机临时服务和合成数据。

## 代码与验证记录

- `src/`：gpui-kit UI、API 状态、内容加密、版本化配置及串行 API worker。
- `crates/protocol/`：DTO、错误码、格式限额及规范化业务请求摘要。
- `crates/transport/`：固定 Noise NK profile 和 HTTP/HTTPS 客户端。
- `crates/server/`：HTTP/TLS 入口、认证、文件 SQLite worker、幂等操作、轮换和管理 CLI。
- [M0 合同](docs/m0-contract.md)、[路线图](docs/server-migration-roadmap.md)、[实施与验证](docs/server-implementation-validation.md)。

内置中文字体和 Claude 配色继续保留；macOS 关闭窗口即退出，支持 Cmd+Q。`vendor/gpui-pre-macos` 继续保留上游许可证及 stable Rust 兼容补丁说明。
