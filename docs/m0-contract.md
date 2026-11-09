# M0：业务与协议合同 v1

日期：2026-11-03。状态：业务问题已获用户回复，已写回 `AGENTS.md` 的 M0 补充。本文冻结首版软件功能边界；具体实现和验证按 roadmap 的 M1–M5 推进，不能用本文代替运行证据。

## 1. 范围和业务决定

| 事项 | 已确认规则 |
| --- | --- |
| 认证 | 单管理员、多客户端、强制登录；token 48 小时有效，不自动续期；本地只保存 token 和用户名，不保存登录密码 |
| 普通修改 | 后提交覆盖，顺序指服务端 SQL 事务的成功提交顺序；字段补丁只改指定字段，不要求旧条目 revision 相等 |
| 删除竞争 | 删除已不存在的条目返回不存在；旧更新不能重建已删除条目；同 operation_id 的重试返回原结果 |
| 读取一致性 | 查看内容仍要求条目 revision 相等；列表分页要求同一 vault revision；不相等则重新取列表 |
| 密钥/恢复世代 | 所有业务写入校验 generation 和 key_epoch；内容轮换仍校验整体 revision 基线，普通后提交覆盖不能绕过它 |
| 临时断网 | 保留配置，清理显示明文、明文编辑缓冲；查看是行内加载，写入和结果未知是全局遮罩；恢复连接后解析原操作结果 |
| 限额 | 内容明文 32 KiB；描述 UTF-8 4 KiB；100,000 条；整个 JSON RPC 明文 60 KiB（61,440 字节），请求和响应均执行 |
| 迁移超限 | 列出条目 ID 和原因并阻止迁移，不截断、不跳过；首版无分帧 |
| 本轮交付 | 软件功能，先以 macOS 为验证平台；备份、自动 WebDAV 备份、部署与 Linux/Windows 交付不在本轮验收中 |

旧 WebDAV 客户端在 M4 切换前继续遵守旧规则。本合同仅适用于新 API；不提前改变旧客户端的失败重置和整库同步。

## 2. 协议边界

协议版本固定为 `1`。共享 Rust DTO 位于 `crates/protocol`，仅依赖序列化、格式验证和摘要等基础库，不依赖 GUI、SQLite 或 HTTP runtime。

请求是 UTF-8 JSON 对象，字段为 `protocol_version`、`request_id`、可空的 `session_token`、`command`。`command` 使用 `operation` 和类型化 `args`，例如：

```json
{
  "protocol_version": 1,
  "request_id": "00000000000000000000000000000001",
  "session_token": "synthetic-token",
  "command": {
    "operation": "entries.update",
    "args": {
      "write": {
        "operation_id": "00000000000000000000000000000002",
        "generation": "00000000000000000000000000000003",
        "key_epoch": 1,
        "valid_until": 1793740800
      },
      "id": 1,
      "description": "新的描述",
      "content": null
    }
  }
}
```

响应回显版本与 request_id；`outcome` 明确区分 `ok`（类型化 result）与 `error`（稳定 code）。上例编号和 token 仅说明结构，不能作为有效认证 fixture。

- request_id / operation_id / generation / rotation job ID 使用 128 位随机值的小写 32 位十六进制。每次传输换 request_id，重试同一业务操作保持 operation_id 和全部业务参数。
- SQLite ID 和 revision 使用非负/正的有符号 64 位整数；溢出报错，不循环归零。时间为 UTC Unix 秒。首版是 Rust 对 Rust，不经浮点转换这些整数。
- 拒绝未知字段、未知操作、重复 JSON 字段、非法 UTF-8、非整数版本值及不支持的协议版本。可空补丁字段的 null 与缺省统一为“不修改”；两个字段均未提供的更新非法。
- 服务端不能接收内容口令、派生密钥和内容明文。只有登录密码出现在 `auth.login` 的受保护请求内。所有业务响应 `Cache-Control: no-store`，不记录请求/响应正文。

### 操作和版本规则

| 操作 | 参数 / 结果 | 规则 |
| --- | --- | --- |
| `server.info` | 版本、服务 ID、初始化状态、服务端时间 | 可信通道内允许未登录；不返回条目、口令、账号 |
| `auth.login` | username/password → token、expires_at | 管理员由本地 CLI 创建；随机 32 字节不透明 token；只存 SHA-256 摘要 |
| `auth.validate` | token → 用户和到期时间 | 不颁发新 token；过期回登录 |
| `auth.logout` | 撤销当前 token | 客户端先清理本地秘密；离线撤销不可宣称成功 |
| `vault.initialize` | write、encryption → meta | 管理员登录后明确初始化；只能从未初始化状态成功一次，key_epoch 输入为 0 |
| `vault.meta` | → meta | 包含 vault_id、generation、vault_revision、key_epoch、encryption |
| `entries.list` | generation、expected_revision、after_id、limit → 描述页 | 不返回内容；首屏可不指定 revision，后续必须用返回的 revision |
| `entries.read_content` | generation、id、expected_revision → 单条密文 | 条目 revision 不符返回 revision_changed；不能把新描述配旧内容 |
| `entries.create` | write、description、content → 条目和库版本 | 服务端分配正 ID；空内容也必须是有效格式密文 |
| `entries.update` | write、id、description?/content? → 条目和库版本 | 无普通编辑 CAS；一个请求的补丁在同一事务内执行 |
| `entries.delete` | write、id → 删除回执和库版本 | 不存在不复活；重试已提交删除返回原回执 |
| `operations.get` | generation、operation_id → 状态及原结果 | 同一管理员重新登录后可查询；不要求当前 key_epoch 等于写入前的 epoch |
| `rotation.begin` | write、expected_vault_revision、new_encryption → job | 记录基线、条目集合，正式内容不变 |
| `rotation.read_batch` | generation、job、游标 → 基线内容密文页 | 不含描述；每批先校验整体 revision 基线 |
| `rotation.stage` | write、job、若干 ID/新密文 | 只写暂存表；与普通写入同样幂等 |
| `rotation.commit` | write、job → 新 meta | 原子替换全部内容、salt/verifier；递增条目版本和库版本、key_epoch |
| `rotation.abort/status` | job → 状态 | 所属管理员可取消/查询；终态不回到 staging |

write 中含 operation_id、generation、key_epoch、valid_until。读取和写入都不接受客户端自选数据库路径。普通条目写只递增被修改条目 revision 和 vault_revision；轮换暂存不递增业务库版本，最终提交才统一递增。

### 错误码

| code | 客户端处理 |
| --- | --- |
| `unsupported_protocol` / `invalid_request` / `limit_exceeded` | 显示明确原因，不重发相同非法请求 |
| `unauthenticated` / `invalid_credentials` / `session_expired` / `forbidden` | 清理明文；失效会话回登录，未确认写保留原 operation_id |
| `vault_uninitialized` | 显式初始化流程，不能自动创建或覆盖 |
| `vault_unavailable` | 停止业务写入；库丢失/损坏不由客户端上传修复 |
| `not_found` | 条目/任务不存在；刷新，不重建 |
| `generation_changed` / `key_epoch_changed` | 清理明文和编辑，重新取 meta；旧请求不得重放到新世代/密钥 |
| `revision_changed` | 读取/分页重试；普通条目编辑不使用此错误拒绝后提交覆盖 |
| `rotation_conflict` / `rotation_incomplete` / `rotation_expired` | 保留旧口令；中止或重新开始轮换 |
| `operation_mismatch` | 同编号参数不同，禁止重做 |
| `operation_expired` | 结果正文已过期或首次提交期限已过；禁止自动生成新编号重做 |
| `rate_limited` / `busy` / `internal` | 区分可信业务拒绝与结果未知；后者先查 operation_id |

本地网络/证书/公钥/通道错误不是已认证的业务错误；不能根据外层 HTTP 200、401 或错误页面认定写入结果。

## 3. 幂等和数据持久层

### 模型草案

服务端单个 `ptoolkit_keys.db`，专用 DB worker 通过有界队列串行处理 SQL。初版使用 rollback journal、synchronous=FULL、foreign_keys=ON；辅助 journal 不算第二个业务库。[SQLite 原子提交文档](https://www.sqlite.org/atomiccommit.html)

| 表 | 关键字段和约束 |
| --- | --- |
| `service_state` | singleton、generation；管理员创建时明确建立，恢复世代独立于 vault 初始化 |
| `vault_meta` | singleton、vault_id、vault_revision、key_epoch、content_format、KDF 参数、salt、verifier；未初始化时无行 |
| `entries` | 自增 id、description、content、revision、key_epoch；保留导入的旧 ID |
| `users` | 单管理员 id=1、唯一 username、Argon2id PHC password_hash |
| `sessions` | token_digest、user_id、created_at、expires_at；不保存原 token |
| `operation_results` | generation/user_id/operation_id 主键、request_digest、结果正文、提交时刻、正文到期时刻 |
| `rotation_jobs` | job ID、owner、generation、基线 revision/key_epoch、目标加密元数据、状态、到期时间 |
| `rotation_members` | job/entry ID、基线条目 revision，冻结 ID 集合 |
| `rotation_entries` | job/entry ID、新密文；只允许基线集合成员 |

schema 从 1 开始显式版本化；只允许显式 init 创建新库。普通打开必须先确认路径存在，再用不含 CREATE 的 flags 打开；拒绝旧/新不支持的 schema 和完整性损坏。检测到运行中库消失或替换后停止写入，不能继续向已脱离路径的连接宣称成功。Unix 数据目录 700、库和身份私钥 600；服务端数据目录不使用客户端 `~/.rust-keyrotation`。

写事务顺序：认证 → 查同主体/世代操作记录 → 比较请求摘要 → 对新操作校验世代、key_epoch、输入和期限 → 修改 → 推进版本 → 写操作结果 → commit。相同编号/相同参数先返回原结果，不能被自己已推进的 key_epoch 拒绝。相同编号/不同参数返回 operation_mismatch。崩溃或 SQL 失败时业务数据与操作记录一起回滚。

摘要输入为协议版本、操作名和完整类型化业务参数（包括 write）；不含 token、request_id、通道 ID。先按 DTO 解析，再转换为 key 按序的 JSON value、无空白 UTF-8 序列化，计算 SHA-256；无浮点数或任意动态对象 key，不把未经规范化的原始 JSON 直接散列。缺省补丁与 null 规范化为同一表示。

首次写入 valid_until 不超过服务端当前时间加 7 天。正文至少保留提交后 7 天；正文过期保留编号和摘要墓碑，返回 operation_expired，不重新执行。客户端重试沿用原 valid_until；记录不存在不等于先前请求永远不可能到达，重试仍用原编号。恢复更换 generation 后拒绝旧世代请求。

### 内容格式和限额

- 格式 1 沿用 `base64 STANDARD(12 字节 nonce || AES-256-GCM 密文和 16 字节 tag)`；规范 padding，不接受只含 nonce 的“密文”。解码长度 28–32,796 字节，编码最多 43,728 字节。
- 旧内容 KDF 的已核对参数：Argon2id v=19，m_cost=19,456 KiB、t_cost=2、p_cost=1、output_len=32，salt 16 字节。首版只接受这组内容 KDF 参数，避免服务端元数据导致任意资源开销。verifier 解密后必须严格为 `ptoolkit-ok`。登录密码哈希独立使用随机盐和 PHC 格式。
- 内容密文结构可由服务端验证，内容明文长度和可解密性由客户端验证；不能宣称服务端已验证内容明文。
- 页大小请求 1–100，按 ID 升序 keyset；实际序列化响应不超过 61,440 字节。JSON escaping、认证字段等也占额度；单字段限额和整个信封限额都必须满足，超限明确报错。
- 轮换按实际序列化大小分批，最大条目可能独占一批；不按固定“条数×平均字节”估算。
- 轮换暂存空闲 1 小时到期，成功进度可刷新空闲时间，绝对寿命最多 24 小时。每次读/暂存/提交检查基线；并发普通写入使轮换冲突，不能把后提交覆盖用于整库密钥提交。

## 4. HTTP profile 与 HTTPS 入口

首版固定 `Noise_NK_25519_ChaChaPoly_SHA256`，由 snow 管理双向状态和 nonce。NK 使用客户端预知服务端静态公钥；使用有状态 TransportState，不调用 nonce setter 或无状态 API 绕过顺序校验。[Noise 规范](https://noiseprotocol.org/noise.html)、[snow TransportState](https://docs.rs/snow/latest/snow/struct.TransportState.html)

- API 基础地址只允许 http/https，拒绝账密、query、fragment。使用 URL 库规范化 host、默认端口和基础路径，尾部补 `/`；非根基础路径保留。公钥及会话按规范化后的完整基础地址绑定，不跨地址复用。
- HTTP 首次公钥由用户经可信途径导入，为 32 字节 X25519 公钥的标准 base64；服务端私钥以独立受限文件稳定保存。不能自动信任同一 HTTP 连接返回的公钥。
- prologue 为 UTF-8 `rust-keyrotation\nv1\nhttp-noise\n<规范化的公开 API 基础地址>`；服务端从显式配置读取公开地址，不根据 Host 或代理 header 猜测。错误地址/基础路径或公钥必须导致握手失败。
- `POST api/v1/channel/handshake`：二进制 Noise NK 第一消息（空 payload）→ 第二消息（空 payload）；响应 header 返回随机 channel ID。握手不携带任何业务秘密。
- `POST api/v1/channel/message`：`application/octet-stream`、header `X-Keyrotation-Channel`；body 只有一个 Noise 密文，响应也是一个密文。channel ID 仅定位状态，不提供授权。业务 token 仅在密文内。
- 限制整个解密后 RPC 为 61,440 字节；snow 的单 Noise 消息上限 65,535 字节，因此传输体另有限额，禁止把 base64/JSON 外封装误算成同一限制。
- 单通道最多一个在途请求；服务端每通道独占顺序处理，排队上限 1。最多 128 个通道、未认证握手并发最多 16；空闲 5 分钟、绝对 1 小时后丢弃并重握手。阈值为首版实现常量，不是允许降级的协商字段。
- 读取失败、错误 tag、乱序、未知 channel、响应丢失或超时后双方销毁通道。下一次使用新握手、新 request_id、原 operation_id。所有 RPC 响应校验 request_id。
- 外层错误仅报告通道失败；登录错误、业务错误、限流等尽可能在可信加密响应内表达。公钥不匹配不能询问网络并自动换钥。
- 公网 HTTP listener 只开放 Noise 两个路径；即使伪造 X-Forwarded-Proto 也拒绝明文 `api/v1/rpc`。HTTPS 使用相同 DTO 和同一 dispatcher，TLS 校验失败终止，不增加 Noise。
- HTTPS JSON listener 可以是直接 TLS，或绑定 loopback 的受信任 TLS 代理后端。当前功能验证允许仅本机 HTTPS；不因此承诺部署交付。禁止仅凭代理 header 开启明文模式。
- API client 禁止自动重定向、HTTPS→HTTP 降级、失败后明文重试。路径不暴露条目 ID、用户名或业务操作。

## 5. UI 状态迁移

| 状态/事件 | 下一状态与反馈 | 内存/持久化动作 |
| --- | --- | --- |
| 配置缺失 / HTTP 无可信公钥 | Wizard | 等待用户输入；不发送认证信息 |
| 配置齐全 | Connecting（全局遮罩） | 建立通道，尝试保存的 token |
| 无 token / 会话无效 | Login | 清理 token；用户名可保留，密码输入缓冲不持久化 |
| 登录及 meta 本地校验成功 | LoadingList → Main | 仅保存描述列表、版本和派生密钥，无客户端 SQLite |
| 内容口令不符 | Wizard，提示不匹配 | 不覆盖服务器；清理查看与编辑 |
| 未初始化库 | 明确初始化确认 | 登录不等同于授权自动创建加密库 |
| 点击遮蔽内容 | ReadingContent（该行加载） | 相同条目请求合并；成功后解密，启动独立 60 秒计时 |
| Enter 描述/内容 / 新增 / 删除确认 | Submitting（全局遮罩） | 生成一次 operation_id，确认前不宣称保存成功；内容暂存在敏感缓冲 |
| 收到可信成功 | Main | 应用服务端版本；内容显示此次明文并重新计时；新增成功后编辑描述 |
| 收到可信拒绝 | Main / Login / Wizard | 按错误码处理；没有自动整库恢复上传 |
| 未取得可信写结果 | ResolvingOperation（全局遮罩） | 清理显示明文，保留原操作；尝试重连/查原编号，后续修改继续禁用 |
| 查询已提交 / 已拒绝 | 应用原结果 / 显示原错误 | 只有确认成功才更新轮换口令和配置 |
| 查询未找到且仍在期限内 | 原编号重试 | 不改参数、不生成新编号；有序执行避免多次依赖写入 |
| 网络仍不可达 | Retry（未确认写保持遮罩与重试/退出操作） | 保留配置，清理明文和编辑；不能永久捕获 Cmd+Q/关闭窗口 |
| 普通轮询无变化 | Main，无提示 | 有焦点的主页每 2 秒只取 meta |
| 远端 revision 改变 | Refreshing（应用快照至少 500ms 遮罩） | 清理所有查看、编辑、对话框，拉同 revision 描述页；右侧持久闪烁提示 |
| Enter 与轮询竞争 | 先解析写结果 | 暂缓采用旧轮询结果；服务端按后提交覆盖处理普通写入 |
| 地址变化 | Connecting / Login | epoch++，丢弃旧任务/结果；清除会话、原地址公钥选择和明文；不跨地址复用秘密 |
| 退出登录 | Wizard | 清除 token、内容口令、派生密钥、明文；尽力撤销服务端会话；保留地址/端口 |
| 内容轮换开始 | Rotating（全局遮罩） | 清理查看和编辑；逐批解密/重加密，只有原子提交确认后更新口令 |

遮蔽、复制、取消编辑是本地操作。保留编辑冻结/取消继续剩余计时、右键复制条件、两次闪烁、删除确认原文、底部固定状态栏、Claude 配色、中文字体、关闭窗口退出和 Cmd+Q。敏感缓冲尽力主动清理，不承诺擦除 OS/渲染器/剪贴板保留的一切副本。

## 6. M0 退出检查与后续阶段

- 五组业务问题已回复并逐项写回 AGENTS.md；后提交覆盖已明确覆盖 roadmap 原冲突拒绝建议。
- DTO/错误码、持久层模型、幂等期限、内容格式、UI 状态和双模式通道边界已形成本文合同。
- M1 增加 workspace、共享协议、独立服务端和文件 DB worker、显式初始化及结构导入；备份/部署排除。
- M2 安全通道必须先通过错误公钥、篡改、重放、跨会话、入口隔离、重启和大小边界测试，再开放真实业务。
- M3–M5 完成认证/API、桌面切换和轮换；M6 只推进本轮范围内的功能验收与合成旧库迁移。真实配置和服务器不会因合成测试被写入。

M0 实施前基线：`cargo fmt --all --check` 通过；`cargo test --locked` 12 passed。测试使用现有合成 fixture，不读取用户配置或 `.env`；缓存保留。新协议和服务端验证现见 [实施记录](server-implementation-validation.md)，没有用旧测试代替。
