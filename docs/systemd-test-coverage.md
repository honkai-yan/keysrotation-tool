# systemd 与隔离回归覆盖计划（2026-11-12）

客户端/GUI 在 Windows 本机测试；服务端、协议与 systemd 在 WSL2 Debian 测试。禁止使用真实配置、数据库或 `.local` 旧库。服务端业务使用随机口令、合成旧库、独立空库及回环临时端口。先列覆盖，再记录实际结果。

| 范围 | 用例/证据 | 执行入口 |
| --- | --- | --- |
| systemd 配置 | unit 校验、非 root MainPID、日志、700/600 权限 | `scripts/test-systemd.sh` |
| 生命周期 | 启用/禁用、独立 target 自动拉起、手动 restart、SIGTERM 正常退出且不重启 | 同上 |
| 崩溃与故障 | SIGKILL 自动重启、旧 token/数据/操作结果保留、配置错误触发启动限流、修复后恢复 | 同上 |
| 管理 CLI | init/check/public-key、重复初始化摘要不变、错误参数、合成旧库 import 摘要不变、reset-password 撤销旧 token | 同上与 `keyrotation-e2e` |
| 业务读写 | 初始化、分页、内容解密、增改删、字段覆盖、删除不复活、限额 | `sandbox` 与 API 合同测试 |
| 幂等与轮换 | 操作重放/摘要不匹配/期限、完整/不完整/取消/冲突/空库轮换、重启后的 operation 查询 | `sandbox` / `resume` 与 API 合同测试 |
| 信任与传输 | Noise、公钥/URL 绑定/篡改/重放/乱序/大小、HTTPS/CA、明文入口隔离 | 传输层/入口测试与 `real` / `https` |
| 通道恢复 | 空闲/绝对寿命、通道丢失有限重试、登录/写入不盲重发、服务端重启复用 token | 传输层和真实 API 重启测试 |
| 客户端配置/状态 | token 持久化无密码、版本拒绝、地址/登出/失效、过时读取刷新、空闲无请求、未知写入原编号 | Windows 客户端测试 |
| GUI | 明文超时、编辑冻结/取消/确认、复制限制、hover、远端替换清理、遮罩下退出 | Windows GPUI 测试 |
| 收尾与隔离 | 双库 check、秘密不进入 journal、停服、禁用、删除临时单元及数据库、保留非秘密报告 | 脚本 EXIT trap |

边界：不终止整个 WSL 实例；自启动测试验证真实 enable 链接和独立 target 的依赖启动事务，不冒充 Windows 开机或 Debian 冷启动实测。通道一小时寿命用测试对象时钟跨边界验证；macOS 原生鼠标/剪贴板实机验收单列，不能由 WSL/Windows 自动测试代替。


## 实测结果

环境：WSL2 Debian GNU/Linux 13.5、systemd 257.13、Rust/Cargo 1.99.1；客户端在 Windows 本机运行。2026-11-12 最终全流程报告位于被 gitignore 的 `.local/systemd-reports/keyrotation-e2e.LgCYt2/`，脚本退出码 0，`checks=21 cleanup=complete`。

| 层次 | 结果 | 说明 |
| --- | --- | --- |
| WSL Rust 测试 | 29 通过，0 跳过 | 协议 4、服务端库 12、真实 API 合同 4、传输 9；此前 Windows 文件锁不兼容的改名测试在 Linux 通过 |
| Windows 客户端/GUI | 25 通过，0 跳过 | 新增同地址无动作/改地址丢旧结果、错误内容口令不覆盖、删除确认取消/提交；其余覆盖状态、配置、真实 API、编辑、计时、复制、遮罩和退出 |
| systemd 流程 | 21 检查点通过 | 语法/权限、enable 链接、target 启动、非 root MainPID、手动重启、崩溃恢复、正常停服、HTTP/HTTPS、永久错误限流、修复恢复、disable、日志及清理 |
| `fixture` | 1 通过 | 现场生成合规合成旧库，不访问真实数据 |
| `real`（此轮为合成导入） | 37 通过 | 只读保真、错误公钥、分页、限额、会话等；不代表重新读取了用户真实旧库 |
| `sandbox` | 63 通过 | 空库 CRUD、字段覆盖、限额、幂等、轮换、并发及注销 |
| `resume` | 9 通过 | systemd SIGKILL 自动重启后 token、数据世代、内容及 operation 结果保留 |
| `https` | 8 通过 | 同一 systemd 单元切换 TLS，自签 CA 校验、可信写入、拒绝明文/Noise 入口 |
| `admin` | 2 通过 | 停服 reset-password 后撤销旧 token，新密码登录 |

六个协议场景合计 120 项，已作为 systemd 流程的业务检查点记录，不与 21 再相加。两个测试库在停服后通过 `check`，合成源库 SHA-256 未改变。崩溃验证使用真实 MainPID 的 SIGKILL；正常停服实测 HTTP/HTTPS `ExecMainStatus=0`。持续无效 URL 实测五次重启后进入 failed、重启次数停止增长且 journal 记录 `Start request repeated too quickly`；Debian 257 的 `Result` 此时保留 `exit-code`，测试不误依赖 `Result=start-limit-hit`。

初轮发现并修正的仅测试工装问题：合成旧库主键 nullability、Bash 临时环境变量赋值导致错误公钥与实际公钥相同、systemd 启动限流 Result 属性差异、GUI 按钮调试选择器。修正后重新执行完整对应流程；失败尝试的临时单元和数据也由 EXIT trap 清理。

复跑：先在普通 Linux 用户下 `bash scripts/wsl-build-test.sh`（Windows 源码映射也可），再运行 README 中 `sudo bash scripts/test-systemd.sh ...`；Windows 执行 `cargo test --locked --bin rust_keyrotation`。脚本遇到首次用例失败会停止并保存报告，然后清理，不把部分成功报告成全通过。


## 一键安装脚本覆盖（2026-11-13）

新增 `scripts/install-service.sh` 与 `scripts/test-install-service.sh`。测试使用单独系统用户 `kri-*`、单独 `keyrotation-install-*` 单元和 `/var/lib/keyrotation-installer.*` 根目录，正式 keyrotation 用户/服务保持不动。

| 用例 | 验证 |
| --- | --- |
| 参数失败 | 端口 0、公网地址 0.0.0.0 在创建账号/数据/单元前拒绝 |
| 自动构建 | 缺少 release 二进制时以 sudo 原用户构建，文件属主核验 |
| 首次安装 | 真实专用非登录账号、全 IPv4 默认 4233、700/600 权限、enable 链接与运行 MainPID |
| 业务操作 | 在安装器部署的实例执行 sandbox 全部业务检查 |
| 重复安装 | 无密码/无 URL 重跑，DB/身份 SHA-256、UID 和原配置保持；token/操作结果可续用 |
| 更换端口 | 通过安装器更新监听与 API 地址，原数据与会话恢复 |
| 崩溃恢复 | SIGKILL 已安装服务，自动产生新 MainPID，验证数据与会话 |
| 回滚 | 新目标端口被另一个临时实例占用，安装失败后恢复原配置、enable 和运行状态 |
| HTTPS | 安装器复制证书/私钥为 root 管理、组可读；TLS 业务与无参数重复安装保持配置 |
| 收尾 | 离线 check、口令不出现在报告；删除临时服务/账号/组/数据库 |

复跑：`sudo bash scripts/test-install-service.sh SERVER_BINARY E2E_BINARY`；附加 `--auto-build` 可验证缺少 release 产物的构建路径（需要普通用户拥有源码、`SUDO_USER` 对应该用户）。该测试的默认端口验证需要本机 4233 空闲。

最终结果：2026-11-13 的 release 二进制全流程报告 `.local/installer-reports/keyrotation-install-eb9846/` 退出码 0，14 个检查点通过、cleanup complete。业务为 sandbox 63 项、四次恢复验证各 9 项、两次 HTTPS 验证各 8 项，共 115 项。另在 `.local/installer-reports/auto-build-20261113/` 保存首次缺失 release 二进制、实际以 dacapo 编译的过程及 12 检查点/99 业务检查通过证据；没有为了复跑而删除构建缓存。Linux 核心 29 项同时回归通过。

测试只创建 `kri-*` 非登录用户和 `keyrotation-install-*` 服务；正式 keyrotation 用户及服务未安装。生成口令只存在 Linux 临时目录，报告扫描未发现口令；所有测试用户/组、单元、启用链接、安装锁和临时数据库在结束时清理。Windows 客户端本轮没有代码行为变化，未重复运行 GUI 测试。
