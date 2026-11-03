# P0：gpui-kit 迁移与清理验证

日期：2026-11-03。本阶段不实施服务端 API 改造。

## 实现

- `gpui-kit = 0.8.1` 替换直接依赖的 egui/eframe；窗口改为 GPUI 原生后端。
- `src/app.rs` 保留业务状态与现有 WebDAV/内存 SQLite 规则，`src/ui.rs` 负责窗口、页面、组件及事件。
- 保留按需解密、独立 60 秒遮蔽、编辑暂停/确认/取消、右键复制与删除确认、状态闪烁、遮罩和焦点轮询。
- 后台任务仍由同一 worker 串行执行；GPUI 定时器收取结果并处理恢复与到期，仅在状态变化或闪烁期间请求重绘。
- 内置中文字体继续使用 Noto Sans SC，正文显式设置空字体 fallback 列表；真实平台的生僻字/emoji 表现仍需人工核对。
- `vendor/gpui-pre-macos` 是上游 0.3.10 的稳定编译兼容补丁，仅替换三处 `Option::map_or_default`，保留 Apache-2.0 许可证与补丁说明。

参考：[gpui-kit 官方安装文档](https://gpui-kit.com/docs/installation/)、[Input 组件文档](https://gpui-kit.com/component/input/)。采用锁文件内版本，不依赖系统全局修改或 nightly 特性开关。

## 已完成检查

本机 macOS ARM64，Rust stable 1.96.0：

| 检查 | 结果 |
| --- | --- |
| `cargo fmt --all --check` | 通过 |
| `cargo clippy --locked --all-targets -- -D warnings` | 通过 |
| `cargo test --locked` | 10 passed，0 failed |
| `cargo build --locked --bin rust_keyrotation` | 通过，普通 Mach-O ARM64 二进制 |
| `git diff --check` | 通过 |

原有 7 项测试继续覆盖数据库、口令及同步决策。新增 3 项 GPUI 组件测试通过真实键盘/鼠标事件验证 Enter 保存、Esc 取消与倒计时恢复、遮蔽时禁止复制、解密后复制反馈、到期移除明文，以及数据库替换时销毁编辑框。

原生预览使用空配置创建同一个 Desktop 窗口，已启动且无 panic；未输入配置、未连接服务器，随后停止进程。电脑控制工具返回 `Computer Use was not approved to use Keyrotation Preview`，因此没有截图证据，也没有通过原生点击核验关闭即退出。临时预览代码、测试包装目录均已移除，产品仍为普通二进制。

上游 `block 0.1.6` 有 Cargo future-incompatibility 提示；本轮 stable 编译、测试成功，未修改全局依赖缓存中的源码。

## 清理与交付

- 开始前 `target/` 的 `du -sh` 占用约 2.6 GB；第一次 `cargo clean` 报告移除 11,053 个文件、2.7 GiB。
- 必要的检查、组件测试及生产依赖构建结束后，`target/` 占用约 2.9 GB；最终 `cargo clean` 报告移除 8,725 个文件、3.0 GiB。
- 已确认最终 `target/` 不存在。已验证的开发版可执行文件保留在 `dist/rust_keyrotation`，`du -sh dist` 约 84 MB；该目录已加入 `.gitignore`。
- 本地兼容补丁目录约 404 KB。开发/测试 profile 关闭 debug 信息和增量缓存，发布 profile 去除调试信息；重新构建仍会生成框架依赖缓存，维护命令见 README。
- 初次 P0 迁移验证未读取 `.env` 凭据，未修改用户配置、真实服务器数据库或字体资源；后续交互修复验证的配置误写事件另见下文。

运行现有二进制：

```sh
./dist/rust_keyrotation
```

需要重建时运行 `cargo build --locked`。本轮保留的是开发版，未另行生成 release 缓存或 App 包。

## 尚待实测

- 原生窗口中文、布局、颜色与生僻字/特殊符号显示。
- 原生窗口焦点、遮罩、输入法、关闭窗口退出，以及完整交互回归。
- 真实 WebDAV 登录、重启恢复配置、上传/自动同步及故障恢复的完整 UI 回归。
- Windows 构建与运行。

上述项目不能由组件测试或预览进程成功启动替代。路线图 M0 及服务端阶段尚未开始。

## Hover 与 Cmd+Q 修复（2026-11-03）

原因与修复：

- 表格行没有元素 ID，GPUI 无法为其保留 hover 状态并在鼠标进入/离开时通知重绘；为每行增加基于条目 ID 的稳定 `entry-row` ID。无需增加轮询或持续重绘。
- 缺少应用级退出 action 和快捷键；注册 `Quit` / `cmd-q`，在 macOS 菜单中增加“退出密钥轮换”。阻塞编辑的键盘处理允许该快捷键继续到达应用处理器。

验证：格式检查、Clippy 全目标检查和普通二进制构建通过；完整测试 12 passed。新增测试确认鼠标进入/离开行时会立即重绘，不推进计时器；在输入框聚焦、同步遮罩、上传失败遮罩和删除确认期间，Cmd+Q 均能到达应用处理器。

Computer use 本轮可用。使用 30 条合成数据运行同一套原生 UI，核对中文显示和第 2/4 行高亮切换；发送 Cmd+Q 后通过进程列表确认验证进程退出。读窗口状态的工具可能再次启动已退出的测试应用，因此以进程消失作为退出证据。完整真实服务端 UI 回归与 Windows 构建仍未验证。

验证事故与处置：首次合成数据程序复用了实际 `config::save`，在自动同步失败重置时将 `~/.rust-keyrotation/config.json` 写成空配置。已立即告知用户并停止进程；后续验证改用完全不读写真实配置的 stub，并暂停合成数据轮询。用户确认没有原窗口或配置备份，将自行重新配置。服务器数据库未访问、未改写；本地原内容加密密钥需要用户重新输入，未在聊天或日志收集秘密。

临时验证源码和 macOS 测试包装目录均已删除。更新后的普通二进制仍位于 `dist/rust_keyrotation`，构建缓存随后清理。

## 构建缓存处理纠正（2026-11-03）

此前每次验证结束执行 `cargo clean`，导致用户下一次 `cargo run` 全量重编译，超出了用户要求的旧依赖清理范围。这些清理记录仅为历史事实，不是后续操作约定。

已撤销开发/测试 profile 中 `debug = 0` 和 `incremental = false`，恢复 Cargo 默认设置；README、路线图和 AGENTS.md 已改为保留 `target/` 缓存、仅清理旧框架废弃依赖及确认属于旧依赖的产物。日常继续使用 `cargo run`，不例行全量清理，也不再使用复制到 `dist/` 后清空构建缓存的交付流程。

此前已经删除的缓存无法恢复；恢复默认 profile 后，下次运行可能仍需重建一次，之后相同工具链、配置与依赖下可正常复用缓存。本次仅修改 manifest 与文档，没有再次构建或清理。
