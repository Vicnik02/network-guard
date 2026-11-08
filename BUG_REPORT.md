# Network Guard Bug 报告

> **✅ 修复状态（2026-11-08）**：P0-1、P0-2、P0-3、P1-4、P1-5、P2-1、P2-2、P2-3、P2-4 已全部修复并测试通过（P2-5 为设计行为，README 已说明）。
> 要点：优雅关闭优先（WM_CLOSE → 树杀 → 硬杀兜底）、超时默认放行（`timeout_action` 可配）、应用组 + 树杀、
> 冻结列表持久化 + 启动时三元组校验恢复、PID 复用防护、系统代理残留自愈（`post_kill_restore_proxy`）、路径白名单（`watch_paths`）、日志轮转、非模态倒计时弹窗。

**报告日期**：2026-11-08
**涉及文件**：`guard.pyw`（核心模块）、`guard_gui.pyw`（GUI 版）
**触发事故**：拦截 Clash Verge 后其崩溃退出，Windows 系统代理设置残留指向 `127.0.0.1:7897`（无进程监听），导致 Edge 等所有走系统代理的应用"网络异常"。

**日志证据**：
```
[2026-11-08 17:26:58] 受控网络「NCU-5G」发现进程: [('clash-verge.exe', 27508)]，先冻结等待确认
[2026-11-08 17:27:01] 用户取消/超时，结束进程 clash-verge.exe (PID 27508) -> 成功
```

---

## P0-1 冻结后直接硬杀进程，没有优雅退出路径（本次事故根因）

**位置**：`guard.pyw` `kill_pid()`（L290-303）；`guard_gui.pyw` `Monitor.run` 取消分支（L206-210）

**问题**：
取消或超时后直接 `TerminateProcess(exit_code=1)` 强杀。这是 Windows 中最暴力的结束方式——进程的清理代码（atexit、窗口关闭消息、配置回写）**完全没有机会执行**。

Clash Verge 是"GUI + 内核 + 系统服务"的多进程应用，GUI 进程负责写系统代理注册表。它被硬杀时：
- 如果它刚设置完系统代理 → 残留 `ProxyEnable=1` 指向 `127.0.0.1:7897`，但没人监听；
- 系统代理指向死端口 → Edge/微信/所有走系统代理的流量全部失败。

另外，**冻结本身也在埋雷**：`NtSuspendProcess` 把进程冻结在任意执行点上（可能正持有注册表句柄、正在写自身配置），之后无论恢复还是硬杀，都可能留下不一致状态。

**修复方案**：
1. 新增"优雅关闭优先"的结束流程：
   ```python
   def graceful_kill(pid, timeout=10):
       # 1) 先温和关闭：给主窗口发 WM_CLOSE，或 taskkill /PID xxx（不带 /F）
       # 2) 轮询等待进程退出（timeout 秒）
       # 3) 仍存活才 TerminateProcess 兜底
   ```
2. 结束**已知代理类应用**后增加自愈检查：若 `ProxyEnable=1` 但代理端口（7897）无监听，自动关闭系统代理并记日志（可在 config 中配置 `post_kill_restore_proxy`）。
3. 对受控应用，弹窗文案明示"取消将强制关闭，可能丢失未保存状态"。

---

## P0-2 只匹配 GUI 进程名，多进程应用管控不完整

**位置**：`config.json` `watch_apps: ["clash-verge.exe"]`；`kill_pid()` 无树杀逻辑

**问题**：
Clash Verge 实际有 `clash-verge.exe`（GUI）、`verge-mihomo-core.exe`（代理内核）、`clash-verge-service.exe`（SYSTEM 权限服务）等多个进程。只杀 GUI 会出现：
- 内核还在跑，代理隧道看似"还活着"，但控制面死了，状态不可预期；
- 服务进程持有系统状态，更不可能被清理。

**修复方案**：
1. 结束时用 `taskkill /T /F /PID`（树杀），或 `NtTerminateProcess` 前先枚举子进程。
2. 配置支持"应用组"：`{"group": "clash-verge", "processes": ["clash-verge.exe", "verge-mihomo-core.exe", "clash-verge-service.exe"]}`，冻结/放行/结束按组操作，弹窗里也按组展示。
3. README 的常见问题里其实已经提示了多进程问题，但代码层面没有任何支持——应落地。

---

## P0-3 弹窗 180 秒无响应自动按"取消"强杀

**位置**：`guard_gui.pyw` `Monitor.run` L195：`self.ask_lock.wait(timeout=180)`

**问题**：
超时被当成"用户取消"→ 强杀进程。**开机自启动场景下这是高危默认值**：用户开机后不在电脑前，受控应用一启动就被冻结，3 分钟后无人应答即被硬杀。本次事故的触发条件（无人确认 + 硬杀代理软件）恰好就是这条路径的变体。

**修复方案**：
1. 超时默认改为"放行（恢复运行）"并记录"超时未确认，已恢复，下次再问"，把"超时即杀"做成配置项（默认关）。
2. 日志区分"用户主动取消"与"超时"，目前两种情况混在一句"用户取消/超时"里，事后无法追溯。
3. 弹窗上显示倒计时，超时前 30 秒闪烁提醒。

---

## P1-4 守护进程异常退出会泄漏冻结的应用

**位置**：`guard_gui.pyw` `Monitor.run` 整体；`suspended_pids` 仅在正常停止/退出路径被恢复

**问题**：
如果 pythonw 进程本身崩溃、被任务管理器结束、或断电，所有已被 `NtSuspendProcess` 冻结的进程**永远不会被恢复也不会被杀**——表现为应用永远"未响应"。正常退出路径有恢复逻辑（`_stop_monitor` / `_quit_all`），但异常路径完全没有。

**修复方案**：
1. 监控循环整体 `try/finally`，finally 里恢复所有 `suspended_pids`。
2. 冻结时把 `(pid, 进程名, 进程创建时间)` 持久化到 `guard_suspended.json`；程序启动时读取该文件，对仍然存活且三元组匹配的 PID 执行 `NtResumeProcess`（带创建时间校验防 PID 复用），然后清理文件。

---

## P1-5 PID 复用未校验，可能杀错进程

**位置**：`Monitor.run` / `guard.pyw` `main_loop` 中 pending 列表的整个生命周期

**问题**：
从检测到 PID → 冻结 → 等待用户确认（最长 180 秒）→ 结束，全程只凭 `(进程名, PID)` 判断。等待期间原进程退出、PID 被系统复用给别的进程时，`kill_pid` 会**误杀无关进程**。`allowed &= alive` 的清理逻辑同样存在该窗口。

**修复方案**：
冻结前通过 `OpenProcess + GetProcessTimes(ProcessCreationTime)` + `QueryFullProcessImageName` 记录三元组；恢复/结束前重新打开句柄校验"PID + 名称 + 创建时间"完全一致，不一致则放弃操作并记日志。

---

## P2 其他问题（建议顺手修）

| # | 问题 | 位置 | 建议 |
|---|------|------|------|
| P2-1 | 进程名匹配无路径校验，同名 exe 会被误伤 | `find_processes` | config 可选 `watch_paths` 前缀校验 |
| P2-2 | `guard.log` 无限增长 | `guard.log()` | 超过 1MB 轮转或启动时截断 |
| P2-3 | 弹窗期间 `_poll_queue` 被模态框阻塞，状态区停止刷新 | `_show_ask_dialog` | 弹窗改用 `Toplevel` + 按钮，不用模态 `messagebox` |
| P2-4 | 冻结失败的应用语义不明（确认后直接继续运行，取消时才杀）| 监控循环 | 弹窗中标注哪些"冻结失败"，或冻结失败时立即询问 |
| P2-5 | 一次拦截放行后，应用重启（新 PID）会再次弹窗 | 设计行为 | 文档明确说明即可（README 已提） |

---

## 修复优先级路线

1. **立即（P0-1 + P0-3）**：优雅退出优先 + 超时默认放行 —— 这两条能直接杜绝本次事故重现。
2. **随后（P0-2）**：应用组 + 树杀，解决 Clash Verge 多进程残留。
3. **加固（P1-4 + P1-5）**：异常安全网 + PID 三元组校验。
4. **清理（P2）**：日志轮转等小项。

## 针对本机的临时补救（不改代码）

- Clash Verge 打开 → 设置里把"系统代理"开关关一次再开（刷新残留状态），或直接在 设置→网络→代理 里手动关闭"使用代理服务器"。
- 在 network_guard 的受控应用里暂时移除 `clash-verge.exe`，等修复上线后再加回。
