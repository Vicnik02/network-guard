# Network Guard — 网络管控守护程序

一个轻量的 Windows 网络管控工具：当电脑连上**指定 Wi-Fi**（如公司、学校、宿舍网络）时，
自动管控**指定应用**——检测到即**冻结进程**并弹窗警告，用户确认后才允许继续运行，取消则立即关闭。

无需管理员权限，无第三方重依赖，常驻后台几乎零占用。

## 功能特性

- 🛡️ **冻结式管控**：命中受控网络时，受控应用一启动就立即被冻结（挂起），无法执行任何功能，直到用户在警告框中做出选择
  - 点「确定」→ 恢复运行（本次不再打扰）
  - 点「取消」→ 立即强制结束进程
  - 应用重新打开会再次触发警告（每次打开都需确认）
- 📊 **可视化界面**：实时显示当前网络状态、受控进程表格（冻结/放行/已检测）、实时日志
- 📌 **系统托盘**：关闭窗口缩到托盘继续守护；左键唤回窗口，右键开启/停止/退出；图标颜色指示守护状态
- ⚙️ **图形化配置**：受控网络、受控应用、检测间隔均可视化编辑，保存即生效（支持热重载）
- 🚀 **高性能**：全部使用 Windows 原生 API（wlanapi / Toolhelp32 / NtSuspendProcess），无子进程轮询，不闪黑框
- 🔄 **开机自启动**：一键注册（HKCU 注册表，无需管理员）
- 🔒 **单实例保护**：互斥锁防重复启动，重复打开会唤回已有窗口

## 工作原理

1. 每 `poll_interval` 秒通过 **wlanapi 原生 API** 读取当前 Wi-Fi SSID（不在受控网络时用更长的 `idle_interval`，几乎零占用）
2. SSID 命中 `watch_ssids` → 用 **Toolhelp32 快照**（毫秒级）扫描 `watch_apps` 对应进程
3. 发现受控进程 → **NtSuspendProcess 立即冻结** → 弹出置顶警告框
4. 用户确认 → NtResumeProcess 恢复运行；取消 → TerminateProcess 强制结束
5. 离开受控网络自动恢复静默

> 所有检测均不启动子进程，因此不会出现 pythonw 下常见的控制台黑框闪现问题。

## 环境要求

- Windows 10 / 11
- Python 3.8+（**必须带 tkinter**，官方安装包默认包含）
- 第三方依赖：`pystray`、`Pillow`（仅托盘图标需要）

```bat
pip install pystray pillow
```

## 快速开始

```bat
:: 1. 复制示例配置并修改
copy config.example.json config.json

:: 2. 启动（启动即自动守护，可双击 guard_gui.pyw）
pythonw guard_gui.pyw

:: 3. 注册开机自启动（任选其一）
pythonw guard_gui.pyw --install
python guard.pyw --install
```

命令行参数（`guard_gui.pyw` 与 `guard.pyw` 均支持）：

| 参数 | 作用 |
|---|---|
| `--install` | 注册开机自启动 |
| `--uninstall` | 取消开机自启动 |
| `--status` | 查看自启动状态 |

## 配置说明（config.json）

```json
{
  "watch_ssids": ["办公室WiFi", "Company-WiFi"],
  "watch_apps": ["game.exe", "someapp.exe"],
  "poll_interval": 2,
  "idle_interval": 5,
  "test_ssid": ""
}
```

| 字段 | 说明 |
|---|---|
| `watch_ssids` | 受控网络的 Wi-Fi 名称列表（不区分大小写）。用 `netsh wlan show interfaces` 查看当前 SSID |
| `watch_apps` | 要管控的进程名，即 exe 文件名（小写），需与任务管理器中显示的一致 |
| `poll_interval` | 受控网络上的检测间隔（秒） |
| `idle_interval` | 不在受控网络时的 SSID 轮询间隔（秒），降低日常占用 |
| `test_ssid` | 测试用：填任意值可模拟"已连接受控网络"，无需真连那个 Wi-Fi 即可测试冻结与弹窗 |

配置支持**热重载**：GUI 中保存即生效；直接编辑文件也会在下一个轮询周期生效。

## 文件说明

```
network_guard/
├── guard_gui.pyw    # 可视化界面版（推荐日常使用，带托盘）
├── guard.pyw        # 核心检测模块 + 无界面静默守护模式
├── config.json      # 你的配置（不入库，参考 config.example.json）
├── config.example.json
└── guard.log        # 运行日志
```

## 常见问题

**Q：进程名怎么填？**
任务管理器 →「详细信息」标签页中的「名称」列，如 `clash-verge.exe`。注意有些应用有多个进程（主程序 + 内核/服务进程），需要分别添加。

**Q：冻结和直接结束有什么区别？**
冻结（挂起）能让应用停在启动瞬间、无法执行任何功能，用户确认后可无缝继续；直接结束则丢失状态。冻结方式对用户更友好。

**Q：托盘图标找不到？**
Windows 11 可能默认折叠托盘图标，点任务栏右下角「^」箭头，把图标拖到外面即可常驻显示。

**Q：为什么不用 IFEO 映像劫持实现"启动前拦截"？**
IFEO 需要管理员权限修改 HKLM，且放行时需绕过劫持（改路径/硬链接），对系统目录和 Program Files 中的应用并不可靠。冻结方案体验等同"先警告后运行"，且完全在用户权限内完成。

## License

MIT
