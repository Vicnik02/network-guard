# -*- coding: utf-8 -*-
"""
Network Guard - 可视化界面版
============================
功能：
  - 实时显示当前 Wi-Fi / 是否处于受控网络 / 守护状态
  - 图形化编辑配置（受控网络、受控应用/应用组、检测间隔、测试 SSID），保存即生效
  - 受控网络命中时：立即冻结受控应用并弹出带倒计时的警告框
    - 允许 -> 恢复运行；关闭 -> 优雅退出优先，超时才强制结束
    - 超时未确认默认放行（可配置 timeout_action）
  - 查看当前受管控进程，可手动强制结束
  - 实时日志窗口
  - 开机自启动开关（注册表 HKCU Run）
  - 系统托盘图标；关闭窗口缩到托盘后台继续守护

依赖：同目录下的 guard.pyw（核心检测逻辑）与 config.json
"""

import ctypes
import importlib.util
import io
import json
import os
import queue
import sys
import threading
import time
import winreg

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# 托盘支持（pystray + Pillow）
try:
    import pystray
    from PIL import Image, ImageDraw
    TRAY_OK = True
except ImportError:
    TRAY_OK = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
LOG_PATH = os.path.join(BASE_DIR, "guard.log")
GUI_PATH = os.path.abspath(__file__)
WINDOW_TITLE = "网络管控 - Network Guard"

RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE_NAME = "NetworkGuard"
MUTEX_NAME = "NetworkGuard_SingleInstance_Mutex"

# ---------------------------------------------------------------- 加载核心模块 guard.pyw
_spec = importlib.util.spec_from_file_location("guard_core", os.path.join(BASE_DIR, "guard.pyw"))
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)

log = guard.log  # 复用同一份日志

COLOR_DANGER = "#c62828"   # 受控网络命中（红）
COLOR_SAFE = "#2e7d32"     # 安全（绿）
COLOR_IDLE = "#757575"     # 未连 Wi-Fi（灰）
COLOR_WARN_BG = "#fdecea"  # 警告横幅背景


# ---------------------------------------------------------------- 配置读写
def read_config():
    return guard.load_config()


def write_config(cfg):
    """更新 GUI 管理的键，保留 config.json 中的其他自定义键。"""
    updates = {
        "watch_ssids": cfg.get("watch_ssids", []),
        "watch_apps": cfg.get("watch_apps", []),
        "poll_interval": cfg.get("poll_interval", 2),
        "idle_interval": cfg.get("idle_interval", 5),
        "test_ssid": cfg.get("test_ssid", ""),
    }
    guard.write_config_partial(updates)
    log("配置已保存: {}".format(updates))


def make_tray_image(color):
    """画一个圆形托盘图标。"""
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse([6, 6, 58, 58], fill=color, outline=(255, 255, 255, 230), width=3)
    d.ellipse([22, 22, 42, 42], fill=(255, 255, 255, 200))
    return img

TRAY_COLOR_RUN = (46, 125, 50, 255)     # 绿色 = 守护运行中
TRAY_COLOR_STOP = (158, 158, 158, 255)  # 灰色 = 已停止


# ---------------------------------------------------------------- 开机自启动（指向本 GUI）
def autostart_command():
    python_exe = sys.executable
    pythonw = python_exe.replace("python.exe", "pythonw.exe").replace("Python.exe", "Pythonw.exe")
    if not os.path.exists(pythonw):
        pythonw = python_exe
    return '"{}" "{}"'.format(pythonw, GUI_PATH)


def autostart_installed():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_READ) as k:
            winreg.QueryValueEx(k, RUN_VALUE_NAME)
        return True
    except FileNotFoundError:
        return False


def set_autostart(enable):
    if enable:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, RUN_VALUE_NAME, 0, winreg.REG_SZ, autostart_command())
        log("开机自启动已开启")
    else:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, RUN_VALUE_NAME)
        except FileNotFoundError:
            pass
        log("开机自启动已关闭")


# ---------------------------------------------------------------- 单实例 + 唤回窗口
_K32_LE = ctypes.WinDLL("kernel32", use_last_error=True)

def try_bring_to_front():
    hwnd = ctypes.windll.user32.FindWindowW(None, WINDOW_TITLE)
    if hwnd:
        ctypes.windll.user32.ShowWindow(hwnd, 9)  # SW_RESTORE
        ctypes.windll.user32.SetForegroundWindow(hwnd)
        return True
    return False


def acquire_mutex():
    _K32_LE.CreateMutexW(None, False, MUTEX_NAME)
    # 必须用 ctypes.get_last_error()（use_last_error=True），否则判断可能失效
    return ctypes.get_last_error() != 183  # ERROR_ALREADY_EXISTS


# ---------------------------------------------------------------- 监控线程
class Monitor(threading.Thread):
    def __init__(self, ui_queue):
        super().__init__(daemon=True)
        self.ui_queue = ui_queue
        self.stop_evt = threading.Event()
        self.ask_lock = threading.Event()   # 等待用户回答
        self.ask_answer = False             # True=放行 / False=关闭
        self.ask_timed_out = False          # 本次是否为超时触发
        self.ask_open = False               # 是否有待确认弹窗
        self.ask_payload = None             # 待确认数据（含 pids）
        self.ask_pids = set()               # 待确认的 PID 集合（供状态表标色）
        self.suspended_pids = set()         # 已被冻结等待确认的 PID

    def run(self):
        allowed = set()  # {(pid, 创建时间)}
        guard.resume_leaked_suspensions()  # P1-4：恢复上次泄漏的冻结进程
        log("GUI 监控线程启动")
        try:
            self._loop(allowed)
        finally:
            # P1-4：任何异常退出都恢复自己冻结的进程
            for pid in list(self.suspended_pids):
                guard.resume_pid(pid)
                log("finally 安全网: 恢复冻结进程 PID {}".format(pid))
            self.suspended_pids.clear()
            guard.clear_suspended()
            log("GUI 监控线程退出")

    def _loop(self, allowed):
        while not self.stop_evt.is_set():
            cfg = guard.load_config()
            interval = cfg["poll_interval"]

            try:
                ssid = (cfg.get("test_ssid") or "").strip() or guard.get_current_ssid()
            except Exception as e:
                log("获取 SSID 异常: {}".format(e))
                ssid = None

            on_net, ssid = guard.is_on_guard_network(cfg, ssid)

            try:
                pending, alive = guard.detect_pending(cfg) if on_net else ({}, set())
            except Exception as e:
                log("进程检测异常: {}".format(e))
                pending, alive = {}, set()

            allowed = {(p, c) for (p, c) in allowed if (p, c) in alive}
            pending = {g: [(n, p, i) for (n, p, i) in items if (p, i[0]) not in allowed]
                       for g, items in pending.items()}
            pending = {g: items for g, items in pending.items() if items}

            all_procs = [(n, p) for items in pending.values() for n, p, _ in items]
            self.ui_queue.put(("status", {
                "ssid": ssid, "on_net": on_net, "interval": interval,
                "procs": all_procs, "allowed": {p for p, _ in allowed},
            }))

            if pending:
                group_lines = []
                all_items = []
                for g, items in sorted(pending.items()):
                    group_lines.append("{}（{}）".format(g, ", ".join(n for n, _, _ in items)))
                    all_items.extend(items)
                pids_desc = [(n, p) for n, p, _ in all_items]
                log("受控网络「{}」发现进程: {}，先冻结等待确认".format(ssid, pids_desc))

                # 冻结 + 持久化（P1-4 安全网）
                suspended_entries = []
                freeze_failed = []
                self.suspended_pids.clear()
                for n, p, ident in all_items:
                    if guard.suspend_pid(p):
                        suspended_entries.append([p, ident[1], ident[0]])
                        self.suspended_pids.add(p)
                    else:
                        freeze_failed.append(n)
                        log("冻结进程 {} (PID {}) 失败，确认前它将继续运行".format(n, p))
                guard.save_suspended(suspended_entries)

                # 弹窗询问（UI 线程渲染；对话框自身负责倒计时超时）
                self.ask_payload = {"pids": all_items}
                self.ask_pids = {p for _, p, _ in all_items}
                self.ask_open = True
                self.ask_answer = False
                self.ask_timed_out = False
                self.ask_lock.clear()
                self.ui_queue.put(("ask", {
                    "ssid": ssid, "groups": group_lines,
                    "freeze_failed": freeze_failed,
                    "timeout": cfg["ask_timeout"],
                    "timeout_action": cfg["timeout_action"],
                }))
                # 对话框保证超时后会 set；+60s 纯兜底
                self.ask_lock.wait(timeout=cfg["ask_timeout"] + 60)
                if self.stop_evt.is_set():
                    # 停止守护：恢复运行而不是关闭（用户主动停止管控）
                    for pid in list(self.suspended_pids):
                        guard.resume_pid(pid)
                    self.suspended_pids.clear()
                    guard.clear_suspended()
                    break
                timed_out = self.ask_timed_out
                self.ask_payload = None
                self.ask_pids = set()
                self.ask_open = False

                if timed_out:
                    log("等待确认超时（{} 秒），按配置默认动作: {}".format(
                        cfg["ask_timeout"], "放行" if self.ask_answer else "关闭"))
                elif self.ask_answer:
                    log("用户确认允许: {}".format(pids_desc))
                else:
                    log("用户取消，开始关闭: {}".format(pids_desc))

                # 逐个处理（带 PID 三元组校验，P1-5）
                for n, p, ident in all_items:
                    if not guard.identity_matches(p, ident):
                        log("PID {} ({}) 身份已变化（退出或被系统复用），跳过操作".format(p, n))
                        self.suspended_pids.discard(p)
                        continue
                    if self.ask_answer:
                        if guard.resume_pid(p):
                            allowed.add((p, ident[0]))
                        else:
                            log("恢复进程 {} (PID {}) 失败".format(n, p))
                    else:
                        ok = guard.graceful_kill(p)  # P0-1：优雅关闭优先
                        log("已关闭 {} (PID {}) -> {}".format(n, p, "成功" if ok else "失败"))
                    self.suspended_pids.discard(p)
                guard.clear_suspended()

                # P0-1：关闭代理类应用后自愈残留的系统代理
                if not self.ask_answer and cfg["post_kill_restore_proxy"]:
                    guard.restore_system_proxy_if_dead()

            self.stop_evt.wait(interval if on_net else cfg["idle_interval"])


# ---------------------------------------------------------------- 主界面
class GuardGUI:
    def __init__(self, root):
        self.root = root
        root.title(WINDOW_TITLE)
        root.geometry("660x700")
        root.minsize(560, 600)
        root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.ui_queue = queue.Queue()
        self.monitor = None
        self.ask_window = None
        self._log_offset = 0

        self._build_ui()
        self._load_config_to_ui()
        self._refresh_log(initial=True)
        self._setup_tray()

        root.after(300, self._poll_queue)
        root.after(1000, self._tick_log)
        root.after(1500, self._tick_status_when_idle)
        # 启动即自动开始守护（开机自启动场景无需手动点击）
        self._start_monitor()

    # ---------- 系统托盘 ----------
    def _setup_tray(self):
        self.tray = None
        if not TRAY_OK:
            return
        try:
            is_running = lambda item=None: bool(self.monitor and self.monitor.is_alive())
            menu = pystray.Menu(
                pystray.MenuItem("显示主窗口", self._tray_show, default=True),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("开启守护", self._tray_start, visible=lambda item: not is_running(item)),
                pystray.MenuItem("停止守护", self._tray_stop, visible=is_running),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("退出程序", self._tray_exit),
            )
            icon = pystray.Icon(
                "NetworkGuard",
                make_tray_image(TRAY_COLOR_STOP),
                "网络管控 - 守护未启动",
                menu,
            )
            icon.run_detached()
            self.tray = icon
        except Exception as e:
            log("托盘初始化失败: {}".format(e))
            self.tray = None

    def _tray_show(self, icon=None, item=None):
        self.root.after(0, self._show_window)

    def _tray_start(self, icon=None, item=None):
        self.root.after(0, lambda: (self._start_monitor(), self._update_tray()))

    def _tray_stop(self, icon=None, item=None):
        self.root.after(0, lambda: (self._stop_monitor(), self._update_tray()))

    def _tray_exit(self, icon=None, item=None):
        self.root.after(0, self._quit_all)
        self.root.after(100, self.root.destroy)

    def _show_window(self):
        self.root.deiconify()
        self.root.lift()
        try:
            self.root.attributes("-topmost", True)
            self.root.after(200, lambda: self.root.attributes("-topmost", False))
        except tk.TclError:
            pass

    def _update_tray(self):
        if not self.tray:
            return
        try:
            running = bool(self.monitor and self.monitor.is_alive())
            self.tray.icon = make_tray_image(TRAY_COLOR_RUN if running else TRAY_COLOR_STOP)
            self.tray.title = "网络管控 - 守护运行中" if running else "网络管控 - 守护未启动"
            self.tray.update_menu()
        except Exception:
            pass

    # ---------- 界面构建 ----------
    def _build_ui(self):
        pad = {"padx": 8, "pady": 4}

        # 状态区
        top = ttk.Frame(self.root)
        top.pack(fill="x", **pad)
        self.lbl_net = ttk.Label(top, text="当前网络：--", font=("Microsoft YaHei", 11, "bold"))
        self.lbl_net.pack(anchor="w")
        self.lbl_state = tk.Label(top, text="● 守护未启动", fg=COLOR_IDLE, font=("Microsoft YaHei", 10))
        self.lbl_state.pack(anchor="w")
        self.banner = tk.Label(self.root, text="", bg=COLOR_WARN_BG, fg=COLOR_DANGER,
                               font=("Microsoft YaHei", 10, "bold"), pady=6)

        # 受控网络
        grp_net = ttk.LabelFrame(self.root, text=" 受控网络（Wi-Fi 名称，命中即管控） ")
        grp_net.pack(fill="x", **pad)
        self.lst_ssids = tk.Listbox(grp_net, height=4, exportselection=False)
        self.lst_ssids.pack(side="left", fill="both", expand=True, padx=6, pady=6)
        fb = ttk.Frame(grp_net)
        fb.pack(side="right", padx=6, pady=6)
        self.ent_ssid = ttk.Entry(fb, width=22)
        self.ent_ssid.pack()
        ttk.Button(fb, text="添加", command=self._add_ssid).pack(pady=2, fill="x")
        ttk.Button(fb, text="删除选中", command=lambda: self._del_selected(self.lst_ssids)).pack(fill="x")

        # 受控应用
        grp_app = ttk.LabelFrame(self.root, text=" 受控应用（进程名；多进程应用可用 组:名字(进程1,进程2) 格式） ")
        grp_app.pack(fill="x", **pad)
        self.lst_apps = tk.Listbox(grp_app, height=4, exportselection=False)
        self.lst_apps.pack(side="left", fill="both", expand=True, padx=6, pady=6)
        fa = ttk.Frame(grp_app)
        fa.pack(side="right", padx=6, pady=6)
        self.ent_app = ttk.Entry(fa, width=22)
        self.ent_app.pack()
        ttk.Button(fa, text="添加", command=self._add_app).pack(pady=2, fill="x")
        ttk.Button(fa, text="删除选中", command=lambda: self._del_selected(self.lst_apps)).pack(fill="x")

        # 参数 + 保存
        grp_opt = ttk.LabelFrame(self.root, text=" 参数 ")
        grp_opt.pack(fill="x", **pad)
        row = ttk.Frame(grp_opt)
        row.pack(padx=6, pady=6)
        ttk.Label(row, text="检测间隔(秒)：").pack(side="left")
        self.spn_interval = ttk.Spinbox(row, from_=1, to=60, width=5)
        self.spn_interval.pack(side="left", padx=(0, 12))
        ttk.Label(row, text="空闲间隔(秒)：").pack(side="left")
        self.spn_idle = ttk.Spinbox(row, from_=1, to=120, width=5)
        self.spn_idle.pack(side="left", padx=(0, 12))
        ttk.Label(row, text="测试SSID：").pack(side="left")
        self.ent_test = ttk.Entry(row, width=14)
        self.ent_test.pack(side="left", padx=(0, 12))
        ttk.Button(row, text="保存配置", command=self._save_config).pack(side="left")
        ttk.Label(grp_opt, text="管控方式：命中受控网络时冻结受控应用并弹窗——允许=继续运行，关闭=先优雅退出再兜底强杀。"
                                "弹窗超时默认放行（ask_timeout/timeout_action 可在 config.json 配置）",
                  foreground="#666666", wraplength=620, justify="left").pack(anchor="w", padx=6, pady=(0, 6))

        # 受控进程实时表
        grp_proc = ttk.LabelFrame(self.root, text=" 当前运行的受控应用 ")
        grp_proc.pack(fill="both", expand=True, **pad)
        cols = ("name", "pid", "state")
        self.tree = ttk.Treeview(grp_proc, columns=cols, show="headings", height=5)
        for c, w, t in (("name", 220, "进程名"), ("pid", 100, "PID"), ("state", 160, "状态")):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True, padx=6, pady=6)
        pb = ttk.Frame(grp_proc)
        pb.pack(side="right", padx=6, pady=6)
        ttk.Button(pb, text="强制结束\n选中进程", command=self._kill_selected).pack(fill="x")

        # 日志
        grp_log = ttk.LabelFrame(self.root, text=" 运行日志 ")
        grp_log.pack(fill="both", expand=True, **pad)
        self.txt_log = scrolledtext.ScrolledText(grp_log, height=8, state="disabled",
                                                 font=("Consolas", 9))
        self.txt_log.pack(fill="both", expand=True, padx=6, pady=6)

        # 底部按钮区
        bot = ttk.Frame(self.root)
        bot.pack(fill="x", **pad)
        self.btn_toggle = ttk.Button(bot, text="停止守护", width=14, command=self.toggle_monitor)
        self.btn_toggle.pack(side="left")
        self.var_autostart = tk.BooleanVar(value=autostart_installed())
        ttk.Checkbutton(bot, text="开机自启动", variable=self.var_autostart,
                        command=self._on_autostart_toggle).pack(side="left", padx=12)
        ttk.Label(bot, text="关闭窗口=缩到右下角托盘继续守护；托盘图标左键=显示窗口，右键=开启/停止/退出",
                  foreground="#888888").pack(side="right")

    # ---------- 配置 <-> 界面 ----------
    def _load_config_to_ui(self):
        cfg = read_config()
        self.lst_ssids.delete(0, "end")
        for s in cfg["watch_ssids"]:
            self.lst_ssids.insert("end", s)
        self.lst_apps.delete(0, "end")
        for g in cfg["watch_apps"]:
            if g["processes"] == [g["name"]]:
                self.lst_apps.insert("end", g["name"])
            else:
                self.lst_apps.insert("end", "组:{}({})".format(g["name"], ",".join(g["processes"])))
        self.spn_interval.delete(0, "end")
        self.spn_interval.insert(0, str(cfg["poll_interval"]))
        self.spn_idle.delete(0, "end")
        self.spn_idle.insert(0, str(cfg.get("idle_interval", 5)))
        self.ent_test.delete(0, "end")
        self.ent_test.insert(0, cfg.get("test_ssid", ""))

    def _add_ssid(self):
        v = self.ent_ssid.get().strip()
        if v:
            self.lst_ssids.insert("end", v)
            self.ent_ssid.delete(0, "end")
            self._save_config(silent=True)  # 自动保存，立即生效

    def _add_app(self):
        v = self.ent_app.get().strip().lower()
        if v:
            self.lst_apps.insert("end", v)
            self.ent_app.delete(0, "end")
            self._save_config(silent=True)  # 自动保存，立即生效

    def _del_selected(self, listbox):
        if listbox.curselection():
            for i in reversed(listbox.curselection()):
                listbox.delete(i)
            self._save_config(silent=True)  # 自动保存，立即生效

    @staticmethod
    def _parse_app_line(line):
        """解析列表行 -> 单进程字符串 或 应用组 dict。"""
        line = line.strip()
        m = __import__("re").match(r"^组[:：](.+?)[\(（](.+)[\)）]$", line)
        if m:
            name = m.group(1).strip().lower()
            procs = [p.strip().lower() for p in __import__("re").split("[,，]", m.group(2)) if p.strip()]
            if name and procs:
                return {"group": name, "processes": procs}
            return None
        return line.lower()

    def _save_config(self, silent=False):
        apps = []
        for i in range(self.lst_apps.size()):
            parsed = self._parse_app_line(self.lst_apps.get(i))
            if parsed:
                apps.append(parsed)
        cfg = {
            "watch_ssids": list(self.lst_ssids.get(0, "end")),
            "watch_apps": apps,
            "poll_interval": max(1, int(float(self.spn_interval.get() or 2))),
            "idle_interval": max(1, int(float(self.spn_idle.get() or 5))),
            "test_ssid": self.ent_test.get().strip(),
        }
        write_config(cfg)
        if not silent:
            messagebox.showinfo("保存成功", "配置已保存，守护将按新配置继续运行。")

    # ---------- 监控控制 ----------
    def toggle_monitor(self):
        if self.monitor and self.monitor.is_alive():
            self._stop_monitor()
        else:
            self._start_monitor()

    def _start_monitor(self):
        self.monitor = Monitor(self.ui_queue)
        self.monitor.start()
        self.btn_toggle.config(text="停止守护")
        self._update_tray()
        log("守护已启动（GUI）")

    def _stop_monitor(self):
        m = self.monitor
        if m:
            m.stop_evt.set()
            if m.ask_open:
                # 停止守护 = 停止管控：放行（恢复运行）而不是关闭
                m.ask_answer = True
                m.ask_lock.set()
            # 恢复所有被冻结的进程，避免应用卡死
            for pid in list(m.suspended_pids):
                guard.resume_pid(pid)
                log("守护已停止，恢复冻结进程 PID {}".format(pid))
            m.suspended_pids.clear()
        self.monitor = None
        self.btn_toggle.config(text="开始守护")
        self._set_state(monitoring=False, ssid=None, on_net=False, procs=[], allowed=set())
        self._update_tray()

    def _kill_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        for iid in sel:
            values = self.tree.item(iid, "values")
            name, pid = values[0], int(values[1])
            ok = guard.graceful_kill(pid)
            log("手动关闭进程 {} (PID {}) -> {}".format(name, pid, "成功" if ok else "失败"))

    # ---------- 状态渲染 ----------
    def _set_state(self, monitoring, ssid, on_net, procs, allowed):
        pending_pids = set(self.monitor.ask_pids) if (self.monitor and self.monitor.ask_open) else set()

        if not monitoring:
            self.lbl_net.config(text="当前网络：--")
            self.lbl_state.config(text="● 守护未启动", fg=COLOR_IDLE)
            self.banner.pack_forget()
        elif on_net:
            self.lbl_net.config(text="当前网络：{}（受控网络）".format(ssid))
            self.lbl_state.config(text="● 守护运行中，受控规则已生效", fg=COLOR_DANGER)
            self.banner.config(text="⚠ 已连接受控网络「{}」，正在监控受控应用！".format(ssid))
            self.banner.pack(fill="x", padx=8, pady=0)
        else:
            self.lbl_net.config(text="当前网络：{}".format(ssid or "未连接 Wi-Fi"))
            self.lbl_state.config(text="● 守护运行中，当前网络不受控", fg=COLOR_SAFE)
            self.banner.pack_forget()

        # 进程表
        self.tree.delete(*self.tree.get_children())
        for n, p in procs:
            if p in pending_pids:
                state = "已冻结待确认"
            elif (p, None) in allowed or p in allowed:
                state = "已放行（本次）"
            else:
                state = "已检测"
            self.tree.insert("", "end", values=(n, p, state))

    def _tick_status_when_idle(self):
        """守护未启动时也周期刷新一次当前网络显示。"""
        if not self.root.winfo_exists():
            return
        if not (self.monitor and self.monitor.is_alive()):
            try:
                cfg = read_config()
                ssid = (cfg.get("test_ssid") or "").strip() or guard.get_current_ssid()
                self.lbl_net.config(text="当前网络：{}".format(ssid or "未连接 Wi-Fi"))
            except Exception:
                pass
        self.root.after(3000, self._tick_status_when_idle)

    # ---------- 队列处理 ----------
    def _poll_queue(self):
        if not self.root.winfo_exists():
            return
        try:
            while True:
                kind, data = self.ui_queue.get_nowait()
                if kind == "status":
                    if self.monitor and self.monitor.is_alive():
                        self._set_state(True, data["ssid"], data["on_net"],
                                        data["procs"], data["allowed"])
                elif kind == "ask":
                    self._show_ask_dialog(data)
        except queue.Empty:
            pass
        self.root.after(300, self._poll_queue)

    def _show_ask_dialog(self, data):
        """带倒计时的非模态警告框（P0-3/P2-3/P2-4）。"""
        try:
            if self.ask_window and self.ask_window.winfo_exists():
                self.ask_window.destroy()
        except Exception:
            pass

        win = tk.Toplevel(self.root)
        win.title("网络管控警告")
        win.attributes("-topmost", True)
        win.resizable(False, False)
        frm = tk.Frame(win, padx=16, pady=12)
        frm.pack()

        tk.Label(frm, text="当前已连接受控网络「{}」。".format(data["ssid"]),
                 font=("Microsoft YaHei", 11, "bold")).pack(anchor="w")
        tk.Label(frm, text="以下受管控的应用已启动，现已被冻结暂停、无法运行：",
                 wraplength=440, justify="left").pack(anchor="w", pady=(8, 2))
        for line in data["groups"]:
            tk.Label(frm, text="  - " + line, fg="#c62828",
                     wraplength=440, justify="left").pack(anchor="w")
        if data.get("freeze_failed"):
            tk.Label(frm, text="（未能冻结，将继续运行直到你选择）：{}".format(", ".join(data["freeze_failed"])),
                     fg="#e65100", wraplength=440, justify="left").pack(anchor="w", pady=(4, 0))
        tk.Label(frm, text="点【允许运行】继续；点【强制关闭】将先尝试优雅退出、超时后强制结束（可能丢失未保存数据）。",
                 wraplength=440, justify="left").pack(anchor="w", pady=(8, 2))

        cd_lbl = tk.Label(frm, text="", fg="#888888")
        cd_lbl.pack(anchor="e")

        def resolve(ans, timed=False):
            m = self.monitor
            if m and m.ask_open:
                m.ask_answer = bool(ans)
                m.ask_timed_out = timed
                m.ask_lock.set()
            try:
                win.destroy()
            except Exception:
                pass
            self.ask_window = None

        def on_timeout():
            resolve(data["timeout_action"] == "allow", timed=True)

        remaining = [max(5, int(data["timeout"]))]
        timeout_action = data["timeout_action"]

        def tick():
            if not win.winfo_exists():
                return
            remaining[0] -= 1
            if remaining[0] <= 0:
                on_timeout()
                return
            cd_lbl.config(text="{} 秒后自动{}".format(remaining[0], "允许运行" if timeout_action == "allow" else "强制关闭"))
            cd_lbl.config(fg="#c62828" if remaining[0] <= 30 else "#888888")
            win.after(1000, tick)

        btns = tk.Frame(frm)
        btns.pack(fill="x", pady=(10, 0))
        tk.Button(btns, text="允许运行", width=12, command=lambda: resolve(True)).pack(side="right", padx=(8, 0))
        tk.Button(btns, text="强制关闭", width=12, command=lambda: resolve(False)).pack(side="right")
        win.protocol("WM_DELETE_WINDOW", lambda: resolve(False))
        win.after(1000, tick)
        self.ask_window = win

    # ---------- 日志窗口 ----------
    def _refresh_log(self, initial=False):
        try:
            size = os.path.getsize(LOG_PATH)
            if initial:
                with io.open(LOG_PATH, "rb") as f:
                    data = f.read()
                text = data[-4000:].decode("utf-8", errors="replace")
                self._log_offset = max(0, size - len(text.encode("utf-8")))
            elif size < self._log_offset:
                # 日志被轮转了，重新开始
                self._log_offset = 0
                return
            elif size == self._log_offset:
                return
            else:
                with io.open(LOG_PATH, "rb") as f:
                    f.seek(self._log_offset)
                    text = f.read().decode("utf-8", errors="replace")
                self._log_offset = size
            self.txt_log.config(state="normal")
            self.txt_log.insert("end", text)
            self.txt_log.see("end")
            self.txt_log.config(state="disabled")
        except OSError:
            pass

    def _tick_log(self):
        if not self.root.winfo_exists():
            return
        self._refresh_log()
        self.root.after(1000, self._tick_log)

    # ---------- 自启动 ----------
    def _on_autostart_toggle(self):
        try:
            set_autostart(self.var_autostart.get())
        except OSError as e:
            messagebox.showerror("失败", "修改自启动失败：{}".format(e))
            self.var_autostart.set(autostart_installed())

    # ---------- 关闭行为 ----------
    def on_close(self):
        """关闭窗口 = 隐藏到托盘后台，守护继续运行；从托盘菜单退出才算真正退出。"""
        self.root.withdraw()
        log("窗口已隐藏到托盘，守护继续在后台运行")
        if self.tray:
            try:
                self.tray.notify("程序已最小化到托盘，守护继续运行。\n左键图标=显示窗口，右键=开启/停止/退出。",
                                 "网络管控")
            except Exception:
                pass

    def _quit_all(self):
        m = self.monitor
        if m:
            m.stop_evt.set()
            if m.ask_open:
                m.ask_answer = True  # 退出程序 = 停止管控，恢复运行
                m.ask_lock.set()
            for pid in list(m.suspended_pids):
                guard.resume_pid(pid)
                log("退出安全网: 恢复冻结进程 PID {}".format(pid))
            m.suspended_pids.clear()
        if self.tray:
            try:
                self.tray.stop()
            except Exception:
                pass
        log("程序退出")


# ---------------------------------------------------------------- 入口
def main():
    # 命令行参数（与 guard.pyw 一致）
    if "--install" in sys.argv:
        set_autostart(True)
        print("开机自启动已注册: {}".format(autostart_command()))
        return
    if "--uninstall" in sys.argv:
        set_autostart(False)
        print("开机自启动已取消。")
        return
    if "--status" in sys.argv:
        print("开机自启动已注册" if autostart_installed() else "未注册开机自启动。")
        return

    if not acquire_mutex():
        # 已有实例（可能是隐藏到托盘的）：重试唤回其窗口 5 秒，然后静默退出
        for _ in range(50):
            if try_bring_to_front():
                return
            time.sleep(0.1)
        log("检测到已有实例在运行但未找到其窗口，本次启动退出。")
        return

    root = tk.Tk()
    GuardGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
