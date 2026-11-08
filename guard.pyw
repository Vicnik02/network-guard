# -*- coding: utf-8 -*-
"""
Network Guard - 网络管控守护程序（核心模块）
============================================
功能：
  1. 开机自启动（写注册表 HKCU Run 键）
  2. 后台静默监控当前 Wi-Fi SSID（wlanapi 原生 API）
  3. 命中受控网络时：发现受控应用立即冻结（NtSuspendProcess）并询问
     - 允许 -> NtResumeProcess 恢复运行
     - 关闭 -> 优雅退出优先（WM_CLOSE/树杀），最后才 TerminateProcess 兜底
  4. 安全设计：
     - PID 三元组校验（PID+镜像路径+创建时间），防 PID 复用误杀
     - 冻结列表持久化，守护崩溃后重启可自动恢复泄漏的冻结进程
     - 弹窗超时默认放行（可配置 timeout_action）
     - 关闭代理类应用后自动检测并修复残留的系统代理设置

用法：
  pythonw guard.pyw              启动守护（静默运行）
  python guard.pyw --install     注册开机自启动
  python guard.pyw --uninstall   取消开机自启动
  python guard.pyw --status      查看自启动是否已注册

配置文件：同目录下 config.json（修改后无需重启，每个轮询周期自动重载）
"""

import csv
import ctypes
from ctypes import wintypes
import io
import json
import os
import re
import socket
import subprocess
import sys
import time
import winreg

# ---------------------------------------------------------------- 基本路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
LOG_PATH = os.path.join(BASE_DIR, "guard.log")
SUSPENDED_PATH = os.path.join(BASE_DIR, "guard_suspended.json")

RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE_NAME = "NetworkGuard"
MUTEX_NAME = "NetworkGuard_SingleInstance_Mutex"

DEFAULT_CONFIG = {
    "watch_ssids": [],              # 受控网络的 Wi-Fi 名称列表
    "watch_apps": [],               # 字符串（单进程）或 {"group": 名, "processes": [...]}（应用组）
    "watch_paths": [],              # 可选：exe 路径前缀白名单，防止同名 exe 误伤
    "poll_interval": 2,             # 受控网络上的检测间隔（秒）
    "idle_interval": 5,             # 不在受控网络时的 SSID 轮询间隔（秒）
    "test_ssid": "",                # 测试用：填了就当作当前 SSID
    "ask_timeout": 180,             # 弹窗等待确认的超时（秒）
    "timeout_action": "allow",      # 超时默认动作：allow=放行 / kill=关闭
    "post_kill_restore_proxy": True,  # 关闭应用后检测系统代理残留并自愈
}

# 所有子进程调用都加 CREATE_NO_WINDOW，避免 pythonw 下弹出黑框
CREATE_NO_WINDOW = 0x08000000

_KERNEL32 = ctypes.windll.kernel32
_NTDLL = ctypes.windll.ntdll
_K32_LE = ctypes.WinDLL("kernel32", use_last_error=True)
_PROCESS_SUSPEND_RESUME = 0x0800
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_PROCESS_TERMINATE = 0x0001
_STILL_ACTIVE = 259
_INTERNET_SETTINGS_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


# ---------------------------------------------------------------- 日志（超过 1MB 自动轮转）
def log(msg):
    line = "[{}] {}".format(time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        try:
            if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > 1024 * 1024:
                try:
                    os.remove(LOG_PATH + ".1")
                except OSError:
                    pass
                os.replace(LOG_PATH, LOG_PATH + ".1")
        except OSError:
            pass
        with io.open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------- 配置
def _normalize_apps(raw):
    """把 watch_apps 归一化为 [{"name": 组名, "processes": [进程名小写]}]。"""
    groups = []
    for item in raw or []:
        if isinstance(item, dict):
            name = str(item.get("group") or item.get("name") or "").strip()
            procs = sorted({str(p).strip().lower() for p in item.get("processes", []) if str(p).strip()})
            if name and procs:
                groups.append({"name": name, "processes": procs})
        else:
            s = str(item).strip().lower()
            if s:
                groups.append({"name": s, "processes": [s]})
    return groups


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    try:
        with io.open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            cfg.update(data)
    except Exception as e:
        log("配置读取失败，使用默认/上次配置: {}".format(e))
    cfg["watch_apps"] = _normalize_apps(cfg.get("watch_apps", []))
    cfg["watch_paths"] = [str(p).rstrip("\\/").lower() for p in cfg.get("watch_paths", []) if str(p).strip()]
    cfg["watch_ssids"] = [str(s).strip() for s in cfg.get("watch_ssids", []) if str(s).strip()]
    try:
        cfg["poll_interval"] = max(1, int(cfg.get("poll_interval", 2)))
    except (TypeError, ValueError):
        cfg["poll_interval"] = 2
    try:
        cfg["idle_interval"] = max(1, int(cfg.get("idle_interval", 5)))
    except (TypeError, ValueError):
        cfg["idle_interval"] = 5
    try:
        cfg["ask_timeout"] = max(5, int(cfg.get("ask_timeout", 180)))
    except (TypeError, ValueError):
        cfg["ask_timeout"] = 180
    cfg["timeout_action"] = "kill" if str(cfg.get("timeout_action", "allow")).strip().lower() == "kill" else "allow"
    cfg["post_kill_restore_proxy"] = bool(cfg.get("post_kill_restore_proxy", True))
    return cfg


def build_app_map(cfg):
    """{进程名小写: 组名}。"""
    mapping = {}
    for g in cfg["watch_apps"]:
        for p in g["processes"]:
            mapping[p] = g["name"]
    return mapping


def write_config_partial(updates):
    """更新部分配置键，保留文件中的其他自定义键。"""
    try:
        with io.open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}
    data.update(updates)
    with io.open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------- 命令执行（正确处理中文控制台编码，不弹黑框）
def run_cmd(args):
    p = subprocess.run(args, capture_output=True, creationflags=CREATE_NO_WINDOW)
    enc = _console_encoding()
    for e in (enc, "utf-8", "gbk"):
        try:
            return p.stdout.decode(e)
        except (UnicodeDecodeError, LookupError):
            continue
    return p.stdout.decode("utf-8", errors="replace")


_CODEPAGE_CACHE = None
def _console_encoding():
    global _CODEPAGE_CACHE
    if _CODEPAGE_CACHE:
        return _CODEPAGE_CACHE
    enc = "gbk"
    try:
        out = subprocess.run("chcp", capture_output=True, shell=True,
                             creationflags=CREATE_NO_WINDOW).stdout.decode("ascii", "replace")
        m = re.search(r"(\d+)", out)
        if m:
            cp = int(m.group(1))
            enc = {936: "gbk", 65001: "utf-8", 950: "big5", 437: "cp437", 1252: "cp1252"}.get(cp, "gbk")
    except Exception:
        pass
    _CODEPAGE_CACHE = enc
    return enc


# ---------------------------------------------------------------- 网络检测（wlanapi 原生 API，无子进程）
_WLAN = ctypes.windll.wlanapi

class _GUID(ctypes.Structure):
    _fields_ = [("D1", ctypes.c_ulong), ("D2", ctypes.c_ushort),
                ("D3", ctypes.c_ushort), ("D4", ctypes.c_ubyte * 8)]

class _WLAN_IF_INFO(ctypes.Structure):
    _fields_ = [("Guid", _GUID), ("Desc", ctypes.c_wchar * 256)]

def _ssid_via_wlanapi():
    import ctypes.wintypes as wt
    h = ctypes.c_void_p()
    neg = wt.DWORD()
    if _WLAN.WlanOpenHandle(2, None, ctypes.byref(neg), ctypes.byref(h)) != 0:
        return None
    try:
        plist = ctypes.c_void_p()
        if _WLAN.WlanEnumInterfaces(h, None, ctypes.byref(plist)) != 0:
            return None
        n = ctypes.cast(plist, ctypes.POINTER(ctypes.c_ulong)).contents.value
        if n <= 0:
            _WLAN.WlanFreeMemory(plist)
            return None
        arr = ctypes.cast(plist.value + 8, ctypes.POINTER(_WLAN_IF_INFO * n)).contents
        size = ctypes.c_ulong()
        data = ctypes.c_void_p()
        rc = _WLAN.WlanQueryInterface(h, ctypes.byref(arr[0].Guid), 7, None,
                                      ctypes.byref(size), ctypes.byref(data), None)
        if rc != 0 or not data.value:
            _WLAN.WlanFreeMemory(plist)
            return None
        buf = ctypes.string_at(data.value, size.value)
        ssid_size = int.from_bytes(buf[520:524], "little")
        ssid = buf[524:524 + ssid_size].decode("utf-8", "replace") if 0 < ssid_size <= 32 else None
        _WLAN.WlanFreeMemory(ctypes.c_void_p(data.value))
        _WLAN.WlanFreeMemory(plist)
        return ssid
    finally:
        _WLAN.WlanCloseHandle(h, None)


def _ssid_via_netsh():
    out = run_cmd(["netsh", "wlan", "show", "interfaces"])
    for line in out.splitlines():
        m = re.match(r"\s*SSID\s*:\s*(.*?)\s*$", line)  # 不会误匹配 BSSID
        if m and m.group(1):
            return m.group(1)
    return None


def get_current_ssid():
    try:
        ssid = _ssid_via_wlanapi()
        if ssid is not None:
            return ssid
    except Exception:
        pass
    return _ssid_via_netsh()


def is_on_guard_network(cfg, current_ssid):
    if not cfg["watch_ssids"]:
        return False, current_ssid
    if current_ssid is None:
        return False, None
    cur = current_ssid.strip().lower()
    for s in cfg["watch_ssids"]:
        if s.strip().lower() == cur:
            return True, current_ssid
    return False, current_ssid


# ---------------------------------------------------------------- 进程身份（PID 三元组，防 PID 复用误杀）
def get_process_identity(pid):
    """返回 (创建时间 FILETIME int, exe 完整路径小写)；进程已退出或无权限返回 None。"""
    h = _KERNEL32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        ct, et, kt, ut = (wintypes.FILETIME() for _ in range(4))
        if not _KERNEL32.GetProcessTimes(h, ctypes.byref(ct), ctypes.byref(et),
                                         ctypes.byref(kt), ctypes.byref(ut)):
            return None
        creation = (ct.dwHighDateTime << 32) | ct.dwLowDateTime
        size = wintypes.DWORD(1024)
        buf = ctypes.create_unicode_buffer(1024)
        if not _KERNEL32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return None
        return (creation, buf.value.lower())
    finally:
        _KERNEL32.CloseHandle(h)


def pid_alive(pid):
    h = _KERNEL32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return False
    try:
        code = wintypes.DWORD()
        if not _KERNEL32.GetExitCodeProcess(h, ctypes.byref(code)):
            return False
        return code.value == _STILL_ACTIVE
    finally:
        _KERNEL32.CloseHandle(h)


def identity_matches(pid, identity):
    """校验 PID 当前归属与记录的 (创建时间, 路径) 一致（防 PID 复用）。"""
    if not pid_alive(pid):
        return False
    cur = get_process_identity(pid)
    return cur is not None and cur == identity


# ---------------------------------------------------------------- 进程检测（Toolhelp32 原生 API）
_TH32CS_SNAPPROCESS = 0x2

class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong),
                ("th32ProcessID", ctypes.c_ulong),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", ctypes.c_ulong), ("cntThreads", ctypes.c_ulong),
                ("th32ParentProcessID", ctypes.c_ulong),
                ("pcPriClassBase", ctypes.c_long), ("dwFlags", ctypes.c_ulong),
                ("szExeFile", ctypes.c_wchar * 260)]


def _find_processes_toolhelp(app_names):
    result = []
    snap = _KERNEL32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if snap in (-1, 0xFFFFFFFFFFFFFFFF):
        raise OSError("CreateToolhelp32Snapshot failed")
    try:
        pe = _PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
        if _KERNEL32.Process32FirstW(snap, ctypes.byref(pe)):
            while True:
                name = pe.szExeFile.lower()
                if name in app_names:
                    result.append((name, pe.th32ProcessID))
                if not _KERNEL32.Process32NextW(snap, ctypes.byref(pe)):
                    break
    finally:
        _KERNEL32.CloseHandle(snap)
    return result


def _find_processes_tasklist(app_names):
    out = run_cmd(["tasklist", "/FO", "CSV", "/NH"])
    result = []
    for row in csv.reader(io.StringIO(out)):
        if len(row) >= 2:
            name = row[0].strip().strip('"').lower()
            pid_s = row[1].strip().strip('"')
            if name in app_names and pid_s.isdigit():
                result.append((name, int(pid_s)))
    return result


def find_processes(app_names):
    if not app_names:
        return []
    wanted = set(app_names)
    try:
        return _find_processes_toolhelp(wanted)
    except Exception as e:
        log("进程快照异常，改用 tasklist: {}".format(e))
        return _find_processes_tasklist(wanted)


# ---------------------------------------------------------------- 进程冻结/恢复/结束
def suspend_pid(pid):
    try:
        h = _KERNEL32.OpenProcess(_PROCESS_SUSPEND_RESUME, False, pid)
        if not h:
            return False
        rc = _NTDLL.NtSuspendProcess(h)
        _KERNEL32.CloseHandle(h)
        return rc == 0
    except Exception:
        return False


def resume_pid(pid):
    try:
        h = _KERNEL32.OpenProcess(_PROCESS_SUSPEND_RESUME, False, pid)
        if not h:
            return False
        rc = _NTDLL.NtResumeProcess(h)
        _KERNEL32.CloseHandle(h)
        return rc == 0
    except Exception:
        return False


def kill_pid(pid):
    """最后的兜底：TerminateProcess 硬杀（可能丢失未保存状态）。"""
    try:
        h = _KERNEL32.OpenProcess(_PROCESS_TERMINATE, False, pid)
        if h:
            ok = bool(_KERNEL32.TerminateProcess(h, 1))
            _KERNEL32.CloseHandle(h)
            if ok:
                return True
    except Exception:
        pass
    r = subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                       capture_output=True, creationflags=CREATE_NO_WINDOW)
    return r.returncode == 0


def graceful_kill(pid, timeout=8):
    """优雅关闭优先：恢复(若冻结) -> taskkill 发 WM_CLOSE（含子进程树）-> 等待 -> /T /F 树杀 -> 硬杀兜底。

    返回 True 表示进程已结束。
    """
    resume_pid(pid)  # 冻结中的进程无法处理窗口消息，先恢复
    # 温和关闭：不带 /F 的 taskkill 会对有窗口的进程发 WM_CLOSE
    subprocess.run(["taskkill", "/T", "/PID", str(pid)],
                   capture_output=True, creationflags=CREATE_NO_WINDOW)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not pid_alive(pid):
            return True
        time.sleep(0.3)
    # 树杀兜底（含子进程，P0-2）
    subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)],
                   capture_output=True, creationflags=CREATE_NO_WINDOW)
    deadline = time.time() + 3
    while time.time() < deadline:
        if not pid_alive(pid):
            return True
        time.sleep(0.2)
    return kill_pid(pid)


# ---------------------------------------------------------------- 冻结列表持久化（守护异常退出后的安全网，P1-4）
def save_suspended(entries):
    """entries: [[pid, exe完整路径小写, 创建时间], ...]"""
    try:
        with io.open(SUSPENDED_PATH, "w", encoding="utf-8") as f:
            json.dump({"suspended": entries}, f)
    except OSError as e:
        log("保存冻结列表失败: {}".format(e))


def load_suspended():
    try:
        with io.open(SUSPENDED_PATH, "r", encoding="utf-8") as f:
            return json.load(f).get("suspended", [])
    except Exception:
        return []


def clear_suspended():
    try:
        os.remove(SUSPENDED_PATH)
    except OSError:
        pass


def resume_leaked_suspensions():
    """守护异常退出会遗留冻结的进程；启动时按三元组校验后逐个恢复。"""
    entries = load_suspended()
    if not entries:
        return
    for pid, path, creation in entries:
        try:
            pid, creation = int(pid), int(creation)
        except (TypeError, ValueError):
            continue
        if identity_matches(pid, (creation, str(path).lower())):
            if resume_pid(pid):
                log("安全网: 已恢复上次泄漏的冻结进程 {} (PID {})".format(path, pid))
            else:
                log("安全网: 恢复 {} (PID {}) 失败".format(path, pid))
        else:
            log("安全网: 记录的进程 {} (PID {}) 已退出或 PID 被复用，跳过".format(path, pid))
    clear_suspended()


# ---------------------------------------------------------------- 系统代理残留自愈（P0-1）
def _port_listening(host, port, timeout=0.6):
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def restore_system_proxy_if_dead():
    """系统代理开启但代理端口无进程监听时，自动关闭系统代理并广播生效。"""
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS_PATH, 0,
                           winreg.KEY_READ | winreg.KEY_WRITE)
    except OSError as e:
        log("系统代理自愈: 打开注册表失败 {}".format(e))
        return
    try:
        try:
            enable, _ = winreg.QueryValueEx(k, "ProxyEnable")
        except FileNotFoundError:
            return
        if not enable:
            return
        try:
            server, _ = winreg.QueryValueEx(k, "ProxyServer")
        except FileNotFoundError:
            server = ""
        # 解析 ProxyServer：支持 "127.0.0.1:7897" 与 "http=...;https=...;socks=..." 两种格式
        endpoints = []
        s = str(server)
        parts = s.split(";") if ";" in s else [s]
        for part in parts:
            if "=" in part:
                part = part.split("=", 1)[1]
            part = part.strip()
            if ":" in part:
                h, p = part.rsplit(":", 1)
                if p.isdigit():
                    endpoints.append((h.strip(), p))
        if endpoints and any(_port_listening(h, p) for h, p in endpoints):
            return  # 代理端口还有进程监听，不需要处理
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        log("系统代理自愈: 代理已开启但端口无人监听({})，已自动关闭系统代理".format(server))
    finally:
        winreg.CloseKey(k)
    # 通知系统代理设置已变更（无需重启）
    try:
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(None, 39, None, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        wininet.InternetSetOptionW(None, 37, None, 0)  # INTERNET_OPTION_REFRESH
    except Exception:
        pass


# ---------------------------------------------------------------- 冻结询问对话框（无界面守护模式用，带倒计时）
def ask_user_allow(ssid, group_lines, timeout, timeout_action, freeze_failed):
    """阻塞式询问。返回 (allowed_bool, timed_out)。"""
    import tkinter as tk
    result = {"answer": None, "timeout": False}

    root = tk.Tk()
    root.title("网络管控警告")
    root.attributes("-topmost", True)
    root.resizable(False, False)
    frm = tk.Frame(root, padx=16, pady=12)
    frm.pack()

    tk.Label(frm, text="当前已连接受控网络「{}」。".format(ssid),
             font=("Microsoft YaHei", 11, "bold")).pack(anchor="w")
    tk.Label(frm, text="以下受管控的应用已启动，现已被冻结暂停、无法运行：",
             wraplength=420, justify="left").pack(anchor="w", pady=(8, 2))
    for line in group_lines:
        tk.Label(frm, text="  - " + line, fg="#c62828",
                 wraplength=420, justify="left").pack(anchor="w")
    if freeze_failed:
        tk.Label(frm, text="（未能冻结，将继续运行直到你选择）：{}".format(", ".join(freeze_failed)),
                 fg="#e65100", wraplength=420, justify="left").pack(anchor="w", pady=(4, 0))
    tk.Label(frm, text="点【允许运行】继续；点【强制关闭】将先尝试优雅退出、超时后强制结束（可能丢失未保存数据）。",
             wraplength=420, justify="left").pack(anchor="w", pady=(8, 2))

    cd_lbl = tk.Label(frm, text="", fg="#888888")
    cd_lbl.pack(anchor="e")

    def finish(ans, timed=False):
        if result["answer"] is None:
            result["answer"] = ans
            result["timeout"] = timed
        root.destroy()

    def on_timeout():
        finish(timeout_action == "allow", timed=True)

    remaining = [max(5, int(timeout))]

    def tick():
        remaining[0] -= 1
        if remaining[0] <= 0:
            on_timeout()
            return
        cd_lbl.config(text="{} 秒后自动{}".format(remaining[0], "允许运行" if timeout_action == "allow" else "强制关闭"))
        if remaining[0] <= 30:
            cd_lbl.config(fg="#c62828")
        root.after(1000, tick)

    btns = tk.Frame(frm)
    btns.pack(fill="x", pady=(10, 0))
    tk.Button(btns, text="允许运行", width=12, command=lambda: finish(True)).pack(side="right", padx=(8, 0))
    tk.Button(btns, text="强制关闭", width=12, command=lambda: finish(False)).pack(side="right")
    root.protocol("WM_DELETE_WINDOW", lambda: finish(False))
    root.after(1000, tick)
    root.mainloop()
    return bool(result["answer"]), bool(result["timeout"])


# ---------------------------------------------------------------- 开机自启动
def autostart_command():
    pythonw = sys.executable.replace("python.exe", "pythonw.exe").replace("Python.exe", "Pythonw.exe")
    if not os.path.exists(pythonw):
        pythonw = sys.executable
    return '"{}" "{}"'.format(pythonw, os.path.abspath(__file__))


def install_autostart():
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, RUN_VALUE_NAME, 0, winreg.REG_SZ, autostart_command())
    print("开机自启动已注册：{}".format(autostart_command()))


def uninstall_autostart():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, RUN_VALUE_NAME)
        print("开机自启动已取消。")
    except FileNotFoundError:
        print("未找到自启动注册项（本来就没注册）。")


def autostart_status():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_READ) as k:
            val, _ = winreg.QueryValueEx(k, RUN_VALUE_NAME)
        print("已注册: {}".format(val))
        return True
    except FileNotFoundError:
        print("未注册开机自启动。")
        return False


# ---------------------------------------------------------------- 单实例保护
def acquire_single_instance():
    """返回 True 表示获得锁（首次运行）；False 表示已有实例在运行。"""
    _K32_LE.CreateMutexW(None, False, MUTEX_NAME)
    # 必须用 ctypes.get_last_error()（use_last_error=True），
    # 直接调 kernel32.GetLastError() 会被 ctypes 内部调用覆盖导致判断失效
    return ctypes.get_last_error() != 183  # ERROR_ALREADY_EXISTS


# ---------------------------------------------------------------- 待处理检测（应用组 + 路径白名单）
def detect_pending(cfg):
    """返回 (pending_groups, alive)。
    pending_groups: {组名: [(进程名, pid, (创建时间, 路径))]}，仅含未放行的进程。
    """
    app_map = build_app_map(cfg)
    procs = find_processes(list(app_map.keys()))
    alive = set()
    pending = {}
    for name, pid in procs:
        ident = get_process_identity(pid)
        if ident is None:
            continue  # 已退出
        creation, path = ident
        alive.add((pid, creation))
        if cfg["watch_paths"] and not any(path.startswith(px) for px in cfg["watch_paths"]):
            continue  # P2-1：路径白名单外
        g = app_map.get(name, name)
        pending.setdefault(g, []).append((name, pid, ident))
    return pending, alive


# ---------------------------------------------------------------- 主循环（无界面守护模式）
def main_loop():
    resume_leaked_suspensions()  # P1-4：恢复上次异常退出遗留的冻结进程
    cfg = load_config()
    log("守护启动。配置: ssids={} 组={} interval={}s 超时动作={}".format(
        cfg["watch_ssids"], [g["name"] for g in cfg["watch_apps"]],
        cfg["poll_interval"], cfg["timeout_action"]))

    allowed = set()  # {(pid, 创建时间)}：本次网络会话中放行的实例

    try:
        while True:
            cfg = load_config()  # 热重载配置
            try:
                ssid = (cfg.get("test_ssid") or "").strip() or get_current_ssid()
            except Exception as e:
                log("获取 SSID 异常: {}".format(e))
                ssid = None

            on_net, ssid = is_on_guard_network(cfg, ssid)
            if not on_net:
                if allowed:
                    allowed.clear()
                time.sleep(cfg["idle_interval"])
                continue

            try:
                pending, alive = detect_pending(cfg)
            except Exception as e:
                log("进程检测异常: {}".format(e))
                pending, alive = {}, set()

            allowed = {(p, c) for (p, c) in allowed if (p, c) in alive}

            # 过滤掉已放行的
            pending = {g: [(n, p, i) for (n, p, i) in items if (p, i[0]) not in allowed]
                       for g, items in pending.items()}
            pending = {g: items for g, items in pending.items() if items}

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
                for n, p, ident in all_items:
                    if suspend_pid(p):
                        suspended_entries.append([p, ident[1], ident[0]])
                    else:
                        freeze_failed.append(n)
                        log("冻结进程 {} (PID {}) 失败，确认前它将继续运行".format(n, p))
                save_suspended(suspended_entries)

                allowed_bool, timed_out = ask_user_allow(
                    ssid, group_lines, cfg["ask_timeout"], cfg["timeout_action"], freeze_failed)
                if timed_out:
                    log("等待确认超时（{} 秒），按配置默认动作: {}".format(
                        cfg["ask_timeout"], "放行" if allowed_bool else "关闭"))
                elif allowed_bool:
                    log("用户确认允许: {}".format(pids_desc))
                else:
                    log("用户取消，开始关闭: {}".format(pids_desc))

                # 逐个处理（带 PID 三元组校验，P1-5）
                for n, p, ident in all_items:
                    if not identity_matches(p, ident):
                        log("PID {} ({}) 身份已变化（退出或被系统复用），跳过操作".format(p, n))
                        continue
                    if allowed_bool:
                        if resume_pid(p):
                            allowed.add((p, ident[0]))
                        else:
                            log("恢复进程 {} (PID {}) 失败".format(n, p))
                    else:
                        ok = graceful_kill(p)
                        log("已关闭 {} (PID {}) -> {}".format(n, p, "成功" if ok else "失败"))
                clear_suspended()

                # P0-1：关闭代理类应用后自愈残留的系统代理
                if not allowed_bool and cfg["post_kill_restore_proxy"]:
                    restore_system_proxy_if_dead()

            time.sleep(cfg["poll_interval"])
    finally:
        # P1-4：任何异常退出都恢复自己冻结的进程
        for pid, path, creation in load_suspended():
            try:
                if identity_matches(int(pid), (int(creation), str(path).lower())):
                    resume_pid(pid)
                    log("finally 安全网: 恢复冻结进程 {} (PID {})".format(path, pid))
            except (TypeError, ValueError):
                continue
        clear_suspended()


def main():
    if "--install" in sys.argv:
        install_autostart()
        return
    if "--uninstall" in sys.argv:
        uninstall_autostart()
        return
    if "--status" in sys.argv:
        autostart_status()
        return

    if not acquire_single_instance():
        log("已有 NetworkGuard 实例在运行，本次退出。")
        return
    main_loop()


if __name__ == "__main__":
    main()
