# -*- coding: utf-8 -*-
"""
Network Guard - 网络管控守护程序
================================
功能：
  1. 开机自启动（写注册表 HKCU Run 键）
  2. 后台静默监控当前 Wi-Fi SSID
  3. 当连上"指定网络"（watch_ssids）时：
     - 检测到指定应用（watch_apps）正在运行 -> 弹出警告
     - 用户点"确定" -> 允许该实例继续运行
     - 用户点"取消" -> 立即强制结束该进程
     - 应用重新打开会再次触发警告（按进程 PID 判定）

用法：
  pythonw guard.pyw              启动守护（静默运行）
  python guard.pyw --install     注册开机自启动
  python guard.pyw --uninstall   取消开机自启动
  python guard.pyw --status      查看自启动是否已注册

配置文件：同目录下 config.json（修改后无需重启，每个轮询周期自动重载）
"""

import csv
import ctypes
import io
import json
import os
import re
import subprocess
import sys
import time
import winreg

# ---------------------------------------------------------------- 基本路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
LOG_PATH = os.path.join(BASE_DIR, "guard.log")

RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE_NAME = "NetworkGuard"
MUTEX_NAME = "NetworkGuard_SingleInstance_Mutex"

DEFAULT_CONFIG = {
    "watch_ssids": [],          # 受控网络的 Wi-Fi 名称列表
    "watch_apps": [],           # 要管控的进程名（exe 文件名，小写）
    "poll_interval": 2,         # 受控网络上的检测间隔（秒）
    "idle_interval": 5,         # 不在受控网络时的 SSID 轮询间隔（秒），降低占用
    "test_ssid": "",            # 测试用：填了就当作当前 SSID，用于模拟受控网络
}

# 所有子进程调用都加 CREATE_NO_WINDOW，避免 pythonw 下弹出黑框
CREATE_NO_WINDOW = 0x08000000

# 进程挂起/恢复（NtSuspendProcess / NtResumeProcess，无需管理员）
_NTDLL = ctypes.windll.ntdll
_KERNEL32 = ctypes.windll.kernel32
_PROCESS_SUSPEND_RESUME = 0x0800


# ---------------------------------------------------------------- 日志
def log(msg):
    line = "[{}] {}".format(time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        with io.open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------- 配置
def load_config():
    cfg = dict(DEFAULT_CONFIG)
    try:
        with io.open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            cfg.update(data)
    except Exception as e:
        log("配置读取失败，使用默认/上次配置: {}".format(e))
    cfg["watch_apps"] = [str(a).strip().lower() for a in cfg.get("watch_apps", []) if str(a).strip()]
    cfg["watch_ssids"] = [str(s).strip() for s in cfg.get("watch_ssids", []) if str(s).strip()]
    try:
        cfg["poll_interval"] = max(1, int(cfg.get("poll_interval", 2)))
    except (TypeError, ValueError):
        cfg["poll_interval"] = 2
    try:
        cfg["idle_interval"] = max(1, int(cfg.get("idle_interval", 5)))
    except (TypeError, ValueError):
        cfg["idle_interval"] = 5
    return cfg


# ---------------------------------------------------------------- 进程挂起/恢复（检测到受控应用后先冻结，等待用户决定）
def suspend_pid(pid):
    """挂起进程：应用冻结在原地，无法继续运行任何功能。返回是否成功。"""
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
    """恢复挂起的进程。返回是否成功。"""
    try:
        h = _KERNEL32.OpenProcess(_PROCESS_SUSPEND_RESUME, False, pid)
        if not h:
            return False
        rc = _NTDLL.NtResumeProcess(h)
        _KERNEL32.CloseHandle(h)
        return rc == 0
    except Exception:
        return False


# ---------------------------------------------------------------- 命令执行（正确处理中文控制台编码）
def run_cmd(args, shell=False):
    """执行命令并按控制台代码页解码输出（不弹出黑框）。"""
    p = subprocess.run(args, capture_output=True, shell=shell,
                       creationflags=CREATE_NO_WINDOW)
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
    enc = "gbk"  # 中文 Windows 默认
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
    """通过 Windows WLAN API 直接取 SSID，开销极小。失败/未连返回 None。"""
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
    """备用方案：netsh 查询（已加防黑框标志）。"""
    out = run_cmd(["netsh", "wlan", "show", "interfaces"])
    for line in out.splitlines():
        m = re.match(r"\s*SSID\s*:\s*(.*?)\s*$", line)  # 不会误匹配 BSSID
        if m and m.group(1):
            return m.group(1)
    return None


def get_current_ssid():
    """当前 Wi-Fi SSID；未连 Wi-Fi 返回 None。优先用原生 API，失败退回 netsh。"""
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


# ---------------------------------------------------------------- 进程检测与控制（Toolhelp32 原生 API，无子进程）
_KERNEL32 = ctypes.windll.kernel32
_TH32CS_SNAPPROCESS = 0x2
_PROCESS_TERMINATE = 0x0001

class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong),
                ("th32ProcessID", ctypes.c_ulong),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", ctypes.c_ulong), ("cntThreads", ctypes.c_ulong),
                ("th32ParentProcessID", ctypes.c_ulong),
                ("pcPriClassBase", ctypes.c_long), ("dwFlags", ctypes.c_ulong),
                ("szExeFile", ctypes.c_wchar * 260)]


def _find_processes_toolhelp(app_names):
    """一次进程快照内完成匹配，毫秒级、无子进程。"""
    result = []
    snap = _KERNEL32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if snap == -1 or snap == 0xFFFFFFFFFFFFFFFF:
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
    """备用方案：tasklist（已加防黑框标志）。"""
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
    """找出进程名在 app_names 中的进程，返回 [(name, pid), ...]。"""
    if not app_names:
        return []
    wanted = set(app_names)
    try:
        return _find_processes_toolhelp(wanted)
    except Exception as e:
        log("进程快照异常，改用 tasklist: {}".format(e))
        return _find_processes_tasklist(wanted)


def kill_pid(pid):
    """用 TerminateProcess 直接结束进程，失败退回 taskkill（无黑框）。"""
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


# ---------------------------------------------------------------- 警告弹窗
def ask_user_allow(app_names, ssid):
    """弹出置顶警告框。返回 True=用户确认允许，False=取消。"""
    import tkinter as tk
    from tkinter import messagebox

    root = tk.Tk()
    root.withdraw()
    try:
        root.attributes("-topmost", True)
        root.lift()
    except tk.TclError:
        pass

    lines = ["当前已连接受控网络「{}」。".format(ssid), "",
             "检测到以下受管控的应用正在启动/运行，已被冻结暂停："]
    lines += ["  - {}".format(n) for n in app_names]
    lines += ["", "点【确定】允许其继续运行，点【取消】将立即强制关闭这些应用。"]
    msg = "\n".join(lines)

    try:
        ok = messagebox.askokcancel("网络管控警告", msg, icon="warning", parent=root)
    except Exception as e:
        log("弹窗失败: {}，按\"取消\"处理".format(e))
        ok = False
    finally:
        root.destroy()
    return ok


# ---------------------------------------------------------------- 开机自启动
def autostart_command():
    python_exe = sys.executable  # .pyw 双击/计划任务时即为 pythonw.exe
    pythonw = python_exe.replace("python.exe", "pythonw.exe").replace("Python.exe", "Pythonw.exe")
    if not os.path.exists(pythonw):
        pythonw = python_exe
    return '"{}" "{}"'.format(pythonw, os.path.abspath(__file__))


def install_autostart():
    cmd = autostart_command()
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, RUN_VALUE_NAME, 0, winreg.REG_SZ, cmd)
    print("开机自启动已注册：{}".format(cmd))


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
_K32_LE = ctypes.WinDLL("kernel32", use_last_error=True)

def acquire_single_instance():
    """返回 True 表示获得锁（首次运行）；False 表示已有实例在运行。"""
    _K32_LE.CreateMutexW(None, False, MUTEX_NAME)
    # 注意：必须用 ctypes.get_last_error()（use_last_error=True），
    # 直接调 kernel32.GetLastError() 会被 ctypes 内部调用覆盖导致判断失效
    return ctypes.get_last_error() != 183  # ERROR_ALREADY_EXISTS


# ---------------------------------------------------------------- 主循环
def main_loop():
    cfg = load_config()
    log("守护启动。配置: ssids={} apps={} interval={}s".format(
        cfg["watch_ssids"], cfg["watch_apps"], cfg["poll_interval"]))

    allowed_pids = set()  # 本次网络会话中用户确认放行的 PID

    while True:
        cfg = load_config()  # 热重载配置
        interval = cfg["poll_interval"]

        try:
            ssid = (cfg.get("test_ssid") or "").strip() or get_current_ssid()
        except Exception as e:
            log("获取 SSID 异常: {}".format(e))
            ssid = None

        on_net, ssid = is_on_guard_network(cfg, ssid)
        if not on_net:
            if allowed_pids:
                allowed_pids.clear()
            time.sleep(cfg["idle_interval"])
            continue

        try:
            procs = find_processes(cfg["watch_apps"])
        except Exception as e:
            log("进程检测异常: {}".format(e))
            procs = []

        alive = {pid for _, pid in procs}
        allowed_pids &= alive  # 清理已退出的 PID

        pending = [(n, p) for n, p in procs if p not in allowed_pids]
        if pending:
            names = sorted({n for n, _ in pending})
            log("受控网络「{}」发现进程: {}，先冻结等待确认".format(ssid, pending))
            # 冻结进程：应用无法继续运行任何功能，直到用户决定
            suspended = []
            for n, p in pending:
                if suspend_pid(p):
                    suspended.append(p)
                else:
                    log("冻结进程 {} (PID {}) 失败，将在确认后直接结束".format(n, p))
            if ask_user_allow(names, ssid):
                for n, p in pending:
                    if p in suspended:
                        resume_pid(p)
                allowed_pids.update(p for _, p in pending)
                log("用户确认允许: {}".format(pending))
            else:
                for n, p in pending:
                    ok = kill_pid(p)
                    log("用户取消，结束进程 {} (PID {}) -> {}".format(n, p, "成功" if ok else "失败"))

        time.sleep(interval)


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
