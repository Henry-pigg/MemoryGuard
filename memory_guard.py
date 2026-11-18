#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
内存守护 Memory Guard
=====================
实时监控物理内存 / 一键回收工作集 / 自动狙杀弹窗推广类流氓进程。

纯标准库实现：ctypes 直调 Win32 API（EnumProcesses + GetProcessMemoryInfo +
EmptyWorkingSet + NtSetSystemInformation），UI 用 tkinter，无需安装任何第三方包。

用法：
    pythonw.exe memory_guard.py        后台启动 GUI
    python  memory_guard.py --selftest 命令行自检
"""

from __future__ import annotations

import base64
import collections
import ctypes
import ctypes.wintypes as wt
import datetime
import json
import math
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
import queue
import zlib

try:
    import tkinter as tk
    import tkinter.font as tkfont
    from tkinter import ttk
except Exception:  # tkinter 未安装时给个友好提示
    tk = None
    ttk = None

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(APP_DIR, "config.json")
LOG_PATH = os.path.join(APP_DIR, "memory_guard.log")
APP_TITLE = "内存守护 · Memory Guard"
SINGLE_PORT = 49731

# ---------------------------------------------------------------- Win32 常量
PROCESS_TERMINATE = 0x0001
PROCESS_SET_QUOTA = 0x0100
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010

SYSTEM_MEMORY_LIST_INFORMATION = 0x50
MEMORY_PURGE_STANDBY_LIST = 4
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x0002

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")
shell32 = ctypes.WinDLL("shell32", use_last_error=True)

try:
    version_dll = ctypes.WinDLL("version", use_last_error=True)
    version_dll.GetFileVersionInfoSizeW.argtypes = [wt.LPCWSTR, ctypes.POINTER(wt.DWORD)]
    version_dll.GetFileVersionInfoSizeW.restype = wt.DWORD
    version_dll.GetFileVersionInfoW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p]
    version_dll.GetFileVersionInfoW.restype = wt.BOOL
    version_dll.VerQueryValueW.argtypes = [
        ctypes.c_void_p, wt.LPCWSTR, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wt.UINT)
    ]
    version_dll.VerQueryValueW.restype = wt.BOOL
    kernel32.ProcessIdToSessionId.argtypes = [wt.DWORD, ctypes.POINTER(wt.DWORD)]
    kernel32.ProcessIdToSessionId.restype = wt.BOOL
except Exception:
    version_dll = None


# ---------------------------------------------------------------- 结构体
class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wt.DWORD),
        ("dwMemoryLoad", wt.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    _fields_ = [
        ("cb", wt.DWORD),
        ("PageFaultCount", wt.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wt.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wt.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]


WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)


# ---------------------------------------------------------------- 基础 API 封装
def mem_info() -> dict:
    """返回物理内存信息（字节）。"""
    st = MEMORYSTATUSEX()
    st.dwLength = ctypes.sizeof(st)
    if not kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
        raise OSError("GlobalMemoryStatusEx failed")
    total, avail = st.ullTotalPhys, st.ullAvailPhys
    used = total - avail
    return {
        "total": total,
        "avail": avail,
        "used": used,
        "percent": round(used * 100.0 / total, 1) if total else 0.0,
        "pagefile_total": st.ullTotalPageFile,
        "pagefile_avail": st.ullAvailPageFile,
    }


def visible_window_titles() -> dict:
    """pid -> 首个可见顶层窗口标题。"""
    titles: dict[int, str] = {}

    def _cb(hwnd, _lparam):
        try:
            if not user32.IsWindowVisible(hwnd):
                return True
            n = user32.GetWindowTextLengthW(hwnd)
            if n <= 0:
                return True
            buf = ctypes.create_unicode_buffer(n + 1)
            user32.GetWindowTextW(hwnd, buf, n + 1)
            text = buf.value.strip()
            if not text:
                return True
            pid = wt.DWORD(0)
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value and pid.value not in titles:
                titles[pid.value] = text
        except Exception:
            pass
        return True

    try:
        user32.EnumWindows(WNDENUMPROC(_cb), 0)
    except Exception:
        pass
    return titles


def _proc_path(handle) -> str:
    buf = ctypes.create_unicode_buffer(1024)
    size = wt.DWORD(1024)
    if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
        return buf.value
    return ""


def snapshot() -> list[dict]:
    """枚举全部进程，返回 [{pid,name,path,ws,priv,title}]，按私有内存降序。"""
    titles = visible_window_titles()
    capacity = 2048
    pids = None
    while capacity <= 65536:
        arr = (wt.DWORD * capacity)()
        needed = wt.DWORD(0)
        if not psapi.EnumProcesses(ctypes.byref(arr), ctypes.sizeof(arr), ctypes.byref(needed)):
            return []
        count = needed.value // ctypes.sizeof(wt.DWORD)
        if count < capacity:
            pids = [arr[i] for i in range(count)]
            break
        capacity *= 2
    if pids is None:
        return []

    out = []
    for pid in pids:
        if pid == 0:
            continue
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            continue
        try:
            path = _proc_path(handle)
            pmc = PROCESS_MEMORY_COUNTERS_EX()
            pmc.cb = ctypes.sizeof(pmc)
            ws = priv = 0
            if psapi.GetProcessMemoryInfo(handle, ctypes.byref(pmc), ctypes.sizeof(pmc)):
                ws = pmc.WorkingSetSize
                priv = pmc.PrivateUsage or pmc.PagefileUsage
        finally:
            kernel32.CloseHandle(handle)

        name = os.path.basename(path).lower() if path else f"pid{pid}"
        out.append(
            {
                "pid": pid,
                "name": name,
                "path": path,
                "ws": int(ws),
                "priv": int(priv),
                "title": titles.get(pid, ""),
            }
        )
    out.sort(key=lambda p: p["priv"], reverse=True)
    return out


def kill_process(pid: int) -> tuple[bool, str]:
    """结束进程。先尝试 TerminateProcess，失败则退回 taskkill。"""
    if pid <= 4:
        return False, "系统进程，拒绝操作"
    handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if handle:
        try:
            if kernel32.TerminateProcess(handle, 1):
                return True, "TerminateProcess"
        finally:
            kernel32.CloseHandle(handle)
    # 退路：taskkill（可处理更高权限的进程）
    try:
        flags = 0x08000000 if os.name == "nt" else 0
        r = subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            capture_output=True,
            creationflags=flags,
            timeout=10,
        )
        if r.returncode == 0:
            return True, "taskkill"
        msg = r.stderr.decode("gbk", "ignore").strip() or r.stdout.decode("gbk", "ignore").strip()
        return False, msg or "结束失败"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def trim_process(pid: int) -> bool:
    """EmptyWorkingSet：把进程工作集还给系统（不杀进程）。"""
    if pid <= 4:
        return False
    handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA, False, pid
    )
    if not handle:
        return False
    try:
        return bool(psapi.EmptyWorkingSet(handle))
    finally:
        kernel32.CloseHandle(handle)


def enable_privilege(name: str) -> bool:
    token = wt.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(token),
    ):
        return False
    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            return False
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
        return ctypes.get_last_error() == 0
    finally:
        kernel32.CloseHandle(token)


def is_admin() -> bool:
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:
        return False


def purge_standby_list() -> bool:
    """清空系统待命(缓存)内存 —— 需要管理员权限。"""
    if not is_admin():
        return False
    enable_privilege("SeProfileSingleProcessPrivilege")
    size = wt.ULONG(MEMORY_PURGE_STANDBY_LIST)
    try:
        status = ntdll.NtSetSystemInformation(
            SYSTEM_MEMORY_LIST_INFORMATION, ctypes.byref(size), ctypes.sizeof(size)
        )
        return status == 0
    except Exception:
        return False


# ---------------------------------------------------------------- 身份判定
_company_cache: dict[str, str] = {}


def file_company(path: str) -> str:
    """读 exe 版本信息里的公司名（小写），带缓存。读不到返回空串。"""
    if not path or version_dll is None:
        return ""
    key = path.lower()
    if key in _company_cache:
        return _company_cache[key]
    company = ""
    try:
        size = version_dll.GetFileVersionInfoSizeW(path, None)
        if size:
            buf = ctypes.create_string_buffer(size)
            if version_dll.GetFileVersionInfoW(path, 0, size, buf):
                ptr = ctypes.c_void_p()
                n = wt.UINT()
                if (version_dll.VerQueryValueW(buf, "\\VarFileInfo\\Translation",
                                               ctypes.byref(ptr), ctypes.byref(n))
                        and n.value >= 4):
                    words = ctypes.cast(ptr, ctypes.POINTER(wt.WORD * 2)).contents
                    lang, codepage = words[0], words[1]
                    sub = "\\StringFileInfo\\%04x%04x\\CompanyName" % (lang, codepage)
                    if version_dll.VerQueryValueW(buf, sub, ctypes.byref(ptr),
                                                  ctypes.byref(n)):
                        company = ctypes.wstring_at(ptr, int(n.value)).strip().lower()
    except Exception:
        company = ""
    _company_cache[key] = company
    return company


def session_id(pid: int) -> int:
    """进程所在会话；0 表示系统服务会话。取不到返回 -1。"""
    sid = wt.DWORD(0)
    try:
        if kernel32.ProcessIdToSessionId(pid, ctypes.byref(sid)):
            return int(sid.value)
    except Exception:
        pass
    return -1


# ---------------------------------------------------------------- 保护名单
# 一道锁：Windows 核心进程（名字命中即永不结束）
SYSTEM_CRITICAL = {
    # 内核 / 会话
    "system", "system idle process", "registry", "memory compression", "secure system",
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "lsaiso.exe", "svchost.exe", "dwm.exe", "fontdrvhost.exe", "logonui.exe",
    "userinit.exe", "wudfhost.exe", "spoolsv.exe", "audiodg.exe", "conhost.exe",
    # shell / 桌面体验
    "explorer.exe", "sihost.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe",
    "searchapp.exe", "searchhost.exe", "searchui.exe", "textinputhost.exe",
    "applicationframehost.exe", "runtimebroker.exe", "lockapp.exe", "ctfmon.exe",
    "taskhostw.exe", "dllhost.exe", "backgroundtaskhost.exe", "widgetservice.exe",
    # 安全 / 更新 / 维护
    "msmpeng.exe", "nissrv.exe", "mpdefendercoreservice.exe", "securityhealthservice.exe",
    "securityhealthsystray.exe", "smartscreen.exe", "mssense.exe", "wuauclt.exe",
    "usoclient.exe", "tiworker.exe", "trustedinstaller.exe", "sppsvc.exe",
    "wermgr.exe", "werfault.exe", "consent.exe", "wmiprvse.exe", "msiexec.exe",
    "taskmgr.exe", "searchindexer.exe", "sysmain.exe", "superfetch.exe",
    # 驱动 / 显卡 / 音频（结束会黑屏或没声音）
    "nvcontainer.exe", "nvdisplay.container.exe", "nvsphelper64.exe", "igfxtray.exe",
    "igfxem.exe", "rtkauduservice64.exe", "rtkaudioservice64.exe",
    # 本程序自己
    "python.exe", "pythonw.exe",
}

# 二道锁：系统目录（路径命中即永不结束）
_SYS_ROOT = (os.environ.get("SystemRoot") or r"C:/Windows").rstrip("\\")
_SYS_DRIVE = os.path.splitdrive(_SYS_ROOT)[0] or "C:"
_SYS_ROOT_L = _SYS_ROOT.lower() + "\\"
PROTECTED_DIRS = tuple(
    d.lower() + "\\" for d in (
        _SYS_ROOT,
        _SYS_DRIVE + r"\Program Files\WindowsApps",
        _SYS_DRIVE + r"\Program Files\Windows Defender",
        _SYS_DRIVE + r"\Program Files (x86)\Windows Defender",
        _SYS_DRIVE + r"\ProgramData\Microsoft\Windows Defender",
        _SYS_DRIVE + r"\Program Files\Common Files\Microsoft Shared",
        _SYS_DRIVE + r"\Program Files (x86)\Common Files\Microsoft Shared",
        _SYS_DRIVE + r"\$WINDOWS.~BT",
        _SYS_DRIVE + r"\$SysReset",
    )
)

# ---------------------------------------------------------------- 规则库
# 只收录「推广 / 弹窗 / 更新 / 后台助手」这类进程，绝不收录软件主程序。
BUILTIN_RULES: list[dict] = [
    # ================= 芒果TV（用户点名） =================
    {"field": "name", "pattern": r"^mangotv[\w\-]*(update|push|mini|ad|dsp|tips|popup|helper|daemon|news|upgrade)",
     "note": "芒果TV 广告 / 更新 / 迷你页"},
    {"field": "name", "pattern": r"^(mgtv|imgo|hunan)[\w\-]*(push|update|ad|popup|mini|tips|news)",
     "note": "芒果TV 关联推广进程"},
    {"field": "title", "pattern": r"^(芒果|mango)\s*tv.{0,20}(推荐|活动|福利|会员|签到|抽奖|游戏|礼包|下载)",
     "note": "芒果TV 推广弹窗窗口"},

    # ================= 视频 / 影音客户端 =================
    {"field": "name", "pattern": r"^(qqlive|txvideo|iqiyi|qyclient|qiyi|pps)[\w\-]*(push|ad|update|mini|recommend|news|dsp|tips)",
     "note": "腾讯视频 / 爱奇艺 / PPS 推广组件"},
    {"field": "name", "pattern": r"^(youku|tudou|sohuva|sohuvideo|pptv|pplive|wasu)[\w\-]*(push|ad|update|news|mini|popup)",
     "note": "优酷 / 搜狐 / PPTV 推广组件"},
    {"field": "name", "pattern": r"^(storm|baofeng)[\w\-]*(update|push|ad|news|mini|box)",
     "note": "暴风影音 推广组件"},
    {"field": "name", "pattern": r"^(kugou|kgmusic|kuwo|kwmusic|kugouad|kuwoad)[\w\-]*(push|ad|update|news|mini|box|svc)",
     "note": "酷狗 / 酷我 推广组件"},

    # ================= 下载 / 网盘 =================
    {"field": "name", "pattern": r"^(thunderpush|thunderplatform|xldl|xlserviceplatform|xlwbbrowser)[\w\-]*",
     "note": "迅雷 推送 / 广告 / 后台服务"},
    {"field": "name", "pattern": r"^thunder[\w\-]*(push|ad|news|mini|box|tips|update)",
     "note": "迅雷 推广 / 更新进程"},
    {"field": "name", "pattern": r"^(baidupush|baidutips|bdpush|baidusdtraypush|baiduyunguanjia)[\w\-]*",
     "note": "百度系 推送 / 网盘管家"},
    {"field": "name", "pattern": r"^(baidunetdisk|quarkpc|adrive|aliyundrive)[\w\-]*(update|push|ad|tips|news|box)",
     "note": "网盘客户端 推广 / 更新"},

    # ================= 安全软件（只关弹窗，不碰防护） =================
    {"field": "name", "pattern": r"^(360|qhsafe|qhsafetray)[\w\-]*(push|news|popup|tips|adbox|show|window|minibox|newstool|daypop|welcome|spots|hotnews)",
     "note": "360 弹窗 / 热点推广"},
    {"field": "name", "pattern": r"^(360newstool|360daypop|360welcome|360tips|360se6push|360sdpush)\.exe$",
     "note": "360 热点弹窗"},
    {"field": "name", "pattern": r"^(qqpctray|qqpcmgr|qmdl|qmsched)[\w\-]*(push|news|popup|tips|ad|box|show|update)",
     "note": "腾讯电脑管家 弹窗推广"},
    {"field": "name", "pattern": r"^(kxetray|kxescore|kxe)[\w\-]*(push|news|ad|tips|popup|box|update)",
     "note": "金山毒霸 弹窗推广"},
    {"field": "name", "pattern": r"^(2345)[\w\-]*(push|news|popup|tips|ad|box|show|assist)",
     "note": "2345 弹窗推广"},
    {"field": "name", "pattern": r"^(ludashi|lds)[\w\-]*(push|news|popup|tips|ad|box|show|gamebox|update|checkup|setup)",
     "note": "鲁大师 弹窗推广"},
    {"field": "name", "pattern": r"^(drivergenius|dtl|drivethelife)[\w\-]*(update|push|news|ad|box)",
     "note": "驱动精灵 / 驱动人生 推广"},
    {"field": "name", "pattern": r"^(baidusd|baidusdtray|baidusdhelper)[\w\-]*(push|news|popup|tips|ad)",
     "note": "百度杀毒 弹窗推广"},

    # ================= 输入法 / 办公 / 压缩 =================
    {"field": "name", "pattern": r"^(sogoucloud|sgiupdate|sogoutool|sgitool|sgtool|sgiupdatex)[\w\-]*",
     "note": "搜狗输入法 云推送 / 更新"},
    {"field": "name", "pattern": r"^sogou[\w\-]*(push|news|ad|tips|popup)",
     "note": "搜狗 弹窗推广"},
    {"field": "name", "pattern": r"^baidu[\w\-]*ime[\w\-]*(push|update|tips)",
     "note": "百度输入法 推送 / 更新"},
    {"field": "name", "pattern": r"^(wpscenter|ksomisc|wpsupdate|wpsofficeupdate|wpsnotify)[\w\-]*",
     "note": "WPS 热点弹窗 / 更新"},
    {"field": "name", "pattern": r"^(kuaizip|haozip|2345haozip|zipassist|haozipassist)[\w\-]*(update|push|ad|news|box)",
     "note": "快压 / 好压 推广组件"},
    {"field": "name", "pattern": r"^(kuaizip|haozip|zipassist)[\w\-]*(helper|assist)\.exe$",
     "note": "快压 / 好压 后台助手"},
    {"field": "name", "pattern": r"^(cntv|cbox|funshion|wasu)[\w\-]*(push|ad|update|news|box|popup)",
     "note": "央视影音 / 风行 推广组件"},
    {"field": "name", "pattern": r"^(aliwangwang|alimini)[\w\-]*(push|news|ad|tips)",
     "note": "千牛 / 阿里旺旺 推送"},
    {"field": "name", "pattern": r"^(xiaoyi|huorong)[\w\-]*(push|news|ad|popup|tips)",
     "note": "小亿 / 火绒 推广弹窗"},

    # ================= 系统厂商 / 平台推广 =================
    {"field": "name", "pattern": r"^lenovo[\w\-]*(news|push|ad|promo|tips|recommend)",
     "note": "联想 推广弹窗"},
    {"field": "name", "pattern": r"^dell[\w\-]*(update|promo|notify)",
     "note": "戴尔 推广 / 更新提示"},
    {"field": "name", "pattern": r"^hp[\w\-]*(support|promo|update)[\w\-]*notify",
     "note": "惠普 推广提示"},
    {"field": "name", "pattern": r"^(toutiao|douyin|jinri|kuaishou)[\w\-]*(push|news|ad)[\w\-]*",
     "note": "头条 / 抖音 / 快手 推送"},
    {"field": "name", "pattern": r"^(qqexternal|txplatform|txupd|qqprotectupd|wechatupdate|wechatappexupdate)\.exe$",
     "note": "QQ / 微信 广告与更新组件"},
    {"field": "name", "pattern": r"^(dingtalkupdate|weworkupdate|feishuupdate|larkupdate)\.exe$",
     "note": "办公软件 更新进程"},

    # ================= 兜底（名字就是推送/弹窗类） =================
    {"field": "name", "pattern": r"^[a-z0-9_\-]{2,14}(push|popup|newspop|adbox|tipsbox|newstool|adshow)\.exe$",
     "note": "通用推送 / 弹窗进程（兜底）"},
    {"field": "title", "pattern": r"^(今日热点|热点推荐|每日推荐|猜你喜欢|限时福利|免费领取|一键领取|开屏广告|广告位|弹窗广告|恭喜中奖|幸运抽奖)",
     "note": "通用推广弹窗标题"},
]

DEFAULT_CONFIG = {
    "auto_kill": True,
    "observe_only": False,
    "auto_trim": True,
    "threshold": 85,
    "scan_interval": 3,
    "trim_cooldown": 120,
    "rules": [],            # 用户自定义拦截规则
    "disabled_rules": [],   # 被停用的规则 pattern
    "whitelist": [],        # 用户自定义保护名单（进程名或路径片段）
}


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            saved = json.load(fh)
        if isinstance(saved, dict):
            cfg.update({k: v for k, v in saved.items() if k in DEFAULT_CONFIG})
    except Exception:
        pass
    return cfg


def save_config(cfg: dict) -> None:
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, ensure_ascii=False, indent=2)
    except Exception:
        pass


def all_rules(cfg: dict) -> list[dict]:
    disabled = set(cfg.get("disabled_rules", []))
    rules = []
    for r in BUILTIN_RULES:
        if r["pattern"] in disabled:
            continue
        rules.append({**r, "builtin": True})
    for r in cfg.get("rules", []):
        rules.append({**r, "builtin": False})
    compiled = []
    for r in rules:
        try:
            compiled.append((r, re.compile(r["pattern"], re.IGNORECASE)))
        except re.error:
            continue
    return compiled


def match_rules(proc: dict, compiled: list) -> dict | None:
    for r, rx in compiled:
        value = proc.get(r["field"], "") or ""
        if not value:
            continue
        if r["field"] == "path":
            value = value.replace("\\", "/")
        if rx.search(value):
            return r
    return None


def protect_reason(proc: dict, self_pid: int, whitelist=None) -> str:
    """返回「为什么不能结束」；空字符串表示可以安全结束。

    四道锁全部在这一处收口，任何规则、任何按钮都绕不过去。
    """
    pid = int(proc.get("pid") or 0)
    name = (proc.get("name") or "").strip().lower()
    path = (proc.get("path") or "").replace("/", "\\").lower()

    if pid <= 4:
        return "系统核心"
    if pid == self_pid:
        return "本程序"
    if name in SYSTEM_CRITICAL:
        return "系统进程"

    for item in whitelist or ():
        key = str(item).strip().lower().replace("/", "\\")
        if not key:
            continue
        if key.endswith(".exe") or ".exe" in key:
            if "/" not in key and "\\" not in key and name == key:
                return "你的白名单"
            if "\\" in key and key in path:
                return "你的白名单"
        elif key in path or key == name:
            return "你的白名单"

    if path:
        for d in PROTECTED_DIRS:
            if path.startswith(d):
                return "系统目录"
        if session_id(pid) == 0:
            return "系统服务"
    else:
        # 连路径都读不到，基本是内核线程 / 受保护进程
        return "系统内核"
    return ""


def is_protected(proc: dict, self_pid: int, whitelist=None) -> bool:
    return bool(protect_reason(proc, self_pid, whitelist))


def is_microsoft_app(path: str) -> bool:
    """微软自家程序 —— 自动规则不碰，但允许用户手动结束。"""
    return "microsoft" in file_company(path or "")


# ---------------------------------------------------------------- 监控线程
class Monitor(threading.Thread):
    def __init__(self, out: queue.Queue, cfg: dict, self_pid: int):
        super().__init__(daemon=True)
        self.out = out
        self.cfg = cfg
        self.self_pid = self_pid
        self.stop_flag = False
        self.trim_requested = False
        self.force_scan = False
        self.last_trim = 0.0
        self.stats = {"killed": 0, "freed_mb": 0.0}
        self.last_skipped = 0
        self._skipped: set = set()

    # -- 工具
    def log(self, level: str, msg: str) -> None:
        self.out.put({"type": "log", "level": level, "msg": msg})

    def _note_skip(self, proc: dict) -> None:
        rule = proc.get("hit_rule") or {}
        reason = proc.get("protect_reason") or "受保护"
        key = (proc.get("name"), reason)
        if key in self._skipped:
            return
        self._skipped.add(key)
        self.log("info", f"规则「{rule.get('note', '')}」命中了 {proc.get('name')}，"
                         f"但它是{reason}，已跳过（安全保护）")

    def _trim_all(self) -> tuple[int, float]:
        """回收工作集。

        只碰后台进程：有可见窗口的程序（你正在用的那个）一律不动。
        把豆包、微信、浏览器这种大程序的工作集整个搬走，它们会立刻把几 GB
        重新读回来，中途卡住甚至自己重启——用户看到的就是「被结束进程了」。
        """
        before = mem_info()["avail"]
        count = 0
        skipped = 0
        procs = snapshot()
        # 按可执行文件路径分组：只要这一组里有一个进程带可见窗口，整组都不动。
        # 豆包、微信这种都是十几个进程共用一个 exe，只跳过带窗口的那个没用，
        # 把它的渲染进程工作集搬走照样卡死。
        busy = {(p.get("path") or "").lower() for p in procs if p.get("title")}
        for p in procs:
            if p["pid"] <= 4:
                continue
            path = (p.get("path") or "").lower()
            if path.startswith("c:\\windows\\"):
                continue
            if p["pid"] == self.self_pid:
                continue
            if path and path in busy:     # 这组程序有人正在用
                skipped += 1
                continue
            if trim_process(p["pid"]):
                count += 1
        purge_standby_list()
        after = mem_info()["avail"]
        freed = max(0.0, (after - before) / 1024 / 1024)
        self.last_skipped = skipped
        return count, freed

    # -- 主循环
    def run(self) -> None:
        last_scan = 0.0
        while not self.stop_flag:
            try:
                cfg = self.cfg
                now = time.time()
                mem = mem_info()
                procs = None

                if self.trim_requested:
                    self.trim_requested = False
                    count, freed = self._trim_all()
                    self.last_trim = now
                    self.stats["freed_mb"] += freed
                    self.log("ok", f"手动回收内存：处理 {count} 个后台进程，"
                                   f"可用内存 +{freed:.0f} MB"
                                   + (f"（跳过 {self.last_skipped} 个正在用的程序）"
                                      if self.last_skipped else ""))

                need_scan = self.force_scan or (now - last_scan >= max(1, cfg["scan_interval"]))
                if need_scan:
                    self.force_scan = False
                    last_scan = now
                    procs = snapshot()
                    procs = [p for p in procs if p["pid"] != self.self_pid]
                    compiled = all_rules(cfg)

                    whitelist = cfg.get("whitelist") or ()
                    hits = []
                    for p in procs:
                        rule = match_rules(p, compiled)
                        p["hit_rule"] = rule
                        reason = protect_reason(p, self.self_pid, whitelist)
                        p["protected"] = bool(reason)
                        p["protect_reason"] = reason
                        if rule:
                            hits.append(p)

                    if hits and cfg["auto_kill"]:
                        for p in hits:
                            if p["protected"]:
                                self._note_skip(p)
                                continue
                            if is_microsoft_app(p.get("path", "")):
                                p["protect_reason"] = "微软签名"
                                self._note_skip(p)
                                continue
                            # 执行前再复核一次（防 PID 复用 / 白名单刚变更）
                            if (p["name"] or "").lower() in SYSTEM_CRITICAL or p["pid"] <= 4:
                                continue
                            mb = p["priv"] / 1024 / 1024
                            if cfg["observe_only"]:
                                self.log(
                                    "info",
                                    f"[观察] 命中「{p['hit_rule']['note']}」：{p['name']} (PID {p['pid']}, {mb:.0f} MB)",
                                )
                                continue
                            ok, how = kill_process(p["pid"])
                            if ok:
                                self.stats["killed"] += 1
                                self.stats["freed_mb"] += mb
                                self.log(
                                    "kill",
                                    f"已结束 {p['name']} (PID {p['pid']}, {mb:.0f} MB) — 规则「{p['hit_rule']['note']}」",
                                )
                            else:
                                self.log("warn", f"结束失败 {p['name']} (PID {p['pid']})：{how}")

                # 内存压力自动回收
                if (
                    cfg["auto_trim"]
                    and mem["percent"] >= cfg["threshold"]
                    and now - self.last_trim >= max(30, cfg["trim_cooldown"])
                ):
                    count, freed = self._trim_all()
                    self.last_trim = now
                    self.stats["freed_mb"] += freed
                    self.log(
                        "ok",
                        f"内存占用 {mem['percent']:.0f}% 超过阈值 {cfg['threshold']}%："
                        f"回收 {count} 个后台进程，可用内存 +{freed:.0f} MB"
                        + (f"（跳过 {self.last_skipped} 个正在用的程序）"
                           if self.last_skipped else ""),
                    )
                    mem = mem_info()

                self.out.put(
                    {
                        "type": "tick",
                        "mem": mem,
                        "procs": procs,
                        "stats": dict(self.stats),
                    }
                )
            except Exception:
                self.log("warn", "监控循环异常：" + traceback.format_exc(limit=2))
            # 1 秒粒度
            for _ in range(10):
                if self.stop_flag:
                    return
                time.sleep(0.1)


# ================================================================ 界面
# 面向普通人的简洁界面：一个大圆环、一个大按钮、几句人话。
# 所有技术细节（进程表 / 规则 / 日志）收进「高级」窗口。

BG = "#ffffff"          # 窗口底色：一张白纸，不用卡片分块
CARD = "#fafafa"        # 高级窗口的内容面板
INK = "#1d1d1f"         # 主文字
SUB = "#6e6e73"         # 次要文字
FAINT = "#a1a1a6"       # 更弱的文字
LINE = "#e8e8ec"        # 分隔线
TRACK = "#e6e6ea"       # 进度条底槽

BLUE = "#0071e3"        # 只留给高级窗口的输入焦点
BLUE_HOVER = "#0077ed"
BLUE_SOFT = "#eaf2fd"

GREEN = "#248a3d"
AMBER = "#a35a00"
RED = "#c4432b"         # 全界面唯一的强调色：暖砖红，只在内存告急时出现
SWITCH_ON = "#1d1d1f"   # 开关开启＝墨色，和按钮同一支笔，不引入第二种彩色
HAIR_LINE = "#f0f0f2"

FONT = "Microsoft YaHei UI"
FONT_NUM = "Segoe UI"

# 兼容旧引用
GREEN_SOFT = AMBER_SOFT = RED_SOFT = CARD


# ================================================================ 抗锯齿图元
# tkinter 的 Canvas 底下就是 GDI：多边形、椭圆全是硬边，系统只给文字做了
# ClearType。所以圆角、胶囊、圆点无论怎么调坐标都会露出台阶——这不是参数问题，
# 是没有抗锯齿的渲染器问题。
#
# 解法：这些形状不再让 Canvas 画，改成让 GDI+ 画进一张内存位图
# （SmoothingModeAntiAlias + PixelOffsetModeHighQuality），再把位图当图片贴到
# Canvas 上。叠加由 GDI+ 自己完成，最后按窗口底色拍平成不透明位图——Tk 的
# photo 只有 1 bit 透明，直接喂带 alpha 的 PNG，半透明边缘反而会被画成硬色块。

_gpdll = None
try:                                    # 只在 Windows 上存在，拿不到就退回折线
    _gpdll = ctypes.WinDLL("gdiplus")
except Exception:
    _gpdll = None

_GPF: dict = {}
_GP_TOKEN = None
_VOIDP = ctypes.c_void_p
_OUTP = ctypes.POINTER(ctypes.c_void_p)
_REAL = ctypes.c_float


class _StartupInput(ctypes.Structure):
    _fields_ = [("GdiplusVersion", ctypes.c_uint),
                ("DebugEventCallback", ctypes.c_void_p),
                ("SuppressBackgroundThread", ctypes.c_int),
                ("SuppressExternalCodecs", ctypes.c_int)]


class _GpRect(ctypes.Structure):
    _fields_ = [("X", ctypes.c_int), ("Y", ctypes.c_int),
                ("Width", ctypes.c_int), ("Height", ctypes.c_int)]


class _BitmapData(ctypes.Structure):
    _fields_ = [("Width", ctypes.c_uint), ("Height", ctypes.c_uint),
                ("Stride", ctypes.c_int), ("PixelFormat", ctypes.c_int),
                ("Scan0", ctypes.c_void_p), ("Reserved", ctypes.c_void_p)]


def _sig(name, args):
    if _gpdll is None:
        return
    fn = getattr(_gpdll, name)
    fn.argtypes = args
    fn.restype = ctypes.c_int
    _GPF[name] = fn


if _gpdll is not None:
    _sig("GdiplusStartup", [ctypes.POINTER(ctypes.c_void_p),
                            ctypes.POINTER(_StartupInput), ctypes.c_void_p])
    _sig("GdipCreateBitmapFromScan0",
         [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
          ctypes.c_void_p, _OUTP])
    _sig("GdipGetImageGraphicsContext", [_VOIDP, _OUTP])
    _sig("GdipDeleteGraphics", [_VOIDP])
    _sig("GdipDisposeImage", [_VOIDP])
    _sig("GdipGraphicsClear", [_VOIDP, ctypes.c_uint])
    _sig("GdipSetSmoothingMode", [_VOIDP, ctypes.c_int])
    _sig("GdipSetPixelOffsetMode", [_VOIDP, ctypes.c_int])
    _sig("GdipSetCompositingQuality", [_VOIDP, ctypes.c_int])
    _sig("GdipSetCompositingMode", [_VOIDP, ctypes.c_int])
    _sig("GdipCreatePath", [ctypes.c_int, _OUTP])
    _sig("GdipAddPathArc", [_VOIDP] + [_REAL] * 6)
    _sig("GdipAddPathRectangle", [_VOIDP] + [_REAL] * 4)
    _sig("GdipClosePathFigure", [_VOIDP])
    _sig("GdipDeletePath", [_VOIDP])
    _sig("GdipCreateSolidFill", [ctypes.c_uint, _OUTP])
    _sig("GdipDeleteBrush", [_VOIDP])
    _sig("GdipFillPath", [_VOIDP, _VOIDP, _VOIDP])
    _sig("GdipCreatePen1", [ctypes.c_uint, _REAL, ctypes.c_int, _OUTP])
    _sig("GdipSetPenLineJoin", [_VOIDP, ctypes.c_int])
    _sig("GdipDrawPath", [_VOIDP, _VOIDP, _VOIDP])
    _sig("GdipDeletePen", [_VOIDP])
    _sig("GdipBitmapLockBits", [_VOIDP, ctypes.POINTER(_GpRect), ctypes.c_uint,
                                ctypes.c_int, ctypes.POINTER(_BitmapData)])
    _sig("GdipBitmapUnlockBits", [_VOIDP, ctypes.POINTER(_BitmapData)])


def _argb(color: str, alpha: int = 255) -> int:
    c = color.lstrip("#")
    if len(c) == 3:
        c = "".join(ch * 2 for ch in c)
    return ((alpha & 0xFF) << 24) | (int(c[0:2], 16) << 16) \
        | (int(c[2:4], 16) << 8) | int(c[4:6], 16)


def _gp_init() -> bool:
    """启动一次 GDI+，整个进程共用；失败就说明这台机器没别的手艺可用。"""
    global _GP_TOKEN
    if _GP_TOKEN is not None:
        return True
    if _gpdll is None:
        return False
    token = ctypes.c_void_p()
    inp = _StartupInput(1, None, 0, 0)
    if _GPF["GdiplusStartup"](ctypes.byref(token), ctypes.byref(inp), None) != 0:
        return False
    _GP_TOKEN = token
    return True


def _gp_rows(w, h, bg, paint):
    """在 bg 底色上画一张 w×h 的位图，返回自上而下的 BGRA 行。"""
    if not _gp_init():
        return None
    bmp = ctypes.c_void_p()
    if _GPF["GdipCreateBitmapFromScan0"](w, h, 0, 0x0026200A, None,
                                         ctypes.byref(bmp)) != 0:
        return None
    gfx = ctypes.c_void_p()
    if _GPF["GdipGetImageGraphicsContext"](bmp, ctypes.byref(gfx)) != 0:
        _GPF["GdipDisposeImage"](bmp)
        return None
    _GPF["GdipSetSmoothingMode"](gfx, 4)        # AntiAlias
    _GPF["GdipSetPixelOffsetMode"](gfx, 4)      # HighQuality
    _GPF["GdipSetCompositingQuality"](gfx, 4)   # HighQuality
    _GPF["GdipSetCompositingMode"](gfx, 0)      # SourceOver
    _GPF["GdipGraphicsClear"](gfx, _argb(bg))
    try:
        paint(gfx)
    finally:
        _GPF["GdipDeleteGraphics"](gfx)

    rect = _GpRect(0, 0, w, h)
    data = _BitmapData()
    rows = None
    if _GPF["GdipBitmapLockBits"](bmp, ctypes.byref(rect), 1, 0x0026200A,
                                  ctypes.byref(data)) == 0:
        stride = abs(data.Stride)
        raw = ctypes.string_at(data.Scan0, stride * h)
        _GPF["GdipBitmapUnlockBits"](bmp, ctypes.byref(data))
        rows = [raw[y * stride:y * stride + w * 4] for y in range(h)]
        if data.Stride < 0:
            rows.reverse()
    _GPF["GdipDisposeImage"](bmp)
    return rows


def _png_rgb(w, h, rows) -> bytes:
    """BGRA 行 → 24 位 RGB 的 PNG（不写 alpha，边缘已经是拍平过的）。"""
    def chunk(tag, data):
        body = tag + data
        return struct.pack(">I", len(data)) + body \
            + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    lines = []
    for row in rows:
        mv = memoryview(row)
        out = bytearray(w * 3)
        out[0::3] = mv[2::4]
        out[1::3] = mv[1::4]
        out[2::3] = mv[0::4]
        lines.append(b"\x00" + bytes(out))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"".join(lines), 6))
            + chunk(b"IEND", b""))


_AA_CACHE: "collections.OrderedDict" = collections.OrderedDict()
_AA_MAX = 120
_AA_RETIRED: list = []      # 刚被挤出缓存、但可能还被画布引用的图，下一帧再放手


def _aa_release():
    """画布清空之后调用：上一帧的旧图这时才可以真正被回收。"""
    _AA_RETIRED.clear()


def _aa(w, h, bg, paint, key):
    """按 key 缓存抗锯齿位图；同一尺寸同一颜色只画一次。"""
    hit = _AA_CACHE.get(key)
    if hit is not None:
        _AA_CACHE.move_to_end(key)
        return hit
    rows = _gp_rows(w, h, bg, paint)
    if not rows:
        return None
    try:
        img = tk.PhotoImage(data=base64.b64encode(_png_rgb(w, h, rows)).decode("ascii"))
    except Exception:
        return None
    _AA_CACHE[key] = img
    while len(_AA_CACHE) > _AA_MAX:
        _old_key, old_img = _AA_CACHE.popitem(last=False)
        _AA_RETIRED.append(old_img)
    return img


def _round_path(x, y, w, h, r):
    """四段 90° 圆弧拼出的圆角矩形，半径自动收敛到短边一半。"""
    if r * 2 > min(w, h):
        r = min(w, h) / 2.0
    path = ctypes.c_void_p()
    if _GPF["GdipCreatePath"](0, ctypes.byref(path)) != 0:
        return None
    if r < 0.25:
        _GPF["GdipAddPathRectangle"](path, float(x), float(y), float(w), float(h))
        return path
    d = 2.0 * r
    _GPF["GdipAddPathArc"](path, float(x), float(y), d, d, 180.0, 90.0)
    _GPF["GdipAddPathArc"](path, float(x + w - d), float(y), d, d, 270.0, 90.0)
    _GPF["GdipAddPathArc"](path, float(x + w - d), float(y + h - d), d, d, 0.0, 90.0)
    _GPF["GdipAddPathArc"](path, float(x), float(y + h - d), d, d, 90.0, 90.0)
    _GPF["GdipClosePathFigure"](path)
    return path


def _fill_round(gfx, x, y, w, h, r, color, alpha=255):
    path = _round_path(x, y, w, h, r)
    if path is None:
        return
    brush = ctypes.c_void_p()
    _GPF["GdipCreateSolidFill"](_argb(color, alpha), ctypes.byref(brush))
    _GPF["GdipFillPath"](gfx, brush, path)
    _GPF["GdipDeleteBrush"](brush)
    _GPF["GdipDeletePath"](path)


def _stroke_round(gfx, x, y, w, h, r, color, width):
    """描边：路径往内缩半个笔宽，笔迹才不会溢出到画布外面。"""
    pad = width / 2.0
    path = _round_path(x + pad, y + pad, w - width, h - width, max(0.0, r - pad))
    if path is None:
        return
    pen = ctypes.c_void_p()
    if _GPF["GdipCreatePen1"](_argb(color), float(width), 2,
                              ctypes.byref(pen)) == 0:
        _GPF["GdipSetPenLineJoin"](pen, 2)      # 圆角接缝
        _GPF["GdipDrawPath"](gfx, pen, path)
        _GPF["GdipDeletePen"](pen)
    _GPF["GdipDeletePath"](path)


# ---------------------------------------------------------------- 圆角控件
# 高级窗口里是真的控件（按钮、分段控件、输入框），它们默认都是直角 + GDI 硬边。
# 这里用同一套 GDI+ 位图当底，文字仍然交给系统渲染（ClearType 比自绘文字好）。
#
# 注意：Canvas 子类不能用 self._w / self._h 存尺寸——那是 tkinter 用来记
# 控件路径名的内部属性，覆盖掉之后任何 tk 调用都会报 invalid command name。

BTN_PALETTE = {
    # kind: (底色, 字色, 悬停底色, 悬停字色, 按下底色)
    "primary": (INK, "#ffffff", "#000000", "#ffffff", "#3a3a3c"),
    "plain": (BG, SUB, "#f4f4f6", INK, "#ececf0"),
    "danger": (BG, "#a03a26", "#fdf2ef", RED, "#f9e4dd"),
}


class AAButton(tk.Canvas):
    """胶囊按钮：底是用 GDI+ 画的图，字是系统字体。"""

    def __init__(self, master, text, command, kind="plain", font=None,
                 scale=1.0, bg=BG, padx=15, pady=7):
        fnt = font or (FONT, -13)
        f = tkfont.Font(font=fnt)
        cw = int(round(f.measure(text) + 2 * padx * scale))
        ch = int(round(f.metrics("linespace") + 2 * pady * scale))
        super().__init__(master, width=cw, height=ch, bg=bg, bd=0,
                         highlightthickness=0, takefocus=0)
        self._cw, self._ch = cw, ch
        self._bg = bg
        self._text = text
        self._cmd = command
        self._kind = kind
        self._font = fnt
        self._img = None
        self.configure(cursor="hand2")
        self.bind("<Enter>", lambda e: self._paint("hover"))
        self.bind("<Leave>", lambda e: self._paint("idle"))
        self.bind("<Button-1>", lambda e: self._paint("press"))
        self.bind("<ButtonRelease-1>", self._fire)
        self._paint("idle")

    def _paint(self, state):
        idle_bg, idle_fg, hot_bg, hot_fg, down_bg = BTN_PALETTE[self._kind]
        fill = down_bg if state == "press" else (hot_bg if state == "hover" else idle_bg)
        fg = idle_fg if state == "idle" else hot_fg
        w, h = self._cw, self._ch
        img = _aa(w, h, self._bg,
                  lambda g: _fill_round(g, 0, 0, w, h, h / 2.0, fill),
                  ("abtn", self._kind, fill, w, h))
        self.delete("all")
        if img is not None:
            self._img = img
            self.create_image(0, 0, image=img, anchor="nw")
        self.create_text(w / 2.0, h / 2.0, text=self._text, fill=fg,
                         font=self._font)

    def _fire(self, _ev=None):
        self._paint("hover")
        if self._cmd:
            self._cmd()


class Segmented(tk.Canvas):
    """分段控件：浅灰胶囊里一颗白色滑块，跟着选中项走。"""

    def __init__(self, master, items, command=None, index=0, font=None,
                 scale=1.0, bg=BG, hpad=14, vpad=6, inset=3):
        self._items = list(items)
        self._cmd = command
        self.index = index
        self._bg = bg
        fnt = font or (FONT, -13)
        self._font = fnt
        self._font_bold = (fnt[0], fnt[1], "bold")
        f = tkfont.Font(font=fnt)
        self._cell = [int(round(f.measure(t) + 2 * hpad * scale)) for t in self._items]
        ch = int(round(f.metrics("linespace") + 2 * vpad * scale))
        self._inset = int(round(inset * scale))
        cw = sum(self._cell) + 2 * self._inset
        super().__init__(master, width=cw, height=ch, bg=bg, bd=0,
                         highlightthickness=0, takefocus=0)
        self._cw, self._ch = cw, ch
        self._img_track = None
        self._img_thumb = None
        self.configure(cursor="hand2")
        self.bind("<Button-1>", self._click)
        self._draw()

    def _draw(self):
        self.delete("all")
        w, h, ins = self._cw, self._ch, self._inset
        track = _aa(w, h, self._bg,
                    lambda g: _fill_round(g, 0, 0, w, h, h / 2.0, "#f2f2f4"),
                    ("seg", w, h))
        if track is not None:
            self._img_track = track
            self.create_image(0, 0, image=track, anchor="nw")

        x = ins + sum(self._cell[:self.index])
        tw, th = self._cell[self.index], h - 2 * ins

        def _thumb(g):
            _fill_round(g, 0, 0, tw, th, th / 2.0, "#ffffff")
            _stroke_round(g, 0.5, 0.5, tw - 1, th - 1, (th - 1) / 2.0, "#e8e8ee", 1)

        th_img = _aa(tw, th, "#f2f2f4", _thumb, ("segthumb", tw, th))
        if th_img is not None:
            self._img_thumb = th_img
            self.create_image(x, ins, image=th_img, anchor="nw")

        cx = ins
        for i, t in enumerate(self._items):
            self.create_text(cx + self._cell[i] / 2.0, h / 2.0, text=t,
                             fill=INK if i == self.index else SUB,
                             font=self._font_bold if i == self.index else self._font)
            cx += self._cell[i]

    def _click(self, ev):
        x = ev.x - self._inset
        acc = 0
        for i, c in enumerate(self._cell):
            if x < acc + c:
                self.set(i)
                return
            acc += c

    def set(self, idx):
        idx = max(0, min(int(idx), len(self._items) - 1))
        if idx == self.index:
            return
        self.index = idx
        self._draw()
        if self._cmd:
            self._cmd(idx)


class RoundEntry(tk.Canvas):
    """圆角输入框：Canvas 画底，真正的 Entry 放在里面，两者底色对齐。"""

    def __init__(self, master, width, placeholder, font, scale=1.0, bg=BG,
                 fill="#f5f5f7", pad=11, vpad=6):
        f = tkfont.Font(font=font)
        ch = int(round(f.metrics("linespace") + 2 * vpad * scale))
        cw = int(round(width * scale))
        super().__init__(master, width=cw, height=ch, bg=bg, bd=0,
                         highlightthickness=0, takefocus=0)
        self._cw, self._ch = cw, ch
        self._bg = bg
        self._fill = fill
        self._img = None
        self.entry = tk.Entry(self, bg=fill, fg=FAINT, insertbackground=INK,
                              relief="flat", highlightthickness=0, bd=0,
                              font=font, width=1)
        self.entry.insert(0, placeholder)
        self._bg_item = self.create_image(0, 0, anchor="nw")
        p = int(round(pad * scale))
        self.create_window(p, ch / 2.0, window=self.entry, anchor="w",
                           width=cw - 2 * p, height=ch - 2)
        self._paint(False)
        self.entry.bind("<FocusIn>", lambda e: self._paint(True))
        self.entry.bind("<FocusOut>", lambda e: self._paint(False))
        self.bind("<Button-1>", lambda e: self.entry.focus_set())
        self.configure(cursor="xterm")

    def _paint(self, focused):
        w, h = self._cw, self._ch
        fill = "#ffffff" if focused else self._fill

        def shape(g):
            _fill_round(g, 0, 0, w, h, h / 2.0, fill)
            if focused:
                _stroke_round(g, 0.5, 0.5, w - 1, h - 1, (h - 1) / 2.0,
                              "#9fc2ee", 1.5)

        img = _aa(w, h, self._bg, shape, ("entry", fill, focused, w, h))
        if img is not None:
            self._img = img
            self.itemconfigure(self._bg_item, image=img)
        self.entry.configure(bg=fill)


class SlimScroll(tk.Canvas):
    """细滚动条：没有轨道、没有箭头，只有一小段圆头滑块。

    系统自带的滚动条即便调成灰色，也还带着槽和直角，是这窗口里最"Windows 95"
    的一处。这里自己画，宽度几像素，内容装得下就什么都不画。
    """

    def __init__(self, master, command, width_css=5, scale=1.0, bg=BG):
        cw = max(3, int(round(width_css * scale)))
        super().__init__(master, width=cw, bg=bg, bd=0, highlightthickness=0,
                         takefocus=0)
        self._cw = cw
        self._cmd = command
        self._first, self._last = 0.0, 1.0
        self._img = None
        self._drag = None
        self.bind("<Configure>", lambda e: self._draw())
        self.bind("<Button-1>", self._press)
        self.bind("<B1-Motion>", self._drag_to)
        self.bind("<ButtonRelease-1>", lambda e: setattr(self, "_drag", None))
        self.bind("<MouseWheel>", self._wheel)

    # 外接口：给 Scrollbar 用过的名字留个同位
    def set(self, first, last):
        self._first, self._last = float(first), float(last)
        self._draw()

    def _span(self):
        h = max(1, self.winfo_height())
        top = int(round(self._first * h))
        bot = int(round(self._last * h))
        minh = max(20, self._cw * 4)
        if bot - top < minh:
            bot = top + minh
        return max(0, top), min(h, max(bot, top + minh))

    def _draw(self):
        self.delete("all")
        if self._last - self._first >= 0.999:      # 全都在视野里，不用画
            return
        h = self.winfo_height()
        if h <= 2:
            return
        y1, y2 = self._span()
        w, th = self._cw, max(4, y2 - y1)
        img = _aa(w, th, BG,
                  lambda g: _fill_round(g, 0, 0, w, th, w / 2.0, "#d3d3d9"),
                  ("slim", w, th))
        if img is not None:
            self._img = img
            self.create_image(0, y1, image=img, anchor="nw")

    def _press(self, ev):
        y1, y2 = self._span()
        h = max(1, self.winfo_height())
        if y1 <= ev.y <= y2:
            self._drag = (ev.y, self._first, self._last)
            return
        frac = min(1.0, max(0.0, ev.y / h))        # 点空白处直接跳过去
        self._cmd("moveto", str(max(0.0, frac - (self._last - self._first) / 2)))
        self._drag = (ev.y, self._first, self._last)

    def _drag_to(self, ev):
        if not self._drag:
            return
        y0, f0, l0 = self._drag
        h = max(1, self.winfo_height())
        span = l0 - f0
        frac = min(1.0 - span, max(0.0, f0 + (ev.y - y0) / h))
        self._cmd("moveto", str(frac))

    def _wheel(self, ev):
        self._cmd("scroll", str(-1 if ev.delta > 0 else 1), "units")


def _rrect(cv, x1, y1, x2, y2, r, **kw):
    """圆角矩形（smooth 折线近似）。
    只在实在没有 GDI+ 的退路里用；主界面的圆角都走 _paste。
    """
    r = max(1, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
    pts = [
        x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
        x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
        x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
    ]
    return cv.create_polygon(pts, smooth=True, **kw)


def _gb(mb: float) -> str:
    return f"{mb / 1024:.2f} GB" if mb >= 1024 else f"{mb:.0f} MB"


def _pretty(name: str) -> str:
    """把 xx.exe / 长名字 变成给人看的名字。"""
    base = name
    for suffix in (".exe", ".EXE"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    base = base.replace("_", " ").strip()
    return base[:16] + "…" if len(base) > 17 else base


class GuardApp:
    # -------------------------------------------------------------- 初始化
    def __init__(self, root):
        self.root = root
        self.cfg = load_config()
        self.self_pid = os.getpid()
        self.q: queue.Queue = queue.Queue()
        self.history = collections.deque([0.0] * 90, maxlen=90)
        self.procs: list[dict] = []
        self.stats = {"killed": 0, "freed_mb": 0.0}
        self.logs = collections.deque(maxlen=600)
        self.admin = is_admin()

        self.hover_row = -1
        self.hover_chip = -1
        self.hover_parts = set()
        self.focus_idx = -1
        self.pressed = ""
        self._confirm_kill = ""
        self.toast_text = ""
        self.toast_until = 0.0
        self.adv = None
        self._all_procs = []
        self._adv_dirty = True

        self.S = root.winfo_fpixels("1i") / 96.0
        self.W, self.H = 720, 646
        self.cv = tk.Canvas(
            root, width=int(self.W * self.S), height=int(self.H * self.S),
            bg=BG, highlightthickness=0,
        )
        self.cv.pack(fill="both", expand=True)
        self.cv.configure(takefocus=1)
        self.cv.bind("<Motion>", self._on_motion)
        self.cv.bind("<Button-1>", self._on_click)
        self.cv.bind("<Key>", self._on_key)
        for seq in ("<Tab>", "<Shift-Tab>", "<ISO_Left_Tab>"):
            self.cv.bind(seq, self._on_tab)

        self.monitor = Monitor(self.q, self.cfg, self.self_pid)
        self.monitor.start()

        self.add_log("ok", "内存守护已启动，正在为你守护")
        self.root.after(300, self.cv.focus_set)
        self.root.after(80, self._pump)
        self.root.after(1000, self._tick_ui)

    # -------------------------------------------------------------- 工具
    def sz(self, v):
        return v * self.S

    def _paste(self, x1, y1, x2, y2, shape, key, bg=BG, fallback=None):
        """把 CSS 坐标的形状交给 GDI+ 画好，再当图片贴回画布。

        shape(gfx, w, h) 在设备像素坐标系里作画，w/h 是取整后的真实像素数——
        圆角形状必须落在整数像素上，否则直边会各铺半行灰。
        """
        px1, py1 = int(round(self.sz(x1))), int(round(self.sz(y1)))
        px2, py2 = int(round(self.sz(x2))), int(round(self.sz(y2)))
        w, h = px2 - px1, py2 - py1
        if w < 1 or h < 1:
            return False
        img = _aa(w, h, bg, lambda g: shape(g, w, h), (key, w, h, bg))
        if img is None:                      # 极端情况下退回直角块，至少别丢控件
            if fallback:
                self.cv.create_rectangle(px1, py1, px2, py2,
                                         fill=fallback, outline="")
            return False
        self.cv.create_image(px1, py1, image=img, anchor="nw")
        return True

    def fn(self, px, weight="normal"):
        return (FONT, -max(9, int(px * self.S)), weight)

    def fnum(self, px, weight="normal"):
        return (FONT_NUM, -max(9, int(px * self.S)), weight)

    def _card(self, x1, y1, x2, y2):
        _rrect(self.cv, self.sz(x1), self.sz(y1), self.sz(x2), self.sz(y2),
               self.sz(14), fill=CARD, outline=LINE, width=1)

    def add_log(self, level, msg):
        self.logs.append((datetime.datetime.now().strftime("%H:%M:%S"), level, msg))
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [{level}] {msg}\n")
        except Exception:
            pass
        self._adv_dirty = True

    # -------------------------------------------------------------- 数据
    def _pump(self):
        try:
            while True:
                msg = self.q.get_nowait()
                if msg["type"] == "tick":
                    self._on_tick(msg)
                elif msg["type"] == "log":
                    self._on_worker_log(msg["level"], msg["msg"])
        except queue.Empty:
            pass
        self.root.after(200, self._pump)

    def _on_worker_log(self, level, msg):
        if msg.startswith("手动回收内存"):
            m = re.search(r"\+([\d.]+) MB", msg)
            if m:
                self.toast("内存已整理完毕")
        elif msg.startswith("内存占用") and "超过阈值" in msg:
            m = re.search(r"\+([\d.]+) MB", msg)
            if m:
                self.toast("内存紧张，已自动释放")
        self.add_log(level, msg)

    def toast(self, text, secs=4.0):
        self.toast_text = text
        self.toast_until = time.time() + secs

    def _on_tick(self, msg):
        self.mem = msg["mem"]
        self.history.append(self.mem["percent"])
        self.stats = msg.get("stats", self.stats)
        if msg.get("procs") is not None:
            self._all_procs = msg["procs"]
            groups: dict[str, dict] = {}
            for p in msg["procs"]:
                if p["pid"] == self.self_pid or p.get("protected"):
                    continue
                g = groups.setdefault(p["name"], {"name": p["name"], "priv": 0, "pids": []})
                g["priv"] += p["priv"]
                g["pids"].append(p["pid"])
            self.procs = sorted(groups.values(), key=lambda g: g["priv"], reverse=True)[:4]
        self.draw()
        if self.adv is not None:
            self._refresh_advanced()

    def _tick_ui(self):
        self.draw()
        self.root.after(1000, self._tick_ui)

    # -------------------------------------------------------------- 绘制
    # 一个主角（大数字）＋一个颜色（告急时才有）＋一条竖直流。
    # 不画卡片、不画圆环、不画图标——层次全靠留白和字号悬殊。
    PAD = 56
    FOCUS_BOXES = ((56, 238, 190, 284), (612, 598, 668, 630), (586, 26, 672, 54))

    def draw(self):
        cv = self.cv
        cv.delete("all")
        _aa_release()

        # ---------------- 键盘焦点：最先画，白色内里就是白纸本身，不会盖住控件
        if self.focus_idx >= 0:
            b = self.FOCUS_BOXES[self.focus_idx]
            wd = max(1.0, float(round(self.sz(2))))

            def _ring(g, w, h, wd=wd):
                _stroke_round(g, 0, 0, w, h, self.sz(18), "#0058b8", wd)

            self._paste(b[0] - 7, b[1] - 7, b[2] + 7, b[3] + 7, _ring,
                        ("ring", wd))
        mem = getattr(self, "mem", None) or {"percent": 0, "used": 0, "total": 1, "avail": 0}
        pct = mem["percent"]
        freed = self.stats["freed_mb"]
        killed = self.stats["killed"]
        L, R = self.PAD, self.W - self.PAD

        # ---------------- 页眉：一句状态 + 入口
        if not self.cfg["auto_kill"]:
            status = "拦截已关闭"
        elif self.cfg["observe_only"]:
            status = "观察模式，只记录不处理"
        elif killed:
            status = f"正在守护 · 已拦下 {killed} 个弹窗"
        else:
            status = "正在守护 · 一切安静"
        cv.create_text(self.sz(L), self.sz(40), text=status, anchor="w",
                       fill=SUB, font=self.fn(11.5))
        adv_hot = "adv" in self.hover_parts
        cv.create_text(self.sz(R), self.sz(40), text="详细信息 ›",
                       anchor="e", fill=INK if adv_hot else FAINT,
                       font=self.fn(11), tags=("adv",))

        # ---------------- 主角：大数字
        hot_pct = pct >= 85
        num_color = RED if hot_pct else INK
        num = f"{pct:.0f}"
        fb = self.fnum(90)
        wn = tkfont.Font(font=fb).measure(num)
        cv.create_text(self.sz(L - 4), self.sz(126), text=num, anchor="w",
                       fill=num_color, font=fb)
        cv.create_text(self.sz(L) + wn - self.sz(3), self.sz(153), text="%",
                       anchor="w", fill=FAINT, font=self.fnum(17))

        verdict = "内存充足" if pct < 70 else ("内存偏紧" if pct < 85 else "需要释放")
        cv.create_text(self.sz(R), self.sz(128), text=verdict, anchor="e",
                       fill=RED if hot_pct else SUB, font=self.fn(11.5))

        cv.create_text(self.sz(L), self.sz(190),
                       text=f"已用 {mem['used'] / 1024 ** 3:.1f} GB · 共 "
                            f"{mem['total'] / 1024 ** 3:.1f} GB",
                       anchor="w", fill=SUB, font=self.fn(12.5))

        # ---------------- 一条横线代替圆环：紧贴数字，读作数字的延伸
        bar_y, bar_h = 214, 4
        if pct > 0:
            bar_fill = RED if hot_pct else INK
            bw = (R - L) * min(pct, 100) / 100.0

            def _bar(g, w, h, bw=bw, bar_fill=bar_fill):
                _fill_round(g, 0, 0, w, h, h / 2.0, TRACK)
                _fill_round(g, 0, 0, max(float(h), w * min(pct, 100) / 100.0),
                            h, h / 2.0, bar_fill)

            self._paste(L, bar_y, R, bar_y + bar_h, _bar,
                        ("bar", bar_fill, int(bw * self.S)), fallback=TRACK)

        # ---------------- 主操作：深色胶囊，宽度只包住文字
        hot = "btn" in self.hover_parts
        down = self.pressed == "btn"
        dy = self.sz(1) if down else 0
        y0 = 241 if down else 240         # 按下时整体下沉 1pt
        fill = "#3a3a3c" if down else ("#000000" if hot else INK)
        self._paste(L, y0, L + 134, y0 + 42,
                    lambda g, w, h: _fill_round(g, 0, 0, w, h, h / 2.0, fill),
                    ("btn", fill), fallback=fill)
        cv.create_text(self.sz(L + 67), self.sz(261) + dy, text="释放内存",
                       fill="#ffffff", font=self.fn(13, "bold"))

        # ---------------- 一行摘要（没有内容就不占位置，留白比敷衍更有品）
        if time.time() < self.toast_until:
            summary = self.toast_text
        elif freed > 0:
            summary = f"本次已释放 {_gb(freed)}"
            if killed:
                summary += f"，关掉 {killed} 个弹窗"
        elif killed:
            summary = f"本次已关掉 {killed} 个弹窗"
        else:
            summary = "还没释放过内存"
        if summary:
            cv.create_text(self.sz(L), self.sz(310), text=summary, anchor="w",
                           fill=FAINT, font=self.fn(11.5))

        # ---------------- 分隔
        cv.create_line(self.sz(L), self.sz(340), self.sz(R), self.sz(340),
                       fill=HAIR_LINE, width=1)

        cv.create_text(self.sz(L), self.sz(370), text="最占内存", anchor="w",
                       fill=INK, font=self.fn(13, "bold"))
        all_hot = "all" in self.hover_parts
        cv.create_text(self.sz(R), self.sz(370), text="全部程序 ›", anchor="e",
                       fill=INK if all_hot else FAINT, font=self.fn(11.5), tags=("all",))

        if not self.procs:
            cv.create_text(self.sz((L + R) / 2), self.sz(470),
                           text="暂时没有占用过大的程序", fill=FAINT, font=self.fn(11.5))
        for i_, p_ in enumerate(self.procs[:4]):
            self._draw_row(i_, p_)

        # ---------------- 页脚：拦截开关
        cv.create_line(self.sz(L), self.sz(592), self.sz(R), self.sz(592),
                       fill=HAIR_LINE, width=1)
        tf = self.fn(13)
        cv.create_text(self.sz(L), self.sz(614), text="自动拦截弹窗", anchor="w",
                       fill=INK, font=tf)
        tw = tkfont.Font(font=tf).measure("自动拦截弹窗")
        sw_on = bool(self.cfg["auto_kill"])
        if not sw_on:
            note = "已暂停"
        elif killed:
            note = f"已拦下 {killed} 个"
        else:
            note = "目前没有动静"
        cv.create_text(self.sz(L) + tw + self.sz(12), self.sz(615),
                       text=note, anchor="w", fill=FAINT, font=self.fn(11))

        # 开关：整颗做成一张图，底座和白色圆钮一次画完，圆弧才是光滑的
        def _switch(g, w, h, on=sw_on):
            _fill_round(g, 0, 0, w, h, h / 2.0, SWITCH_ON if on else "#dcdce2")
            pad = max(2.0, round(h * 0.12))
            kr = h / 2.0 - pad
            cx = (w - pad - kr) if on else (pad + kr)
            cy = h / 2.0
            # 圆钮底下垫一层极淡的影：关闭态是白钮配浅灰底座，
            # 不垫影两者几乎同一亮度，钮会「消失」
            _fill_round(g, cx - kr - 1, cy - kr + 0.6, 2 * kr + 2, 2 * kr + 2,
                        kr + 1, "#000000", alpha=16)
            _fill_round(g, cx - kr, cy - kr, 2 * kr, 2 * kr, kr, "#ffffff")

        self._paste(618, 602, 664, 630, _switch, ("sw", sw_on),
                    fallback=SWITCH_ON if sw_on else "#dcdce2")

    def _draw_row(self, i, p: dict):
        cv = self.cv
        L, R = self.PAD, self.W - self.PAD
        top = 394 + i * 46
        cy = top + 23
        if self.hover_row == i:
            self._paste(L - 12, top + 3, R + 12, top + 43,
                        lambda g, w, h: _fill_round(g, 0, 0, w, h, self.sz(10),
                                                    "#f5f5f7"),
                        ("rowhot",), fallback="#f5f5f7")
        if i:
            cv.create_line(self.sz(L), self.sz(top), self.sz(R), self.sz(top),
                           fill=HAIR_LINE, width=1)

        name = _pretty(p["name"])
        nf = self.fn(13.5)
        cv.create_text(self.sz(L), self.sz(cy), text=name, anchor="w",
                       fill=INK, font=nf)
        n = len(p.get("pids", []))
        if n > 1:
            w = tkfont.Font(font=nf).measure(name)
            cv.create_text(self.sz(L) + w + self.sz(9), self.sz(cy + 1),
                           text=f"{n} 个进程", anchor="w", fill=FAINT,
                           font=self.fn(10.5))

        cv.create_text(self.sz(596), self.sz(cy), text=_gb(p["priv"] / 1024 / 1024),
                       anchor="e", fill=SUB, font=self.fnum(12.5))

        armed = self._confirm_kill == p["name"] and self._confirm_kill
        if armed:
            cv.create_text(self.sz(R), self.sz(cy), text="确定？", fill=RED,
                           font=self.fn(11, "bold"))
        else:
            cv.create_text(self.sz(R), self.sz(cy), text="结束",
                           fill=RED if self.hover_chip == i else "#b0b0b6",
                           font=self.fn(11))

    # -------------------------------------------------------------- 交互
    def _hit(self, ex, ey):
        """返回鼠标命中的区域。"""
        x, y = ex / self.S, ey / self.S
        if 586 <= x <= 672 and 26 <= y <= 54:
            return "adv"
        if 56 <= x <= 190 and 238 <= y <= 284:
            return "btn"
        if 580 <= x <= 672 and 356 <= y <= 384:
            return "all"
        if 44 <= x <= 676 and 394 <= y <= 578:
            idx = int((y - 394) // 46)
            if 0 <= idx < min(len(self.procs), 4):
                if 606 <= x <= 676:
                    return f"chip:{idx}"
                return f"row:{idx}"
            return "list"
        if 608 <= x <= 672 and 596 <= y <= 632:
            return "toggle"
        return ""

    def _on_motion(self, ev):
        hit = self._hit(ev.x, ev.y)
        parts, row, chip = set(), -1, -1
        if hit in ("btn", "adv", "all", "toggle"):
            parts.add(hit)
        elif hit.startswith("chip:"):
            row = int(hit.split(":")[1])
            chip = row
            parts.add("chip")
        elif hit.startswith("row:"):
            row = int(hit.split(":")[1])
        changed = (parts != self.hover_parts or row != self.hover_row
                   or chip != self.hover_chip)
        self.hover_parts, self.hover_row, self.hover_chip = parts, row, chip
        if changed:
            clickable = hit in ("btn", "adv", "all", "toggle") or hit.startswith("chip:")
            self.cv.configure(cursor="hand2" if clickable else "arrow")
            self.draw()

    def _on_click(self, ev):
        self.cv.focus_set()
        if self.focus_idx >= 0:
            self.focus_idx = -1
        hit = self._hit(ev.x, ev.y)
        if hit == "btn":
            self._do_release()
        elif hit == "toggle":
            self._do_toggle()
        elif hit == "adv" or hit == "all":
            self.open_advanced()
        elif hit.startswith("chip:"):
            idx = int(hit.split(":")[1])
            if idx < len(self.procs):
                g = self.procs[idx]
                # 「结束」是个破坏性动作，放在列表右下角，离鼠标动线很近。
                # 第一次点只是把它变成「确定？」，3 秒内再点才真的关掉。
                if self._confirm_kill != g["name"]:
                    self._confirm_kill = g["name"]
                    self.draw()
                    self.root.after(3000, lambda n=g["name"]: self._drop_confirm(n))
                    return
                self._confirm_kill = ""
                self.pressed = f"chip:{idx}"
                self.draw()
                self.root.after(110, lambda: setattr(self, "pressed", ""))
                done = 0
                for pid in g["pids"]:
                    ok, _how = kill_process(pid)
                    done += 1 if ok else 0
                if done:
                    self.stats["killed"] += done
                    self.stats["freed_mb"] += g["priv"] / 1024 / 1024
                    self.monitor.stats = dict(self.stats)
                    self.add_log("kill", f"你结束了 {g['name']}（{_gb(g['priv'] / 1024 / 1024)}）")
                    self.toast(f"已结束 {_pretty(g['name'])}，腾出 {_gb(g['priv'] / 1024 / 1024)}")
                else:
                    self.toast("没能结束它，可能需要管理员权限")
                self.monitor.force_scan = True
                self.procs = [x for x in self.procs if x["name"] != g["name"]]
                self.draw()

    def _do_release(self):
        self.pressed = "btn"
        self.draw()
        self.root.after(110, lambda: (setattr(self, "pressed", ""), self.draw()))
        self.monitor.trim_requested = True
        self.toast("正在整理内存…", 6)

    def _do_toggle(self):
        self.cfg["auto_kill"] = not self.cfg["auto_kill"]
        save_config(self.cfg)
        self.toast("弹窗拦截已" + ("开启" if self.cfg["auto_kill"] else "关闭"))
        self.draw()

    def _drop_confirm(self, name):
        if self._confirm_kill == name:
            self._confirm_kill = ""
            self.draw()

    def _on_tab(self, ev):
        back = bool(ev.state & 0x0001) or ev.keysym == "ISO_Left_Tab"
        n = len(self.FOCUS_BOXES)
        if self.focus_idx < 0:
            self.focus_idx = n - 1 if back else 0
        else:
            self.focus_idx = (self.focus_idx + (-1 if back else 1)) % n
        self.draw()
        return "break"

    def _on_key(self, ev):
        if ev.keysym in ("Return", "KP_Enter", "space"):
            if self.focus_idx == 1:
                self._do_toggle()
            elif self.focus_idx == 2:
                self.open_advanced()
            elif self.focus_idx == 0 or ev.keysym != "space":
                self._do_release()
            return "break"
        if ev.keysym == "Escape":
            self.focus_idx = -1
            self.draw()
            return "break"
        return ""

    # -------------------------------------------------------------- 详细信息
    def open_advanced(self):
        if self.adv is not None and self.adv.winfo_exists():
            self.adv.deiconify()
            self.adv.lift()
            self.adv.focus_force()
            return
        self.adv = tk.Toplevel(self.root)
        w = self.adv
        w.title("详细信息 — 内存守护")
        w.configure(bg=BG)
        try:
            w.iconbitmap(os.path.join(APP_DIR, "icon.ico"))
        except Exception:
            pass
        # 高 DPI 下 676 逻辑像素可能高过屏幕（1080p + 150% 只有 720 逻辑高度）
        vh = int(min(676 * self.S, self.root.winfo_screenheight() * 0.84))
        w.geometry(f"{int(940 * self.S)}x{vh}")
        w.minsize(int(720 * self.S), int(460 * self.S))

        self._init_styles()

        # ---- 页眉：左边是页面名，右边一行灰字说明这是什么
        head = tk.Frame(w, bg=BG)
        head.pack(fill="x", padx=self.sz(24), pady=(self.sz(16), 0))
        tk.Label(head, text="详细信息", bg=BG, fg=INK,
                 font=self.fn(15, "bold")).pack(side="left")
        self.adv_sub = tk.Label(head, text="", bg=BG, fg=FAINT, font=self.fn(11))
        self.adv_sub.pack(side="right", pady=(self.sz(4), 0))

        nav = tk.Frame(w, bg=BG)
        nav.pack(fill="x", padx=self.sz(24), pady=(self.sz(10), 0))
        self.nav_items = []
        for idx, text in enumerate(("程序", "记录")):
            holder = tk.Frame(nav, bg=BG)
            holder.pack(side="left", padx=(0, self.sz(24)))
            lb = tk.Label(holder, text=text, bg=BG, fg=SUB, font=self.fn(11.5),
                          cursor="hand2")
            lb.pack()
            line = tk.Frame(holder, bg=BG, height=max(2, int(2 * self.S)))
            line.pack(fill="x", pady=(self.sz(5), 0))
            lb.bind("<Button-1>", lambda e, i=idx: self._set_tab(i))
            self.nav_items.append((lb, line))

        # 一条极淡的横线把页眉和内容分开，跟主窗口同一支笔
        tk.Frame(w, bg=HAIR_LINE, height=1).pack(fill="x", pady=(self.sz(8), 0))

        body = tk.Frame(w, bg=BG)
        body.pack(fill="both", expand=True, padx=self.sz(24),
                  pady=(0, self.sz(18)))
        self.adv_nb = None
        self.page_prog = tk.Frame(body, bg=BG)
        self.page_log = tk.Frame(body, bg=BG)
        self._build_proc_tab(self.page_prog)
        self._build_log_tab(self.page_log)
        self.tab_idx = 0
        self._set_tab(0)

        self._apply_seg_ui()
        self._refresh_advanced(force=True)
        w.protocol("WM_DELETE_WINDOW", self._close_advanced)

    def _init_styles(self):
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except Exception:
            pass
        # 表格：没有外框、没有表头底色，只在视觉上留一条极淡的列头分隔
        st.configure("D.Treeview", background=BG, fieldbackground=BG, foreground=INK,
                     rowheight=int(35 * self.S), borderwidth=0,
                     relief="flat", font=self.fn(11.5))
        st.configure("D.Treeview.Heading", background=BG, foreground=FAINT,
                     relief="flat", borderwidth=0, font=self.fn(10.5),
                     padding=(10, 11))
        # 去掉 clam 主题给表格加的四周描边和内部 padding
        try:
            st.layout("D.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        except Exception:
            pass
        st.map("D.Treeview", background=[("selected", "#ededf0")],
               foreground=[("selected", INK)])
        st.map("D.Treeview.Heading", background=[("active", BG)])
        try:
            st.layout("D.Vertical.TScrollbar", [
                ("Vertical.Scrollbar.trough", {"sticky": "ns", "children": [
                    ("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})]})])
        except Exception:
            pass
        st.configure("D.Vertical.TScrollbar", background=BG, troughcolor=BG,
                     bordercolor=BG, darkcolor="#d2d2d8", lightcolor="#d2d2d8",
                     arrowcolor=BG, gripcount=0, borderwidth=0, width=6)
        st.map("D.Vertical.TScrollbar",
               background=[("active", BG), ("pressed", BG)],
               darkcolor=[("active", "#b8b8be"), ("pressed", "#a8a8ae")],
               lightcolor=[("active", "#b8b8be"), ("pressed", "#a8a8ae")])
        # 元素级：轨道涂成白底，只让滑块露出来
        for el, opts in (
            ("trough", dict(background=BG, bordercolor=BG, lightcolor=BG, darkcolor=BG)),
            ("thumb", dict(background="#d6d6dc", bordercolor="#d6d6dc",
                           lightcolor="#d6d6dc", darkcolor="#d6d6dc")),
        ):
            try:
                st.configure(f"D.Vertical.TScrollbar.{el}", **opts)
            except Exception:
                pass

    def _set_tab(self, idx):
        self.tab_idx = idx
        for i, (lb, line) in enumerate(self.nav_items):
            on = (i == idx)
            lb.configure(fg=INK if on else SUB,
                         font=self.fn(11.5, "bold") if on else self.fn(11.5))
            line.configure(bg=INK if on else BG)
        self.page_prog.pack_forget()
        self.page_log.pack_forget()
        target = self.page_prog if idx == 0 else self.page_log
        target.pack(fill="both", expand=True)
        if idx == 1:
            self._refresh_log()
        self._update_sub()

    def _update_sub(self):
        """右上角那行灰字：只报事实，不说第二遍提示。"""
        if self.adv is None or not hasattr(self, "adv_sub"):
            return
        if self.tab_idx == 1:
            text = f"最近 {len(self.logs)} 条记录"
        elif self.seg_idx == 0:
            text = f"共 {max(0, len(self._all_procs) - 1)} 个进程 · 按占用排序"
        elif self.seg_idx == 1:
            text = f"内置 {len(BUILTIN_RULES)} 条规则"
        else:
            text = f"保护名单 {len(self.cfg.get('whitelist') or [])} 项"
        self.adv_sub.configure(text=text)

    # ---- 程序页
    def _build_proc_tab(self, t):
        top = tk.Frame(t, bg=BG)
        top.pack(fill="x", pady=(self.sz(16), self.sz(12)))

        self.seg_idx = 0
        self.seg = Segmented(top, ("全部程序", "已拦截", "已保护"), self._set_seg,
                             font=self.fn(11), scale=self.S)
        self.seg.pack(side="left")

        self._search_ph = "搜索程序名"
        self.search_wrap = RoundEntry(top, 160, self._search_ph, self.fn(11), self.S)
        self.search_wrap.pack(side="right")
        self.adv_search = self.search_wrap.entry
        self.adv_search.bind("<KeyRelease>", lambda e: self._refresh_tree())
        self.adv_search.bind("<FocusIn>", self._search_focus_in)
        self.adv_search.bind("<FocusOut>", self._search_focus_out)

        wrap = tk.Frame(t, bg=BG)
        wrap.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(wrap, columns=("c1", "c2", "c3"), show="headings",
                                 style="D.Treeview")
        self.sb_tree = SlimScroll(wrap, self.tree.yview, scale=self.S)
        self.tree.configure(yscrollcommand=self.sb_tree.set)
        self.tree.pack(side="left", fill="both", expand=True)
        self.sb_tree.pack(side="right", fill="y", padx=(self.sz(4), 0))
        self.tree.tag_configure("odd", background="#fcfcfd")
        self.tree.tag_configure("off", foreground=FAINT)
        self.tree.bind("<Double-1>", self._on_row_double)
        self._last_w = 0
        self.tree.bind("<Configure>", self._on_tree_conf)

        bar = tk.Frame(t, bg=BG)
        bar.pack(side="bottom", fill="x", pady=(self.sz(14), self.sz(6)))
        self.hint_lbl = tk.Label(bar, text="", bg=BG, fg=FAINT, font=self.fn(11),
                                 anchor="w")
        self.hint_lbl.pack(side="left", pady=(self.sz(6), 0))

        self.act_wrap = tk.Frame(bar, bg=BG)
        self.act_wrap.pack(side="right")
        self.btn_kill = self._btn(self.act_wrap, "结束进程", self._act_kill, "danger")
        self.btn_block = self._btn(self.act_wrap, "加入拦截", self._act_block, "plain")
        self.btn_protect = self._btn(self.act_wrap, "加入保护", self._act_protect, "plain")
        self.btn_off = self._btn(self.act_wrap, "停用选中", self._act_rule_off, "plain")
        self.btn_on = self._btn(self.act_wrap, "启用选中", self._act_rule_on, "plain")

        self.wl_wrap = tk.Frame(bar, bg=BG)
        self._wl_ph = "程序名或安装目录"
        wl_box = RoundEntry(self.wl_wrap, 210, self._wl_ph, self.fn(11), self.S)
        self.wl_entry = wl_box.entry
        self.wl_entry.bind("<FocusIn>", self._wl_focus_in)
        self.wl_entry.bind("<FocusOut>", self._wl_focus_out)
        self.wl_entry.bind("<Return>", lambda e: self._add_whitelist())
        wl_box.pack(side="left", padx=(0, self.sz(8)))
        self._btn(self.wl_wrap, "加入保护", self._add_whitelist,
                  "primary").pack(side="left")
        self._btn(self.wl_wrap, "移出保护", self._del_whitelist,
                  "plain").pack(side="left", padx=(self.sz(6), 0))

    def _build_log_tab(self, t):
        tk.Frame(t, bg=BG, height=self.sz(14)).pack(fill="x")
        wrap = tk.Frame(t, bg=BG)
        wrap.pack(fill="both", expand=True, pady=(0, self.sz(8)))
        self.adv_log = tk.Text(wrap, bg=BG, fg=INK, relief="flat", font=self.fn(10),
                               wrap="word", padx=self.sz(2), pady=self.sz(2),
                               spacing1=3, spacing3=4, state="disabled",
                               highlightthickness=0, borderwidth=0)
        self.sb_log = SlimScroll(wrap, self.adv_log.yview, scale=self.S)
        self.adv_log.configure(yscrollcommand=self.sb_log.set)
        self.adv_log.pack(side="left", fill="both", expand=True)
        self.sb_log.pack(side="right", fill="y", padx=(self.sz(4), 0))
        for tag, color in (("ok", GREEN), ("kill", RED), ("warn", AMBER),
                           ("info", SUB), ("time", FAINT)):
            self.adv_log.tag_configure(tag, foreground=color)
        self.adv_log.tag_configure("time", font=self.fnum(10))

    # ---- 段控件
    def _set_seg(self, idx):
        if idx == self.seg_idx:
            return
        self.seg_idx = idx
        self.tree.selection_remove(*self.tree.selection()) if self.tree.selection() else None
        self._apply_seg_ui()
        self._refresh_tree()
        self.tree.yview_moveto(0)      # 换一类，从顶上重新看

    def _apply_seg_ui(self):
        if getattr(self, "seg", None) is not None and self.seg.index != self.seg_idx:
            self.seg.set(self.seg_idx)

        for wdg in (self.btn_kill, self.btn_block, self.btn_protect,
                    self.btn_off, self.btn_on, self.wl_wrap, self.search_wrap):
            wdg.pack_forget()

        self.hint_lbl.configure(fg=FAINT)
        if self.seg_idx == 0:
            self.search_wrap.pack(side="right")
            self.btn_kill.pack(side="left")
            self.btn_block.pack(side="left", padx=(self.sz(6), 0))
            self.btn_protect.pack(side="left", padx=(self.sz(6), 0))
            self.hint_lbl.configure(text="选中一个程序，再决定怎么处理它")
            heads = (("程序", 320, "w"), ("窗口标题", 420, "w"), ("占用内存", 140, "e"))
        elif self.seg_idx == 1:
            self.btn_off.pack(side="left")
            self.btn_on.pack(side="left", padx=(self.sz(6), 0))
            self.hint_lbl.configure(text="这些进程一冒头就会被自动关掉，双击某条可临时停用")
            heads = (("拦截对象", 400, "w"), ("匹配方式", 110, "w"), ("状态", 100, "center"))
        else:
            self.wl_wrap.pack(side="right")
            self.hint_lbl.configure(text="系统进程、系统目录、微软签名、系统服务始终受保护")
            heads = (("保护对象", 400, "w"), ("类型", 110, "w"), ("说明", 100, "center"))

        for key, (text, width, anchor) in zip(("c1", "c2", "c3"), heads):
            self.tree.heading(key, text=text, anchor=anchor)
            self.tree.column(key, width=int(width * self.S), anchor=anchor,
                             stretch=False)
        self._fit_columns()
        self._update_sub()

    def _on_tree_conf(self, ev):
        if abs(ev.width - getattr(self, "_last_w", 0)) > 4:
            self._last_w = ev.width
            self._fit_columns()

    def _fit_columns(self):
        """按实际宽度等比分列，窗口拉大缩小时都不会把最后一列挤掉。"""
        tree = getattr(self, "tree", None)
        if tree is None or not tree.winfo_exists():
            return
        total = tree.winfo_width()
        if total < 60:
            return
        if self.seg_idx == 0:
            ratios = (0.33, 0.49, 0.18)
        elif self.seg_idx == 1:
            ratios = (0.44, 0.28, 0.28)
        else:
            ratios = (0.44, 0.28, 0.28)
        avail = total - 4
        for key, r in zip(("c1", "c2", "c3"), ratios):
            tree.column(key, width=int(avail * r))

    def _refresh_advanced(self, force=False):
        if self.adv is None or not self.adv.winfo_exists():
            return
        if self.tab_idx == 0:
            self._refresh_tree()
        else:
            self._refresh_log()

    def _refresh_tree(self):
        if self.adv is None or not self.adv.winfo_exists():
            return
        keep = set(self.tree.selection())
        if self.seg_idx == 0:
            self._fill_procs()
        elif self.seg_idx == 1:
            self._fill_rules()
        else:
            self._fill_whitelist()
        for iid in keep:
            if self.tree.exists(iid):
                self.tree.selection_add(iid)
        self._update_sub()

    def _fill_procs(self):
        kw = self.adv_search.get().strip().lower()
        if kw == self._search_ph:
            kw = ""
        rows = [p for p in getattr(self, "_all_procs", []) if p["pid"] != self.self_pid]
        if kw:
            rows = [p for p in rows if kw in p["name"] or kw in (p.get("title") or "").lower()]
        self.tree.delete(*self.tree.get_children())
        if not rows:
            self.tree.insert("", "end", iid="none",
                             values=("没有匹配的程序", "", ""), tags=("off",))
            return
        for idx, p in enumerate(rows):
            note = f"（{p['protect_reason']}）" if p.get("protect_reason") else ""
            self.tree.insert("", "end", iid=str(p["pid"]),
                             values=(p["name"] + note,
                                     (p.get("title") or "")[:64],
                                     _gb(p["priv"] / 1024 / 1024)),
                             tags=("odd",) if idx % 2 else ())

    def _fill_rules(self):
        self.tree.delete(*self.tree.get_children())
        field_map = {"name": "程序名", "title": "窗口标题", "path": "安装路径"}
        disabled = set(self.cfg.get("disabled_rules", []))
        for idx, r in enumerate(BUILTIN_RULES):
            on = r["pattern"] not in disabled
            tags = ("odd",) if idx % 2 else ()
            if not on:
                tags = tags + ("off",)
            self.tree.insert("", "end", iid=f"b::{r['pattern']}",
                             values=(r["note"], field_map.get(r["field"], r["field"]),
                                     "生效中" if on else "已停用"), tags=tags)
        for i, r in enumerate(self.cfg.get("rules", [])):
            self.tree.insert("", "end", iid=f"u::{i}",
                             values=(r.get("note", ""), field_map.get(r["field"], ""),
                                     "你自己加的"))

    def _fill_whitelist(self):
        self.tree.delete(*self.tree.get_children())
        items = self.cfg.get("whitelist") or []
        if not items:
            self.tree.insert("", "end", iid="empty",
                             values=("还没有添加。上面那四类已经在保护系统了", "", ""))
            self.tree.item("empty", tags=("off",))
            return
        for i, item in enumerate(items):
            kind = "程序名" if str(item).strip().lower().endswith(".exe") else "路径"
            self.tree.insert("", "end", iid=f"w::{i}", values=(item, kind, "不会被结束"))

    def _refresh_log(self):
        if self.adv is None or not self.adv.winfo_exists():
            return
        self.adv_log.configure(state="normal")
        self.adv_log.delete("1.0", "end")
        for ts, level, msg in list(self.logs)[-500:]:
            self.adv_log.insert("end", f"{ts}   ", "time")
            self.adv_log.insert("end", msg + "\n", level)
        self.adv_log.see("end")
        self.adv_log.configure(state="disabled")

    # ---- 动作
    def _on_row_double(self, _ev=None):
        if self.seg_idx == 1:
            self._toggle_rules(self.tree.selection())

    def _sel_rows(self):
        return [iid for iid in self.tree.selection() if self.tree.exists(iid)]

    def _current_proc(self, iid):
        pid = int(iid)
        return next((p for p in getattr(self, "_all_procs", []) if p["pid"] == pid), None)

    def _act_kill(self):
        rows = [x for x in self._sel_rows() if x.isdigit()]
        if not rows:
            self.hint_lbl.configure(text="先在上面选中要结束的程序", fg=RED)
            return
        for iid in rows:
            row = self._current_proc(iid)
            if row:
                reason = protect_reason(row, self.self_pid, self.cfg.get("whitelist") or ())
                if reason:
                    self.add_log("warn", f"{row['name']} 受保护（{reason}），已跳过")
                    continue
            ok, _how = kill_process(int(iid))
            if ok:
                self.add_log("kill", f"手动结束 {row['name'] if row else iid}")
            else:
                self.add_log("warn", f"结束 {row['name'] if row else iid} 失败（可能需要管理员）")
        self.monitor.force_scan = True
        self._refresh_tree()

    def _act_block(self):
        rows = [x for x in self._sel_rows() if x.isdigit()]
        if not rows:
            self.hint_lbl.configure(text="先在上面选中要拦截的程序", fg=RED)
            return
        added = 0
        for iid in rows:
            row = self._current_proc(iid)
            if not row:
                continue
            if protect_reason(row, self.self_pid, self.cfg.get("whitelist") or ()):
                self.add_log("warn", f"{row['name']} 是受保护的系统进程，不能加入拦截")
                continue
            pattern = "^" + re.escape(os.path.splitext(row["name"])[0])
            rules = self.cfg.setdefault("rules", [])
            if any(r["pattern"] == pattern for r in rules):
                continue
            rules.append({"field": "name", "pattern": pattern,
                          "note": f"你手动拦截的 {row['name']}"})
            added += 1
        if added:
            save_config(self.cfg)
            self.add_log("ok", f"已把 {added} 个程序加入拦截名单")
            self.monitor.force_scan = True
            self._refresh_tree()

    def _act_protect(self):
        rows = [x for x in self._sel_rows() if x.isdigit()]
        if not rows:
            self.hint_lbl.configure(text="先在上面选中要保护的程序", fg=RED)
            return
        wl = self.cfg.setdefault("whitelist", [])
        added = 0
        for iid in rows:
            row = self._current_proc(iid)
            if not row:
                continue
            key = row["name"]
            if key.lower() in [str(x).lower() for x in wl]:
                continue
            wl.append(key)
            added += 1
        if added:
            save_config(self.cfg)
            self.add_log("ok", f"已把 {added} 个程序加入保护名单")
            self.monitor.force_scan = True
            self._refresh_tree()

    def _toggle_rules(self, sel):
        if not sel:
            return
        for iid in sel:
            if iid.startswith("b::"):
                pattern = iid.split("::", 1)[1]
                off = self.cfg.setdefault("disabled_rules", [])
                off.remove(pattern) if pattern in off else off.append(pattern)
            elif iid.startswith("u::"):
                idx = int(iid.split("::")[1])
                rules = self.cfg.get("rules", [])
                if 0 <= idx < len(rules):
                    removed = rules.pop(idx)
                    self.add_log("ok", f"已删除规则：{removed.get('note')}")
        save_config(self.cfg)
        self.monitor.force_scan = True
        self._refresh_tree()

    def _act_rule_off(self):
        rows = [x for x in self._sel_rows()]
        if not rows:
            self.hint_lbl.configure(text="先在上面选中要停用的规则", fg=RED)
            return
        off = self.cfg.setdefault("disabled_rules", [])
        for iid in rows:
            if iid.startswith("b::"):
                p = iid.split("::", 1)[1]
                if p not in off:
                    off.append(p)
        save_config(self.cfg)
        self.monitor.force_scan = True
        self._refresh_tree()

    def _act_rule_on(self):
        rows = [x for x in self._sel_rows()]
        if not rows:
            self.hint_lbl.configure(text="先在上面选中要启用的规则", fg=RED)
            return
        off = self.cfg.setdefault("disabled_rules", [])
        for iid in rows:
            if iid.startswith("b::"):
                p = iid.split("::", 1)[1]
                if p in off:
                    off.remove(p)
        save_config(self.cfg)
        self.monitor.force_scan = True
        self._refresh_tree()

    # ---- 白名单输入
    def _wl_focus_in(self, _ev=None):
        if self.wl_entry.get() == self._wl_ph:
            self.wl_entry.delete(0, "end")
        self.wl_entry.configure(fg=INK)

    def _wl_focus_out(self, _ev=None):
        if not self.wl_entry.get().strip():
            self.wl_entry.delete(0, "end")
            self.wl_entry.insert(0, self._wl_ph)
            self.wl_entry.configure(fg=FAINT)

    def _add_whitelist(self):
        text = self.wl_entry.get().strip()
        if not text or text == self._wl_ph:
            return
        wl = self.cfg.setdefault("whitelist", [])
        if text.lower() in [str(x).lower() for x in wl]:
            self.hint_lbl.configure(text=f"「{text}」已经在保护名单里了", fg=AMBER)
            return
        wl.append(text)
        save_config(self.cfg)
        self.wl_entry.delete(0, "end")
        self._wl_focus_out()
        self._refresh_tree()
        self.add_log("ok", f"已把「{text}」加入保护名单")
        self.hint_lbl.configure(text=f"已保护 {text}", fg=GREEN)
        self.monitor.force_scan = True

    def _del_whitelist(self):
        rows = [x for x in self._sel_rows() if x.startswith("w::")]
        if not rows:
            self.hint_lbl.configure(text="先在上面选中要移出的对象", fg=RED)
            return
        wl = self.cfg.get("whitelist") or []
        targets = {wl[int(i.split("::")[1])] for i in rows
                   if 0 <= int(i.split("::")[1]) < len(wl)}
        self.cfg["whitelist"] = [x for x in wl if x not in targets]
        save_config(self.cfg)
        self._refresh_tree()
        self.add_log("info", "已移出保护名单：" + "、".join(str(t) for t in targets))
        self.monitor.force_scan = True

    # ---- 搜索框
    def _search_focus_in(self, _ev=None):
        if self.adv_search.get() == self._search_ph:
            self.adv_search.delete(0, "end")
        self.adv_search.configure(fg=INK)

    def _search_focus_out(self, _ev=None):
        if not self.adv_search.get().strip():
            self.adv_search.delete(0, "end")
            self.adv_search.insert(0, self._search_ph)
            self.adv_search.configure(fg=FAINT)

    # ---- 通用按钮
    def _btn(self, parent, text, cmd, kind="plain"):
        return AAButton(parent, text, cmd, kind=kind, font=self.fn(11), scale=self.S)

    def _close_advanced(self):
        self.adv.destroy()
        self.adv = None


# ---------------------------------------------------------------- 启动
def make_dpi_aware():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
        return
    except Exception:
        pass
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def set_app_identity():
    """给进程一个独立身份。

    不设这个，Windows 会把任务栏按钮归到 pythonw.exe 名下，图标也就用
    Python 那个。必须在创建任何窗口之前调用。
    """
    try:
        shell32.SetCurrentProcessExplicitAppUserModelID.argtypes = [wt.LPCWSTR]
        shell32.SetCurrentProcessExplicitAppUserModelID.restype = ctypes.c_long
        shell32.SetCurrentProcessExplicitAppUserModelID("Henry.MemoryGuard.Desktop")
    except Exception:
        pass


def apply_icon(win):
    """给窗口装图标：多尺寸 PNG 优先，再用 Win32 补大图标给任务栏。"""
    ico = os.path.join(APP_DIR, "icon.ico")

    photos = []
    try:
        # 从大到小：Tk 取第一个当主图标，其余作后备
        for size in (256, 128, 96, 72, 64, 48, 40, 36, 32, 24, 20, 16):
            path = os.path.join(APP_DIR, f"icon-{size}.png")
            if os.path.exists(path):
                photos.append(tk.PhotoImage(file=path))
        if photos:
            win.iconphoto(True, *photos)
            win._icon_photos = photos          # 留住引用，否则被回收成空白
    except Exception:
        pass

    try:
        win.iconbitmap(default=ico)
    except Exception:
        pass

    # Tk 只往窗口塞了小图标，任务栏读的是 ICON_BIG。这里的关键是尺寸要对上：
    # 系统按 DPI 决定任务栏图标多大（150% 缩放时是 36px），给的 HICON 若比它大，
    # 系统会把大图缩小——那一步插入的像素台阶，就是"图标看着有锯齿"的来源。
    # 所以按当前 DPI 算出实际像素尺寸，从 ico 里取同尺寸的那一帧，一步到位。
    try:
        win.update_idletasks()
        hwnd = user32.GetAncestor(wt.HWND(win.winfo_id()), 2)   # GA_ROOT
        scale = 1.0
        try:
            user32.GetDpiForWindow.argtypes = [wt.HWND]
            user32.GetDpiForWindow.restype = wt.UINT
            scale = (user32.GetDpiForWindow(hwnd) or 96) / 96.0
        except Exception:
            scale = win.winfo_fpixels("1i") / 96.0

        user32.LoadImageW.restype = wt.HANDLE
        user32.LoadImageW.argtypes = [wt.HINSTANCE, wt.LPCWSTR, wt.UINT,
                                      ctypes.c_int, ctypes.c_int, wt.UINT]
        user32.SendMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
        # 任务栏图标 24 逻辑像素，标题栏 16 逻辑像素
        for kind, logical in ((1, 24), (0, 16)):        # ICON_BIG / ICON_SMALL
            px = max(16, int(round(logical * scale)))
            handle = user32.LoadImageW(None, ico, 1, px, px, 0x10 | 0x8000)
            if handle:
                user32.SendMessageW(hwnd, 0x0080, kind, wt.LPARAM(handle))
    except Exception:
        pass


def _focus_server(srv, wake):
    """第二个实例连上来时说一句 SHOW，这里只负责把事件立起来。

    注意：这个函数跑在普通线程里，绝对不能碰 Tk——Tcl 解释器不是线程安全的，
    从别的线程调 root.after/deiconify 会把整个进程带走。窗口操作交给主线程轮询。
    """
    while True:
        try:
            conn, _addr = srv.accept()
        except OSError:
            return
        try:
            with conn:
                conn.recv(32)
        except OSError:
            pass
        wake.set()


def selftest():
    m = mem_info()
    print(f"内存：{m['used'] / 1024 ** 3:.1f}/{m['total'] / 1024 ** 3:.1f} GB  占用 {m['percent']}%")
    procs = snapshot()
    print(f"进程：{len(procs)} 个，最大的 {procs[0]['name']} {procs[0]['priv'] / 1024 / 1024:.0f} MB")
    compiled = all_rules(load_config())
    hits = [p for p in procs if match_rules(p, compiled)]
    print(f"规则 {len(compiled)} 条，命中 {len(hits)} 个：" + ", ".join(p["name"] for p in hits[:6]))
    print(f"admin={is_admin()}")


def _instance_mutex():
    """命名互斥体做单实例：返回 (句柄, 是否已有实例在跑)。

    句柄要一直攥着，进程退出时系统自动释放，不需要手动关。
    """
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateMutexW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.LPCWSTR]
        k32.CreateMutexW.restype = wt.HANDLE
        handle = k32.CreateMutexW(None, False, "Local\\MemoryGuard.SingleInstance")
        return handle, ctypes.get_last_error() == 183      # ERROR_ALREADY_EXISTS
    except Exception:
        return None, False


def main():
    if "--selftest" in sys.argv:
        selftest()
        return
    if tk is None:
        user32.MessageBoxW(None, "当前 Python 缺少 tkinter，无法显示界面。", "内存守护", 0x10)
        return

    # 单实例：Windows 上 SO_REUSEADDR 允许两个进程绑同一个端口，靠 bind 失败来判重
    # 是判不住的（实测能同时开出两个窗口）。命名互斥体是系统级唯一对象，才算数。
    mutex, running = _instance_mutex()
    srv = None
    if running:
        try:
            with socket.create_connection(("127.0.0.1", SINGLE_PORT), timeout=0.6) as conn:
                conn.sendall(b"SHOW")
        except OSError:
            pass
        return

    try:
        srv = socket.socket()
        srv.bind(("127.0.0.1", SINGLE_PORT))
        srv.listen(2)
    except OSError:
        srv = None      # 端口被别的程序占着：照样能用，只是没法被别人唤到前台

    make_dpi_aware()
    set_app_identity()
    root = tk.Tk()
    root.title("内存守护")
    root.configure(bg=BG)
    root.resizable(False, False)
    apply_icon(root)

    app = GuardApp(root)

    # 居中
    root.update_idletasks()
    w, h = root.winfo_width(), root.winfo_height()
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(f"+{(sw - w) // 2}+{max(0, (sh - h) // 2 - 40)}")

    wake = threading.Event()
    if srv is not None:
        threading.Thread(target=_focus_server, args=(srv, wake), daemon=True).start()

    def _watch_wake():
        if wake.is_set():
            wake.clear()
            root.deiconify()
            root.lift()
            root.focus_force()
        root.after(300, _watch_wake)

    root.after(300, _watch_wake)

    def _open_adv_tab(idx: int):
        app.open_advanced()
        try:
            app._set_tab(idx)
        except Exception:
            pass

    for arg in sys.argv[1:]:
        if arg == "--adv":
            root.after(400, app.open_advanced)
        elif arg.startswith("--advtab="):
            try:
                root.after(400, lambda i=int(arg.split("=")[1]): _open_adv_tab(i))
            except Exception:
                pass

    def _on_close():
        app.monitor.stop_flag = True
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", _on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
