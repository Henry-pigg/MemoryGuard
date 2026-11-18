#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在桌面创建「内存守护」快捷方式（用 -EncodedCommand 传参，彻底避开中文编码问题）。"""

import base64
import os
import subprocess

APP_DIR = os.path.dirname(os.path.abspath(__file__))
VBS = os.path.join(APP_DIR, "launch.vbs")
ICON = os.path.join(APP_DIR, "icon.ico")
LNK_NAME = "内存守护.lnk"

ps = r"""
$ErrorActionPreference = 'Stop'
$desktop = [Environment]::GetFolderPath('Desktop')
$ws = New-Object -ComObject WScript.Shell
$lnkPath = Join-Path $desktop 'LNKNAME'
$s = $ws.CreateShortcut($lnkPath)
$s.TargetPath = "$env:SystemRoot\System32\wscript.exe"
$s.Arguments = '"VBS"'
$s.WorkingDirectory = 'APPDIR'
$s.IconLocation = 'ICON,0'
$s.Description = 'DESC'
$s.WindowStyle = 1
$s.Save()
Write-Output ('OK ' + $lnkPath)
Write-Output ('Exists=' + (Test-Path $lnkPath))
""".replace("LNKNAME", LNK_NAME).replace("VBS", VBS).replace("APPDIR", APP_DIR).replace(
    "ICON", ICON
).replace("DESC", "实时内存监控 · 一键回收 · 弹窗推广进程清理")

encoded = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
r = subprocess.run(
    ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
    capture_output=True,
)
print("rc =", r.returncode)
print(r.stdout.decode("gbk", "ignore"))
print(r.stderr.decode("gbk", "ignore"))
