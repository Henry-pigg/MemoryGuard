# 内存守护 Memory Guard



[English](README.en.md)


Windows 上的单文件内存监控工具。看物理内存占用、按需回收工作集、关掉部分桌面软件在后台开的推广和弹窗进程。

纯标准库：`ctypes` 调 Win32，界面用 `tkinter`，不需要 `pip install`。

![主界面](preview-main.png)

## 功能

- **按程序合并进程**：十八个 `doubao.exe` 合成一行，标着「18 个进程」。
- **释放内存，不关程序**：把后台进程的工作集移到硬盘（`EmptyWorkingSet`）。以管理员身份运行可额外清空待命列表。
- **超过阈值自动释放**：默认 85%，冷却 120 秒。
- **关闭已知推广进程**：广告、推送、更新、后台助手。软件主程序不在规则里。
- **跳过正在使用的程序**：同一程序只要有一个进程带可见窗口，整组不动。

## 环境要求

Windows 10 / 11，Python 3.9 及以上。不需要其他依赖。

## 用法

```bat
python  memory_guard.py --version      :: 打印版本
python  memory_guard.py --selftest     :: 命令行自检
pythonw memory_guard.py                :: 后台启动
python  make_icon.py                   :: 生成图标
python  install_shortcut.py            :: 创建桌面快捷方式
```

重复点击快捷方式不会开第二个窗口，只会把已运行的窗口叫到前面。

## 详细信息窗口

![详细信息](preview-advanced.png)

两个页面（程序 / 记录）、三个视图（全部程序 / 已拦截 / 已保护）。内置的保护规则可以逐条停用，也可以自己加白名单。

## 文件

| 文件 | 说明 |
| --- | --- |
| `memory_guard.py` | 全部功能，约 2500 行 |
| `make_icon.py` | 用 GDI+ 生成整套图标 |
| `install_shortcut.py` | 桌面快捷方式 |
| `launch.vbs` | 无控制台的启动器 |
| `使用说明.txt` | 面向普通用户的说明 |

## 限制

- 规则是 36 条静态正则，没收录的软件需要自己加，程序不会自动识别。
- 释放内存只是把后台进程的工作集移走，程序再次访问会读回来。这是 Windows 的机制，不是失效。
- 界面按 150% 缩放调的，其他 DPI 下排版可能有偏差。
- 没有打包成 `.exe`，需要本机有 Python。

## 许可

MIT，见 [LICENSE](LICENSE)。
