#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成程序图标。

一、绘制交给 GDI+（gdiplus.dll），不手算像素：
    · 圆角：GraphicsPath + 四段 Arc
    · 抗锯齿：SmoothingModeAntiAlias + PixelOffsetModeHighQuality
    · 每档按目标尺寸矢量绘制，不做位图放大

二、ICO 按 Windows 官方 ICONDIR / ICONDIRENTRY 规范封装：
    · 尺寸 <= 128 一律写 32bpp DIB（BITMAPINFOHEADER + BGRA + AND 掩码），
      这是 GDI 原生能读的格式
    · 只有 256x256 用 PNG 压缩帧（规范里 PNG 帧就是为这一档加的）
    · 尺寸表覆盖 100/125/150/175/200% 缩放下的实际显示尺寸，
      例如 150% 时任务栏要 36px、桌面图标要 72px，必须真实存在，
      否则 Windows 会把邻近档硬拉大，那才是锯齿的真正来源

三、设计：墨色圆角方块，中央一条横向占用条——左边白色是被占用的部分，
    右端直切（读作"填到这里"，而不是一颗可拖动的滑块）。
"""

import ctypes
import os
import struct
from ctypes import wintypes as wt

APP_DIR = os.path.dirname(os.path.abspath(__file__))
ICO = os.path.join(APP_DIR, "icon.ico")

# 覆盖 16px(100%)→16*2(200%) 与 24px(100%)→24*2(200%) 两套栅格的所有落点
SIZES = (16, 20, 24, 28, 32, 36, 40, 48, 64, 72, 96, 128, 256)
PNG_MIN = 256               # 只有这一档用 PNG 帧

SS = 1                      # 直接按目标尺寸矢量绘制；>1 则超采样后缩小

# ---------------------------------------------------------------- 配色
BG_TOP = 0xFF242426
BG_BOT = 0xFF141415
TRACK = 0xFF47474C
FILL = 0xFFFFFFFF

# ---------------------------------------------------------------- 几何（0..1）
CORNER = 0.2235             # 圆角半径 / 边长
BAR_H = 0.160
BAR_X0, BAR_X1 = 0.140, 0.860
USED = 0.67

# ---------------------------------------------------------------- GDI+
gp = ctypes.WinDLL("gdiplus")


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD),
                ("Data4", ctypes.c_ubyte * 8)]


class GdiplusStartupInput(ctypes.Structure):
    _fields_ = [("GdiplusVersion", wt.UINT), ("DebugEventCallback", ctypes.c_void_p),
                ("SuppressBackgroundThread", wt.BOOL), ("SuppressExternalCodecs", wt.BOOL)]


class ImageCodecInfo(ctypes.Structure):
    _fields_ = [("Clsid", GUID), ("FormatID", GUID),
                ("CodecName", wt.LPWSTR), ("DllName", wt.LPWSTR),
                ("FormatDescription", wt.LPWSTR), ("FilenameExtension", wt.LPWSTR),
                ("MimeType", wt.LPWSTR), ("Flags", wt.DWORD), ("Version", wt.DWORD),
                ("SigCount", wt.DWORD), ("SigSize", wt.DWORD),
                ("SigPattern", ctypes.c_void_p), ("SigMask", ctypes.c_void_p)]


class PointF(ctypes.Structure):
    _fields_ = [("X", ctypes.c_float), ("Y", ctypes.c_float)]


class GpRect(ctypes.Structure):
    _fields_ = [("X", ctypes.c_int), ("Y", ctypes.c_int),
                ("Width", ctypes.c_int), ("Height", ctypes.c_int)]


class BitmapData(ctypes.Structure):
    _fields_ = [("Width", wt.UINT), ("Height", wt.UINT), ("Stride", ctypes.c_int),
                ("PixelFormat", ctypes.c_int), ("Scan0", ctypes.c_void_p),
                ("Reserved", ctypes.c_void_p)]


def _sig(name, args):
    fn = getattr(gp, name)
    fn.argtypes = args
    fn.restype = ctypes.c_int
    return fn


VOIDP = ctypes.c_void_p
OUTP = ctypes.POINTER(ctypes.c_void_p)
REAL = ctypes.c_float

CreateBitmapFromScan0 = _sig("GdipCreateBitmapFromScan0",
                             [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                              ctypes.c_char_p, OUTP])
GetImageGraphicsContext = _sig("GdipGetImageGraphicsContext", [VOIDP, OUTP])
DisposeImage = _sig("GdipDisposeImage", [VOIDP])
DeleteGraphics = _sig("GdipDeleteGraphics", [VOIDP])
GraphicsClear = _sig("GdipGraphicsClear", [VOIDP, ctypes.c_uint])

SetSmoothingMode = _sig("GdipSetSmoothingMode", [VOIDP, ctypes.c_int])
SetPixelOffsetMode = _sig("GdipSetPixelOffsetMode", [VOIDP, ctypes.c_int])
SetCompositingQuality = _sig("GdipSetCompositingQuality", [VOIDP, ctypes.c_int])
SetInterpolationMode = _sig("GdipSetInterpolationMode", [VOIDP, ctypes.c_int])
SetCompositingMode = _sig("GdipSetCompositingMode", [VOIDP, ctypes.c_int])

CreatePath = _sig("GdipCreatePath", [ctypes.c_int, OUTP])
AddPathArc = _sig("GdipAddPathArc", [VOIDP, REAL, REAL, REAL, REAL, REAL, REAL])
AddPathLine = _sig("GdipAddPathLine", [VOIDP, REAL, REAL, REAL, REAL])
ClosePathFigure = _sig("GdipClosePathFigure", [VOIDP])
DeletePath = _sig("GdipDeletePath", [VOIDP])

CreateSolidFill = _sig("GdipCreateSolidFill", [ctypes.c_uint, OUTP])
CreateLineBrush = _sig("GdipCreateLineBrush", [ctypes.POINTER(PointF), ctypes.POINTER(PointF),
                                               ctypes.c_uint, ctypes.c_uint,
                                               ctypes.c_int, OUTP])
DeleteBrush = _sig("GdipDeleteBrush", [VOIDP])
FillPath = _sig("GdipFillPath", [VOIDP, VOIDP, VOIDP])
DrawImageRect = _sig("GdipDrawImageRect", [VOIDP, VOIDP, REAL, REAL, REAL, REAL])

LockBits = _sig("GdipBitmapLockBits", [VOIDP, ctypes.POINTER(GpRect), wt.UINT,
                                       ctypes.c_int, ctypes.POINTER(BitmapData)])
UnlockBits = _sig("GdipBitmapUnlockBits", [VOIDP, ctypes.POINTER(BitmapData)])

GetImageEncodersSize = _sig("GdipGetImageEncodersSize",
                            [ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)])
GetImageEncoders = _sig("GdipGetImageEncoders", [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p])
SaveImageToFile = _sig("GdipSaveImageToFile",
                       [VOIDP, wt.LPCWSTR, ctypes.POINTER(GUID), ctypes.c_void_p])


# ---------------------------------------------------------------- 基础件
def startup():
    token = ctypes.c_void_p()
    buf = GdiplusStartupInput(1, None, False, False)
    status = gp.GdiplusStartup(ctypes.byref(token), ctypes.byref(buf), None)
    if status != 0:
        raise OSError(f"GdiplusStartup 失败，status={status}")
    return token


def png_encoder_clsid():
    num, size = ctypes.c_uint(), ctypes.c_uint()
    GetImageEncodersSize(ctypes.byref(num), ctypes.byref(size))
    if not size.value:
        raise OSError("找不到图像编码器")
    buf = ctypes.create_string_buffer(size.value)
    GetImageEncoders(num, size, buf)
    infos = ctypes.cast(buf, ctypes.POINTER(ImageCodecInfo))
    for i in range(num.value):
        if infos[i].MimeType and infos[i].MimeType.lower() == "image/png":
            return infos[i].Clsid
    raise OSError("找不到 PNG 编码器")


def new_target(w, h):
    """32bpp ARGB 位图 + 配好的绘图上下文。"""
    bmp = ctypes.c_void_p()
    status = CreateBitmapFromScan0(w, h, 0, 0x0026200A, None, ctypes.byref(bmp))
    if status != 0:
        raise OSError(f"GdipCreateBitmapFromScan0 失败，status={status}")
    gfx = ctypes.c_void_p()
    status = GetImageGraphicsContext(bmp, ctypes.byref(gfx))
    if status != 0:
        raise OSError(f"GdipGetImageGraphicsContext 失败，status={status}")
    SetSmoothingMode(gfx, 4)        # AntiAlias
    SetPixelOffsetMode(gfx, 4)      # HighQuality
    SetCompositingQuality(gfx, 2)   # HighQuality
    SetInterpolationMode(gfx, 7)    # HighQualityBicubic
    SetCompositingMode(gfx, 0)      # SourceOver
    GraphicsClear(gfx, 0x00000000)
    return bmp, gfx


def round_rect_path(x, y, w, h, r):
    """四段 90° 圆弧拼成的圆角矩形（GDI+ 里 0° 朝右、90° 朝下）。"""
    path = ctypes.c_void_p()
    CreatePath(0, ctypes.byref(path))       # FillModeAlternate
    AddPathArc(path, x, y, 2 * r, 2 * r, 180, 90)
    AddPathArc(path, x + w - 2 * r, y, 2 * r, 2 * r, 270, 90)
    AddPathArc(path, x + w - 2 * r, y + h - 2 * r, 2 * r, 2 * r, 0, 90)
    AddPathArc(path, x, y + h - 2 * r, 2 * r, 2 * r, 90, 90)
    ClosePathFigure(path)
    return path


def progress_path(x, y, w, h):
    """已占用段：左端圆头、右端直切。"""
    r = h / 2
    path = ctypes.c_void_p()
    CreatePath(0, ctypes.byref(path))
    AddPathArc(path, x, y, h, h, 90, 180)          # 左侧半圆：底 → 左 → 顶
    AddPathLine(path, x + r, y, x + w, y)          # 顶边到右
    AddPathLine(path, x + w, y, x + w, y + h)      # 右边到底
    ClosePathFigure(path)                          # 回到圆弧起点
    return path


def fill_solid(gfx, path, argb):
    brush = ctypes.c_void_p()
    CreateSolidFill(argb, ctypes.byref(brush))
    FillPath(gfx, brush, path)
    DeleteBrush(brush)


def fill_gradient(gfx, path, c1, c2, y0, y1):
    p1, p2 = PointF(0.0, y0), PointF(0.0, y1)
    brush = ctypes.c_void_p()
    status = CreateLineBrush(ctypes.byref(p1), ctypes.byref(p2), c1, c2, 0,
                             ctypes.byref(brush))
    if status != 0:
        raise OSError(f"GdipCreateLineBrush 失败，status={status}")
    FillPath(gfx, brush, path)
    DeleteBrush(brush)


# ---------------------------------------------------------------- 图形
def metrics(size):
    """把几何吸附到像素栅格上。

    按比例算出来的坐标几乎总是小数（36px 时条高 5.76、上边 15.12），
    直边落在半像素上会让 GDI+ 在两侧各铺一行灰，读起来就是"糊""毛"。
    取整之后这些边正好压在像素边界，抗锯齿只留在圆角弧线上。
    """
    r = round(size * CORNER)
    if size <= 20:
        r = max(2, round(size * 0.19))      # 小尺寸半径太大，弧线会碎成台阶
    bar_h = max(2, round(size * BAR_H))
    bar_y = round((size - bar_h) / 2)
    bar_x0 = round(size * BAR_X0)
    bar_x1 = round(size * BAR_X1)
    fill_x1 = round(bar_x0 + (bar_x1 - bar_x0) * USED)
    return r, bar_x0, bar_y, bar_x1, bar_h, fill_x1


def draw_icon(gfx, size):
    size = float(size)
    r, bar_x0, bar_y, bar_x1, bar_h, fill_x1 = metrics(int(size))

    plate = round_rect_path(0.0, 0.0, size, size, float(r))
    fill_gradient(gfx, plate, BG_TOP, BG_BOT, 0, size)
    DeletePath(plate)

    track = round_rect_path(float(bar_x0), float(bar_y),
                            float(bar_x1 - bar_x0), float(bar_h), bar_h / 2.0)
    fill_solid(gfx, track, TRACK)
    DeletePath(track)

    bar = progress_path(float(bar_x0), float(bar_y),
                        float(fill_x1 - bar_x0), float(bar_h))
    fill_solid(gfx, bar, FILL)
    DeletePath(bar)


def render(size):
    """返回一张 size×size、32bpp ARGB 的 GDI+ 位图。"""
    if SS == 1:
        bmp, gfx = new_target(size, size)
        draw_icon(gfx, float(size))
        DeleteGraphics(gfx)
        return bmp

    big = size * SS
    src, gfx = new_target(big, big)
    draw_icon(gfx, float(big))
    DeleteGraphics(gfx)
    dst, gfx2 = new_target(size, size)
    DrawImageRect(gfx2, src, 0.0, 0.0, float(size), float(size))
    DeleteGraphics(gfx2)
    DisposeImage(src)
    return dst


def bgra(bmp, size):
    """取出位图像素，返回自上而下的 BGRA 行列表。"""
    rect = GpRect(0, 0, size, size)
    lock = BitmapData()
    status = LockBits(bmp, ctypes.byref(rect), 1, 0x0026200A, ctypes.byref(lock))
    if status != 0:
        raise OSError(f"GdipBitmapLockBits 失败，status={status}")
    stride = abs(lock.Stride)
    raw = ctypes.string_at(lock.Scan0, stride * size)
    UnlockBits(bmp, ctypes.byref(lock))
    rows = [raw[y * stride:y * stride + size * 4] for y in range(size)]
    if lock.Stride < 0:
        rows.reverse()
    return rows


def save_png(bmp, path, clsid):
    status = SaveImageToFile(bmp, path, ctypes.byref(clsid), None)
    if status != 0:
        raise OSError(f"保存 {path} 失败，status={status}")


# ---------------------------------------------------------------- 封装
def dib_frame(rows, size):
    """32bpp DIB：BITMAPINFOHEADER + 自下而上的 BGRA + 1bpp AND 掩码。

    这是 MSDN 里 ICONIMAGE 的标准结构，GDI 直接能画，不需要解码器。
    """
    header = struct.pack("<IiiHHIIiiII",
                         40,                    # biSize
                         size,                  # biWidth
                         size * 2,              # biHeight = XOR 图 + AND 掩码
                         1,                     # biPlanes
                         32,                    # biBitCount
                         0,                     # biCompression = BI_RGB
                         size * size * 4,       # biSizeImage
                         0, 0, 0, 0)
    xor = b"".join(reversed(rows))              # DIB 行序是自下而上
    mask_stride = ((size + 31) // 32) * 4       # 1bpp，每行 4 字节对齐
    # 32bpp 用的是 alpha 通道，掩码全 0 表示全部不透明
    and_mask = b"\x00" * (mask_stride * size)
    return header + xor + and_mask


def build_ico(frames):
    """frames: [(size, bytes), ...]，按 ICONDIR / ICONDIRENTRY 排布。"""
    head = struct.pack("<HHH", 0, 1, len(frames))
    offset = 6 + 16 * len(frames)
    entries = b""
    for size, data in frames:
        dim = 0 if size >= 256 else size        # 256 在字段里记作 0
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    return head + entries + b"".join(d for _s, d in frames)


def main():
    token = startup()
    try:
        clsid = png_encoder_clsid()
        frames = []
        for size in SIZES:
            bmp = render(size)
            rows = bgra(bmp, size)

            png_path = os.path.join(APP_DIR, f"icon-{size}.png")
            save_png(bmp, png_path, clsid)
            DisposeImage(bmp)

            if size >= PNG_MIN:
                with open(png_path, "rb") as fh:
                    data = fh.read()
                kind = "PNG"
            else:
                data = dib_frame(rows, size)
                kind = "DIB"

            frames.append((size, data))
            print(f"  {size:3d}x{size:<3d} {kind}  {len(data):6d} B")

        ico = build_ico(frames)
        with open(ICO, "wb") as fh:
            fh.write(ico)
        print(f"icon.ico  {len(ico) / 1024:.1f} KB  ({len(SIZES)} 档)")
    finally:
        gp.GdiplusShutdown(token)


if __name__ == "__main__":
    main()
