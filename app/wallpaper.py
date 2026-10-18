"""登录页壁纸:在「设置 → 安全与隐私」上传一张图,登录页就像 Argon 主题那样以它为背景(登录卡片是毛玻璃)。
图片存在 data/wallpaper.bin;只接受 JPEG / PNG / WebP(按文件头判断,不信浏览器给的类型),最大 700KB(页面里会先自动压缩)。"""
import base64
import os
import re

from . import config

MAX = 700 * 1024


def _path():
    return os.path.join(config.DATA_DIR, "wallpaper.bin")


def kind(b):
    if b[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        return "image/webp"
    return ""


def read():
    """返回 (字节, 类型, 版本号);没有壁纸返回 (None, '', 0)。"""
    try:
        with open(_path(), "rb") as f:
            b = f.read(MAX + 1)
        t = kind(b)
        if not t or len(b) > MAX:
            return None, "", 0
        return b, t, int(os.path.getmtime(_path()))
    except OSError:
        return None, "", 0


def info():
    b, t, v = read()
    return {"has": b is not None, "bytes": len(b) if b else 0, "type": t, "v": v}


def save(data_url):
    m = re.match(r"^data:[\w/+.-]*;base64,(.+)$", str(data_url or ""), re.S)
    if not m:
        raise ValueError("图片数据格式不对")
    try:
        b = base64.b64decode(m.group(1), validate=False)
    except Exception:
        raise ValueError("图片数据解码失败")
    if len(b) > MAX:
        raise ValueError("图片太大(压缩后仍超过 700KB),换一张小一点的")
    if not kind(b):
        raise ValueError("只支持 JPEG / PNG / WebP 图片")
    os.makedirs(config.DATA_DIR, exist_ok=True)
    tmp = _path() + ".tmp"
    with open(tmp, "wb") as f:
        f.write(b)
    os.replace(tmp, _path())
    return info()


def remove():
    try:
        os.remove(_path())
    except OSError:
        pass
    return info()
