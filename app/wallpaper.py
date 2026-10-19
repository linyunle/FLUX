"""登录页壁纸:在「设置 → 安全与隐私」上传一张图,登录页就像 Argon 主题那样以它为背景(登录卡片是毛玻璃)。
图片存在 data/wallpaper.bin;只接受 JPEG / PNG / WebP(按文件头判断,不信浏览器给的类型),最大 700KB(页面里会先自动压缩)。"""
import base64
import json
import os
import random
import re
import threading
import time
import urllib.request

from . import config
from .util import log

MAX = 700 * 1024            # 手动上传的上限(页面会先压缩)
READ_MAX = 3 * 1024 * 1024  # 必应图片的上限
BING = "https://www.bing.com"
_lock = threading.Lock()
ST = {"at": 0, "err": "", "title": ""}


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
            b = f.read(READ_MAX + 1)
        t = kind(b)
        if not t or len(b) > READ_MAX:
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


# ---------- 自动更换(必应每日图片) ----------
def _cfg_path():
    return os.path.join(config.DATA_DIR, "wallpaper.json")


def cfg():
    c = {"source": "upload", "mode": "daily", "every": 24, "mkt": "zh-CN"}
    try:
        with open(_cfg_path(), encoding="utf-8") as f:
            c.update({k: v for k, v in json.load(f).items() if k in c})
    except (OSError, ValueError):
        pass
    return c


def save_cfg(body):
    c = cfg()
    if body.get("source") in ("upload", "bing"):
        c["source"] = body["source"]
    if body.get("mode") in ("daily", "random"):
        c["mode"] = body["mode"]
    if body.get("every") is not None:
        c["every"] = max(1, min(168, int(body["every"])))
    if body.get("mkt") in ("zh-CN", "en-US", "ja-JP", "de-DE", "fr-FR", "en-GB"):
        c["mkt"] = body["mkt"]
    os.makedirs(config.DATA_DIR, exist_ok=True)
    with open(_cfg_path(), "w", encoding="utf-8") as f:
        json.dump(c, f)
    return c


def status():
    return {**info(), "cfg": cfg(), "bing": dict(ST)}


def _get(url, limit):
    from . import geo        # 复用 GeoIP 下载用的代理设置(设置 → 数据 里那个)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 FLUX"})
    with geo._opener().open(req, timeout=30) as r:
        return r.read(limit + 1)


def refresh():
    """从必应取一张图换上去。只访问 www.bing.com,图片地址必须是它的 /th?id= 路径。"""
    c = cfg()
    with _lock:
        try:
            n = 8 if c["mode"] == "random" else 1
            idx = random.randrange(0, 8) if c["mode"] == "random" else 0
            j = json.loads(_get(f"{BING}/HPImageArchive.aspx?format=js&idx={idx}&n=1&mkt={c['mkt']}", 200000))
            im = (j.get("images") or [None])[0]
            u = (im or {}).get("url") or ""
            if not u.startswith("/th?id="):
                raise ValueError("必应返回的图片地址不对")
            b = _get(BING + u, READ_MAX)
            if len(b) > READ_MAX or not kind(b):
                raise ValueError("下载的不是图片或太大")
            os.makedirs(config.DATA_DIR, exist_ok=True)
            tmp = _path() + ".tmp"
            with open(tmp, "wb") as f:
                f.write(b)
            os.replace(tmp, _path())
            ST.update(at=int(time.time()), err="", title=str(im.get("title") or im.get("copyright") or "")[:80])
        except Exception as e:
            ST.update(at=int(time.time()), err=f"{type(e).__name__}: {e}"[:160])
            log("登录壁纸更换失败", e)
    return status()


def run():
    """后台线程:选了必应来源就按间隔自动换。"""
    time.sleep(30)
    while True:
        try:
            c = cfg()
            if c["source"] == "bing":
                try:
                    age = time.time() - os.path.getmtime(_path())
                except OSError:
                    age = 1e9
                if age >= c["every"] * 3600 and time.time() - ST["at"] > 900:
                    refresh()
        except Exception as e:
            log("壁纸线程出错", e)
        time.sleep(600)
