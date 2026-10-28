"""顶栏快捷方式的网站图标。

浏览器的内容安全策略不允许页面直接加载外站图片,所以由面板服务端去取:只取「已保存的快捷方式」所在的站点,
先读页面里的 <link rel="icon">,没有再试 /favicon.ico;结果缓存在 data/favicons(成功 7 天,失败 1 小时)。
只跟随同一主机的跳转,单个图标最大 100KB,类型必须是图片。局域网里用自签名证书的 HTTPS 站点也能取到(这里只取图标,不校验证书)。"""
import hashlib
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from . import config
from .util import log

MAX_ICON = 100_000
MAX_PAGE = 150_000
TTL_OK, TTL_MISS = 7 * 86400, 3600
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


class _SameHost(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).hostname != urllib.parse.urlsplit(req.full_url).hostname:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener():
    return urllib.request.build_opener(_SameHost, urllib.request.HTTPSHandler(context=_CTX))


def _get(url, limit):
    req = urllib.request.Request(url, headers={"User-Agent": "FLUX-favicon/1", "Accept": "*/*"})
    with _opener().open(req, timeout=4) as r:
        return r.read(limit + 1)[:limit], (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()


def _kind(b, ct):
    """按内容判断图片类型(不信服务器给的 Content-Type);不是图片给空。"""
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if b[:4] == b"\x00\x00\x01\x00":
        return "image/x-icon"
    if b[:3] == b"GIF":
        return "image/gif"
    if b[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        return "image/webp"
    head = b[:400].lstrip().lower()
    if (head.startswith(b"<?xml") or head.startswith(b"<svg")) and b"<svg" in b[:2000].lower():
        return "image/svg+xml"
    return ""


_LINK = re.compile(r"<link\b[^>]*>", re.I)


def _candidates(page_url, html):
    out = []
    for tag in _LINK.findall(html):
        rel = re.search(r"""rel\s*=\s*["']([^"']*)["']""", tag, re.I)
        href = re.search(r"""href\s*=\s*["']([^"']+)["']""", tag, re.I)
        if rel and href and "icon" in rel.group(1).lower() and not href.group(1).lower().startswith("data:"):
            u = urllib.parse.urljoin(page_url, href.group(1).strip())
            if u.lower().startswith(("http://", "https://")) and u not in out:
                out.append(u)
    p = urllib.parse.urlsplit(page_url)
    out.append(f"{p.scheme}://{p.netloc}/favicon.ico")
    return out[:4]


def _fetch(link):
    cands = []
    try:
        b, _ = _get(link, MAX_PAGE)
        cands = _candidates(link, b.decode("utf-8", "ignore"))
    except Exception:
        p = urllib.parse.urlsplit(link)
        cands = [f"{p.scheme}://{p.netloc}/favicon.ico"]
    for u in cands:
        try:
            b, ct = _get(u, MAX_ICON)
        except Exception:
            continue
        k = _kind(b, ct)
        if k and 0 < len(b) <= MAX_ICON:
            return b, k
    return None


def _paths(link):
    p = urllib.parse.urlsplit(link)
    h = hashlib.sha1(f"{p.scheme}://{p.netloc}".encode()).hexdigest()[:24]
    d = os.path.join(config.DATA_DIR, "favicons")
    return d, os.path.join(d, h + ".bin"), os.path.join(d, h + ".json")


def get(link):
    """(图片字节, 类型) 或 None。带缓存。"""
    d, fb, fm = _paths(link)
    try:
        with open(fm, encoding="utf-8") as f:
            m = json.load(f)
        if time.time() - m.get("at", 0) < (TTL_OK if m.get("ct") else TTL_MISS):
            if not m.get("ct"):
                return None
            with open(fb, "rb") as f:
                return f.read(), m["ct"]
    except (OSError, ValueError):
        pass
    try:
        res = _fetch(link)
    except Exception as e:
        log("网站图标", link, e)
        res = None
    try:
        os.makedirs(d, exist_ok=True)
        if res:
            with open(fb, "wb") as f:
                f.write(res[0])
        with open(fm, "w", encoding="utf-8") as f:
            json.dump({"at": time.time(), "ct": res[1] if res else ""}, f)
        _trim(d)
    except OSError:
        pass
    return res


def _trim(d, keep=60):
    """缓存目录最多留 keep 个图标(按修改时间留最新的)。"""
    try:
        fs = sorted((os.path.getmtime(os.path.join(d, x)), x) for x in os.listdir(d) if x.endswith(".json"))
        for _, x in fs[:-keep]:
            for ext in (".json", ".bin"):
                try:
                    os.remove(os.path.join(d, x[:-5] + ext))
                except OSError:
                    pass
    except OSError:
        pass


def saved_links(con):
    """已保存的快捷方式网址(只允许为这些站点取图标,避免被拿来探测任意地址)。"""
    from . import backup
    t = (backup.get_ui(con) or {}).get("theme") or {}
    out = []
    for r in t.get("links") or []:
        u = str((r or {}).get("u") or "")
        if u.lower().startswith(("http://", "https://")):
            out.append(u)
    return out
