"""新版本提示:查 GitHub Releases 的最新版本(缓存 6 小时,失败静默)。"""
import re
import threading
import time

from . import config
from .util import http_json

_cache = {"at": 0, "data": {}}
_lock = threading.Lock()


def _ver(s):
    return tuple(int(x) for x in re.findall(r"\d+", s or "")[:3])


def check(force=False):
    info = {"current": config.VERSION, "latest": "", "url": "", "newer": False, "enabled": bool(config.GITHUB_REPO), "error": ""}
    if not config.GITHUB_REPO:
        return info
    with _lock:
        if not force and time.time() - _cache["at"] < 6 * 3600 and _cache["data"]:
            return dict(_cache["data"], current=config.VERSION, newer=_newer(_cache["data"].get("latest")))
        try:
            d = http_json(f"https://api.github.com/repos/{config.GITHUB_REPO}/releases/latest", timeout=6)
            info["latest"] = str(d.get("tag_name") or "")
            info["url"] = str(d.get("html_url") or "")
        except Exception as e:
            info["error"] = f"{type(e).__name__}"
            _cache["at"] = time.time() - 5 * 3600  # 1 小时后重试
            _cache["data"] = {k: info[k] for k in ("latest", "url", "error", "enabled")} if info["latest"] else {}
            return info
        info["newer"] = _newer(info["latest"])
        _cache.update(at=time.time(), data=dict(info))
        return info


def _newer(latest):
    cur = config.VERSION
    if not latest or not re.search(r"\d", cur or ""):
        return False
    return _ver(latest) > _ver(cur)
