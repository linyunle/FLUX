"""实时速度:读 mihomo 的 /traffic 流(每秒一条 {"up":..,"down":..},单位 字节/秒),留最近 10 分钟。"""
import collections
import json
import time
import urllib.request

from . import config
from .util import log, stop

SAMPLES = collections.deque(maxlen=600)   # (时间戳, up, down)
STATE = {"ok": False, "error": ""}


def run():
    fail_logged = False
    while not stop.is_set():
        c = config.get()
        rev = c["rev"]
        headers = {"Authorization": "Bearer " + c["secret"]} if c["secret"] else {}
        try:
            req = urllib.request.Request(c["api"] + "/traffic", headers=headers)
            with urllib.request.urlopen(req, timeout=10) as r:
                STATE.update(ok=True, error="")
                if fail_logged:
                    log("实时速度已恢复")
                    fail_logged = False
                for line in r:
                    if stop.is_set() or config.get()["rev"] != rev:
                        break
                    try:
                        d = json.loads(line.decode("utf-8", "replace"))
                        SAMPLES.append((time.time(), int(d.get("up") or 0), int(d.get("down") or 0)))
                    except (ValueError, TypeError):
                        continue
        except Exception as e:
            STATE.update(ok=False, error=f"{type(e).__name__}: {e}"[:120])
            if not fail_logged:
                log("实时速度连接失败(会自动重试):", e)
                fail_logged = True
        stop.wait(2)
