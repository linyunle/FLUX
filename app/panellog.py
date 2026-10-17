"""面板自己的运行日志(内存里最近 800 行)和访问记录(谁、从哪台设备、用什么浏览器打开/登录了面板)。"""
import collections
import json
import re
import threading
import time

LINES = collections.deque(maxlen=800)
_lock = threading.Lock()
MAX_CLIENTS = 100


def add_line(text):
    with _lock:
        LINES.append(text)


def tail(n=400):
    with _lock:
        return list(LINES)[-n:]


def short_ua(ua):
    ua = ua or ""
    os_ = ("iPhone" if "iPhone" in ua else "iPad" if "iPad" in ua else "Android" if "Android" in ua else "Mac" if "Macintosh" in ua
           else "Windows" if "Windows" in ua else "Linux" if "Linux" in ua else "")
    br = ("Edge" if "Edg/" in ua else "Chrome" if re.search(r"Chrome/|CriOS/", ua) else "Firefox" if "Firefox/" in ua
          else "Safari" if "Safari/" in ua else "curl" if ua.startswith("curl") else "")
    return (os_ + " " + br).strip() or (ua[:30] or "未知")


def _label(con, ip):
    """IP -> 设备名(按 ARP/DHCP 记录找 MAC,再取你起的名字);找不到返回空。"""
    try:
        from . import alerts
        r = con.execute("SELECT mac FROM ipmap WHERE ip=? ORDER BY seen DESC LIMIT 1", (ip,)).fetchone()
        if r:
            return alerts._dev_label(con, r[0])
    except Exception:
        pass
    return ""


def record(con, ip, ua, kind, now=None):
    """kind: page(打开页面) / login_ok / login_fail。第一次见到的 来源+浏览器 会在告警时间线里记一条。"""
    now = int(now or time.time())
    key = f"{ip}|{short_ua(ua)}"
    try:
        r = con.execute("SELECT v FROM kv WHERE k='panel_access'").fetchone()
        d = json.loads(r[0]) if r else {}
    except Exception:
        d = {}
    new = key not in d
    c = d.setdefault(key, {"ip": ip, "ua": short_ua(ua), "first": now, "last": now, "n": 0, "fails": 0})
    c["last"] = now
    if kind == "login_fail":
        c["fails"] += 1
    else:
        c["n"] += 1
    if len(d) > MAX_CLIENTS:
        for k in sorted(d, key=lambda k: d[k]["last"])[:len(d) - MAX_CLIENTS]:
            del d[k]
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES('panel_access',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (json.dumps(d, ensure_ascii=False),))
    if new or kind == "login_fail":
        from . import alerts
        who = _label(con, ip) or ip
        if kind == "login_fail":
            alerts.note(con, "audit", "panel_login_fail", "面板登录失败", f"{who}({ip},{short_ua(ua)})输错了密码", level="warn", now=now)
        else:
            alerts.note(con, "audit", "panel_new_client", "有新设备打开了面板", f"{who}({ip},{short_ua(ua)})第一次访问", now=now)


def clients(con):
    try:
        r = con.execute("SELECT v FROM kv WHERE k='panel_access'").fetchone()
        d = json.loads(r[0]) if r else {}
    except Exception:
        d = {}
    out = []
    for c in sorted(d.values(), key=lambda c: -c["last"]):
        out.append({**c, "name": _label(con, c["ip"])})
    return out
