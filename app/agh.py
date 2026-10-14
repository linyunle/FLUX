"""AdGuard Home 接入:读 DNS 统计和被拦截的查询。

账号密码在面板「设置 → DNS(AdGuard Home)」里填,只存在 data 目录的数据库里(kv 表 agh_cfg),
接口不会原样返回密码。只读:面板不会改 AdGuard 的任何设置。
"""
import base64
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import devices
from .util import is_mac, log

_lock = threading.Lock()
_cache = {"at": 0.0, "key": "", "data": None}
TTL = 60


def _norm_url(u):
    u = (u or "").strip().rstrip("/")
    if not u:
        return ""
    if "://" not in u:
        u = "http://" + u
    p = urllib.parse.urlparse(u)
    if p.scheme not in ("http", "https") or not p.netloc:
        raise ValueError("地址格式不对,例如 http://192.168.100.1:2000")
    return u


def load_cfg(con):
    try:
        r = con.execute("SELECT v FROM kv WHERE k='agh_cfg'").fetchone()
        d = json.loads(r[0]) if r else {}
    except Exception:
        d = {}
    return {"url": str(d.get("url") or ""), "user": str(d.get("user") or ""), "pass": str(d.get("pass") or ""), "on": bool(d.get("on", True))}


def public_cfg(con):
    c = load_cfg(con)
    return {"url": c["url"], "user": c["user"], "has_secret": bool(c["pass"]), "on": c["on"]}


def save_cfg(con, body):
    cur = load_cfg(con)
    url = _norm_url(str(body.get("url") or ""))
    user = str(body.get("user") if body.get("user") is not None else cur["user"]).strip()[:100]
    pw = body.get("pass")
    pw = cur["pass"] if pw in (None, "") else str(pw)[:200]
    on = bool(body.get("on", True)) and bool(url)
    if url and cur["url"] and url != cur["url"] and body.get("pass") in (None, ""):
        pw = ""  # 换了地址又没填密码:不把旧密码发给新地址
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES('agh_cfg',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                    (json.dumps({"url": url, "user": user, "pass": pw, "on": on}, ensure_ascii=False),))
    with _lock:
        _cache.update(at=0.0, data=None)
    return public_cfg(con)


def _req(cfg, path, timeout=6):
    h = {"User-Agent": "FLUX"}
    if cfg["user"] or cfg["pass"]:
        h["Authorization"] = "Basic " + base64.b64encode(f"{cfg['user']}:{cfg['pass']}".encode()).decode()
    req = urllib.request.Request(cfg["url"] + path, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _err(e):
    if isinstance(e, urllib.error.HTTPError):
        return "账号或密码不对(401)" if e.code == 401 else f"AdGuard 返回 {e.code}"
    return f"连不上:{type(e).__name__}"


def _rule(it):
    r = it.get("rule")
    if not r and isinstance(it.get("rules"), list) and it["rules"] and isinstance(it["rules"][0], dict):
        r = it["rules"][0].get("text")
    return str(r or "")[:100]


def _pairs(lst, n=10):
    out = []
    for it in (lst or [])[:n]:
        if isinstance(it, dict) and it:
            k, v = next(iter(it.items()))
            out.append((str(k), int(v or 0)))
    return out


def _ip_names(con):
    """IP → 设备名(面板已知的设备),AdGuard 里的客户端是 IP。"""
    from . import alerts
    cache = alerts._dev_names(con)
    out = {}
    try:
        for ip, mac in con.execute("SELECT ip, mac FROM ipmap"):
            out[ip] = alerts._dev_label(con, mac, cache)
    except Exception:
        pass
    return out


def fetch(con, force=False):
    """返回 {ok, error, ...};60 秒缓存。没配置返回 {configured: False}。"""
    cfg = load_cfg(con)
    if not cfg["url"] or not cfg["on"]:
        return {"configured": False}
    key = cfg["url"] + cfg["user"]
    with _lock:
        if not force and _cache["data"] is not None and _cache["key"] == key and time.time() - _cache["at"] < TTL:
            return _cache["data"]
    out = {"configured": True, "ok": False, "error": "", "url": cfg["url"], "at": int(time.time())}
    try:
        st = _req(cfg, "/control/stats")
        names = _ip_names(con)
        total, blocked = int(st.get("num_dns_queries") or 0), int(st.get("num_blocked_filtering") or 0)
        out.update(ok=True, total=total, blocked=blocked,
                   safebrowsing=int(st.get("num_replaced_safebrowsing") or 0), parental=int(st.get("num_replaced_parental") or 0),
                   rate=round(blocked * 100 / total, 1) if total else 0, avg_ms=round(float(st.get("avg_processing_time") or 0) * 1000, 1),
                   top_blocked=[{"d": d, "n": n} for d, n in _pairs(st.get("top_blocked_domains"))],
                   top_domains=[{"d": d, "n": n} for d, n in _pairs(st.get("top_queried_domains"))],
                   top_clients=[{"ip": ip, "name": names.get(ip, ""), "n": n} for ip, n in _pairs(st.get("top_clients"))],
                   series=[int(x or 0) for x in (st.get("dns_queries") or [])][-48:],
                   series_blocked=[int(x or 0) for x in (st.get("blocked_filtering") or [])][-48:],
                   unit=str(st.get("time_units") or "hours"))
        try:
            try:
                ql = _req(cfg, "/control/querylog?limit=300&response_status=blocked")
            except urllib.error.HTTPError as e:
                if e.code != 400:
                    raise
                ql = _req(cfg, "/control/querylog?limit=300&response_status=filtered")
            rows = []
            for it in (ql.get("data") or [])[:300]:
                q = it.get("question") or {}
                ip = str(it.get("client") or "")
                rows.append({"t": str(it.get("time") or "")[:19].replace("T", " "), "d": str(q.get("name") or "")[:100], "ip": ip,
                             "name": names.get(ip, ""), "reason": str(it.get("reason") or ""), "rule": _rule(it)})
            out["recent"] = rows[:40]
            by = {}
            for r in rows:
                by[r["ip"]] = by.get(r["ip"], 0) + 1
            out["blocked_by_client"] = [{"ip": ip, "name": names.get(ip, ""), "n": n} for ip, n in sorted(by.items(), key=lambda x: -x[1])[:8]]
        except Exception as e:
            out["recent"] = []
            out["log_error"] = _err(e)
    except Exception as e:
        out["error"] = _err(e)
        log("AdGuard 读取失败:", out["error"])
    with _lock:
        _cache.update(at=time.time(), key=key, data=out)
    return out


def test(con, body):
    """用页面里填的(可能还没保存的)参数试连一次。密码留空沿用已保存的。"""
    cur = load_cfg(con)
    try:
        url = _norm_url(str(body.get("url") or "")) or cur["url"]
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    if not url:
        return {"ok": False, "error": "先填 AdGuard Home 的地址"}
    pw = body.get("pass")
    cfg = {"url": url, "user": str(body.get("user") if body.get("user") is not None else cur["user"]),
           "pass": cur["pass"] if pw in (None, "") and url == cur["url"] else str(pw or "")}
    try:
        s = _req(cfg, "/control/status")
        return {"ok": True, "version": str(s.get("version", "")), "running": bool(s.get("running", True)), "error": ""}
    except Exception as e:
        return {"ok": False, "error": _err(e)}
