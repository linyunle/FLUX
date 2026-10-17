"""机场官方数据:读 nikki(mihomo)的订阅信息(/providers/proxies 里的 subscriptionInfo)。

nikki 刷新订阅时会带回机场后台的已用/总量/到期时间,这里只读取、不改任何配置。
每天记一个「官方已用」的最后读数,和面板自己统计的流量逐日对比,看面板准不准。
"""
import datetime
import re
import time
from collections import Counter

from .util import api_call, log

KEEP = 30


def _web():
    from . import web
    return web


def _kv_get(con, k, default=None):
    from .insight import _kv_get as g
    return g(con, k, default)


_cache = {"t": 0, "v": []}
_FRAC = re.compile(r"(\.\d+)")


def parse_ts(v):
    """nikki 给的 updatedAt(RFC3339,可能带纳秒) -> 秒;零值/解析不了返回 0。"""
    try:
        t = datetime.datetime.fromisoformat(_FRAC.sub("", str(v), count=1)).timestamp()
    except Exception:
        return 0
    return t if t > 1e9 else 0

NEVER = 4070908800   # 2099-01-01:机场用这种日期表示「永不过期」


def fetch():
    now = time.time()
    if now - _cache["t"] < 15:
        return _cache["v"]
    v = _fetch()
    _cache.update(t=now, v=v)
    return v


def official():
    """{机场名: {used, total, expire}}:只含有订阅用量信息的;读不到就是空(出错也不抛)。"""
    try:
        ps = fetch()
    except Exception:
        return {}
    out = {}
    for p in ps:
        if p["has_info"] and p["total"] > 0:
            out.setdefault(airport_for(p), {"used": p["used"], "total": p["total"],
                                            "expire": (p["expire"] if p["expire"] and p["expire"] < NEVER else 0),
                                            "at": parse_ts(p["updated"])})
    return out


def _fetch():
    """返回 [{name, vehicle, used, total, expire, updated, nodes:[...] }];没有订阅型 provider 时是空列表。"""
    j = api_call("/providers/proxies") or {}
    out = []
    for name, p in sorted((j.get("providers") or {}).items()):
        si = p.get("subscriptionInfo") or {}
        if not si and p.get("vehicleType") not in ("HTTP",):
            continue
        if name == "default":
            continue
        used = (si.get("Upload") or 0) + (si.get("Download") or 0)
        out.append({"name": name, "vehicle": p.get("vehicleType") or "", "used": used, "total": si.get("Total") or 0,
                    "expire": si.get("Expire") or 0, "updated": p.get("updatedAt") or "",
                    "nodes": [x.get("name") for x in (p.get("proxies") or []) if x.get("name")], "has_info": bool(si)})
    m = {}
    for p in out:
        for n in p["nodes"]:
            m.setdefault(n, p["name"])
    from . import airports
    airports.set_providers(m)
    return out


def airport_for(p):
    w = _web()
    c = Counter(w.airport_of(n) for n in p["nodes"])
    for k in list(c):
        if k in ("未分类", "直连", "拒绝", "未知"):
            del c[k]
    return c.most_common(1)[0][0] if c else p["name"]


def sample(con, now=None):
    """每次 nikki 更新订阅(updatedAt 变了),就记下那一刻的官方已用;只保留最近 KEEP 次。"""
    try:
        ps = fetch()
    except Exception as e:
        log("读取机场订阅信息失败:", e)
        return
    h = _kv_get(con, "prov_upd", {})
    changed = False
    for p in ps:
        at = parse_ts(p["updated"])
        if not p["has_info"] or not at:
            continue
        a = h.setdefault(p["name"], [])
        if not a or a[-1][0] != at:
            if a and a[-1][1] > p["used"] + 1024:
                a.clear()   # 官方读数变小 = 套餐重置了,从头记
            a.append([at, p["used"]])
            del a[:-KEEP]
            changed = True
    if changed:
        from .insight import _kv_set
        _kv_set(con, "prov_upd", h)


def _hour(ts):
    return time.strftime("%Y-%m-%d %H", time.localtime(ts))


def panel_between(con, nodes, t0, t1):
    """面板在 [t0, t1) 之间统计到的这些节点的流量(按小时汇总,首尾小时只算整点后的部分,有 1 小时内的误差)。"""
    if not nodes or t1 <= t0:
        return 0
    ph = ",".join("?" * len(nodes))
    return con.execute(f"SELECT COALESCE(SUM(up+down),0) FROM hourly WHERE hour>? AND hour<=? AND node IN ({ph})",
                       [_hour(t0), _hour(t1)] + list(nodes)).fetchone()[0]


def compare(con, name, nodes):
    """两次相邻更新之间:官方增加的流量 vs 面板同一时间段统计到的流量(面板按小时存,只能比最近 14 天内的)。"""
    a = (_kv_get(con, "prov_upd", {}) or {}).get(name, [])
    rows = []
    cut = time.time() - 13 * 86400
    for (t0, u0), (t1, u1) in zip(a, a[1:]):
        if t0 < cut or u1 < u0:
            continue
        rows.append({"from": t0, "to": t1, "official": u1 - u0, "flux": panel_between(con, nodes, t0, t1)})
    rows = rows[-14:]
    to, tf = sum(r["official"] for r in rows), sum(r["flux"] for r in rows)
    return {"rows": rows, "official": to, "flux": tf, "ratio": round(tf * 100 / to, 1) if to > 0 else None}


def status(con):
    try:
        ps = fetch()
    except Exception as e:
        return {"ok": False, "error": str(e), "rows": []}
    out = []
    for p in ps:
        ap = airport_for(p)
        c = compare(con, p["name"], [n for n in _web().all_nodes() if _web().airport_of(n) == ap])
        exp_days = None
        if p["expire"] and p["expire"] >= NEVER:
            p = dict(p, expire=0)
        if p["expire"]:
            exp_days = int((p["expire"] - time.time()) // 86400)
        out.append({"name": p["name"], "airport": ap, "used": p["used"], "total": p["total"], "expire": p["expire"] or None,
                    "expire_days": exp_days, "updated": p["updated"], "nodes": len(p["nodes"]), "has_info": p["has_info"],
                    "cmp": c})
    return {"ok": True, "rows": out}
