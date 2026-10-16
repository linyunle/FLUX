"""机场官方数据:读 nikki(mihomo)的订阅信息(/providers/proxies 里的 subscriptionInfo)。

nikki 刷新订阅时会带回机场后台的已用/总量/到期时间,这里只读取、不改任何配置。
每天记一个「官方已用」的最后读数,和面板自己统计的流量逐日对比,看面板准不准。
"""
import time
from collections import Counter

from .util import api_call, log

KEEP_DAYS = 40


def _web():
    from . import web
    return web


def _kv_get(con, k, default=None):
    from .insight import _kv_get as g
    return g(con, k, default)


def fetch():
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
    return out


def airport_for(p):
    w = _web()
    c = Counter(w.airport_of(n) for n in p["nodes"])
    for k in list(c):
        if k in ("未分类", "直连", "拒绝", "未知"):
            del c[k]
    return c.most_common(1)[0][0] if c else p["name"]


def sample(con, now=None):
    """每次调用记下今天的最新官方读数(同一天覆盖);只保留近 KEEP_DAYS 天。"""
    now = now or time.time()
    day = time.strftime("%Y-%m-%d", time.localtime(now))
    try:
        ps = fetch()
    except Exception as e:
        log("读取机场订阅信息失败:", e)
        return
    h = _kv_get(con, "prov_hist", {})
    for p in ps:
        if not p["has_info"]:
            continue
        a = h.setdefault(p["name"], {})
        a[day] = p["used"]
        for d in sorted(a)[:-KEEP_DAYS]:
            del a[d]
    from .insight import _kv_set
    _kv_set(con, "prov_hist", h)


def compare(con, name, nodes, today=None):
    """逐日对比:官方每天增加的量(相邻两天读数相减,遇到重置跳过) vs 面板统计的同一天流量。"""
    h = (_kv_get(con, "prov_hist", {}) or {}).get(name, {})
    days = sorted(h)
    rows = []
    if nodes:
        ph = ",".join("?" * len(nodes))
        for a, b in zip(days, days[1:]):
            if (time.mktime(time.strptime(b, "%Y-%m-%d")) - time.mktime(time.strptime(a, "%Y-%m-%d"))) > 86400 * 1.5:
                continue   # 中间缺天,不比
            off = h[b] - h[a]
            if off < 0:
                continue   # 官方读数变小 = 套餐重置了
            mine = con.execute(f"SELECT COALESCE(SUM(up+down),0) FROM traffic WHERE day=? AND node IN ({ph})", [b] + list(nodes)).fetchone()[0]
            rows.append({"day": b, "official": off, "flux": mine})
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
        if p["expire"]:
            exp_days = int((p["expire"] - time.time()) // 86400)
        out.append({"name": p["name"], "airport": ap, "used": p["used"], "total": p["total"], "expire": p["expire"] or None,
                    "expire_days": exp_days, "updated": p["updated"], "nodes": len(p["nodes"]), "has_info": p["has_info"],
                    "cmp": c})
    return {"ok": True, "rows": out}
