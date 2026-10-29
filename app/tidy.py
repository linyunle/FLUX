"""v0.49:自检降噪与诊断包对比。
- nikki 日志里「某设备反复直连某域名失败」按 设备+域名 归并,可一键忽略
- 订阅停用提醒(长期不更新、不想再被提醒的订阅)
- 两份诊断包对比:自检项新增 / 消失 / 变化,以及关键数字的变化
"""
import json
import re
import time

from .insight import _kv_get, _kv_set

NOISE_K = "noise_ign"
SUB_K = "sub_mute"
DIAL = re.compile(r"dial (\S+) \([^)]*\) (\d+\.\d+\.\d+\.\d+):\d+ --> ([^\s:]+):\d+ error")
NUM = re.compile(r"\d+(?:\.\d+)?")


def _lst(con, k):
    v = _kv_get(con, k, [])
    return [str(x) for x in v] if isinstance(v, list) else []


def _toggle(con, k, item, on, cap=300):
    item = str(item or "").strip()[:200]
    lst = _lst(con, k)
    if on and item and item not in lst:
        lst.append(item)
    if not on:
        lst = [x for x in lst if x != item]
    _kv_set(con, k, lst[-cap:])
    return lst


def noise_ignored(con):
    return _lst(con, NOISE_K)


def set_noise(con, key, on):
    return _toggle(con, NOISE_K, key, on)


def sub_muted(con):
    return _lst(con, SUB_K)


def set_sub_mute(con, name, on):
    return _toggle(con, SUB_K, name, on, 100)


def noise(con, since, n=5):
    """近 N 秒 nikki 日志里「设备 → 域名 直连失败」的次数,按 设备+域名 归并。返回 {rows, ign_n}。"""
    cnt = {}
    for (msg,) in con.execute("SELECT msg FROM nklog WHERE src='core' AND ts>=? AND lvl<=4", (since,)):
        m = DIAL.search(msg)
        if m:
            k = f"{m.group(2)}|{m.group(3)}"
            cnt[k] = cnt.get(k, 0) + 1
    ign = set(noise_ignored(con))
    rows = [{"key": k, "src": k.split("|")[0], "host": k.split("|", 1)[1], "n": c, "ignored": k in ign} for k, c in cnt.items()]
    rows.sort(key=lambda x: -x["n"])
    return {"rows": rows[:max(1, n) + 20], "ign_n": sum(x["n"] for x in rows if x["ignored"])}


# ---------------------------------------------------------------- 诊断包对比
def _key(title):
    return NUM.sub("#", str(title or ""))[:100]


def _num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def compare(a, b):
    """a=较早的诊断包,b=较新的。只比较结构化的关键信息,返回 {ok, a, b, finds, metrics, alerts}。"""
    if not isinstance(a, dict) or not isinstance(b, dict) or "flux_diag" not in a or "flux_diag" not in b:
        raise ValueError("不是诊断包文件(缺少 flux_diag 标记)")
    fa = {_key(x.get("title")): x for x in (a.get("selfcheck") or []) if isinstance(x, dict)}
    fb = {_key(x.get("title")): x for x in (b.get("selfcheck") or []) if isinstance(x, dict)}
    rank = {"info": 0, "warn": 1, "bad": 2}
    added = [x for k, x in fb.items() if k not in fa]
    gone = [x for k, x in fa.items() if k not in fb]
    changed = []
    for k in fa.keys() & fb.keys():
        x, y = fa[k], fb[k]
        if x.get("level") != y.get("level") or x.get("title") != y.get("title"):
            changed.append({"before": {"level": x.get("level"), "title": x.get("title")}, "after": {"level": y.get("level"), "title": y.get("title")},
                            "worse": rank.get(y.get("level"), 0) > rank.get(x.get("level"), 0)})
    mets = []

    def add(name, va, vb, unit=""):
        va, vb = _num(va), _num(vb)
        if va is None and vb is None:
            return
        mets.append({"name": name, "a": va, "b": vb, "delta": None if va is None or vb is None else round(vb - va, 2), "unit": unit})

    add("面板占用内存", a.get("rss_mb"), b.get("rss_mb"), "MB")
    add("路由器负载(1 分钟)", ((a.get("sys") or {}).get("load") or [None])[0], ((b.get("sys") or {}).get("load") or [None])[0])
    add("路由器内存占用", ((a.get("sys") or {}).get("mem") or {}).get("used"), ((b.get("sys") or {}).get("mem") or {}).get("used"), "B")
    add("连接跟踪占用", ((a.get("sys") or {}).get("ct") or {}).get("pct"), ((b.get("sys") or {}).get("ct") or {}).get("pct"), "%")
    add("数据库大小", (a.get("db") or {}).get("size_bytes"), (b.get("db") or {}).get("size_bytes"), "B")
    for t, lab in (("syslog", "路由器日志条数"), ("dns", "DNS 记录条数"), ("alerts", "告警条数")):
        add(lab, ((a.get("db") or {}).get("rows") or {}).get(t), ((b.get("db") or {}).get("rows") or {}).get(t))
    sa = ((a.get("ext") or {}).get("syslog") or {}).get("by_sev_24h") or {}
    sb = ((b.get("ext") or {}).get("syslog") or {}).get("by_sev_24h") or {}
    for lv in ("严重", "错误", "警告"):
        add(f"路由器日志 24 小时「{lv}」", sa.get(lv), sb.get(lv), "条")
    da = {d.get("mp"): d for d in ((a.get("ext") or {}).get("disks") or []) if isinstance(d, dict)}
    db_ = {d.get("mp"): d for d in ((b.get("ext") or {}).get("disks") or []) if isinstance(d, dict)}
    for mp in db_:
        add(f"磁盘已用「{(db_[mp].get('name') or mp)}」", (da.get(mp) or {}).get("pct"), db_[mp].get("pct"), "%")
    na = {x.get("name"): x for x in (a.get("nodes") or []) if isinstance(x, dict)}
    nb = {x.get("name"): x for x in (b.get("nodes") or []) if isinstance(x, dict)}
    dead_a = {k for k, x in na.items() if x.get("delay") is None and x.get("type") not in ("PassRule", "Selector", "URLTest", "Direct", "Reject")}
    dead_b = {k for k, x in nb.items() if x.get("delay") is None and x.get("type") not in ("PassRule", "Selector", "URLTest", "Direct", "Reject")}
    add("没有延迟数据的节点数", len(dead_a) if na else None, len(dead_b) if nb else None, "个")

    def kinds(x):
        c = {}
        for r in x.get("alerts_recent") or []:
            if isinstance(r, dict) and r.get("level") not in ("note", "info"):
                c[r.get("kind")] = c.get(r.get("kind"), 0) + 1
        return c
    ka, kb = kinds(a), kinds(b)
    al = [{"kind": k, "a": ka.get(k, 0), "b": kb.get(k, 0)} for k in sorted(ka.keys() | kb.keys(), key=lambda k: -(kb.get(k, 0) + ka.get(k, 0)))][:12]
    return {"ok": True, "a": {"at": a.get("created"), "version": a.get("version")}, "b": {"at": b.get("created"), "version": b.get("version")},
            "finds": {"added": added, "gone": gone, "changed": changed}, "metrics": [m for m in mets if m["delta"] != 0 or m["a"] is None or m["b"] is None], "alerts": [x for x in al if x["a"] != x["b"]]}
