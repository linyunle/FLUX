"""分析类查询:规则健康、分流检查、热力图、套餐用量、周报、Prometheus 指标、数据质量。
都只读已有数据(traffic / hourly / dns / wan …),不会额外请求外网。
"""
import calendar
import datetime
import json
import os
import re
import time

from . import agh, alerts, collector, config, geo, netstat, realtime
from .util import api_call, log


def _web():
    from . import web  # 延迟导入:web 也依赖本模块
    return web


def _days_ago(n):
    return time.strftime("%Y-%m-%d", time.localtime(time.time() - n * 86400))


def _kv_get(con, k, default=None):
    try:
        r = con.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
        return json.loads(r[0]) if r else default
    except Exception:
        return default


def _kv_set(con, k, v):
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, json.dumps(v, ensure_ascii=False)))


# ---------------------------------------------------------------- 规则健康
def rule_health(con, days=30):
    since = _days_ago(days - 1)
    used = {}
    for rule, b, hosts in con.execute("SELECT rule, SUM(up+down), COUNT(DISTINCT host) FROM traffic WHERE day>=? GROUP BY rule", (since,)):
        used[rule] = (b or 0, hosts or 0)
    total = sum(v[0] for v in used.values()) or 1
    out = {"days": days, "source": "traffic", "rule_count": 0, "has_hits": False, "error": "", "zero": [], "top": [], "match": None}
    out["top"] = [{"rule": r, "bytes": v[0], "hosts": v[1], "share": round(v[0] * 100 / total, 1)}
                  for r, v in sorted(used.items(), key=lambda x: -x[1][0])[:15]]
    m = [(r, v) for r, v in used.items() if r.lower().startswith(("match", "final"))]
    if m:
        mb = sum(v[1][0] for v in m)
        hosts = con.execute("SELECT host, SUM(up+down) s FROM traffic WHERE day>=? AND (rule LIKE 'Match%' OR rule LIKE 'Final%') GROUP BY host ORDER BY s DESC LIMIT 10", (since,)).fetchall()
        out["match"] = {"bytes": mb, "share": round(mb * 100 / total, 1), "hosts": [{"host": h, "bytes": s} for h, s in hosts]}
    try:
        rules = (api_call("/rules", timeout=8) or {}).get("rules") or []
    except Exception as e:
        out["error"] = f"读取 nikki 规则列表失败:{type(e).__name__}"
        return out
    out["source"] = "mihomo"
    out["rule_count"] = len(rules)
    hit_known = [r for r in rules if isinstance(r.get("extra"), dict) and "hitCount" in r["extra"]]
    out["has_hits"] = bool(hit_known)
    zero = []
    for i, r in enumerate(rules):
        typ, pl = str(r.get("type") or ""), str(r.get("payload") or "")
        if typ.lower() in ("match", "final"):
            continue
        key = ((typ + "," + pl) if pl else typ)[:80]
        ex = r.get("extra") if isinstance(r.get("extra"), dict) else {}
        if "hitCount" in ex:
            if int(ex.get("hitCount") or 0) == 0 and not ex.get("disabled"):
                zero.append({"rule": key, "proxy": str(r.get("proxy") or ""), "index": i})
        elif key not in used:
            zero.append({"rule": key, "proxy": str(r.get("proxy") or ""), "index": i})
    out["zero_total"] = len(zero)
    out["zero"] = zero[:40]
    if hit_known:
        hot = sorted(((int((r["extra"] or {}).get("hitCount") or 0), r) for r in hit_known), key=lambda x: -x[0])[:10]
        out["hot"] = [{"rule": (str(r.get("type")) + "," + str(r.get("payload")))[:80], "proxy": str(r.get("proxy") or ""), "hits": n} for n, r in hot if n]
    return out


# ---------------------------------------------------------------- 分流检查(启发式)
CN_SUFFIX = ("baidu.com", "qq.com", "taobao.com", "tmall.com", "alipay.com", "alicdn.com", "aliyun.com", "aliyuncs.com", "jd.com",
             "bilibili.com", "hdslb.com", "douyin.com", "bytedance.com", "toutiao.com", "xiaohongshu.com", "weibo.com", "sina.com.cn",
             "zhihu.com", "163.com", "126.net", "netease.com", "sohu.com", "meituan.com", "dianping.com", "pinduoduo.com", "tencent.com",
             "gtimg.com", "qpic.cn", "iqiyi.com", "youku.com", "xiaomi.com", "mi.com", "csdn.net", "douban.com", "kuaishou.com",
             "ctrip.com", "amap.com", "12306.cn", "quark.cn", "cn")
FOREIGN_SUFFIX = ("google.com", "googleapis.com", "gstatic.com", "googlevideo.com", "youtube.com", "ytimg.com", "facebook.com",
                  "instagram.com", "twitter.com", "x.com", "twimg.com", "openai.com", "chatgpt.com", "anthropic.com", "claude.ai",
                  "netflix.com", "telegram.org", "t.me", "github.com", "githubusercontent.com", "wikipedia.org", "whatsapp.net",
                  "whatsapp.com", "discord.com", "spotify.com", "reddit.com", "medium.com", "dropbox.com")
_IPLIT = re.compile(r"^[0-9a-f:.]+$")


def _in_list(host, lst):
    return any(host == s or host.endswith("." + s) for s in lst)


def leaks(con, days=7):
    w = _web()
    since = _days_ago(days - 1)
    d, r = w.kind_names()
    rows = con.execute("SELECT host, node, rule, SUM(up+down) b, COUNT(DISTINCT client) c FROM traffic WHERE day>=? GROUP BY host, node, rule", (since,)).fetchall()
    cn_proxy, fo_direct = {}, {}
    for host, node, rule, b, c in rows:
        if not host or _IPLIT.match(host):
            continue
        kind = w.node_kind(node, d, r)
        if kind == "proxy" and _in_list(host, CN_SUFFIX):
            x = cn_proxy.setdefault(host, {"host": host, "bytes": 0, "devices": 0, "node": node, "rule": rule})
        elif kind == "direct" and _in_list(host, FOREIGN_SUFFIX):
            x = fo_direct.setdefault(host, {"host": host, "bytes": 0, "devices": 0, "node": node, "rule": rule})
        else:
            continue
        x["bytes"] += b
        x["devices"] = max(x["devices"], c)
    dns_rows = []
    try:
        for host, b in con.execute(
                "SELECT t.host, SUM(t.up+t.down) s FROM traffic t WHERE t.day>=? AND t.host IN (SELECT host FROM dns WHERE mode='normal') "
                "AND t.node NOT IN (%s) AND t.node NOT LIKE 'REJECT%%' GROUP BY t.host ORDER BY s DESC LIMIT 60" % ",".join("?" * len(d)), [since] + list(d)):
            if not _IPLIT.match(host) and not _in_list(host, CN_SUFFIX):
                dns_rows.append({"host": host, "bytes": b})
    except Exception:
        pass
    f = lambda m: sorted(m.values(), key=lambda x: -x["bytes"])[:15]
    return {"days": days, "cn_proxy": f(cn_proxy), "cn_proxy_bytes": sum(x["bytes"] for x in cn_proxy.values()),
            "fo_direct": f(fo_direct), "fo_direct_bytes": sum(x["bytes"] for x in fo_direct.values()),
            "dns_local": dns_rows[:12], "dns_local_bytes": sum(x["bytes"] for x in dns_rows)}


# ---------------------------------------------------------------- 热力图
def heatmap(con, devs=None, days=14):
    w = _web()
    since = time.strftime("%Y-%m-%d %H", time.localtime(time.time() - days * 86400))
    where, args = "hour >= ?", [since]
    if devs:
        where += f" AND {w.DEVX} IN ({','.join('?' * len(devs))})"
        args += [x.lower() for x in devs]
    sums = [[0] * 24 for _ in range(7)]
    seen = [set() for _ in range(7)]
    for hour, b in con.execute(f"SELECT hour, SUM(up+down) FROM hourly WHERE {where} GROUP BY hour", args):
        try:
            dt = datetime.datetime.strptime(hour, "%Y-%m-%d %H")
        except ValueError:
            continue
        sums[dt.weekday()][dt.hour] += b or 0
        seen[dt.weekday()].add(dt.date())
    cells = [[round(sums[wd][h] / max(1, len(seen[wd]))) for h in range(24)] for wd in range(7)]
    peak = max((v, wd, h) for wd in range(7) for h, v in enumerate(cells[wd]))
    return {"days": days, "cells": cells, "max": peak[0], "peak": {"weekday": peak[1], "hour": peak[2], "bytes": peak[0]} if peak[0] else None}


# ---------------------------------------------------------------- 机场套餐
def quota_cfg(con):
    d = _kv_get(con, "quota", {}) or {}
    out = {}
    for ap, v in d.items():
        if isinstance(v, dict) and v.get("gb"):
            out[str(ap)[:40]] = {"gb": float(v["gb"]), "reset_day": int(v.get("reset_day") or 1)}
    return out


def save_quota(con, body):
    out = {}
    for ap, v in (body.get("quota") or {}).items():
        if not isinstance(v, dict) or not str(ap).strip():
            continue
        try:
            gb = float(v.get("gb") or 0)
            rd = int(v.get("reset_day") or 1)
        except (TypeError, ValueError):
            raise ValueError(f"「{ap}」的流量或重置日不是数字")
        if gb <= 0:
            continue
        out[str(ap).strip()[:40]] = {"gb": min(gb, 1e6), "reset_day": max(1, min(31, rd))}
    _kv_set(con, "quota", out)
    return out


def _clamp(y, m, d):
    return datetime.date(y, m, min(d, calendar.monthrange(y, m)[1]))


def period(reset_day, today=None):
    t = today or datetime.date.today()
    cur = _clamp(t.year, t.month, reset_day)
    if t >= cur:
        start = cur
    else:
        py, pm = (t.year, t.month - 1) if t.month > 1 else (t.year - 1, 12)
        start = _clamp(py, pm, reset_day)
    ny, nm = (start.year, start.month + 1) if start.month < 12 else (start.year + 1, 1)
    return start, _clamp(ny, nm, reset_day)


def quota_status(con, today=None):
    w = _web()
    cfg = quota_cfg(con)
    t = today or datetime.date.today()
    nodes = w.all_nodes()
    d, r = w.kind_names()
    out = []
    for ap, c in sorted(cfg.items()):
        ns = [n for n in nodes if w.airport_of(n) == ap]
        start, end = period(c["reset_day"], t)
        used = rate = 0
        if ns:
            ph = ",".join("?" * len(ns))
            used = con.execute(f"SELECT COALESCE(SUM(up+down),0) FROM traffic WHERE day>=? AND day<? AND node IN ({ph})",
                               [start.isoformat(), end.isoformat()] + ns).fetchone()[0]
            ws = max(start, t - datetime.timedelta(days=6))
            n = (t - ws).days + 1
            rate = con.execute(f"SELECT COALESCE(SUM(up+down),0) FROM traffic WHERE day>=? AND day<? AND node IN ({ph})",
                               [ws.isoformat(), end.isoformat()] + ns).fetchone()[0] / n
        limit = c["gb"] * 1024 ** 3
        left = max(0.0, limit - used)
        exhaust = None
        if rate > 0 and left > 0:
            exhaust = (t + datetime.timedelta(days=int(left / rate))).isoformat()
        elif left <= 0:
            exhaust = t.isoformat()
        out.append({"airport": ap, "gb": c["gb"], "reset_day": c["reset_day"], "used": used, "pct": round(used * 100 / limit, 1) if limit else 0,
                    "start": start.isoformat(), "end": end.isoformat(), "days_left": (end - t).days, "rate": round(rate),
                    "exhaust": exhaust, "over": bool(exhaust and exhaust < end.isoformat()), "known": bool(ns)})
    return out


# ---------------------------------------------------------------- 周报
def report_cfg(con):
    d = _kv_get(con, "report_cfg", {}) or {}
    try:
        wd, hr = int(d.get("weekday", 0)), int(d.get("hour", 9))
    except (TypeError, ValueError):
        wd, hr = 0, 9
    return {"on": bool(d.get("on")), "weekday": max(0, min(6, wd)), "hour": max(0, min(23, hr))}


def save_report_cfg(con, body):
    c = {"on": bool(body.get("on")), "weekday": int(body.get("weekday", 0)), "hour": int(body.get("hour", 9))}
    c["weekday"], c["hour"] = max(0, min(6, c["weekday"])), max(0, min(23, c["hour"]))
    _kv_set(con, "report_cfg", c)
    return c


def report(con, days=7):
    w = _web()
    days = max(1, min(90, days))
    s1, s0 = _days_ago(days - 1), _days_ago(2 * days - 1)
    e0 = _days_ago(days)
    cur = con.execute("SELECT COALESCE(SUM(up),0), COALESCE(SUM(down),0) FROM traffic WHERE day>=?", (s1,)).fetchone()
    prev = con.execute("SELECT COALESCE(SUM(up),0), COALESCE(SUM(down),0) FROM traffic WHERE day>=? AND day<=?", (s0, e0)).fetchone()
    d, r = w.kind_names()
    kinds = {"direct": 0, "proxy": 0, "reject": 0}
    ap = {}
    for node, b in con.execute("SELECT node, SUM(up+down) FROM traffic WHERE day>=? GROUP BY node", (s1,)):
        k = w.node_kind(node, d, r)
        kinds[k] += b
        if k == "proxy":
            a = w.airport_of(node)
            ap[a] = ap.get(a, 0) + b
    cache = alerts._dev_names(con)
    devs = []
    for cl, b in con.execute(f"SELECT {w.DEVX} k, SUM(up+down) s FROM traffic WHERE day>=? GROUP BY k ORDER BY s DESC LIMIT 8", (s1,)):
        devs.append({"name": alerts._dev_label(con, cl, cache), "bytes": b})
    doms = [{"host": h, "bytes": b} for h, b in con.execute("SELECT host, SUM(up+down) s FROM traffic WHERE day>=? AND host!='' GROUP BY host ORDER BY s DESC LIMIT 8", (s1,))]
    apps = []
    try:
        apps = [{"app": a, "bytes": b} for a, b in con.execute("SELECT app, SUM(up+down) s FROM app WHERE day>=? GROUP BY app ORDER BY s DESC LIMIT 6", (s1,))]
    except Exception:
        pass
    peak = con.execute("SELECT substr(hour,12,2) h, SUM(up+down) s FROM hourly WHERE hour>=? GROUP BY h ORDER BY s DESC LIMIT 1",
                       (time.strftime("%Y-%m-%d %H", time.localtime(time.time() - days * 86400)),)).fetchone()
    t = con.execute("SELECT COALESCE(SUM(out),0), COALESCE(SUM(retrans),0) FROM tcp WHERE hour>=?",
                    (time.strftime("%Y-%m-%d %H", time.localtime(time.time() - days * 86400)),)).fetchone()
    al = {k: n for k, n in con.execute("SELECT kind, COUNT(*) FROM alerts WHERE ts>=? AND kind!='report' GROUP BY kind", (int(time.time() - days * 86400),))}
    bad = []
    for node, n, fails in con.execute("SELECT node, SUM(n), SUM(fails) FROM qoe WHERE hour>=? GROUP BY node", (time.strftime("%Y-%m-%d %H", time.localtime(time.time() - days * 86400)),)):
        tot = (n or 0) + (fails or 0)
        if tot >= 10 and fails * 100 / tot >= 10:
            bad.append({"node": node, "fail_pct": round(fails * 100 / tot, 1)})
    nd = con.execute("SELECT COUNT(DISTINCT client) FROM known_dev WHERE first>=?", (int(time.time() - days * 86400),)).fetchone()[0]
    return {"days": days, "from": s1, "to": time.strftime("%Y-%m-%d"), "up": cur[0], "down": cur[1], "prev": prev[0] + prev[1],
            "kinds": kinds, "airports": [{"name": a, "bytes": b} for a, b in sorted(ap.items(), key=lambda x: -x[1])[:5]],
            "devices": devs, "domains": doms, "apps": apps, "peak_hour": int(peak[0]) if peak and peak[0] else None,
            "retrans_pct": round(t[1] * 100 / t[0], 2) if t[0] else None, "alerts": al, "bad_nodes": bad,
            "new_devices": nd, "quota": quota_status(con)}


def _b(n):
    return alerts._fmt(n)


def report_text(rp):
    tot = rp["up"] + rp["down"]
    ch = f"({'+' if tot >= rp['prev'] else '-'}{abs(tot - rp['prev']) * 100 // max(1, rp['prev'])}% 对比上期)" if rp["prev"] else ""
    k = rp["kinds"]
    L = [f"{rp['from']} ~ {rp['to']}({rp['days']} 天)",
         f"总流量 {_b(tot)} {ch}:下行 {_b(rp['down'])} / 上行 {_b(rp['up'])}",
         f"代理 {_b(k['proxy'])} · 直连 {_b(k['direct'])}"]
    if rp["airports"]:
        L.append("机场:" + "、".join(f"{a['name']} {_b(a['bytes'])}" for a in rp["airports"][:3]))
    if rp["devices"]:
        L.append("设备 Top:" + "、".join(f"{x['name']} {_b(x['bytes'])}" for x in rp["devices"][:3]))
    if rp["domains"]:
        L.append("域名 Top:" + "、".join(x["host"] for x in rp["domains"][:3]))
    if rp["peak_hour"] is not None:
        L.append(f"最忙时段 {rp['peak_hour']:02d}:00")
    if rp["retrans_pct"] is not None:
        L.append(f"TCP 重传率 {rp['retrans_pct']}%")
    if rp["alerts"]:
        L.append("告警:" + "、".join(f"{alerts.KINDS.get(a, a)} {n}" for a, n in rp["alerts"].items()))
    for q in rp["quota"]:
        L.append(f"套餐 {q['airport']}:{q['pct']}%({_b(q['used'])} / {q['gb']:g} GB)")
    for b in rp["bad_nodes"][:3]:
        L.append(f"节点 {b['node']} 测速失败率 {b['fail_pct']}%")
    return "\n".join(L)


def send_report(con, days=7, now=None):
    cfg = alerts.load_cfg(con)
    rp = report(con, days)
    alerts.fire(con, cfg, "report", "info", "weekly", "FLUX 周报" if days == 7 else f"FLUX {days} 天报告", report_text(rp), now)
    return rp


def maybe_push_report(con, now=None):
    now = now or time.time()
    c = report_cfg(con)
    if not c["on"]:
        return
    lt = time.localtime(now)
    today = time.strftime("%Y-%m-%d", lt)
    if lt.tm_wday != c["weekday"] or lt.tm_hour < c["hour"] or _kv_get(con, "report_last") == today:
        return
    _kv_set(con, "report_last", today)
    send_report(con, 7, now)


# ---------------------------------------------------------------- 套餐告警
def check_quota(con, cfg, now):
    r = cfg["rules"].get("quota")
    if not r or not r["on"]:
        return
    for q in quota_status(con):
        if not q["known"] or q["pct"] < r["pct"]:
            continue
        lvl = "bad" if q["pct"] >= 95 else "warn"
        if alerts._allow("quota", q["airport"] + ("95" if lvl == "bad" else ""), r["cool_min"], now):
            extra = f"按近 7 天速度,预计 {q['exhaust']} 用完(重置日 {q['end']})。" if q["exhaust"] else ""
            alerts.fire(con, cfg, "quota", lvl, q["airport"], f"套餐用量 {q['pct']}%:{q['airport']}",
                        f"本周期已用 {_b(q['used'])} / {q['gb']:g} GB。{extra}", now)


# ---------------------------------------------------------------- Prometheus
def _lab(s):
    return str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def metrics_text(con):
    now = time.time()
    L = []

    def add(name, typ, help_, rows):
        L.append(f"# HELP {name} {help_}")
        L.append(f"# TYPE {name} {typ}")
        for labels, v in rows:
            lb = ("{" + ",".join(f'{k}="{_lab(x)}"' for k, x in labels.items()) + "}") if labels else ""
            L.append(f"{name}{lb} {v}")
    c = collector.COLLECTOR
    add("flux_nikki_up", "gauge", "面板是否连得上 nikki API", [({}, 1 if (c and c.status.get("ok")) else 0)])
    add("flux_last_poll_age_seconds", "gauge", "距上次成功采样的秒数", [({}, round(now - c.status.get("last_ok", 0), 1) if c and c.status.get("last_ok") else -1)])
    today = time.strftime("%Y-%m-%d")
    up, down = con.execute("SELECT COALESCE(SUM(up),0), COALESCE(SUM(down),0) FROM traffic WHERE day=?", (today,)).fetchone()
    add("flux_traffic_bytes_today", "gauge", "今天累计流量(字节)", [({"dir": "up"}, up), ({"dir": "down"}, down)])
    cache = alerts._dev_names(con)
    w = _web()
    rows = []
    for cl, u, dn in con.execute(f"SELECT {w.DEVX} k, SUM(up), SUM(down) FROM traffic WHERE day=? GROUP BY k ORDER BY SUM(up+down) DESC LIMIT 50", (today,)):
        nm = alerts._dev_label(con, cl, cache)
        rows += [({"device": nm, "dir": "up"}, u), ({"device": nm, "dir": "down"}, dn)]
    add("flux_device_bytes_today", "gauge", "各设备今天累计流量(前 50)", rows)
    lv = realtime.LIVE if realtime.LIVE["at"] else (c.live if c else {"clients": {}, "nodes": {}})
    cl = lv.get("clients", {})
    add("flux_connections", "gauge", "当前并发连接数", [({}, sum(v["conns"] for v in cl.values()))])
    add("flux_rate_bytes_per_second", "gauge", "当前总速率", [({"dir": "up"}, round(sum(v["up_rate"] for v in cl.values()))), ({"dir": "down"}, round(sum(v["down_rate"] for v in cl.values())))])
    rows = []
    for k, v in cl.items():
        nm = alerts._dev_label(con, k, cache)
        rows += [({"device": nm, "dir": "up"}, round(v["up_rate"])), ({"device": nm, "dir": "down"}, round(v["down_rate"]))]
    add("flux_device_rate_bytes_per_second", "gauge", "各设备当前速率", rows)
    add("flux_node_connections", "gauge", "各节点当前连接数", [({"node": k}, v["conns"]) for k, v in lv.get("nodes", {}).items()])
    add("flux_node_delay_ms", "gauge", "各节点最近一次测速延迟(0=失败)", [({"node": n}, v.get("delay") or 0) for n, v in (c.nodes if c else {}).items()])
    s = [x for x in list(netstat.SERIES) if now - x[0] <= 300]
    out_, rt = sum(x[1] for x in s), sum(x[2] for x in s)
    add("flux_tcp_retrans_ratio", "gauge", "最近 5 分钟路由器 TCP 重传率(0~1)", [({}, round(rt / out_, 5) if out_ else 0)])
    from . import sysinfo
    sy = sysinfo.STATE
    if sy.get("cpu") is not None:
        add("flux_router_cpu_percent", "gauge", "路由器 CPU 使用率", [({}, sy["cpu"])])
    if sy.get("ct"):
        add("flux_router_conntrack", "gauge", "连接跟踪条目数", [({}, sy["ct"]["n"])])
    if sy.get("temps"):
        add("flux_router_temp_celsius", "gauge", "路由器温度", [({"sensor": t["name"]}, t["c"]) for t in sy["temps"]])
    add("flux_alerts_24h", "gauge", "最近 24 小时告警数", [({"level": lv_}, n) for lv_, n in alerts.counts(con, now - 86400).items()])
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- 数据质量
_rc = {"at": 0.0, "v": {}}


def _row_counts(con):
    if time.time() - _rc["at"] < 300 and _rc["v"]:
        return _rc["v"]
    out = {}
    for t in ("traffic", "hourly", "app", "proto", "dns", "alerts", "qoe", "geo"):
        try:
            out[t] = con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        except Exception:
            pass
    _rc.update(at=time.time(), v=out)
    return out


def quality(con):
    c = collector.COLLECTOR
    now = time.time()
    ps = dict(c.pstat) if c else {}
    size = {}
    for k, p in (("db", config.DB_PATH), ("wal", config.DB_PATH + "-wal")):
        try:
            size[k] = os.path.getsize(p)
        except OSError:
            size[k] = 0
    wan = []
    try:
        for day, wu, wd in con.execute("SELECT day, up, down FROM wan WHERE day>=? ORDER BY day", (_days_ago(6),)):
            tu, td = con.execute("SELECT COALESCE(SUM(up),0), COALESCE(SUM(down),0) FROM traffic WHERE day=?", (day,)).fetchone()
            wt, tt = wu + wd, tu + td
            wan.append({"day": day, "wan": wt, "traffic": tt, "ratio": round(tt * 100 / wt, 1) if wt else None})
    except Exception:
        pass
    return {
        "poll": {"interval": config.INTERVAL, "ok": ps.get("ok", 0), "fail": ps.get("fail", 0), "last_dur_ms": round(ps.get("last_dur", 0) * 1000),
                 "avg_dur_ms": round(ps.get("avg_dur", 0) * 1000), "last_ok_age": round(now - c.status["last_ok"]) if c and c.status.get("last_ok") else None,
                 "last_error": (c.status.get("error") if c else "") or ps.get("last_fail", ""), "since": ps.get("since", 0),
                 "baseline": bool(c and c.baseline_done)},
        "size": size, "rows": _row_counts(con),
        "retention": {"days": config.KEEP_DAYS, "hour_days": config.HOUR_KEEP_DAYS},
        "wan": wan, "wan_on": bool(collector.WAN_IFACES),
        "netstat": bool(netstat.STATE.get("ok")), "geo": geo.status(), "agh": _agh_brief(con),
        "mihomo": getattr(c, "mihomo_version", "") if c else "", "version": config.VERSION,
    }


def _agh_brief(con):
    cf = agh.load_cfg(con)
    if not cf["url"] or not cf["on"]:
        return None
    d = agh._cache.get("data") or {}
    return {"url": cf["url"], "ok": d.get("ok"), "error": d.get("error", "")}


# ---------------------------------------------------------------- 目的地国家
def geo_summary(con, days=7):
    since = _days_ago(days - 1)
    by_cc = [{"cc": cc or "??", "bytes": b, "up": u, "down": dn} for cc, b, u, dn in con.execute(
        "SELECT cc, SUM(up+down) b, SUM(up), SUM(down) FROM geo WHERE day>=? GROUP BY cc ORDER BY b DESC LIMIT 20", (since,))]
    by_asn = [{"asn": a or "未知", "bytes": b} for a, b in con.execute(
        "SELECT asn, SUM(up+down) b FROM geo WHERE day>=? GROUP BY asn ORDER BY b DESC LIMIT 12", (since,))]
    tot = con.execute("SELECT COALESCE(SUM(up+down),0) FROM geo WHERE day>=?", (since,)).fetchone()[0]
    all_ = con.execute("SELECT COALESCE(SUM(up+down),0) FROM traffic WHERE day>=?", (since,)).fetchone()[0]
    # 节点服务器所在国家(代理流量的真实目的地看不到,只能看出口)
    nodes = []
    for node, remote in con.execute("SELECT node, remote FROM nodeinfo WHERE remote IS NOT NULL AND remote != ''"):
        cc, asn = geo.lookup(remote)
        if cc or asn:
            nodes.append({"node": node, "cc": cc, "asn": asn})
    return {"days": days, "available": geo.available(), "by_cc": by_cc, "by_asn": by_asn, "known": tot, "all": all_, "nodes": nodes[:40]}


# ---------------------------------------------------------------- 安全页顶部:指标卡 + 需要关注
_sec = {"at": 0.0, "v": None}
_LV = {"bad": 0, "warn": 1, "info": 2, "ok": 3}


def secsum(con, force=False):
    """汇总各处的状态:几张指标卡 + 按轻重排序的「需要关注」。只在打开安全页时计算,结果缓存 45 秒。"""
    if not force and _sec["v"] and time.time() - _sec["at"] < 45:
        return _sec["v"]
    from . import auth
    tiles, finds = [], []

    def tile(key, label, value, sub, level, go):
        tiles.append({"key": key, "label": label, "value": value, "sub": sub, "level": level, "go": go})

    def find(level, title, detail, go):
        finds.append({"level": level, "title": title, "detail": detail, "go": go})

    c = collector.COLLECTOR
    up = bool(c and c.status.get("ok"))
    tile("collect", "nikki 采集", "正常" if up else "失联", "每 %g 秒采样" % config.INTERVAL if up else ((c.status.get("error") if c else "") or "未启动"), "ok" if up else "bad", "sec:q")
    if not up:
        find("bad", "面板连不上 nikki", (c.status.get("error") if c else "") or "采集器未启动,这段时间的流量不会被统计", "set:conn")
    try:
        cnt = alerts.counts(con, time.time() - 86400)
        unread = alerts.unread(con)
        lvl = "bad" if cnt["bad"] else "warn" if cnt["warn"] else "ok"
        tile("alerts", "告警(24 小时)", cnt["bad"] + cnt["warn"], f"严重 {cnt['bad']} · 警告 {cnt['warn']} · 未读 {unread}", lvl, "tab:alerts")
        if cnt["bad"]:
            find("bad", f"最近 24 小时有 {cnt['bad']} 条严重告警", "到「告警」页查看详情", "tab:alerts")
        elif cnt["warn"]:
            find("warn", f"最近 24 小时有 {cnt['warn']} 条警告", "到「告警」页查看详情", "tab:alerts")
        nd = con.execute("SELECT COUNT(*) FROM alerts WHERE kind='new_device' AND ts>=?", (int(time.time() - 86400),)).fetchone()[0]
        if nd:
            find("info", f"24 小时内出现 {nd} 台新设备", "如果不认识,检查 Wi-Fi 密码或 DHCP 列表", "tab:alerts")
    except Exception as e:
        log("安全概览(告警)", e)
    try:
        ns = dict(c.nodes) if c else {}
        if ns:
            bad = [n for n, v in ns.items() if (v.get("fails") or 0) >= 3]
            lvl = "bad" if len(bad) == len(ns) else "warn" if bad else "ok"
            tile("nodes", "节点测速", f"{len(ns) - len(bad)} / {len(ns)}", "可用 / 全部" if not bad else "失败:" + "、".join(bad[:2]), lvl, "tab:nodes")
            if bad:
                find("bad" if lvl == "bad" else "warn", f"{len(bad)} 个节点连续测速失败", "、".join(bad[:5]), "tab:nodes")
    except Exception as e:
        log("安全概览(节点)", e)
    try:
        a = agh.fetch(con)
        if not a.get("configured"):
            tile("dns", "DNS 过滤", "未接入", "AdGuard Home", "info", "set:dns")
        elif a.get("ok"):
            tile("dns", "DNS 拦截率", f"{a['rate']}%", f"拦截 {a['blocked']:,} / {a['total']:,}", "ok", "sec:agh")
        else:
            tile("dns", "DNS 过滤", "读取失败", a.get("error", ""), "warn", "set:dns")
            find("warn", "读不到 AdGuard Home", a.get("error", ""), "set:dns")
    except Exception as e:
        log("安全概览(DNS)", e)
    try:
        lk = leaks(con, 7)
        n = len(lk["cn_proxy"]) + len(lk["fo_direct"])
        tot = lk["cn_proxy_bytes"] + lk["fo_direct_bytes"]
        tile("leak", "分流异常(7 天)", n, _b(tot) if n else "未发现", "warn" if tot >= 100 * 1024 * 1024 else "info" if n else "ok", "sec:lk")
        if lk["cn_proxy_bytes"] >= 100 * 1024 * 1024:
            find("warn", f"国内站点走了代理 {_b(lk['cn_proxy_bytes'])}", "占用机场流量并增加延迟,检查是否漏了国内规则集", "sec:lk")
        if lk["fo_direct_bytes"] >= 100 * 1024 * 1024:
            find("warn", f"境外站点直连 {_b(lk['fo_direct_bytes'])}", "可能被阻断或暴露真实访问,检查是否漏了境外规则", "sec:lk")
        if lk["dns_local_bytes"] >= 500 * 1024 * 1024:
            find("info", f"{_b(lk['dns_local_bytes'])} 代理流量的域名在本机解析", "没走 fake-ip / 远程解析,可能把查询暴露给本地 DNS", "sec:lk")
    except Exception as e:
        log("安全概览(分流)", e)
    try:
        rh = rule_health(con, 30)
        if rh["match"]:
            sh = rh["match"]["share"]
            tile("match", "兜底规则占比", f"{sh}%", "落到 Match 的流量", "warn" if sh >= 30 else "ok", "tab:rules")
            if sh >= 30:
                find("warn", f"{sh}% 的流量落到兜底规则", "大量域名没被任何规则覆盖,到「规则策略」页查看", "tab:rules")
        if rh.get("has_hits") and rh.get("zero_total", 0) >= 20:
            find("info", f"{rh['zero_total']} 条规则从未命中", "可以考虑清理,到「规则策略」页查看", "tab:rules")
    except Exception as e:
        log("安全概览(规则)", e)
    try:
        qs = [q for q in quota_status(con) if q["known"]]
        if qs:
            q = max(qs, key=lambda x: x["pct"])
            lvl = "bad" if q["pct"] >= 95 else "warn" if q["pct"] >= 80 or q["over"] else "ok"
            tile("quota", "套餐用量", f"{q['pct']}%", f"{q['airport']} · 还有 {q['days_left']} 天重置", lvl, "tab:nodes")
            for q in qs:
                if q["pct"] >= 80 or q["over"]:
                    find("bad" if q["pct"] >= 95 else "warn", f"{q['airport']} 套餐已用 {q['pct']}%",
                         f"{_b(q['used'])} / {q['gb']:g} GB" + (f";按近 7 天速度预计 {q['exhaust']} 用完" if q["exhaust"] else ""), "tab:nodes")
        else:
            tile("quota", "套餐用量", "未设置", "机场套餐", "info", "set:quota")
    except Exception as e:
        log("安全概览(套餐)", e)
    on = auth.enabled() or bool(config.PAGE_TOKEN)
    tile("auth", "面板保护", "已启用" if on else "未设置", "访问密码" if on else "局域网内人人可看", "ok" if on else "warn", "set:security")
    if not on:
        find("warn", "面板没有设置访问密码", "局域网里任何人打开页面都能看到每台设备访问过的域名", "set:security")
    if not geo.available():
        find("info", "没有 GeoIP 数据库", "装上后「目的地国家 / ASN」才有数据", "set:geo")
    finds.sort(key=lambda x: _LV[x["level"]])
    v = {"at": int(time.time()), "tiles": tiles, "findings": finds[:10], "bad": sum(1 for f in finds if f["level"] == "bad"),
         "warn": sum(1 for f in finds if f["level"] == "warn")}
    _sec.update(at=time.time(), v=v)
    return v
