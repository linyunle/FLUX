"""关联分析:本周 vs 上周对比、故障时间线(丢包 / 重传 / 节点 / 流量放在同一条时间轴上并给出倾向)、无线连接事件。
全部只读面板自己的统计表;不碰路由器和 nikki。"""
import re
import time

from . import collector, devices
from .util import is_mac, log


def _web():
    from . import web
    return web


def _days(n_from, n_to=0):
    """[今天-n_from, 今天-n_to] 的起止日期字符串。"""
    t = time.time()
    f = lambda k: time.strftime("%Y-%m-%d", time.localtime(t - k * 86400))
    return f(n_from), f(n_to)


def _pct(a, b):
    return None if not b else round((a - b) * 100 / b)


def _day_ok(v):
    try:
        time.strptime(str(v), "%Y-%m-%d")
        return str(v)
    except (TypeError, ValueError):
        return None


def _shift(day, n):
    """日期字符串 day 往前推 n 天(n 可为负)。用中午避开夏令时。"""
    t = time.mktime(time.strptime(day, "%Y-%m-%d")) + 12 * 3600
    return time.strftime("%Y-%m-%d", time.localtime(t - n * 86400))


def compare(con, days=7, cur_end=None, prev_end=None):
    """动态对比窗口:最近 days 天(含今天)和紧挨着它之前的 days 天;也可指定两段同样长度的任意日期(cur_end / prev_end 为各段最后一天)。"""
    w = _web()
    d, r = w.kind_names()
    try:
        days = max(1, min(90, int(days)))
    except (TypeError, ValueError):
        days = 7
    today = _days(0, 0)[0]
    ce = _day_ok(cur_end) or today
    ce = min(ce, today)
    cs = _shift(ce, days - 1)
    pe = _day_ok(prev_end) or _shift(cs, 1)
    if pe >= cs:                       # 上期不能和本期重叠:退回紧挨着本期之前
        pe = _shift(cs, 1)
    ps = _shift(pe, days - 1)
    cur, prev = (cs, ce), (ps, pe)
    weekly = days == 7 and ce == today and pe == _shift(cs, 1)
    pn = ("本周", "上周") if weekly else ("本期", "上期")
    out = {"cur": cur, "prev": prev, "days": days, "names": list(pn)}

    def tot(rng):
        rows = con.execute("SELECT day, node, SUM(up), SUM(down) FROM traffic WHERE day>=? AND day<=? GROUP BY day, node", rng).fetchall()
        up = sum(x[2] or 0 for x in rows)
        down = sum(x[3] or 0 for x in rows)
        proxy = sum((x[2] or 0) + (x[3] or 0) for x in rows if w.node_kind(x[1], d, r) == "proxy")
        by_day = {}
        for day, _, u, dn in rows:
            by_day[day] = by_day.get(day, 0) + (u or 0) + (dn or 0)
        return {"up": up, "down": down, "total": up + down, "proxy": proxy, "by_day": by_day}
    a, b = tot(cur), tot(prev)
    out["traffic"] = {"cur": a, "prev": b, "delta_pct": _pct(a["total"], b["total"])}

    def days_list(rng):
        return [_shift(rng[0], -i) for i in range(days)]
    out["series"] = {"cur": [a["by_day"].get(x, 0) for x in days_list(cur)], "prev": [b["by_day"].get(x, 0) for x in days_list(prev)],
                     "cur_labels": [x[5:] for x in days_list(cur)], "prev_labels": [x[5:] for x in days_list(prev)]}

    def retrans(rng):
        o, rt = con.execute("SELECT SUM(out), SUM(retrans) FROM tcp WHERE substr(hour,1,10)>=? AND substr(hour,1,10)<=?", rng).fetchone()
        return round((rt or 0) * 100 / o, 2) if o and o > 2000 else None
    out["retrans"] = {"cur": retrans(cur), "prev": retrans(prev)}

    def loss(rng):
        row = con.execute("SELECT SUM(n), SUM(lost), SUM(sum_rtt) FROM wanq WHERE substr(hour,1,10)>=? AND substr(hour,1,10)<=? AND target NOT IN "
                          "(SELECT target FROM wanq GROUP BY target HAVING SUM(n)=SUM(lost))", rng).fetchone()
        n, lost, rtt = row
        return {"loss": round((lost or 0) * 100 / n, 1), "rtt": round(rtt / max(1, n - lost), 1)} if n else None
    out["wan"] = {"cur": loss(cur), "prev": loss(prev)}

    def nodes(rng):
        res = {}
        for node, n, sd, fails in con.execute("SELECT node, SUM(n), SUM(sum_d), SUM(fails) FROM qoe WHERE substr(hour,1,10)>=? AND substr(hour,1,10)<=? GROUP BY node", rng):
            tests = (n or 0) + (fails or 0)        # qoe.n 只数成功的测速,失败另记在 fails
            if tests >= 10:
                res[node] = {"avg": round(sd / n) if n else None, "fail": round((fails or 0) * 100 / tests, 1), "n": tests}
        return res
    na, nb = nodes(cur), nodes(prev)
    chg = []
    for n_, v in na.items():
        o = nb.get(n_)
        if not o:
            continue
        va, oa = v["avg"], o["avg"]
        dd = (va - oa) if (va is not None and oa is not None) else 0
        if (oa and dd * 100 / oa >= 30 and dd >= 30) or v["fail"] - o["fail"] >= 10:
            if va is None:        # 本期一次都没测通:延迟显示为 0,以失败率为准
                va = 0
            chg.append({"node": n_, "avg": va, "avg_prev": oa or 0, "fail": v["fail"], "fail_prev": o["fail"]})
    out["nodes_worse"] = sorted(chg, key=lambda x: (-(x["fail"] - x["fail_prev"]), -(x["avg"] - x["avg_prev"])))[:30]

    ipm = dict(con.execute("SELECT ip, mac FROM ipmap").fetchall())

    def devs(rng):
        o = {}
        for c, b in con.execute("SELECT client, SUM(up+down) FROM traffic WHERE day>=? AND day<=? GROUP BY client", rng):
            k = ipm.get(c, c)
            k = devices.MERGE.get(k, k)     # 旧记录按 IP→MAC→合并后的主设备归并
            o[k] = o.get(k, 0) + (b or 0)
        return o
    da, db_ = devs(cur), devs(prev)
    macips, stored = devices.ips_by_dev(con), devices.stored_names(con)
    nm = lambda k: devices.NAMES.label(k, macips.get(k, [] if is_mac(k) else [k]), stored) or (macips.get(k) or [k])[0]
    moves = sorted(((da.get(k, 0) - db_.get(k, 0), k) for k in set(da) | set(db_)), key=lambda x: -abs(x[0]))[:30]
    out["devices"] = [{"name": nm(k), "delta": dv, "cur": da.get(k, 0), "prev": db_.get(k, 0)} for dv, k in moves if dv]
    ha = {x[0] for x in con.execute("SELECT DISTINCT host FROM traffic WHERE day>=? AND day<=?", cur)}
    hb = {x[0] for x in con.execute("SELECT DISTINCT host FROM traffic WHERE day>=? AND day<=?", prev)}
    new = [h for h in ha - hb if h and not re.match(r"^[0-9a-f:.]+$", h)]
    if new:
        top = con.execute("SELECT host, SUM(up+down) s FROM traffic WHERE day>=? AND day<=? AND host IN (%s) GROUP BY host ORDER BY s DESC LIMIT 30" % ",".join("?" * min(len(new), 500)),
                          list(cur) + new[:500]).fetchall()
        out["new_hosts"] = {"count": len(new), "top": [{"host": h, "bytes": s} for h, s in top]}
    else:
        out["new_hosts"] = {"count": 0, "top": []}
    # 一句话结论
    notes = []
    t = out["traffic"]
    if t["delta_pct"] is not None and abs(t["delta_pct"]) >= 25:
        notes.append((f"流量比{pn[1]}" + ("多" if t["delta_pct"] > 0 else "少") + f" {abs(t['delta_pct'])}%", "info"))
    rc, rp = out["retrans"]["cur"], out["retrans"]["prev"]
    if rc is not None and rp is not None and rc - rp >= 1:
        notes.append((f"TCP 重传率 {rp}% → {rc}%,线路 / 上游比{pn[1]}差", "warn"))
    wc, wp = out["wan"]["cur"], out["wan"]["prev"]
    if wc and wp and wc["loss"] - wp["loss"] >= 10:
        notes.append((f"到公共 DNS 的 ICMP 丢包 {wp['loss']}% → {wc['loss']}%(常是运营商限速,结合重传率看)", "info"))
    if out["nodes_worse"]:
        notes.append((f"{len(out['nodes_worse'])} 个节点比{pn[1]}明显变差(延迟 +30% 以上或失败率 +10 个点)", "warn"))
    if out["new_hosts"]["count"] >= 50:
        notes.append((f"{pn[0]}新出现 {out['new_hosts']['count']} 个域名,多半是新装了应用或有设备行为变了", "info"))
    out["notes"] = [{"text": x, "level": lv} for x, lv in notes]
    return out


def timeline(con, hours=48, until=None):
    """逐小时把 丢包 / 重传 / 节点测速 / 流量 放在一起,标出同时异常的小时并给倾向。"""
    hours = max(6, min(720, int(hours)))
    step = -(-hours // 168)            # 超过 168 小时按 step 小时聚合,避免时间轴太挤
    now = min(time.time(), float(until)) if until else time.time()
    hrs = [time.strftime("%Y-%m-%d %H", time.localtime(now - i * 3600)) for i in range(hours - 1, -1, -1)]
    first = hrs[0]
    last = hrs[-1]
    gw = None
    try:
        from . import wan
        gw = wan.STATE.get("gw")
    except Exception:
        pass
    silent = {t for (t,) in con.execute("SELECT target FROM wanq GROUP BY target HAVING SUM(n)=SUM(lost)")}
    loss, gloss, rtt = {}, {}, {}
    for h, t, n, lost, srtt in con.execute("SELECT hour, target, n, lost, sum_rtt FROM wanq WHERE hour>=? AND hour<=?", (first, last)):
        if t in silent or not n:
            continue
        (gloss if t == gw else loss).setdefault(h, []).append((n, lost, srtt))
    agg = lambda d: {h: (round(sum(x[1] for x in v) * 100 / max(1, sum(x[0] for x in v)), 1), round(sum(x[2] for x in v) / max(1, sum(x[0] - x[1] for x in v)), 1)) for h, v in d.items()}
    L, G = agg(loss), agg(gloss)
    ret = {h: round(rt * 100 / o, 2) for h, o, rt in con.execute("SELECT hour, out, retrans FROM tcp WHERE hour>=? AND hour<=?", (first, last)) if o and o >= 500}
    q = {}
    for h, n, sd, fails in con.execute("SELECT hour, SUM(n), SUM(sum_d), SUM(fails) FROM qoe WHERE hour>=? AND hour<=? GROUP BY hour", (first, last)):
        tests = (n or 0) + (fails or 0)
        if tests:
            q[h] = {"fail": round((fails or 0) * 100 / tests, 1), "avg": round(sd / n) if n else 0}
    tr = dict(con.execute("SELECT hour, SUM(up+down) FROM hourly WHERE hour>=? AND hour<=? GROUP BY hour", (first, last)).fetchall())
    base_avg = sorted(v["avg"] for v in q.values() if v["avg"])
    med = base_avg[len(base_avg) // 2] if base_avg else 0
    rows, marks = [], []
    for h in hrs:
        lo = (L.get(h) or (None, None))[0]
        go = (G.get(h) or (None, None))[0]
        rt_ = ret.get(h)
        qq = q.get(h) or {}
        f_loss = lo is not None and lo >= 20
        f_ret = rt_ is not None and rt_ >= 3
        f_node = bool(qq) and (qq["fail"] >= 30 or (med and qq["avg"] >= med * 2 and qq["avg"] >= 300))
        verdict = ""
        if f_ret and f_loss and not f_node:
            verdict = "丢包和重传同时偏高、节点测速正常:倾向线路 / 运营商问题"
        elif f_ret and f_node:
            verdict = "重传高且节点测速变差:倾向节点或境外上游问题"
        elif f_node and not f_ret:
            verdict = "只有节点测速变差:倾向某些节点本身的问题,换节点试试"
        elif f_loss and not f_ret:
            verdict = "只有 ICMP 丢包、TCP 正常:多半是运营商对 ICMP 限速,不影响上网"
        elif f_ret and not f_loss:
            verdict = "只有重传高:可能是某条链路或某个节点拥塞"
        rows.append({"hour": h, "loss": lo, "gw_loss": go, "rtt": (L.get(h) or (None, None))[1], "retrans": rt_, "node_fail": qq.get("fail"), "node_avg": qq.get("avg"),
                     "bytes": tr.get(h, 0), "flags": [k for k, f in (("loss", f_loss), ("retrans", f_ret), ("node", f_node)) if f], "verdict": verdict})
    # 连续同判断的小时合并成区间
    cur = None
    for r in rows:
        if r["verdict"]:
            if cur and cur["verdict"] == r["verdict"]:
                cur["to"] = r["hour"]
            else:
                cur = {"from": r["hour"], "to": r["hour"], "verdict": r["verdict"], "flags": r["flags"]}
                marks.append(cur)
        else:
            cur = None
    flag_hours = sum(1 for r in rows if r["verdict"])
    if step > 1:
        agg_rows = []
        for i in range(0, len(rows), step):
            g = rows[i:i + step]
            mx = lambda k: max((x[k] for x in g if x[k] is not None), default=None)
            vs = [x["verdict"] for x in g if x["verdict"]]
            agg_rows.append({"hour": g[0]["hour"], "loss": mx("loss"), "gw_loss": mx("gw_loss"), "rtt": mx("rtt"), "retrans": mx("retrans"), "node_fail": mx("node_fail"),
                             "node_avg": mx("node_avg"), "bytes": sum(x["bytes"] for x in g), "flags": sorted({f for x in g for f in x["flags"]}), "verdict": vs[0] if vs else ""})
        rows = agg_rows
    since = int(now - hours * 3600)
    ev = [{"ts": t, "kind": k, "level": lv, "title": ti} for t, k, lv, ti in
          con.execute("SELECT ts, kind, level, title FROM alerts WHERE ts>=? AND ts<=? AND level IN ('warn','bad') ORDER BY ts DESC LIMIT 30", (since, int(now)))]
    return {"hours": hours, "step": step, "flag_hours": flag_hours, "rows": rows, "marks": marks[-12:], "events": ev, "median_node_delay": med,
            "has_wan": bool(L), "has_tcp": bool(ret), "has_nodes": bool(q)}


_MAC = r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})"
_WIFI = [
    ("conn", re.compile(r"AP-STA-CONNECTED\s+" + _MAC, re.I)),
    ("disc", re.compile(r"AP-STA-DISCONNECTED\s+" + _MAC, re.I)),
    ("deauth", re.compile(r"STA\s+" + _MAC + r".*?(deauthenticated|disassociated)(?:\s+due to\s+(inactivity|local deauth|[a-z ]+))?", re.I)),
    ("assoc", re.compile(r"STA\s+" + _MAC + r".*?\bassociated\b", re.I)),
]


def wifi(con, hours=24, until=None):
    """路由器把 hostapd 日志转发给面板时,统计每台无线设备的连接 / 断开次数,找出频繁掉线的。"""
    hours = max(1, min(168, int(hours)))
    end = int(min(time.time(), float(until))) if until else int(time.time())
    since = end - hours * 3600
    rows = con.execute("SELECT ts, tag, msg FROM syslog WHERE ts>=? AND ts<=? AND (tag LIKE 'hostapd%' OR tag LIKE 'wpa%' OR tag LIKE 'netifd%' OR msg LIKE '%AP-STA-%')", (since, end)).fetchall()
    ev = {}
    hourly = {}
    for ts, tag, msg in rows:
        for kind, rx in _WIFI:
            m = rx.search(msg)
            if not m:
                continue
            mac = next((g for g in m.groups() if g and re.match(r"^[0-9a-f:]{17}$", g, re.I)), "").lower()
            if not mac:
                continue
            e = ev.setdefault(mac, {"conn": 0, "disc": 0, "deauth": 0, "inactive": 0, "last": 0, "last_kind": "", "iface": ""})
            if kind == "disc" or kind == "deauth":
                e["disc" if kind == "disc" else "deauth"] += 1
                hh = time.strftime("%m-%d %H", time.localtime(ts))
                hourly[hh] = hourly.get(hh, 0) + 1
                if kind == "deauth" and "inactiv" in msg.lower():
                    e["inactive"] += 1
            elif kind == "conn":
                e["conn"] += 1
            if ts >= e["last"]:
                e["last"], e["last_kind"] = ts, kind
            mi = re.match(r"^\s*([a-z0-9.\-]+):", msg, re.I)
            if mi:
                e["iface"] = mi.group(1)
            break
    out = {"hours": hours, "available": bool(ev), "lines": len(rows), "devices": [], "hourly": [{"hour": k, "n": v} for k, v in sorted(hourly.items())][-48:]}
    if not ev:
        out["hint"] = ("没有收到无线(hostapd)日志。要看到无线掉线 / 漫游:路由器上开启系统日志转发给面板(设置 → 路由器系统日志),"
                       "并确认无线 AP 就是这台路由器;AP 单独放在别处时,这里看不到。")
        return out
    macips, stored = devices.ips_by_dev(con), devices.stored_names(con)
    for mac, e in ev.items():
        name = devices.NAMES.label(mac, macips.get(mac, []), stored) or (macips.get(mac) or [mac])[0]
        drops = e["disc"] + e["deauth"]
        out["devices"].append({"mac": mac, "name": name, "connects": e["conn"], "drops": drops, "inactive": e["inactive"], "iface": e["iface"],
                               "last": e["last"], "flap": drops >= 6 and e["conn"] >= 3})
    out["devices"].sort(key=lambda x: (-x["drops"], -x["connects"]))
    out["devices"] = out["devices"][:20]
    out["flap"] = [d["name"] for d in out["devices"] if d["flap"]]
    return out
