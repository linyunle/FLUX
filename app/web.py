"""网页和 JSON 接口。"""
import ipaddress
import json
import mimetypes
import os
import re
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import gzip
import hashlib
import hmac

from . import agh, alerts, auth, airports, appsig, collector, config, db, devices, geo, insight, netstat, realtime, sysinfo, update, backup, groups, advisor, providers, panellog, lookup, analysis, probe, presence, wan, diag, syslog, ups, expiry, dockerapi, listen, nodepurge, wallpaper, dnsx, nikkilog, health, nodegeo, favicon
from .util import api_call, is_mac, log, stop

STATIC = os.path.join(os.path.dirname(__file__), "static")
DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
RAW_COL = {"node": "node", "group": "grp", "rule": "rule", "host": "host"}
MODES = ("direct", "reject", "proxy")
_kind_cache = {"at": 0.0, "d": ["DIRECT"], "r": []}


def kind_names():
    """按节点「类型」判断直连/拒绝,而不是按名字(你的直连出口可能叫「直连」而不是 DIRECT)。"""
    if time.time() - _kind_cache["at"] < 5:
        return _kind_cache["d"], _kind_cache["r"]
    d, r = {"DIRECT"}, set()
    c = collector.COLLECTOR
    pt = dict(c.ptype) if c else {}
    try:
        con = ro()
        try:
            for n, typ in con.execute("SELECT node, type FROM nodeinfo"):
                pt.setdefault(n, typ or "")
        finally:
            con.close()
    except Exception:
        pass
    for n, typ in pt.items():
        tl = (typ or "").lower()
        if tl == "direct":
            d.add(n)
        elif tl in ("reject", "rejectdrop"):
            r.add(n)
    _kind_cache.update(at=time.time(), d=sorted(d), r=sorted(r))
    return _kind_cache["d"], _kind_cache["r"]


def _in(names):
    return "(" + ",".join("?" * len(names)) + ")"


_nodes_cache = {"at": 0.0, "v": []}


def all_nodes():
    """出现过的所有节点名(缓存 15 秒)。用来把「机场」展开成节点列表。"""
    if time.time() - _nodes_cache["at"] < 15:
        return _nodes_cache["v"]
    names = set()
    try:
        con = ro()
        try:
            names |= {r[0] for r in con.execute("SELECT node FROM nodeinfo")}
            names |= {r[0] for r in con.execute("SELECT DISTINCT node FROM hourly")}
        finally:
            con.close()
    except Exception:
        pass
    names.discard("")
    _nodes_cache.update(at=time.time(), v=sorted(names))
    return _nodes_cache["v"]


def node_kind(n, d, r):
    return "direct" if n in d else "reject" if (n in r or n.startswith("REJECT")) else "proxy"


def airport_of(n):
    d, r = kind_names()
    return airports.of(n, node_kind(n, d, r))


def airport_names():
    """真正的机场名(不含 直连/拒绝/未知)。"""
    d, r = kind_names()
    return sorted({airports.of(n, node_kind(n, d, r)) for n in all_nodes()} - airports.SPECIAL)


def mode_clause(mode):
    """返回 (sql, args)。"""
    d, r = kind_names()
    rej = f"(node IN {_in(r)} OR node LIKE 'REJECT%')" if r else "node LIKE 'REJECT%'"
    if mode == "direct":
        return f"node IN {_in(d)}", list(d)
    if mode == "reject":
        return rej, list(r)
    return f"(node NOT IN {_in(d)} AND NOT {rej})", list(d) + list(r)
_DEV0 = "COALESCE((SELECT mac FROM ipmap WHERE ip = client), client)"  # 旧数据里的 IP 也并到设备上
DEVX = f"COALESCE((SELECT main FROM devmerge WHERE alias = {_DEV0}), {_DEV0})"      # 再按「设备合并」归到主设备


def one(p, k, d=""):
    return p.get(k, [d])[0]


def csv(p, k):
    return [x for x in one(p, k).split(",") if x]


def day_range(p):
    today = time.strftime("%Y-%m-%d")
    d1, d2 = one(p, "from", today), one(p, "to", "")
    d2 = d2 or d1
    if not (DAY_RE.match(d1) and DAY_RE.match(d2)):
        d1 = d2 = today
    if d1 > d2:
        d1, d2 = d2, d1
    return d1, d2


def dev_keys_like(kw):
    """名字 / IP / MAC 里含关键字的设备(返回设备键)。"""
    kw = kw.lower()
    con = ro()
    try:
        macips = devices.ips_by_dev(con)
        stored = devices.stored_names(con)
    finally:
        con.close()
    out = []
    for k, ips in macips.items():
        name = devices.NAMES.label(k, ips, stored) or ""
        if kw in (name + " " + " ".join(ips) + " " + k).lower():
            out.append(k.lower())
    return out[:200]


def filters(p, cols, skip_mode=False, skip_airport=False):
    """cols: 该表有哪些可筛选维度。返回 (where 列表, 参数)。"""
    where, args = [], []
    devs = [d.lower() for d in csv(p, "dev")]
    if devs and "dev" in cols:
        where.append(f"{DEVX} IN ({','.join('?' * len(devs))})")
        args += devs
    for f, col in RAW_COL.items():
        v = one(p, f)
        if v and f in cols:
            where.append(f"{col} = ?")
            args.append(v)
    dom = one(p, "dom").strip().lower()
    if dom and "host" in cols:
        # 域名及其所有子域名(用于「合并子域名」后的域名点开看设备)
        where.append("(host = ? OR host LIKE ? ESCAPE '\\')")
        args += [dom, "%." + dom.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")]
    kw = one(p, "q").strip()
    if kw and "host" in cols:
        # 全局搜索:域名 / 节点 / 策略组 / 规则 / 设备(名字、IP、MAC)任意一项匹配
        like = "%" + kw.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        parts, pa = ["host LIKE ? ESCAPE '\\'", "node LIKE ? ESCAPE '\\'", "client LIKE ? ESCAPE '\\'"], [like, like, like]
        if "group" in cols:
            parts.append("grp LIKE ? ESCAPE '\\'")
            pa.append(like)
        if "rule" in cols:
            parts.append("rule LIKE ? ESCAPE '\\'")
            pa.append(like)
        keys = dev_keys_like(kw)
        if keys:
            parts.append(f"{DEVX} IN ({','.join('?' * len(keys))})")
            pa += keys
        where.append("(" + " OR ".join(parts) + ")")
        args += pa
    ap = one(p, "airport")
    if ap and "node" in cols and not skip_airport:
        d, r = kind_names()
        ns = [n for n in all_nodes() if airports.of(n, node_kind(n, d, r)) == ap]
        where.append(f"node IN {_in(ns)}" if ns else "0")
        args += ns
    mode = one(p, "mode")
    if mode in MODES and not skip_mode:
        sql, a = mode_clause(mode)
        where.append(sql)
        args += a
    return where, args


T_COLS = {"dev", "node", "group", "rule", "host"}
H_COLS = {"dev", "node"}


def ro():
    return db.open_db(readonly=True)


def live():
    if realtime.LIVE["at"]:
        return realtime.LIVE
    c = collector.COLLECTOR
    return c.live if c else {"at": 0, "nodes": {}, "clients": {}}


# ---------------------------------------------------------------- 查询
def q_summary(p):
    by = one(p, "by", "client")
    if by not in ("client", "node", "group", "rule", "host"):
        return 400, {"error": "by 不对"}
    expr = DEVX if by == "client" else RAW_COL[by]
    d1, d2 = day_range(p)
    try:
        limit = max(1, min(500, int(one(p, "limit", "50"))))
    except ValueError:
        limit = 50
    fw, fa = filters(p, T_COLS)
    where = " AND ".join(["day >= ?", "day <= ?"] + fw)
    args = [d1, d2] + fa
    con = ro()
    try:
        rows = con.execute(f"SELECT {expr} k, SUM(up), SUM(down) FROM traffic WHERE {where} GROUP BY k "
                           f"ORDER BY SUM(up)+SUM(down) DESC LIMIT ?", (*args, limit)).fetchall()
        tot = con.execute(f"SELECT COALESCE(SUM(up),0), COALESCE(SUM(down),0) FROM traffic WHERE {where}", args).fetchone()
        n_all = con.execute(f"SELECT COUNT(DISTINCT {expr}) FROM traffic WHERE {where}", args).fetchone()[0]
        macips = devices.ips_by_dev(con) if by == "client" else {}
        stored = devices.stored_names(con) if by == "client" else {}
        nodes_by = {}
        if by in ("group", "rule") and rows:  # 每个策略组/规则最终走了哪些节点
            keys = [r[0] for r in rows]
            for k, n, b in con.execute(
                    f"SELECT {expr}, node, SUM(up)+SUM(down) FROM traffic WHERE {where} AND {expr} IN {_in(keys)} "
                    f"GROUP BY {expr}, node", args + keys):
                nodes_by.setdefault(k, []).append((n, b))
    finally:
        con.close()
    lv = live()
    out = []
    for key, up, down in rows:
        r = {"key": key, "up": up, "down": down}
        if by == "client":
            ips = macips.get(key, [] if is_mac(key) else [key])
            r.update(name=devices.NAMES.label(key, ips, stored), ips=ips[:8], is_mac=is_mac(key),
                     live=lv["clients"].get(key))
        elif by == "node":
            r["live"] = lv["nodes"].get(key)
            r["airport"] = airport_of(key)
        elif by in ("group", "rule"):
            r["nodes"] = [{"node": n, "bytes": b} for n, b in sorted(nodes_by.get(key, []), key=lambda x: -x[1])[:3]]
        out.append(r)
    return 200, {"from": d1, "to": d2, "by": by, "total": {"up": tot[0], "down": tot[1]}, "count": n_all, "rows": out}


TR_COLS = {"client": DEVX, "host": "host", "node": "node", "group": "grp", "rule": "rule"}


def q_trace(p):
    """流量追踪:设备 → 域名 → 规则 → 策略组 → 节点 的流量明细,附带 DNS 解析记录。cols 决定按哪几列分组。"""
    cols = [c for c in one(p, "cols", "client,host,node,group,rule").split(",") if c in TR_COLS] or ["client", "host", "node"]
    try:
        limit = max(1, min(100, int(one(p, "limit", "20"))))
    except ValueError:
        limit = 20
    d1, d2 = day_range(p)
    fw, fa = filters(p, T_COLS)
    where = " AND ".join(["day >= ?", "day <= ?"] + fw)
    args = [d1, d2] + fa
    sel = ", ".join(TR_COLS[c] for c in cols)
    con = ro()
    try:
        rows = con.execute(f"SELECT {sel}, SUM(up), SUM(down) FROM traffic WHERE {where} GROUP BY {sel} "
                           f"ORDER BY SUM(up)+SUM(down) DESC LIMIT ?", (*args, limit + 1)).fetchall()
        by_node = con.execute(f"SELECT node, SUM(up), SUM(down) FROM traffic WHERE {where} GROUP BY node", args).fetchall()
        if "host" in cols:
            hosts = list({r[cols.index("host")] for r in rows[:limit]})
        else:
            hosts = [r[0] for r in con.execute(f"SELECT host FROM traffic WHERE {where} GROUP BY host "
                                               f"ORDER BY SUM(up)+SUM(down) DESC LIMIT 8", args)]
        dns = {}
        if hosts:
            for h, ip, md, last in con.execute(f"SELECT host, ip, mode, last FROM dns WHERE host IN {_in(hosts)} ORDER BY last DESC", hosts):
                dns.setdefault(h, []).append({"ip": ip, "mode": md, "last": last})
        macips = devices.ips_by_dev(con) if "client" in cols else {}
        stored = devices.stored_names(con) if "client" in cols else {}
    finally:
        con.close()
    dn, rj = kind_names()
    kinds = {"direct": [0, 0], "proxy": [0, 0], "reject": [0, 0]}
    for n, u, d in by_node:
        k = kinds[node_kind(n, dn, rj)]
        k[0] += u
        k[1] += d
    more = len(rows) > limit
    out = []
    for r in rows[:limit]:
        o = dict(zip(cols, r[:-2]))
        o["up"], o["down"] = r[-2], r[-1]
        if "client" in o:
            ips = macips.get(o["client"], [] if is_mac(o["client"]) else [o["client"]])
            o["name"] = devices.NAMES.label(o["client"], ips, stored) or next((i for i in ips if ":" not in i), "") or o["client"]
        if "node" in o:
            o["kind"] = node_kind(o["node"], dn, rj)
        out.append(o)
    return 200, {"from": d1, "to": d2, "cols": cols, "rows": out, "more": more,
                 "total": {"up": sum(v[0] for v in kinds.values()), "down": sum(v[1] for v in kinds.values())},
                 "kinds": {k: {"up": v[0], "down": v[1]} for k, v in kinds.items()}, "dns": dns}


def _limit(p, d=30, mx=500):
    try:
        return max(1, min(mx, int(one(p, "limit", str(d)))))
    except ValueError:
        return d


def _client_rows(con, rows):
    """(设备键, up, down) → [{key,name,ips,...}]"""
    macips, stored = devices.ips_by_dev(con), devices.stored_names(con)
    out = []
    for k, u, d in rows:
        ips = macips.get(k, [] if is_mac(k) else [k])
        out.append({"key": k, "up": u, "down": d, "name": devices.NAMES.label(k, ips, stored), "ips": ips[:8], "is_mac": is_mac(k)})
    return out


def q_protocols(p):
    """端口协议分布。by=proto(默认)或 client(谁在用这个协议:Top Talkers 下钻)。"""
    d1, d2 = day_range(p)
    by = "client" if one(p, "by") == "client" else "proto"
    fw, fa = filters(p, {"dev", "node"})
    pr = one(p, "proto")
    if pr:
        fw.append("proto = ?")
        fa.append(pr)
    where = " AND ".join(["day >= ?", "day <= ?"] + fw)
    expr = DEVX if by == "client" else "proto"
    con = ro()
    try:
        rows = con.execute(f"SELECT {expr}, SUM(up), SUM(down) FROM proto WHERE {where} GROUP BY 1 "
                           f"ORDER BY SUM(up)+SUM(down) DESC LIMIT ?", [d1, d2] + fa + [_limit(p, 30, 100)]).fetchall()
        first = con.execute("SELECT MIN(day) FROM proto").fetchone()[0]
        out = _client_rows(con, rows) if by == "client" else [{"key": k, "up": u, "down": d} for k, u, d in rows]
    finally:
        con.close()
    return 200, {"from": d1, "to": d2, "since": first or "", "total": {"up": sum(r["up"] for r in out), "down": sum(r["down"] for r in out)}, "rows": out}


def q_apps(p):
    """应用特征库(域名特征 + 端口)。by=app / cat / client(Top Talkers) / node;可用 app、cat 过滤做联动下钻。"""
    by = one(p, "by", "app")
    if by not in ("app", "cat", "client", "node"):
        return 400, {"error": "by 不对"}
    d1, d2 = day_range(p)
    fw, fa = filters(p, {"dev", "node"})
    for f in ("app", "cat"):
        if one(p, f):
            fw.append(f"{f} = ?")
            fa.append(one(p, f))
    where = " AND ".join(["day >= ?", "day <= ?"] + fw)
    expr = {"app": "app", "cat": "cat", "client": DEVX, "node": "node"}[by]
    con = ro()
    try:
        if by == "app":
            rows = con.execute(f"SELECT app, cat, SUM(up), SUM(down) FROM app WHERE {where} GROUP BY app, cat "
                               f"ORDER BY SUM(up)+SUM(down) DESC LIMIT ?", [d1, d2] + fa + [_limit(p)]).fetchall()
            out = [{"key": a, "cat": c, "up": u, "down": d} for a, c, u, d in rows]
        else:
            rows = con.execute(f"SELECT {expr}, SUM(up), SUM(down) FROM app WHERE {where} GROUP BY 1 "
                               f"ORDER BY SUM(up)+SUM(down) DESC LIMIT ?", [d1, d2] + fa + [_limit(p)]).fetchall()
            out = _client_rows(con, rows) if by == "client" else [{"key": k, "up": u, "down": d} for k, u, d in rows]
        first = con.execute("SELECT MIN(day) FROM app").fetchone()[0]
    finally:
        con.close()
    return 200, {"from": d1, "to": d2, "since": first or "", "by": by,
                 "total": {"up": sum(r["up"] for r in out), "down": sum(r["down"] for r in out)}, "rows": out}


def q_tunnels(p):
    """出口隧道协议分布:你的节点用的是 Shadowsocks / VLESS / Trojan / WireGuard …,各自走了多少流量。"""
    d1, d2 = day_range(p)
    fw, fa = filters(p, T_COLS)
    where = " AND ".join(["day >= ?", "day <= ?"] + fw)
    con = ro()
    try:
        rows = con.execute(f"SELECT node, SUM(up), SUM(down) FROM traffic WHERE {where} GROUP BY node", [d1, d2] + fa).fetchall()
        types = {n: t for n, t in con.execute("SELECT node, type FROM nodeinfo")}
    finally:
        con.close()
    c = collector.COLLECTOR
    if c:
        types.update({k: v for k, v in c.ptype.items() if v})
    dn, rj = kind_names()
    agg = {}
    for n, u, d in rows:
        k = node_kind(n, dn, rj)
        t = "直连" if k == "direct" else "拒绝" if k == "reject" else (types.get(n) or "未知")
        a = agg.setdefault(t, {"key": t, "up": 0, "down": 0, "nodes": 0})
        a["up"] += u
        a["down"] += d
        a["nodes"] += 1
    out = sorted(agg.values(), key=lambda r: -(r["up"] + r["down"]))
    return 200, {"from": d1, "to": d2, "rows": out}


def q_qoe(p):
    """网络质量:节点延迟 / 抖动 / 超时率(来自 mihomo 的延迟测试),以及路由器本机 TCP 重传率。"""
    try:
        n = max(1, min(14 * 24, int(one(p, "hours", "24"))))
    except ValueError:
        n = 24
    now = time.time()
    labels = [time.strftime("%Y-%m-%d %H", time.localtime(now - i * 3600)) for i in range(n - 1, -1, -1)]
    idx = {h: i for i, h in enumerate(labels)}
    per = {}
    con = ro()
    try:
        for node, hour, cnt, sd, sq, fl in con.execute("SELECT node, hour, n, sum_d, sum_sq, fails FROM qoe WHERE hour >= ? AND hour <= ?",
                                                        (labels[0], labels[-1])):
            a = per.setdefault(node, {"n": 0, "sd": 0.0, "sq": 0.0, "f": 0, "h": [None] * n})
            a["n"] += cnt
            a["sd"] += sd
            a["sq"] += sq
            a["f"] += fl
            if cnt and hour in idx:
                a["h"][idx[hour]] = round(sd / cnt)
        tcp = {h: (o, r, rs) for h, o, r, rs in con.execute("SELECT hour, out, retrans, resets FROM tcp WHERE hour >= ? AND hour <= ?",
                                                             (labels[0], labels[-1]))}
        types = {nm: t for nm, t in con.execute("SELECT node, type FROM nodeinfo")}
        nbytes = {nm: b for nm, b in con.execute("SELECT node, SUM(up + down) FROM hourly WHERE hour >= ? AND hour <= ? GROUP BY node",
                                                  (labels[0], labels[-1]))}
    finally:
        con.close()
    c = collector.COLLECTOR
    live = dict(c.nodes) if c else {}
    nodes = []
    for node in set(per) | set(live):
        a = per.get(node)
        lv = live.get(node) or {}
        cnt = a["n"] if a else 0
        avg = a["sd"] / cnt if cnt else None
        jit = (max(0.0, a["sq"] / cnt - avg * avg) ** 0.5) if cnt else None
        tests = (a["n"] + a["f"]) if a else 0
        nodes.append({"node": node, "type": lv.get("type") or types.get(node, ""), "airport": airport_of(node), "delay": lv.get("delay"),
                      "avg": round(avg) if avg is not None else None, "jitter": round(jit) if jit is not None else None,
                      "fail_rate": round(a["f"] / tests, 4) if tests else None, "tests": tests, "series": a["h"] if a else [],
                      "bytes": int(nbytes.get(node) or 0)})
    # 汇总:有流量的节点按流量加权(常年不用的坏节点不拉低/拉高整体),没有流量数据时退回简单平均
    wn = [r for r in nodes if r["avg"] is not None and r["bytes"] > 0]
    if wn:
        wsum = sum(r["bytes"] for r in wn)
        summ = {"basis": "流量加权", "avg": round(sum(r["avg"] * r["bytes"] for r in wn) / wsum),
                "jitter": round(sum((r["jitter"] or 0) * r["bytes"] for r in wn) / wsum)}
    else:
        an = [r for r in nodes if r["avg"] is not None]
        summ = {"basis": "简单平均", "avg": round(sum(r["avg"] for r in an) / len(an)) if an else None,
                "jitter": round(sum((r["jitter"] or 0) for r in an) / len(an)) if an else None}
    allt = sum(r["tests"] for r in nodes)
    summ["fail_rate"] = round(sum(round((r["fail_rate"] or 0) * r["tests"]) for r in nodes) / allt, 4) if allt else None
    nodes.sort(key=lambda r: (r["avg"] is None, r["avg"] or 0))
    hourly = []
    for h in labels:
        o, r, rs = tcp.get(h, (0, 0, 0))
        hourly.append({"hour": h, "out": o, "retrans": r, "resets": rs, "rate": round(r / o * 100, 3) if o else None})
    tot_o, tot_r = sum(x["out"] for x in hourly), sum(x["retrans"] for x in hourly)
    w = [r for r in list(netstat.SERIES) if r[0] >= now - 60]
    wo, wr = sum(r[1] for r in w), sum(r[2] for r in w)
    return 200, {"hours": n, "nodes": nodes[:400], "summary": summ, "tcp": {"ok": netstat.STATE["ok"], "hourly": hourly,
                 "avg_rate": round(tot_r / tot_o * 100, 3) if tot_o else None,
                 "now": {"rate": round(wr / wo * 100, 3) if wo else None, "out": wo, "retrans": wr}},
                 "test_note": "" if per else "还没有延迟测试记录(需要 nikki 里的策略组开启 url-test / 自动测速)"}


STACK_BY = ("client", "node", "mode", "app", "cat", "proto")


def q_stack(p):
    """按小时的堆叠面积图数据。by=client/node/mode/app/cat/proto。"""
    by = one(p, "by", "client")
    if by not in STACK_BY:
        return 400, {"error": "by 不对"}
    try:
        n = max(2, min(14 * 24, int(one(p, "hours", "24"))))
    except ValueError:
        n = 24
    now = time.time()
    labels = [time.strftime("%Y-%m-%d %H", time.localtime(now - i * 3600)) for i in range(n - 1, -1, -1)]
    idx = {h: i for i, h in enumerate(labels)}
    con = ro()
    try:
        if by in ("client", "node", "mode"):
            fw, fa = filters(p, H_COLS)
            where = " AND ".join(["hour >= ?", "hour <= ?"] + fw)
            expr = DEVX if by == "client" else "node"
            rows = con.execute(f"SELECT hour, {expr}, SUM(up)+SUM(down) FROM hourly WHERE {where} GROUP BY 1, 2", [labels[0], labels[-1]] + fa).fetchall()
        else:
            fw, fa = filters(p, {"dev"})
            where = " AND ".join(["hour >= ?", "hour <= ?"] + fw)
            col, tbl = {"app": ("app", "app_hourly"), "cat": ("cat", "app_hourly"), "proto": ("proto", "proto_hourly")}[by]
            rows = con.execute(f"SELECT hour, {col}, SUM(up)+SUM(down) FROM {tbl} WHERE {where} GROUP BY 1, 2", [labels[0], labels[-1]] + fa).fetchall()
        macips = devices.ips_by_dev(con) if by == "client" else {}
        stored = devices.stored_names(con) if by == "client" else {}
    finally:
        con.close()
    if by == "mode":
        dn, rj = kind_names()
        nm = {"direct": "直连", "reject": "拒绝", "proxy": "代理"}
        rows = [(h, nm[node_kind(k, dn, rj)], b) for h, k, b in rows]
    per, tot = {}, {}
    for h, k, b in rows:
        if h not in idx:
            continue
        per.setdefault(k, [0] * n)[idx[h]] += b
        tot[k] = tot.get(k, 0) + b
    keys = sorted(tot, key=lambda k: -tot[k])
    top, rest = keys[:8], keys[8:]
    series = []
    for k in top:
        name = k
        if by == "client":
            ips = macips.get(k, [] if is_mac(k) else [k])
            name = devices.NAMES.label(k, ips, stored) or next((i for i in ips if ":" not in i), "") or k
        series.append({"key": k, "name": name, "values": per[k], "total": tot[k]})
    if rest:
        vals = [sum(per[k][i] for k in rest) for i in range(n)]
        series.append({"key": "", "name": f"其他({len(rest)})", "values": vals, "total": sum(vals), "other": True})
    totals = [sum(s["values"][i] for s in series) for i in range(n)]
    pk = max(range(n), key=lambda i: totals[i]) if any(totals) else 0
    since = None
    return 200, {"by": by, "labels": labels, "series": series, "totals": totals,
                 "peak": {"hour": labels[pk], "bytes": totals[pk], "avg": round(sum(totals) / n)} if any(totals) else None}


def q_modes(p):
    d1, d2 = day_range(p)
    fw, fa = filters(p, T_COLS, skip_mode=True)
    where = " AND ".join(["day >= ?", "day <= ?"] + fw)
    con = ro()
    try:
        d, r = kind_names()
        case = (f"CASE WHEN node IN {_in(d)} THEN 'direct' "
                f"WHEN {('node IN ' + _in(r) + ' OR ') if r else ''}node LIKE 'REJECT%' THEN 'reject' ELSE 'proxy' END")
        rows = con.execute(f"SELECT {case}, SUM(up), SUM(down) FROM traffic WHERE {where} GROUP BY 1",
                           list(d) + list(r) + [d1, d2] + fa).fetchall()
        wan = con.execute("SELECT COALESCE(SUM(up),0), COALESCE(SUM(down),0), COUNT(*) FROM wan WHERE day >= ? AND day <= ?",
                          (d1, d2)).fetchone()
    finally:
        con.close()
    m = {k: {"up": 0, "down": 0} for k in ("proxy", "direct", "reject")}
    for k, u, d in rows:
        m[k] = {"up": u, "down": d}
    return 200, {"from": d1, "to": d2, "modes": m, "wan": {"up": wan[0], "down": wan[1]} if wan[2] else None}


def q_days(p):
    d1, d2 = day_range(p)
    if one(p, "days"):
        try:
            n = max(1, min(180, int(one(p, "days"))))
        except ValueError:
            n = 14
        d2 = time.strftime("%Y-%m-%d")
        d1 = time.strftime("%Y-%m-%d", time.localtime(time.time() - (n - 1) * 86400))
    fw, fa = filters(p, T_COLS)
    where = " AND ".join(["day >= ?", "day <= ?"] + fw)
    con = ro()
    try:
        rows = {d: (u, w) for d, u, w in con.execute(
            f"SELECT day, SUM(up), SUM(down) FROM traffic WHERE {where} GROUP BY day", [d1, d2] + fa)}
    finally:
        con.close()
    out, t = [], time.mktime(time.strptime(d1, "%Y-%m-%d"))
    end = time.mktime(time.strptime(d2, "%Y-%m-%d"))
    while t <= end + 1:
        d = time.strftime("%Y-%m-%d", time.localtime(t))
        u, w = rows.get(d, (0, 0))
        out.append({"day": d, "up": u, "down": w})
        t += 86400
        t = time.mktime(time.strptime(time.strftime("%Y-%m-%d", time.localtime(t + 3600)), "%Y-%m-%d"))
    return 200, {"from": d1, "to": d2, "days": out}


CC_SLD = {"com", "net", "org", "gov", "edu", "ac", "co"}


def reg_domain(h):
    """a.b.example.com -> example.com;com.cn / co.uk 这类按三段算。IP 和单段名不动。"""
    h = (h or "").strip().lower().rstrip(".")
    if not h or "." not in h:
        return h
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass
    parts = h.split(".")
    if len(parts) <= 2:
        return h
    n = 3 if len(parts[-1]) == 2 and parts[-2] in CC_SLD else 2
    return ".".join(parts[-n:])


def q_domains(p):
    """每个域名:总量、去向(直连/代理)、哪些设备访问、最近哪天。可合并子域名。"""
    d1, d2 = day_range(p)
    try:
        limit = max(1, min(2000, int(one(p, "limit", "300"))))
    except ValueError:
        limit = 300
    merge = one(p, "merge", "1") != "0"
    fw, fa = filters(p, T_COLS)
    where = " AND ".join(["day >= ?", "day <= ?"] + fw)
    d, _r = kind_names()
    con = ro()
    try:
        rows = con.execute(
            f"SELECT host, {DEVX} k, SUM(up), SUM(down), COUNT(DISTINCT day), MAX(day), "
            f"SUM(CASE WHEN node IN {_in(d)} THEN up+down ELSE 0 END) "
            f"FROM traffic WHERE {where} GROUP BY host, k LIMIT 200000", list(d) + [d1, d2] + fa).fetchall()
        macips = devices.ips_by_dev(con)
        stored = devices.stored_names(con)
    finally:
        con.close()
    label_cache = {}

    def label(k):
        if k not in label_cache:
            ips = macips.get(k, [] if is_mac(k) else [k])
            label_cache[k] = devices.NAMES.label(k, ips, stored) or next((i for i in ips if ":" not in i), "") or k
        return label_cache[k]

    agg = {}
    for host, k, up, down, days, last, direct in rows:
        key = reg_domain(host) if merge else host
        a = agg.setdefault(key, {"key": key, "up": 0, "down": 0, "direct": 0, "days": 0, "last": "", "devs": {}, "subs": set()})
        a["up"] += up
        a["down"] += down
        a["direct"] += direct
        a["days"] = max(a["days"], days)
        a["last"] = max(a["last"], last or "")
        a["devs"][k] = a["devs"].get(k, 0) + up + down
        if merge and host != key:
            a["subs"].add(host)
    out = []
    for a in sorted(agg.values(), key=lambda a: -(a["up"] + a["down"]))[:limit]:
        top = sorted(a["devs"].items(), key=lambda kv: -kv[1])
        out.append({"key": a["key"], "up": a["up"], "down": a["down"], "direct": a["direct"], "days": a["days"],
                    "last": a["last"], "ndev": len(top), "subs": len(a["subs"]),
                    "devs": [{"key": k, "name": label(k), "bytes": b} for k, b in top[:3]]})
    return 200, {"from": d1, "to": d2, "merge": merge, "count": len(agg), "rows": out}


def q_realtime(p):
    try:
        secs = max(10, min(600, int(one(p, "seconds", "120"))))
    except ValueError:
        secs = 120
    now = time.time()
    rows = [r for r in list(realtime.SAMPLES) if r[0] >= now - secs]
    lv = live()
    con = ro()
    try:
        stored = devices.stored_names(con)
        macips = devices.ips_by_dev(con)
    finally:
        con.close()

    def rate(v):
        return v["up_rate"] + v["down_rate"]
    want = {x for x in one(p, "dev", "").split(",") if x}
    devs = []
    for k, v in sorted(lv["clients"].items(), key=lambda kv: -rate(kv[1])):
        if k not in want and (rate(v) <= 0 or len(devs) >= 60):
            continue
        ips = macips.get(k, [] if is_mac(k) else [k])
        name = devices.NAMES.label(k, ips, stored) or next((i for i in ips if ":" not in i), "") or k
        devs.append({"key": k, "name": name, **v})
    dn, rj = kind_names()
    merged = {}
    for k, v in lv["nodes"].items():
        key = "直连" if k in dn else ("拒绝" if k in rj else k)
        a = merged.setdefault(key, {"conns": 0, "up_rate": 0.0, "down_rate": 0.0})
        a["conns"] += v["conns"]
        a["up_rate"] += v["up_rate"]
        a["down_rate"] += v["down_rate"]
    nodes = [{"node": k, **v} for k, v in sorted(merged.items(), key=lambda kv: -rate(kv[1])) if rate(v) > 0][:60]
    mrows = [r for r in list(realtime.MEM) if r[0] >= now - secs]
    ml = mrows[-1] if mrows else None
    mem = {"mihomo": ml[1] if ml else 0, "used": ml[2] if ml else 0, "total": ml[3] if ml else 0,
           "series": [[round(r[0], 1), r[1], r[2]] for r in mrows]}
    hosts = [{"host": k, **v} for k, v in sorted(lv.get("hosts", {}).items(), key=lambda kv: -rate(kv[1])) if rate(v) > 0][:60]
    last = rows[-1] if rows else None
    L = lambda i: round(last[i]) if last else 0
    return 200, {
        "ok": realtime.STATE["ok"], "error": realtime.STATE["error"], "interval": realtime.INTERVAL, "at": lv["at"],
        "direct": {"up": L(1), "down": L(2), "conns": L(6),
                   "series": [[round(r[0], 1), round(r[1]), round(r[2])] for r in rows]},
        "proxy": {"up": L(3), "down": L(4), "conns": L(7),
                  "series": [[round(r[0], 1), round(r[3]), round(r[4])] for r in rows]},
        "conns": {"total": L(5), "direct": L(6), "proxy": L(7),
                  "series": [[round(r[0], 1), r[5]] for r in rows]},
        "devices": devs, "nodes": nodes, "hosts": hosts, "mem": mem}


def q_hours(p):
    try:
        n = max(1, min(14 * 24, int(one(p, "hours", "24"))))
    except ValueError:
        n = 24
    now = time.time()
    labels = [time.strftime("%Y-%m-%d %H", time.localtime(now - i * 3600)) for i in range(n - 1, -1, -1)]
    fw, fa = filters(p, H_COLS)
    where = " AND ".join(["hour >= ?", "hour <= ?"] + fw)
    con = ro()
    try:
        rows = {h: (u, d) for h, u, d in con.execute(
            f"SELECT hour, SUM(up), SUM(down) FROM hourly WHERE {where} GROUP BY hour", [labels[0], labels[-1]] + fa)}
    finally:
        con.close()
    return 200, {"hours": [{"hour": h, "up": rows.get(h, (0, 0))[0], "down": rows.get(h, (0, 0))[1]} for h in labels]}


def q_devices(p):
    """筛选用的设备清单:近 KEEP_DAYS 天内有流量的设备,按流量降序。"""
    d2 = time.strftime("%Y-%m-%d")
    d1 = time.strftime("%Y-%m-%d", time.localtime(time.time() - 30 * 86400))
    con = ro()
    try:
        rows = con.execute(f"SELECT {DEVX} k, SUM(up)+SUM(down) FROM traffic WHERE day >= ? AND day <= ? AND client != '' "
                           "GROUP BY k ORDER BY 2 DESC LIMIT 200", (d1, d2)).fetchall()
        macips = devices.ips_by_dev(con)
        stored = devices.stored_names(con)
    finally:
        con.close()
    out = []
    for k, total in rows:
        ips = macips.get(k, [] if is_mac(k) else [k])
        out.append({"key": k, "name": devices.NAMES.label(k, ips, stored), "ips": ips[:8]})
    return 200, {"devices": out}


def iter_days(d1, d2):
    import datetime
    a, b = datetime.date.fromisoformat(d1), datetime.date.fromisoformat(d2)
    out = []
    while a <= b and len(out) < 400:
        out.append(a.isoformat())
        a += datetime.timedelta(days=1)
    return out


def q_airports(p):
    """每个机场的流量(按节点名归类)。直连/拒绝不算机场,单独给个合计。"""
    d1, d2 = day_range(p)
    fw, fa = filters(p, T_COLS, skip_mode=True, skip_airport=True)
    where = " AND ".join(["day >= ?", "day <= ?"] + fw)
    con = ro()
    try:
        rows = con.execute(f"SELECT node, day, SUM(up), SUM(down) FROM traffic WHERE {where} GROUP BY node, day",
                           [d1, d2] + fa).fetchall()
    finally:
        con.close()
    days = iter_days(d1, d2)
    d, r = kind_names()
    ag, special = {}, {}
    for node, day, up, down in rows:
        name = airports.of(node, node_kind(node, d, r))
        if name in airports.SPECIAL:
            s = special.setdefault(name, {"up": 0, "down": 0})
            s["up"] += up
            s["down"] += down
            continue
        a = ag.setdefault(name, {"key": name, "up": 0, "down": 0, "nodes": {}, "by_day": {}})
        a["up"] += up
        a["down"] += down
        a["nodes"][node] = a["nodes"].get(node, 0) + up + down
        a["by_day"][day] = a["by_day"].get(day, 0) + up + down
    out = []
    for a in sorted(ag.values(), key=lambda x: -(x["up"] + x["down"])):
        out.append({"key": a["key"], "up": a["up"], "down": a["down"], "nodes": len(a["nodes"]),
                    "top": [{"node": n, "bytes": b} for n, b in sorted(a["nodes"].items(), key=lambda x: -x[1])[:3]],
                    "series": [a["by_day"].get(x, 0) for x in days[-62:]] if len(days) > 1 else []})
    tot = {"up": sum(x["up"] for x in out), "down": sum(x["down"] for x in out)}
    return 200, {"from": d1, "to": d2, "rows": out, "total": tot, "special": special,
                 "rules": airports.rules_text(), "names": airport_names()}


def _nikki_ui():
    con = ro()
    try:
        return backup.nikki_ui(con)
    except Exception:
        return {"host": "", "port": "", "path": ""}
    finally:
        con.close()


def q_status(p):
    c = collector.COLLECTOR
    cf = config.get()
    return 200, {
        "version": config.VERSION, "update": update.check(), "nikki_ui": _nikki_ui(),
        "conn": dict(c.status) if c else {"ok": False, "error": "采集器未启动"},
        "config": {"api": cf["api"], "has_secret": bool(cf["secret"]), "source": cf["source"]},
        "interval": config.INTERVAL, "keep_days": config.KEEP_DAYS, "hour_keep_days": config.HOUR_KEEP_DAYS,
        "now": int(time.time()), "live_at": live()["at"],
        "auth": {"enabled": auth.enabled(), "env": auth.is_env(), "role": getattr(_ctx, "role", "a"), "viewer": auth.has_viewer(), "perms": auth.perms(), "viewer_env": auth.viewer_is_env(), "allow_nets": bool(os.environ.get("ALLOW_NETS"))}, "alerts_unread": _wcon_ro(alerts.unread),
        "wan": bool(collector.WAN_IFACES), "airports": airport_names(),
        "docker": bool(_wcon_ro(lambda con: dockerapi.load_cfg(con)["on"])),
    }


def _wcon_ro(fn):
    con = ro()
    try:
        return fn(con)
    except Exception:
        return 0
    finally:
        con.close()


def q_live(p):
    return 200, live()


def q_alerts(p):
    con = ro()
    try:
        try:
            lim = int(one(p, "limit", "50"))
            before = int(one(p, "before", "0"))
        except ValueError:
            lim, before = 50, 0
        rows = alerts.list_events(con, one(p, "kind"), lim, before)
        cutoff = time.time() - 86400
        return 200, {"rows": rows, "unread": alerts.unread(con), "seen": alerts.seen_ts(con), "counts": alerts.counts(con, cutoff),
                     "kinds": alerts.KINDS, "has_channel": any(c.get("on", True) for c in alerts.load_cfg(con)["channels"])}
    finally:
        con.close()


def q_alert_cfg(p):
    con = ro()
    try:
        return 200, alerts.public_cfg(con)
    finally:
        con.close()


def q_alert_base(p):
    con = ro()
    try:
        return 200, {"rows": alerts.baseline_table(con)}
    finally:
        con.close()


def _wcon(fn):
    con = db.open_db()
    try:
        return fn(con)
    finally:
        con.close()


def p_alert_cfg(body):
    _wcon(lambda con: alerts.save_cfg(con, body))
    return _wcon(alerts.public_cfg)


def p_alert_test(body):
    return _wcon(lambda con: alerts.test_channel(con, body))


def p_alert_seen(body):
    _wcon(alerts.mark_seen)
    return {"ok": True}


def p_alert_clear(body):
    def f(con):
        with con:
            con.execute("DELETE FROM alerts")
    _wcon(f)
    return {"ok": True}


def q_apprules(p):
    return 200, {"rules": appsig.rules_text(), "cats": appsig.CATS}


def _app_hosts(con, p, want, limit):
    """按域名重新归类 traffic 表里的流量,取出归到 want(应用名)的域名明细(含设备、节点)。
    app 表本身不存域名;这里只按域名判断(不带端口),端口才能识别出来的应用不会出现在「未识别」里。"""
    d1, d2 = day_range(p)
    fw, fa = filters(p, {"dev", "node"})
    where = " AND ".join(["day >= ?", "day <= ?", "host != ''"] + fw)
    rows = con.execute(f"SELECT host, SUM(up), SUM(down), COUNT(DISTINCT {DEVX}), GROUP_CONCAT(DISTINCT node) FROM traffic WHERE {where} GROUP BY host", [d1, d2] + fa).fetchall()
    out = []
    for host, u, d, nd, nodes in rows:
        app, cat = appsig.classify(host)
        if app == want:
            out.append({"host": host, "up": u, "down": d, "bytes": (u or 0) + (d or 0), "devices": nd, "nodes": (nodes or "").split(",")[:4], "cat": cat})
    out.sort(key=lambda x: -x["bytes"])
    return out[:limit], len(out), sum(x["bytes"] for x in out)


def q_apphosts(p):
    """某个应用(可限定设备 / 节点)下面有哪些域名。"""
    want = one(p, "app")
    if not want:
        return 400, {"error": "缺少 app"}
    con = ro()
    try:
        rows, n, tot = _app_hosts(con, p, want, _limit(p))
    finally:
        con.close()
    return 200, {"app": want, "rows": rows, "count": n, "bytes": tot}


def q_appunknown(p):
    """导出「未识别」的域名明细,附一段可以直接发给 AI 的说明,让它按 域名关键字=应用名|类别 给出可导入的文本。"""
    con = ro()
    try:
        rows, n, tot = _app_hosts(con, p, appsig.UNKNOWN[0], 300)
    finally:
        con.close()
    d1, d2 = day_range(p)
    cats = "、".join(c for c in appsig.CATS if c not in ("局域网",))
    head = ("下面是家用路由器(nikki / mihomo)流量统计里「未识别」的访问域名,按流量从大到小排列(数据来自 FLUX 面板,已不含设备名和 IP)。\n"
            "请把能确定归属的域名归到「应用名 + 类别」,输出可以直接导入 FLUX「设置 → 应用特征库」的纯文本,每行一条:\n"
            "域名关键字=应用名|类别\n"
            "要求:\n"
            "1. 域名关键字写主域名(例如 example.com 会匹配它的所有子域名);同一个应用的多个域名各写一行,应用名保持一致。\n"
            f"2. 类别只能从这些里选:{cats}。选不准就写「其他」。\n"
            "3. 不确定的域名直接跳过,不要猜测、不要编造。\n"
            "4. 只输出规则本身:不要序号、不要解释、不要代码块标记、不要表头。\n"
            f"\n范围:{d1} ~ {d2};共 {n} 个未识别域名(下面列出流量最大的 {len(rows)} 个),合计 {tot} 字节。\n"
            "清单格式:域名<TAB>流量字节<TAB>访问它的设备数\n")
    body = "\n".join(f"{r['host']}\t{r['bytes']}\t{r['devices']}" for r in rows)
    return 200, {"rows": rows, "count": n, "bytes": tot, "text": head.replace("\\n", "\n") + body, "cats": appsig.CATS}


def p_apprules(body):
    con = db.open_db()
    try:
        n = appsig.save(con, str(body.get("text") or ""))
    finally:
        con.close()
    return {"ok": True, "rules": n, "text": appsig.rules_text(), "dedup": dict(appsig.DEDUP)}


def _days_p(p, d=7, mx=90):
    try:
        return max(1, min(mx, int(one(p, "days", str(d)))))
    except ValueError:
        return d


def _q(fn):
    def h(p):
        con = ro()
        try:
            return 200, fn(con, p)
        finally:
            con.close()
    return h


def q_lookup(p):
    con = ro()
    try:
        return 200, lookup.lookup(con, one(p, "host"))
    except ValueError as e:
        return 400, {"error": str(e)}
    finally:
        con.close()


def q_dns(con, p):
    names = agh._ip_names(con)
    sv = dnsx.servers_status(con)
    return {"dnsmasq": dnsx.dnsmasq_stats(con, names), **sv, "syslog_on": syslog.load_cfg(con)["on"]}


q_agh = _q(lambda con, p: agh.fetch(con, force=one(p, "force") == "1"))
q_agh_cfg = _q(lambda con, p: agh.public_cfg(con))
q_rulehealth = _q(lambda con, p: insight.rule_health(con, _days_p(p, 30)))
def _until_day(p):
    try:
        u = float(one(p, "until", "") or 0)
    except ValueError:
        u = 0
    return time.strftime("%Y-%m-%d", time.localtime(u)) if u else None


def _until_ts(p):
    try:
        return float(one(p, "until", "") or 0) or None
    except ValueError:
        return None


q_leaks = _q(lambda con, p: insight.leaks(con, _days_p(p, 7), _until_day(p)))
q_heatmap = _q(lambda con, p: insight.heatmap(con, csv(p, "dev"), _days_p(p, 14, config.HOUR_KEEP_DAYS), one(p, "stat", "avg"), one(p, "day") or None, one(p, "split", "week")))
q_panel = _q(lambda con, p: {"clients": panellog.clients(con), "log": panellog.tail(int(one(p, "n") or 400))})
q_probe = _q(lambda con, p: probe.status(con))
q_presence = _q(lambda con, p: presence.status(con))
q_selfcheck = _q(lambda con, p: {"findings": diag.selfcheck(con)})
q_diag = _q(lambda con, p: diag.bundle(con, full=one(p, "full") == "1", logs=one(p, "logs") == "1", dom=one(p, "dom") == "1"))
q_providers = _q(lambda con, p: providers.status(con))
q_quota = _q(lambda con, p: {"rows": insight.quota_status(con), "cfg": insight.quota_cfg(con), "airports": airport_names()})
q_report = _q(lambda con, p: dict(insight.report(con, _days_p(p, 7)), cfg=insight.report_cfg(con)))
q_report_cfg = _q(lambda con, p: insight.report_cfg(con))
q_quality = _q(lambda con, p: insight.quality(con))
q_geo = _q(lambda con, p: insight.geo_summary(con, _days_p(p, 7), _until_day(p)))
def q_devmerge(p):
    con = ro()
    try:
        macips, stored = devices.ips_by_dev(con), devices.stored_names(con)
        groups = devices.merged_groups(con)
    finally:
        con.close()
    raw = {}
    con = ro()
    try:
        for ip, mac in con.execute("SELECT ip, mac FROM ipmap ORDER BY seen DESC"):
            raw.setdefault(mac, []).append(ip)
    finally:
        con.close()
    out = {}
    for main, al in groups.items():
        out[main] = [{"key": a, "name": devices.NAMES.label(a, raw.get(a, [] if is_mac(a) else [a]), stored), "ips": (raw.get(a) or ([] if is_mac(a) else [a]))[:6]} for a in al]
    return 200, {"groups": out}


def p_devmerge(body):
    con = db.open_db()
    try:
        devices.set_merge(con, body.get("main"), body.get("alias"), bool(body.get("on", True)))
    finally:
        con.close()
    return {"ok": True}


q_nodegeo = _q(lambda con, p: nodegeo.api(con))


def p_nodegeo_ignore(body):
    node = str(body.get("node") or "")[:120]
    if not node:
        return {"ok": False, "error": "缺少节点名"}
    lst = _wcon(lambda con: nodegeo.set_ignore(con, node, bool(body.get("on", True))))
    return {"ok": True, "ignored": lst}


def p_agh_cfg(body):
    return _wcon(lambda con: agh.save_cfg(con, body))


def p_agh_test(body):
    return _wcon(lambda con: agh.test(con, body))


def p_geo_proxy(body):
    geo.proxy_set(str(body.get("proxy") or ""))
    return geo.status()


def p_geo_dl(body):
    return {"started": geo.start_download(), "status": geo.status()}


def p_quota(body):
    _wcon(lambda con: insight.save_quota(con, body))
    return _wcon(lambda con: {"rows": insight.quota_status(con), "cfg": insight.quota_cfg(con)})


def p_report_cfg(body):
    return _wcon(lambda con: insight.save_report_cfg(con, body))


def p_group_set(body):
    _wcon(lambda con: groups.set_group(con, body.get("dev"), body.get("group")))
    return {"ok": True}


def p_group_policy(body):
    return _wcon(lambda con: groups.save_policy(con, body.get("group"), body.get("on"), body.get("allow")))


AUDIT = {"/api/alerts/config": "修改告警规则 / 推送渠道", "/api/agh/config": "修改 AdGuard 连接", "/api/quota": "修改订阅额度",
         "/api/report/config": "修改周报设置", "/api/apps/rules": "修改应用特征库规则", "/api/airports/rules": "修改订阅归类规则",
         "/api/groups/policy": "修改分组白名单", "/api/restore": "从备份恢复设置", "/api/config": "修改 nikki 连接",
         "/api/geo/proxy": "修改 GeoIP 下载代理", "/api/retention": "修改数据保留天数", "/api/probe": "修改节点探测设置"}


def _audit(path, body):
    t = AUDIT.get(path)
    if not t:
        return
    detail = ""
    if path == "/api/groups/policy":
        detail = f"分组 {str(body.get('group') or '')[:20]}"
    elif path == "/api/devmerge":
        detail = f"{'合并' if body.get('on', True) else '拆分'}:{str(body.get('alias') or '')[:40]} → {str(body.get('main') or '')[:40]}(只改归并显示,原始记录不动)"
    elif path == "/api/nodegeo/ignore":
        detail = f"{'忽略' if body.get('on', True) else '恢复提示'}节点 {str(body.get('node') or '')[:40]}(节点服务器登记地与节点名地区不符的安全提示;登记在中国大陆的属重点关注)"
    try:
        _wcon(lambda con: alerts.note(con, "audit", path, t, detail))
    except Exception:
        pass


def p_ui(body):
    return _wcon(lambda con: backup.set_ui(con, body.get("theme")))


def p_restore(body):
    def f(con):
        r = backup.restore(con, body.get("backup"))
        _nodes_cache["at"] = 0.0
        return r
    return _wcon(f)


def _backup_resp(secrets):
    con = ro()
    try:
        return 200, backup.export(con, secrets)
    finally:
        con.close()


def p_report_send(body):
    _wcon(lambda con: insight.send_report(con, 7))
    return {"ok": True}


q_secsum = _q(lambda con, p: insight.secsum(con, force=one(p, "force") == "1"))
q_geo_status = lambda p: (200, geo.status())
q_ui = _q(lambda con, p: backup.get_ui(con))
q_backup = lambda p: _backup_resp(one(p, "secrets") == "1")
q_groups = _q(lambda con, p: {"groups": groups.dev_groups(con), "names": groups.names(con), "policy": groups.policy(con)})
q_group_learn = _q(lambda con, p: {"rows": groups.learn(con, one(p, "group", ""))})
q_nodescore = _q(lambda con, p: {"rows": advisor.node_scores(con)})
def q_sys(p):
    con = ro()
    try:
        src = sysinfo.temp_src(con)
    finally:
        con.close()
    s = sysinfo.snapshot(max(10, min(600, int(one(p, "seconds", "120") or 120))), src)
    s["wan"] = wan.snapshot()
    u = ups.STATE
    s["ups"] = {"ok": u["ok"], "info": u["info"], "onbatt_since": u["onbatt_since"]} if u["ok"] is not None else None
    return 200, s


q_wan = _q(lambda con, p: {**wan.snapshot(), "hours": wan.hours(con, 24)})


GET_ROUTES = {"/api/nodescore": q_nodescore, "/api/groups": q_groups, "/api/groups/learn": q_group_learn, "/api/ui": q_ui, "/api/backup": q_backup, "/api/sys": q_sys, "/api/secsum": q_secsum, "/api/geo/status": q_geo_status, "/api/agh": q_agh, "/api/agh/config": q_agh_cfg, "/api/rulehealth": q_rulehealth, "/api/leaks": q_leaks, "/api/heatmap": q_heatmap,
              "/api/quota": q_quota, "/api/report": q_report, "/api/report/config": q_report_cfg, "/api/quality": q_quality, "/api/geo": q_geo, "/api/nodegeo": q_nodegeo, "/api/devmerge": q_devmerge,
              "/api/status": q_status, "/api/summary": q_summary, "/api/modes": q_modes, "/api/days": q_days,
              "/api/hours": q_hours, "/api/domains": q_domains, "/api/trace": q_trace, "/api/protocols": q_protocols, "/api/apps": q_apps, "/api/tunnels": q_tunnels, "/api/qoe": q_qoe, "/api/stack": q_stack, "/api/apprules": q_apprules, "/api/apps/hosts": q_apphosts, "/api/syslog/groups": _q(lambda con, p: syslog.groups(con, int(one(p, "level", "3") or 3), int(one(p, "hours", "24") or 24), one(p, "q"))), "/api/apps/unknown": q_appunknown, "/api/providers": q_providers, "/api/panel": q_panel, "/api/presence": q_presence, "/api/wan": q_wan, "/api/selfcheck": q_selfcheck, "/api/diag": q_diag, "/api/probe": q_probe, "/api/alerts": q_alerts, "/api/alerts/config": q_alert_cfg, "/api/alerts/baseline": q_alert_base, "/api/airports": q_airports, "/api/realtime": q_realtime, "/api/devices": q_devices, "/api/devices/new": _q(lambda con, p: {"days": int(one(p, "days", "14") or 14), "rows": devices.new_devices(con, int(one(p, "days", "14") or 14))}), "/api/live": q_live}


# ---------------------------------------------------------------- POST
def p_retention(body):
    r = config.set_retention(body.get("hour_days"), body.get("days"))
    log(f"保留天数已修改:小时数据 {r['hour_days']} 天,按天明细 {r['days']} 天")
    return {"ok": True, **r}


def p_config(body):
    import urllib.error
    api = config.normalize_api(str(body.get("api") or ""))
    if not api:
        raise ValueError("地址不能为空")
    secret = body.get("secret")
    secret = None if secret is None else str(secret)
    if body.get("clear_secret"):
        secret = ""
    test = {"api": api, "secret": config.get()["secret"] if secret is None else secret}
    try:
        v = api_call("/version", timeout=5, conf=test)
    except urllib.error.HTTPError as e:
        raise ValueError("密码不对(401)" if e.code == 401 else f"接口返回 {e.code}")
    except Exception as e:
        raise ValueError(f"连不上 {api}:{e}")
    if body.get("test_only"):
        return {"ok": True, "version": (v or {}).get("version", ""), "test_only": True}
    st = config.save(api, secret)
    log(f"连接设置已更新:{st['api']}")
    return {"ok": True, "version": (v or {}).get("version", "")}


def _purge_nodes(con, body):
    r = nodepurge.purge(con, body.get("nodes") if isinstance(body.get("nodes"), list) else None, bool(body.get("history")), airport_of)
    _nodes_cache["at"] = 0
    return r


def p_listen(body):
    if body.get("cancel"):
        return listen.cancel()
    r = listen.change(body.get("host"), body.get("port"), reset=bool(body.get("reset")))
    return r


def p_listen_confirm(body):
    return listen.confirm(getattr(_ctx, "server", None))


def p_airport_rules(body):
    con = db.open_db()
    try:
        n = airports.save(con, str(body.get("text") or ""))
    finally:
        con.close()
    _nodes_cache["at"] = 0.0
    return {"ok": True, "rules": n}


def p_device(body):
    con = db.open_db()
    try:
        devices.rename(con, body.get("dev"), body.get("name"))
    finally:
        con.close()
    return {"ok": True}


def p_import(body):
    con = db.open_db()
    try:
        r = devices.import_uci(con, str(body.get("text") or ""))
    finally:
        con.close()
    if not r["hosts"]:
        raise ValueError("没找到 host 段。请粘贴 `uci show dhcp` 的输出或 /etc/config/dhcp 的内容")
    return dict(r, ok=True)


def p_update(body):
    return update.check(force=True)


POST_ROUTES = {"/api/devmerge": p_devmerge, "/api/nodegeo/ignore": p_nodegeo_ignore, "/api/clienterr": lambda body: panellog.add_client_error(body.get("msg"), body.get("src"), body.get("ua")) or {"ok": True}, "/api/presence/watch": lambda body: _wcon(lambda con: presence.set_watch(con, body.get("key"), bool(body.get("on")))), "/api/probe": lambda body: _wcon(lambda con: probe.save_cfg(con, body)), "/api/groups/set": p_group_set, "/api/groups/policy": p_group_policy, "/api/ui": p_ui, "/api/restore": p_restore, "/api/geo/proxy": p_geo_proxy, "/api/retention": p_retention, "/api/agh/config": p_agh_cfg, "/api/agh/test": p_agh_test, "/api/geo/download": p_geo_dl, "/api/quota": p_quota, "/api/report/config": p_report_cfg, "/api/report/send": p_report_send, "/api/alerts/config": p_alert_cfg, "/api/alerts/test": p_alert_test, "/api/alerts/seen": p_alert_seen, "/api/alerts/clear": p_alert_clear, "/api/apps/rules": p_apprules, "/api/config": p_config, "/api/device": p_device, "/api/airports/rules": p_airport_rules,
               "/api/devices/import": p_import, "/api/update/check": p_update}


q_syslog = _q(lambda con, p: dict(syslog.status(con), rows_data=syslog.query(
    con, int(one(p, "level", "7") or 7), one(p, "q"), int(one(p, "n", "200") or 200), int(one(p, "before", "0") or 0))))
q_ups = _q(lambda con, p: ups.status(con))
q_docker = _q(lambda con, p: dockerapi.snapshot(con, force=one(p, "force") == "1"))
q_docker_cfg = _q(lambda con, p: {"cfg": dockerapi.load_cfg(con), "password": dockerapi.control_ok()})
q_docker_logs = _q(lambda con, p: dockerapi.logs(con, one(p, "id"), int(one(p, "tail", "200") or 200)))


def p_docker_act(body):
    return _wcon(lambda con: dockerapi.act(con, str(body.get("id") or ""), str(body.get("action") or ""), getattr(_ctx, "ip", "")))

q_expiry = _q(lambda con, p: expiry.status(con))
GET_ROUTES.update({"/api/nklog": _q(lambda con, p: dict(nikkilog.status(con), rows_data=nikkilog.query(con, one(p, "src"), int(one(p, "level", "7") or 7), one(p, "q"), int(one(p, "n", "200") or 200), int(one(p, "before", "0") or 0)))), "/api/dns": _q(q_dns), "/api/dns/cfg": _q(lambda con, p: dnsx.load_cfg(con)), "/api/wallpaper": lambda p=None: (200, wallpaper.status()), "/api/nodes/stale": _q(lambda con, p: nodepurge.stale(con, airport_of)), "/api/listen": lambda p=None: (200, listen.status()), "/api/docker": q_docker, "/api/docker/cfg": q_docker_cfg, "/api/docker/logs": q_docker_logs, "/api/syslog": q_syslog, "/api/ups": q_ups, "/api/expiry": q_expiry})
def p_wallpaper(body):
    if body.get("remove"):
        wallpaper.remove()
        wallpaper.save_cfg({"source": "upload"})
    else:
        wallpaper.save(body.get("data"))
        wallpaper.save_cfg({"source": "upload"})      # 手动上传 = 不再自动更换
    return {"ok": True, **wallpaper.status()}


def q_sessions(con, p):
    rows = []
    for x in auth.list_sessions(getattr(_ctx, "sid", "")):
        rows.append({"id": x["id"], "role": x["role"], "ip": x["ip"], "name": panellog._label(con, x["ip"]) if x["ip"] else "", "ua": panellog.short_ua(x["ua"]),
                     "created": x["created"], "last": x["last"], "current": x["current"]})
    return {"rows": rows, "note": "升级到 v0.28.2 之前登录的设备不在这个列表里(它们没有会话号);用「退出所有设备」可以一并清掉。"}


GET_ROUTES.update({"/api/lookup": q_lookup, "/api/compare": _q(lambda con, p: analysis.compare(con, one(p, "days", "7"), one(p, "cur_end"), one(p, "prev_end"))), "/api/timeline": _q(lambda con, p: analysis.timeline(con, int(one(p, "hours", "48") or 48), _until_ts(p))), "/api/wifi": _q(lambda con, p: analysis.wifi(con, int(one(p, "hours", "24") or 24), _until_ts(p))), "/api/auth/sessions": _q(q_sessions), "/api/health": _q(lambda con, p: {"checks": health.checks(con), "backups": health.listing()}), "/api/storage": _q(lambda con, p: health.storage(con))})
POST_ROUTES.update({"/api/nikkiui": lambda body: _wcon(lambda con: backup.set_nikki_ui(con, body)), "/api/lookup/probe": lambda body: lookup.probe(body), "/api/lookup/test": lambda body: lookup.live_test(body),
    "/api/storage/clean": lambda body: health.clean(body),
    "/api/nklog/cfg": lambda body: _wcon(lambda con: nikkilog.save_cfg(con, body)),
    "/api/nklog/clear": lambda body: _wcon(lambda con: nikkilog.clear(con)),
    "/api/dns/cfg": lambda body: _wcon(lambda con: dnsx.save_cfg(con, body)),
    "/api/dns/test": lambda body: dnsx.test(body),
    "/api/wallpaper": p_wallpaper,
    "/api/wallpaper/cfg": lambda body: (wallpaper.save_cfg(body), {"ok": True, **wallpaper.status()})[1],
    "/api/wallpaper/refresh": lambda body: {"ok": True, **wallpaper.refresh()},
    "/api/sys/temp": lambda body: _wcon(lambda con: {"ok": True, "src": sysinfo.save_temp_src(con, body.get("src"))}),
    "/api/nodes/purge": lambda body: _wcon(lambda con: _purge_nodes(con, body)),
    "/api/listen": p_listen, "/api/listen/confirm": p_listen_confirm,
    "/api/docker/cfg": lambda body: _wcon(lambda con: {"cfg": dockerapi.save_cfg(con, body)}),
    "/api/docker/test": lambda body: dockerapi.test(body),
    "/api/docker/act": p_docker_act,
    "/api/syslog/cfg": lambda body: _wcon(lambda con: (lambda c: {"cfg": c, "purged": syslog.purge_ignored(con, c)})(syslog.save_cfg(con, body))),
    "/api/syslog/clear": lambda body: _wcon(lambda con: syslog.clear(con)),
    "/api/ups": lambda body: _wcon(lambda con: {"cfg": ups.save_cfg(con, body)}),
    "/api/ups/test": lambda body: _wcon(lambda con: ups.test(con, body)),
    "/api/expiry": lambda body: _wcon(lambda con: {"cfg": expiry.save_cfg(con, body)}),
    "/api/expiry/check": lambda body: {"ok": True, "started": expiry.refresh_async(force=True)},
})
AUDIT.update({"/api/nikkiui": "修改 nikki 面板链接地址", "/api/storage/clean": "清理 / 压缩数据库", "/api/nklog/cfg": "修改 nikki 日志设置", "/api/nklog/clear": "清空 nikki 日志", "/api/dns/cfg": "修改自定义 DNS 服务器", "/api/wallpaper": "修改登录页壁纸", "/api/wallpaper/cfg": "修改壁纸自动更换设置", "/api/wallpaper/refresh": "立即更换登录页壁纸", "/api/sys/temp": "修改主温度传感器", "/api/nodes/purge": "清理已不存在的节点数据", "/api/listen": "修改面板监听地址 / 端口", "/api/listen/confirm": "确认面板新监听地址", "/api/syslog/cfg": "修改系统日志设置", "/api/syslog/clear": "清空系统日志", "/api/ups": "修改 UPS 设置", "/api/expiry": "修改证书/域名到期检查名单", "/api/docker/cfg": "修改容器管理设置", "/api/nodegeo/ignore": "忽略 / 恢复「节点登记地与名称不符」提示", "/api/devmerge": "合并 / 拆分设备(把多个 MAC / IP 并成一台)"})


_ctx = threading.local()


# ---------------------------------------------------------------- HTTP
_GZ = {}
# 只允许本站的脚本/样式/图片/请求;页面用了内联脚本和样式所以保留 unsafe-inline,但禁止被别的网页嵌入、禁止提交到外站、禁用 object
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
       "font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
# 只读账号不能读的接口(含敏感配置 / 可能带内网细节的原始数据),以及唯一允许"假装成功"的写接口
VIEWER_DENY_GET = {"/api/backup", "/api/apps/unknown", "/api/diag", "/api/syslog/export", "/api/nklog/export", "/api/docker/logs", "/api/docker/cfg", "/api/agh/config",
                   "/api/alerts/config", "/api/report/config", "/api/dns/cfg", "/api/listen", "/api/storage", "/api/health", "/api/autobackup/get", "/api/auth/sessions"}
VIEWER_DENY_GET |= {"/api/panel", "/api/syslog/groups", "/api/geo/status", "/api/nodes/stale"}   # 面板访问记录 / GeoIP 目录与代理 / 清理建议:管理用,只读账号不需要
# 只读账号能看的接口里夹带的「配置」要在服务端剥掉(前端藏起来不算):只留 on 开关,不给地址 / 目录 / 域名清单 / URL
_VIEWER_CFG_KEEP = {"/api/expiry": (), "/api/probe": ("on",), "/api/ups": ("on",), "/api/nklog": ("on",), "/api/syslog": ("on",), "/api/docker": ("on", "control")}


def _viewer_scrub(path, data):
    if not isinstance(data, dict):
        return data
    if path in _VIEWER_CFG_KEEP and isinstance(data.get("cfg"), dict):
        data = dict(data)
        data["cfg"] = {k: v for k, v in data["cfg"].items() if k in _VIEWER_CFG_KEEP[path]}
        if path == "/api/nklog":
            data.pop("err", None)    # 里面带内核日志文件路径
            data.pop("mode", None)
        if path == "/api/expiry":    # 到期监控的目标(域名 / 证书主机)也是配置
            data["certs"] = [{**{k: v for k, v in r.items() if k != "target"}, "target": "(已隐藏)"} for r in data.get("certs") or []]
            data["domains"] = [{**{k: v for k, v in r.items() if k != "target"}, "target": "(已隐藏)"} for r in data.get("domains") or []]
    if path == "/api/status":
        data = dict(data)
        data["config"] = {"api": "", "has_secret": False, "source": ""}
        data["nikki_ui"] = {"host": "", "port": "", "path": ""}
    return data


VIEWER_POST_OK = {"/api/logout", "/api/clienterr"}
VIEWER_EDIT_POST = {"/api/device", "/api/groups/set", "/api/presence/watch"}   # 管理员给只读账号开了「修改设备别名 / 分组 / 关注」才放行
VIEWER_POST_NOOP = {"/api/ui", "/api/alerts/seen"}     # 外观 / 已读标记:只读账号改了也不写到服务器(否则会覆盖管理员的布局),但不报错


def _gzip(body, key=None):
    """gzip 压缩;带 etag 的(首页)按 etag 缓存压缩结果,不用每次重压 270KB。"""
    if key and key in _GZ:
        return _GZ[key]
    z = gzip.compress(body, 6, mtime=0)
    if key:
        _GZ.clear()
        _GZ[key] = z
    return z


class Handler(BaseHTTPRequestHandler):
    server_version = "flux"

    def log_message(self, *a):
        pass

    def _gz_ok(self):
        return "gzip" in (self.headers.get("Accept-Encoding") or "").lower()

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None, etag=None):
        """文本类响应(JSON / HTML / 文本)超过 1KB 且浏览器接受 gzip 时压缩;etag 给了就支持 If-None-Match → 304。"""
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False).encode()
        extra = dict(extra or {})
        if etag and code == 200:
            inm = self.headers.get("If-None-Match") or ""
            if etag in [x.strip() for x in inm.split(",")]:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Cache-Control", "private, no-cache")
                self.end_headers()
                return
            extra["ETag"] = etag
            extra.setdefault("Cache-Control", "private, no-cache")     # 每次都向服务器确认(要登录),没变就 304
        zipped = False
        if len(body) > 1024 and self._gz_ok() and (ctype.startswith("text/") or "json" in ctype):
            body = _gzip(body, etag)
            zipped = True
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if zipped:
            self.send_header("Content-Encoding", "gzip")
        self.send_header("Vary", "Accept-Encoding, Cookie")
        if "Cache-Control" not in extra:
            self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        if ctype.startswith("text/html"):
            self.send_header("Content-Security-Policy", CSP)
        for k, v in extra.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _cookie(self):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == auth.COOKIE:
                return v
        return ""

    def _who(self):
        """(真实来源 IP, 是否经 https 反代)。只信受信代理给的 X-Forwarded-For。"""
        return auth.client_ip(self.client_address[0], self.headers.get("X-Forwarded-For", ""), self.headers.get("X-Forwarded-Proto", ""))

    def _ip(self):
        return self._who()[0]

    def _ck(self, val, clear=False, remember=True):
        return {"Set-Cookie": auth.cookie_header(val, clear=clear, secure=self._who()[1], remember=remember)}

    def _net_ok(self):
        peer = self.client_address[0]
        return auth.net_allowed(self._ip()) or peer in ("127.0.0.1", "::1")

    def _role(self, params):
        """'a' 管理员 / 'v' 只读 / None 没登录。"""
        tok = config.PAGE_TOKEN
        if not tok and not auth.enabled():
            return "a"
        if tok and (one(params, "t") == tok or self.headers.get("X-Token", "") == tok):
            return "a"
        if not auth.enabled():
            return None
        ck = self._cookie()
        role = auth.cookie_role(ck)
        if role:
            sid = auth.cookie_sid(ck)
            if sid:
                auth.touch(sid, self._ip(), self.headers.get("User-Agent", ""))
        return role

    def _mk(self, role, remember=None):
        """给这次登录发一个新会话 Cookie(记下来源 IP 和浏览器)。remember=None:沿用当前 Cookie 的模式(30 天 / 仅本次)。"""
        if remember is None:
            remember = not auth.cookie_short(self._cookie()) if self._cookie() else True
        return self._ck(auth.make_cookie(role, self._ip(), self.headers.get("User-Agent", ""), remember), remember=remember)

    def _authed(self, params):
        return self._role(params) is not None

    def _deny(self, page=False):
        if auth.enabled() and page:
            return self._send(200, auth.login_html().encode(), "text/html; charset=utf-8")
        if auth.enabled():
            return self._send(401, {"error": "需要登录", "login": True})
        return self._send(401, {"error": "需要 ?t=<token>"})

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(u.query)
        if u.path == "/health":
            return self._send(200, b"ok", "text/plain")
        if not self._net_ok():
            return self._send(403, {"error": "这个地址不在允许访问的网段内"})
        if u.path in ("/logo.png", "/favicon.png", "/favicon.ico", "/apple-touch-icon.png"):
            # logo 不需要口令,方便 sun-panel 等导航页直接拉取
            name = "favicon.png" if u.path in ("/favicon.png", "/favicon.ico") else "logo.png"
            with open(os.path.join(STATIC, name), "rb") as f:
                return self._send(200, f.read(), "image/png", {"Cache-Control": "public, max-age=86400"})
        if u.path == "/wallpaper":          # 登录页要在登录前就能拿到壁纸,所以不需要口令(只会返回壁纸图片本身)
            b, ty, _ = wallpaper.read()
            if not b:
                return self._send(404, {"error": "no wallpaper"})
            return self._send(200, b, ty, {"Cache-Control": "public, max-age=300", "X-Content-Type-Options": "nosniff"})
        if u.path == "/metrics":
            tok = config.METRICS_TOKEN
            given = self.headers.get("Authorization", "")
            given = given[7:] if given.startswith("Bearer ") else one(params, "t")
            if not ((tok and given and hmac.compare_digest(given, tok)) or self._role(params) == "a"):
                return self._deny()
            con = ro()
            try:
                return self._send(200, insight.metrics_text(con).encode(), "text/plain; version=0.0.4; charset=utf-8")
            finally:
                con.close()
        role = self._role(params)
        if role is None:
            return self._deny(page=u.path in ("/", "/index.html"))
        _ctx.role = role
        _ctx.ip = self._ip()
        _ctx.sid = auth.cookie_sid(self._cookie())
        if role == "v" and u.path in VIEWER_DENY_GET:
            return self._send(403, {"error": "只读账号不能查看这个内容"})
        if u.path in ("/", "/index.html"):
            self._seen("page")
            with open(os.path.join(STATIC, "index.html"), "rb") as f:
                html = f.read()
            return self._send(200, html, "text/html; charset=utf-8", etag='"' + hashlib.sha1(html).hexdigest()[:20] + '"')
        if u.path == "/api/favicon":
            link = one(params, "u")
            con = ro()
            try:
                ok = link in favicon.saved_links(con)
            finally:
                con.close()
            res = favicon.get(link) if ok else None
            if not res:
                return self._send(404, {"error": "no icon"}, extra={"Cache-Control": "private, max-age=600"})
            return self._send(200, res[0], res[1], {"Cache-Control": "private, max-age=86400", "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
        if u.path == "/api/syslog/export":
            return self._syslog_export(params)
        if u.path == "/api/nklog/export":
            return self._nklog_export(params)
        if u.path == "/api/autobackup/get":
            try:
                body = health.read_backup(one(params, "name"))
            except (OSError, ValueError):
                return self._send(404, {"error": "没有这个备份"})
            return self._send(200, body, "application/json; charset=utf-8", {"Content-Disposition": f'attachment; filename="{one(params, "name")}"'})
        fn = GET_ROUTES.get(u.path)
        if not fn:
            return self._send(404, {"error": "not found"})
        try:
            code, data = fn(params)
        except Exception as e:
            log("接口出错", u.path, e)
            return self._send(500, {"error": f"{type(e).__name__}: {e}"})
        if role == "v":
            data = _viewer_scrub(u.path, data)
        self._send(code, data)

    def _syslog_export(self, params):
        """把当前筛选条件下的路由器日志导出成纯文本(最多 5000 条);默认把 IP / MAC / 设备别名打码,方便发给别人看。"""
        con = ro()
        try:
            rows = syslog.query(con, int(one(params, "level", "7") or 7), one(params, "q"), min(5000, int(one(params, "n", "1000") or 1000)))
            names = [] if one(params, "mask") == "0" else diag._names(con)
        finally:
            con.close()
        mk = (lambda t: t) if one(params, "mask") == "0" else (lambda t: diag.mask_text(t, names))
        lines = [f"{time.strftime('%F %T', time.localtime(r['ts']))} [{r['lv']}] {mk(r['tag'])}: {mk(r['msg'])}" for r in reversed(rows)]
        body = ("\n".join(lines) + "\n").encode("utf-8")
        name = "flux-router-log-" + time.strftime("%Y%m%d-%H%M%S") + ".txt"
        extra = {"Content-Disposition": f'attachment; filename="{name}"'} if one(params, "dl") == "1" else None
        return self._send(200, body, "text/plain; charset=utf-8", extra)

    def _nklog_export(self, params):
        """nikki 内核 / 插件日志导出成纯文本(最多 5000 条);默认打码 IP / MAC / 设备别名,dom=1 再把域名换成代号。"""
        con = ro()
        try:
            rows = nikkilog.query(con, one(params, "src"), int(one(params, "level", "7") or 7), one(params, "q"), min(5000, int(one(params, "n", "1000") or 1000)))
            names = [] if one(params, "mask") == "0" else diag._names(con)
        finally:
            con.close()
        dm = diag.domain_masker() if one(params, "dom") == "1" else None
        def mk(t):
            if one(params, "mask") != "0":
                t = diag.mask_text(t, names)
            return diag.mask_domains(t, dm) if dm else t
        lines = [f"{time.strftime('%F %T', time.localtime(r['ts']))} [{r['src_name']}/{r['lv']}] {mk(r['msg'])}" for r in reversed(rows)]
        body = ("\n".join(lines) + "\n").encode("utf-8")
        name = "flux-nikki-log-" + time.strftime("%Y%m%d-%H%M%S") + ".txt"
        extra = {"Content-Disposition": f'attachment; filename="{name}"'} if one(params, "dl") == "1" else None
        return self._send(200, body, "text/plain; charset=utf-8", extra)

    def _seen(self, kind):
        """记录是谁(哪个 IP、什么浏览器)打开/登录了面板;出错不影响正常访问。"""
        try:
            ip = self._ip()
            _wcon(lambda con: panellog.record(con, ip, self.headers.get("User-Agent", ""), kind))
        except Exception as e:
            log("记录面板访问出错", e)

    def _json_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 8192:
            raise ValueError("内容太大")
        d = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        if not isinstance(d, dict):
            raise ValueError("需要 JSON 对象")
        return d

    def _login(self):
        ip = self._ip()
        if auth.locked(ip):
            return self._send(429, {"error": "尝试次数太多,请 1 分钟后再试"})
        try:
            d_ = self._json_body()
            pw = str(d_.get("password") or "")
            rem = d_.get("remember", True) is not False
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        role = auth.check_role(pw)
        if role:
            auth.ok(ip)
            if auth.enabled():
                self._seen("login_ok")
                if role == "v":
                    log("只读账号登录", ip)
            return self._send(200, {"ok": True, "role": role}, extra=self._mk(role, rem) if auth.enabled() else None)
        auth.fail(ip)
        log("登录失败", ip)
        self._seen("login_fail")
        return self._send(401, {"error": "密码不对"})

    def _auth_set(self):
        try:
            d = self._json_body()
            if auth.enabled() and not auth.check(str(d.get("old") or "")):
                auth.fail(self._ip())
                return self._send(401, {"error": "当前密码不对"})
            auth.set_password(str(d.get("new") or ""))
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        log("访问密码已" + ("设置" if auth.enabled() else "关闭"))
        extra = self._mk("a") if auth.enabled() else self._ck("", clear=True)
        return self._send(200, {"ok": True, "enabled": auth.enabled()}, extra=extra)

    def _auth_viewer(self):
        try:
            d = self._json_body()
            if not auth.check(str(d.get("old") or "")):
                auth.fail(self._ip())
                return self._send(401, {"error": "管理员密码不对"})
            auth.set_viewer(str(d.get("new") or ""))
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        log("只读密码已" + ("设置" if auth.has_viewer() else "关闭"), self._ip())
        return self._send(200, {"ok": True, "viewer": auth.has_viewer()})

    def _auth_sess_revoke(self):
        try:
            sid = str(self._json_body().get("id") or "")
            cur = auth.cookie_sid(self._cookie())
            auth.revoke_sid(sid)
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        log("已让一台设备退出登录", sid[:4] + "…", "来自", self._ip())
        return self._send(200, {"ok": True, "self": bool(sid and sid == cur)}, extra=self._ck("", clear=True) if sid == cur else None)

    def _auth_revoke(self):
        try:
            auth.revoke_all()
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        log("已让所有设备退出登录", self._ip())
        return self._send(200, {"ok": True}, extra=self._mk("a"))

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(u.query)
        if not self._net_ok():
            return self._send(403, {"error": "这个地址不在允许访问的网段内"})
        origin = self.headers.get("Origin")
        if (origin and urllib.parse.urlparse(origin).netloc != self.headers.get("Host", "")) or (not origin and self.headers.get("Sec-Fetch-Site") == "cross-site"):
            return self._send(403, {"error": "跨站请求被拒绝"})
        if u.path == "/api/login":
            return self._login()
        role = self._role(params)
        if role is None:
            return self._deny()
        if u.path == "/api/logout":
            return self._send(200, {"ok": True}, extra=self._ck("", clear=True))
        if role == "v" and u.path not in VIEWER_POST_OK and not (u.path in VIEWER_EDIT_POST and auth.perms()["edit"]):
            if u.path in VIEWER_POST_NOOP:
                return self._send(200, {"ok": True, "readonly": True})
            return self._send(403, {"error": "只读账号不能修改设置"})
        if u.path == "/api/auth/set":
            return self._auth_set()
        if u.path == "/api/auth/viewer":
            return self._auth_viewer()
        if u.path == "/api/auth/revoke":
            return self._auth_revoke()
        if u.path == "/api/auth/viewer/perms":
            try:
                auth.set_perms(self._json_body())
            except ValueError as e:
                return self._send(400, {"error": str(e)})
            log("只读账号权限已修改", self._ip())
            return self._send(200, {"ok": True, "perms": auth.perms()})
        if u.path == "/api/auth/session/revoke":
            return self._auth_sess_revoke()
        fn = POST_ROUTES.get(u.path)
        if not fn:
            return self._send(404, {"error": "not found"})
        _ctx.role = role
        _ctx.ip = self._ip()
        _ctx.server = self.server
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 1024 * 1024:
                return self._send(413, {"error": "内容太大"})
            body = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
            if not isinstance(body, dict):
                raise ValueError("需要 JSON 对象")
            data = fn(body)
            _audit(u.path, body)
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        except Exception as e:
            log("接口出错", u.path, e)
            return self._send(500, {"error": f"{type(e).__name__}: {e}"})
        self._send(200, data)


def serve():
    srv = listen.boot(Handler)
    return srv
