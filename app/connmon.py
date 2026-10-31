"""v0.50(P1-lite):设备级「当前连接明细」。

数据来源只有两个,都是只读:
  1. nikki /connections(realtime 线程已经每 2 秒读一次,这里复用它的结果,不新增轮询)
  2. 路由器 /proc/net/nf_conntrack(文本,不需要任何额外容器权限),用来补 TCP 状态

约定(不把未知当成已知):
  - 走代理的连接(fake-ip),路由器看不到真实目标 IP,只有域名;目标 IP 留空,界面显示「代理解析」。
  - 没有 conntrack 时,状态显示「未知」,关联状态是「无法判断」。
  - 状态来自 conntrack,持续时间来自 nikki 记录的 start。
本模块任何异常都只记在 STATE["err"],不影响 realtime 主循环。
"""
import ipaddress
import os
import threading
import time

CT_PATH = os.environ.get("CT_PATH", "/proc/net/nf_conntrack")
MAX_ROWS = 5000          # 内存里最多保留多少条连接明细(超出只统计、不保留明细)
MAX_ROWS_LOW = 1000      # 容器内存紧张时的上限
CT_MAX = 8000            # 最多保留多少条 conntrack 记录
CT_EVERY = 10            # conntrack 读取间隔(秒)
BASE_EVERY = 4           # 连接明细刷新间隔(秒);耗时太长会自动加大
FAKE = (ipaddress.ip_network("198.18.0.0/15"),)
STATE = {"on": True, "cfg_at": 0.0, "at": 0.0, "interval": BASE_EVERY, "ms": 0.0, "slow": 0, "fast": 0,
         "total": 0, "kept": 0, "trunc": False, "err": "", "degraded": "", "ct_ok": None, "ct_err": "", "ct_at": 0.0, "ct_n": 0, "ct_trunc": False}
SNAP = {"at": 0.0, "rows": []}
DEVSTAT = {}             # 设备 -> {"conns","tcp","udp","new","closed"}(两次刷新之间的变化)
CT = {"map": {}, "dev": {}, "other": 0}
_prev = {}               # 上一次的 连接ID -> 设备,用来算新增 / 关闭
_lock = threading.Lock()

TCP_CN = {"ESTABLISHED": "已建立", "SYN_SENT": "正在连接", "SYN_RECV": "握手中", "FIN_WAIT": "正在关闭", "CLOSE_WAIT": "对端已关",
          "TIME_WAIT": "已结束", "LAST_ACK": "正在关闭", "CLOSE": "已关闭"}
# 一行行读取字段的下标:row[i]
(R_ID, R_DEV, R_SRC, R_SPORT, R_PROTO, R_DST, R_DPORT, R_HOST, R_NODE, R_RULE, R_START, R_UP, R_DOWN, R_KIND, R_DNS, R_STATE, R_LINK, R_UNREP) = range(18)


RCOL = {"id": R_ID, "dev": R_DEV, "src": R_SRC, "sport": R_SPORT, "proto": R_PROTO, "dst": R_DST, "dport": R_DPORT, "host": R_HOST, "node": R_NODE,
        "start": R_START, "up": R_UP, "down": R_DOWN, "state": R_STATE, "link": R_LINK, "unrep": R_UNREP}


def nip(s):
    """IPv6 统一成压缩写法(conntrack 里是补零的长写法,nikki / 邻居表里是压缩写法)。"""
    s = (s or "").strip()
    if ":" in s:
        try:
            return str(ipaddress.ip_address(s))
        except ValueError:
            return s
    return s


def is_fake(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in FAKE if a.version == n.version)


# ---------------------------------------------------------------- 开关
def load_cfg(con):
    from .insight import _kv_get
    c = _kv_get(con, "connmon", {}) or {}
    STATE["on"] = bool(c.get("on", True)) if isinstance(c, dict) else True
    STATE["cfg_at"] = time.time()
    from . import connhist
    connhist.load_cfg(c if isinstance(c, dict) else {})
    return {"on": STATE["on"], **connhist.cfg_out()}


def save_cfg(con, body):
    from .insight import _kv_get, _kv_set
    from . import connhist
    old = _kv_get(con, "connmon", {}) or {}
    on = bool(body.get("on", old.get("on", True)))
    new = {"on": on}
    for k in ("tier", "budget_mb", "hist", "events"):
        new[k] = body[k] if k in body else old.get(k, "auto" if k == "tier" else 0)
    _kv_set(con, "connmon", new)
    connhist.load_cfg(new)
    STATE["on"] = on
    STATE["cfg_at"] = time.time()
    if not on:
        with _lock:
            SNAP.update(at=0.0, rows=[])
            DEVSTAT.clear()
            _prev.clear()
            CT.update(map={}, dev={}, other=0)
    return {"on": on, **connhist.cfg_out()}


def _enabled():
    if time.time() - STATE["cfg_at"] > 60:
        try:
            from . import db
            con = db.open_db()
            try:
                load_cfg(con)
            finally:
                con.close()
        except Exception:
            STATE["cfg_at"] = time.time()
    return STATE["on"]


def _mem_pressure():
    """容器内存用量 / 上限(cgroup v2 或 v1);读不到返回 None。"""
    for cur, mx in (("/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory.max"),
                    ("/sys/fs/cgroup/memory/memory.usage_in_bytes", "/sys/fs/cgroup/memory/memory.limit_in_bytes")):
        try:
            with open(cur) as f:
                c = int(f.read().strip())
            with open(mx) as f:
                m = f.read().strip()
            if m == "max" or int(m) <= 0 or int(m) > 1 << 50:
                return None
            return c / int(m)
        except (OSError, ValueError):
            continue
    return None


# ---------------------------------------------------------------- conntrack
def parse_ct_line(ln):
    """解析 /proc/net/nf_conntrack 的一行。只认 TCP / UDP;其它协议返回 None。
    返回 {proto, state, timeout, src, dst, sport, dport, op, ob, rp, rb, unreplied}"""
    t = ln.split()
    if len(t) < 9 or t[2] not in ("tcp", "udp"):
        return None
    try:
        timeout = int(t[4])
    except ValueError:
        timeout = 0
    i, state = 5, ""
    if "=" not in t[i] and not t[i].startswith("["):
        state, i = t[i], i + 1
    o, r, cur, unrep = {}, {}, None, False
    cur = o
    for tok in t[i:]:
        k, eq, v = tok.partition("=")
        if not eq:
            if tok == "[UNREPLIED]":
                unrep = True
            continue
        if k not in ("src", "dst", "sport", "dport", "packets", "bytes"):
            continue
        if k in cur:
            if cur is o:
                cur = r
            else:
                continue
        cur[k] = v
    if "src" not in o or "dport" not in o or "sport" not in o:
        return None
    try:
        return {"proto": t[2], "state": state, "timeout": timeout, "src": nip(o["src"]), "dst": nip(o.get("dst", "")),
                "sport": o["sport"], "dport": o["dport"], "op": int(o.get("packets") or 0), "ob": int(o.get("bytes") or 0),
                "rp": int(r.get("packets") or 0), "rb": int(r.get("bytes") or 0), "unreplied": unrep}
    except ValueError:
        return None


def read_ct(col, known, now):
    """读一次 conntrack。known = 已知局域网设备 IP 集合(邻居表 + 本次 nikki 里出现的来源);其它来源只计数。"""
    try:
        with open(CT_PATH, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError as e:
        STATE.update(ct_ok=False, ct_err=f"{type(e).__name__}", ct_at=now, ct_n=0)
        CT.update(map={}, dev={}, other=0)
        return
    m, dev, other, trunc = {}, {}, 0, False
    keyc = {}
    for ln in lines:
        e = parse_ct_line(ln)
        if not e:
            continue
        if e["src"] not in known:
            other += 1
            continue
        if len(m) >= CT_MAX:
            trunc = True
            continue
        m[f"{e['proto']}|{e['src']}|{e['sport']}|{e['dport']}"] = (e["state"], e["timeout"], e["unreplied"], e["op"] + e["rp"], e["ob"] + e["rb"])
        k = keyc.get(e["src"])
        if k is None:
            k = keyc[e["src"]] = (col.neigh.key(e["src"]) if col else e["src"])
        d = dev.setdefault(k, {"tcp": 0, "udp": 0, "states": {}, "unreplied": 0, "tcp_unreplied": 0})
        if e["proto"] == "tcp":
            d["tcp"] += 1
            d["states"][e["state"] or "?"] = d["states"].get(e["state"] or "?", 0) + 1
        else:
            d["udp"] += 1
        if e["unreplied"]:
            d["unreplied"] += 1
            if e["proto"] == "tcp":
                d["tcp_unreplied"] += 1      # 只有 TCP 没回应才可能是连接失败;UDP 单向(DNS / mDNS / QUIC 被丢弃等)很常见
    CT.update(map=m, dev=dev, other=other)
    STATE.update(ct_ok=True, ct_err="", ct_at=now, ct_n=len(m), ct_trunc=trunc)


# ---------------------------------------------------------------- 采样
def _start_ts(s):
    try:
        from .providers import parse_ts
        return parse_ts(s)
    except Exception:
        return 0


def feed(conns, col, now, kindf):
    """realtime 循环每次读到连接后调用。自己限速、自己兜底异常。"""
    if not _enabled():
        return
    from . import connhist
    base = connhist.params()["every"]
    if STATE["interval"] < base:
        STATE["interval"] = base
    if now - STATE["at"] < STATE["interval"]:
        return
    t0 = time.perf_counter()
    try:
        _build(conns, col, now, kindf)
        STATE["err"] = ""
    except Exception as e:
        STATE["err"] = f"{type(e).__name__}: {e}"[:120]
    ms = (time.perf_counter() - t0) * 1000
    try:
        from . import connhist
        connhist.SLOW.append(ms)
        connhist.evaluate(now, _mem_pressure())
        with _lock:
            rows, dstat = SNAP["rows"], {k: dict(v) for k, v in DEVSTAT.items()}
        connhist.record(now, dstat, CT["dev"], rows, RCOL)
        connhist.tick(now, dstat, CT["dev"])
        from . import connanom
        connanom.check(now, dstat, CT["dev"], rows, RCOL, bool(STATE["ct_ok"]))
    except Exception as e:
        connhist.STATE["err"] = f"{type(e).__name__}: {e}"[:120]
    STATE["ms"] = round(ms, 1)
    STATE["at"] = now
    # 耗时自适应:一次超过 150ms 就把间隔翻倍(最多 30 秒),连续 5 次都很快才一点点回到基础间隔,避免来回抖动
    if ms > 150:
        STATE["fast"] = 0
        STATE["slow"] += 1
        STATE["interval"] = min(30, STATE["interval"] * 2)
    elif ms < 40:
        STATE["fast"] += 1
        if STATE["fast"] >= 5 and STATE["interval"] > base:
            STATE["interval"] = max(base, STATE["interval"] // 2)
            STATE["fast"] = 0
    else:
        STATE["fast"] = 0


def _build(conns, col, now, kindf):
    press = _mem_pressure()
    from . import connhist
    tp = connhist.params()
    cap = min(MAX_ROWS, tp["rows"])
    STATE["degraded"] = ""
    if press is not None and press > 0.9:
        cap = min(cap, MAX_ROWS_LOW)
        STATE["degraded"] = f"容器内存已用 {int(press * 100)}%,连接明细上限降到 {MAX_ROWS_LOW} 条"
    ptype = dict(col.ptype) if col else {}
    rows, srcs = [], set()
    total = 0
    for cn in conns:
        cid = cn.get("id")
        if not cid:
            continue
        total += 1
        m = cn.get("metadata") or {}
        src = nip(str(m.get("sourceIP") or ""))
        srcs.add(src)
        if len(rows) >= cap:
            continue
        chains = cn.get("chains") or []
        node = col.leaf(chains) if col else (str(chains[0]) if chains else "UNKNOWN")
        dst = nip(str(m.get("destinationIP") or ""))
        if dst and is_fake(dst):
            dst = ""
        if not dst and kindf(node, ptype) == "direct":
            dst = nip(str(m.get("remoteDestination") or "").rsplit(":", 1)[0].strip("[]")) if m.get("remoteDestination") else ""
        host = str(m.get("host") or "").strip().lower() or str(m.get("sniffHost") or "").strip().lower()
        r, p = str(cn.get("rule") or ""), str(cn.get("rulePayload") or "")
        rows.append([cid, (col.neigh.key(src) if col else src), src, str(m.get("sourcePort") or ""), str(m.get("network") or "").lower(),
                     dst, str(m.get("destinationPort") or ""), host, node, ((r + "," + p) if p else r)[:80],
                     _start_ts(cn.get("start")), int(cn.get("upload") or 0), int(cn.get("download") or 0), kindf(node, ptype),
                     str(m.get("dnsMode") or ""), "", "", False])
    if now - STATE["ct_at"] >= tp["ct"]:
        known = set(srcs)
        if col:
            known |= set(col.neigh.map)
        read_ct(col, known, now)
    ct_ok, cmap = STATE["ct_ok"], CT["map"]
    for rw in rows:
        e = cmap.get(f"{rw[R_PROTO]}|{rw[R_SRC]}|{rw[R_SPORT]}|{rw[R_DPORT]}") if ct_ok else None
        if e:
            rw[R_STATE] = e[0] or ("UDP" if rw[R_PROTO] == "udp" else "")
            rw[R_UNREP] = bool(e[2]) and rw[R_PROTO] == "tcp"
            rw[R_LINK] = "已确认"
        elif ct_ok:
            rw[R_STATE], rw[R_LINK] = "", "未关联"
        else:
            rw[R_STATE], rw[R_LINK] = "", "无法判断"
    # 每台设备:当前连接数、TCP / UDP、两次刷新之间新增 / 关闭
    cur, ds = {}, {}
    for rw in rows:
        cur[rw[R_ID]] = rw[R_DEV]
        d = ds.setdefault(rw[R_DEV], {"conns": 0, "tcp": 0, "udp": 0, "new": 0, "closed": 0})
        d["conns"] += 1
        if rw[R_PROTO] == "tcp":
            d["tcp"] += 1
        elif rw[R_PROTO] == "udp":
            d["udp"] += 1
        if _prev and rw[R_ID] not in _prev:
            d["new"] += 1
    for cid, dv in _prev.items():
        if cid not in cur:
            ds.setdefault(dv, {"conns": 0, "tcp": 0, "udp": 0, "new": 0, "closed": 0})["closed"] += 1
    with _lock:
        SNAP.update(at=now, rows=rows)
        DEVSTAT.clear()
        DEVSTAT.update(ds)
        _prev.clear()
        _prev.update(cur)
    STATE.update(total=total, kept=len(rows), trunc=total > len(rows))


# ---------------------------------------------------------------- 查询
def _dst_text(rw):
    return rw[R_HOST] or rw[R_DST] or ""


def _row_out(rw, now, label):
    st = rw[R_STATE]
    return {"id": rw[R_ID], "dev": rw[R_DEV], "name": label(rw[R_DEV]), "src": rw[R_SRC], "sport": rw[R_SPORT], "proto": rw[R_PROTO],
            "dst_ip": rw[R_DST], "dport": rw[R_DPORT], "host": rw[R_HOST], "node": rw[R_NODE], "rule": rw[R_RULE], "kind": rw[R_KIND],
            "age": int(now - rw[R_START]) if rw[R_START] else None, "up": rw[R_UP], "down": rw[R_DOWN], "dns": rw[R_DNS],
            "state": st, "state_cn": ("无回应" if rw[R_UNREP] and rw[R_PROTO] == "tcp" else TCP_CN.get(st, st)) if rw[R_PROTO] == "tcp" and st else ("UDP" if rw[R_PROTO] == "udp" and st else ""),
            "unreplied": rw[R_UNREP], "link": rw[R_LINK]}


def _top(counter, n=8):
    return [{"k": k, "n": c} for k, c in sorted(counter.items(), key=lambda x: -x[1])[:n]]


def summary(rows):
    tcp = sum(1 for r in rows if r[R_PROTO] == "tcp")
    udp = sum(1 for r in rows if r[R_PROTO] == "udp")
    states, dst, ports, nodes, kinds = {}, {}, {}, {}, {}
    unrep = 0
    for r in rows:
        if r[R_PROTO] == "tcp" and r[R_STATE]:
            states[r[R_STATE]] = states.get(r[R_STATE], 0) + 1
        if r[R_UNREP]:
            unrep += 1
        k = _dst_text(r) or "(代理解析,路由器看不到)"
        dst[k] = dst.get(k, 0) + 1
        pk = f"{r[R_DPORT] or '?'}/{r[R_PROTO] or '?'}"
        ports[pk] = ports.get(pk, 0) + 1
        nodes[r[R_NODE]] = nodes.get(r[R_NODE], 0) + 1
        kinds[r[R_KIND]] = kinds.get(r[R_KIND], 0) + 1
    return {"total": len(rows), "tcp": tcp, "udp": udp, "states": states, "unreplied": unrep, "top_dst": _top(dst), "top_ports": _top(ports),
            "top_nodes": _top(nodes), "kinds": kinds}


def snapshot(dev="", proto="", q="", state="", node="", sort="age", limit=300, label=lambda k: k, now=None):
    """界面 / 导出用。dev 为空 = 全网。返回 {ok, at, status, summary, rows, devices}。"""
    now = now or time.time()
    with _lock:
        rows = list(SNAP["rows"])
        at = SNAP["at"]
        dstat = {k: dict(v) for k, v in DEVSTAT.items()}
    q = (q or "").strip().lower()

    def keep(r):
        if dev and r[R_DEV] != dev:
            return False
        if proto and r[R_PROTO] != proto:
            return False
        if state and r[R_STATE] != state:
            return False
        if node and r[R_NODE] != node:
            return False
        if q and q not in (r[R_HOST] + " " + r[R_DST] + " " + r[R_DPORT] + " " + r[R_NODE] + " " + r[R_SRC] + " " + r[R_RULE]).lower():
            return False
        return True
    sel = [r for r in rows if keep(r)]
    key = {"age": lambda r: -(now - r[R_START]) if r[R_START] else 0, "traffic": lambda r: -(r[R_UP] + r[R_DOWN]), "dst": lambda r: _dst_text(r)}.get(sort)
    if key:
        sel.sort(key=key)
    ct_dev = CT["dev"]
    devs = []
    if not dev:
        for k, d in sorted(dstat.items(), key=lambda x: -x[1]["conns"])[:50]:
            c = ct_dev.get(k) or {}
            devs.append({"key": k, "name": label(k), "conns": d["conns"], "tcp": d["tcp"], "udp": d["udp"], "new": d["new"], "closed": d["closed"],
                         "syn_sent": (c.get("states") or {}).get("SYN_SENT", 0), "unreplied": c.get("tcp_unreplied", 0), "ct_tcp": c.get("tcp"), "ct_udp": c.get("udp")})
    cd = ct_dev.get(dev) if dev else None
    return {"ok": True, "at": int(at), "age": int(now - at) if at else None, "on": STATE["on"],
            "status": {k: STATE[k] for k in ("interval", "ms", "total", "kept", "trunc", "err", "degraded", "ct_ok", "ct_err", "ct_n", "ct_trunc")} | {"ct_at": int(STATE["ct_at"])},
            "summary": summary(sel), "dev_ct": cd, "dev_stat": dstat.get(dev) if dev else None,
            "rows": [_row_out(r, now, label) for r in sel[:max(1, min(1000, limit))]], "matched": len(sel), "devices": devs}


def brief(dev, label=lambda k: k, n=3):
    """告警正文用的一段话:这台设备此刻的连接构成。没有数据返回空串。"""
    with _lock:
        rows = [r for r in SNAP["rows"] if r[R_DEV] == dev]
        at = SNAP["at"]
    if not rows or time.time() - at > 60:
        return ""
    s = summary(rows)
    parts = [f"TCP {s['tcp']} / UDP {s['udp']}"]
    if s["states"]:
        parts.append("TCP 状态:" + "、".join(f"{TCP_CN.get(k, k)} {v}" for k, v in sorted(s["states"].items(), key=lambda x: -x[1])[:4]))
    if s["unreplied"]:
        parts.append(f"对端没有回应的 {s['unreplied']} 个")
    parts.append("目标最多:" + "、".join(f"{x['k']}({x['n']})" for x in s["top_dst"][:n]))
    parts.append("端口最多:" + "、".join(f"{x['k']}({x['n']})" for x in s["top_ports"][:n]))
    parts.append("节点:" + "、".join(f"{x['k']}({x['n']})" for x in s["top_nodes"][:n]))
    return "。".join(parts) + "。"


def diag(mask=lambda t: t, top_devs=3, rows_per=15):
    """诊断包用:全网汇总 + 连接最多的几台设备的 Top 目标和若干条明细(已按 mask 处理)。"""
    with _lock:
        rows = list(SNAP["rows"])
        at = SNAP["at"]
        dstat = {k: dict(v) for k, v in DEVSTAT.items()}
    out = {"on": STATE["on"], "at": int(at), "status": {k: STATE[k] for k in ("interval", "ms", "total", "kept", "trunc", "err", "degraded", "ct_ok", "ct_err", "ct_n")},
           "note": "走代理的连接看不到真实目标 IP,只有域名;状态来自 conntrack,不可用时为空。"}
    if not rows:
        return out
    s = summary(rows)
    out["summary"] = {k: ([{"k": mask(x["k"]), "n": x["n"]} for x in v] if k in ("top_dst",) else v) for k, v in s.items()}
    devs = []
    for k, d in sorted(dstat.items(), key=lambda x: -x[1]["conns"])[:top_devs]:
        rs = [r for r in rows if r[R_DEV] == k]
        sm = summary(rs)
        devs.append({"dev": mask(k), "conns": d["conns"], "tcp": d["tcp"], "udp": d["udp"], "new": d["new"], "closed": d["closed"], "states": sm["states"],
                     "unreplied": sm["unreplied"], "top_dst": [{"k": mask(x["k"]), "n": x["n"]} for x in sm["top_dst"]], "top_ports": sm["top_ports"], "top_nodes": sm["top_nodes"],
                     "sample": [{"proto": r[R_PROTO], "dst": mask(_dst_text(r) or "(代理解析)"), "port": r[R_DPORT], "node": r[R_NODE], "state": r[R_STATE] or "?",
                                 "age": int(at - r[R_START]) if r[R_START] else None, "link": r[R_LINK]} for r in rs[:rows_per]]})
    out["top_devices"] = devs
    return out
