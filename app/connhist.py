"""v0.51(P2):连接监控的 运行档位 / 设备分钟历史 / 异常事件与前后现场快照。

- 档位:启动时按 CPU、主机内存、数据盘剩余空间等实际情况选 高性能 / 标准 / 轻量;运行中按内存、负载、
  单次采集耗时降档,恢复后升回。切换有门槛(持续 5 分钟才切换、切换后至少停留 10 分钟),避免来回抖动。
  档位只决定「采多勤、存多少」,同一套代码,不按 CPU 架构硬分档。
- 历史:每台设备每分钟(轻量档 5 分钟)一行汇总,保留天数随档位;写入合并、批量,不做高频写库。
- 事件与快照:出现异常时记一条事件,并保存 异常前 60 秒 / 触发时 / 异常后 180 秒 的现场(轻量档只存汇总 + Top)。
- 预算:新增数据总量有上限(默认 300MB),超了先清最老的快照,再缩短历史;磁盘不足时进一步收缩。
本模块任何异常都只记在 STATE["err"],不影响采集与实时速度。
"""
import collections
import json
import os
import platform
import shutil
import threading
import time

from . import config
from .util import log

LEVELS = {"attention": "需要关注", "suspect": "高度可疑", "unknown": "无法判断"}
TIER_NAME = {"high": "高性能", "standard": "标准", "light": "轻量"}
# every=明细刷新间隔(秒) rows=内存里最多保留的连接明细 ct=conntrack 读取间隔 res=历史分辨率(分钟) hist=历史保留天数
# snap_rows=快照里的连接明细条数(0=只存汇总和 Top) pre/post=快照前后秒数 events=事件保留天数
TIERS = {
    "high": {"every": 4, "rows": 5000, "ct": 10, "res": 1, "hist": 14, "snap_rows": 300, "pre": 60, "post": 180, "events": 90, "baseline": "full"},
    "standard": {"every": 10, "rows": 2000, "ct": 30, "res": 1, "hist": 7, "snap_rows": 100, "pre": 60, "post": 180, "events": 60, "baseline": "full"},
    "light": {"every": 30, "rows": 500, "ct": 60, "res": 5, "hist": 3, "snap_rows": 0, "pre": 60, "post": 180, "events": 30, "baseline": "lite"},
}
ORDER = ["light", "standard", "high"]
CFG = {"tier": "auto", "budget_mb": 300, "hist": 0, "events": 0}   # 0 = 用档位默认
STATE = {"tier": "standard", "since": 0.0, "cand": "", "cand_since": 0.0, "reasons": [], "hw": {}, "hw_at": 0.0, "eval_at": 0.0,
         "err": "", "last_flush": 0, "flush_n": 0, "prune_at": 0.0, "snap_skipped": "", "storage_note": ""}
_lock = threading.Lock()
_agg = {}                # 当前这一个历史分辨率窗口里的 设备 -> 汇总
_bucket = 0
RING = {}                # 设备 -> 最近若干次采样(用来做「异常前 60 秒」)
ACTIVE = {}              # (设备, 类型) -> 正在进行的事件
SLOW = collections.deque(maxlen=12)   # 最近的单次采集耗时(毫秒)


# ---------------------------------------------------------------- 配置
def load_cfg(c):
    """c = kv 里 connmon 的字典。"""
    t = str(c.get("tier") or "auto")
    CFG["tier"] = t if t in ("auto",) + tuple(TIERS) else "auto"
    for k, lo, hi, d in (("budget_mb", 20, 20000, 300), ("hist", 0, 90, 0), ("events", 0, 365, 0)):
        try:
            v = int(c.get(k, d))
        except (TypeError, ValueError):
            v = d
        CFG[k] = max(lo, min(hi, v)) if v else (d if k == "budget_mb" else 0)


def cfg_out():
    return dict(CFG)


def params():
    p = dict(TIERS.get(STATE["tier"], TIERS["standard"]))
    if CFG["hist"]:
        p["hist"] = CFG["hist"]
    if CFG["events"]:
        p["events"] = CFG["events"]
    return p


# ---------------------------------------------------------------- 档位
def read_hw(now=None):
    """识别运行环境(5 分钟缓存)。读不到的项为 None,按保守值处理。"""
    now = now or time.time()
    if STATE["hw"] and now - STATE["hw_at"] < 300:
        return STATE["hw"]
    hw = {"arch": platform.machine(), "cpu": os.cpu_count() or 1, "mem_mb": None, "limit_mb": None, "disk_free_mb": None, "load1": None}
    try:
        with open("/proc/meminfo") as f:
            for ln in f:
                if ln.startswith("MemTotal:"):
                    hw["mem_mb"] = int(ln.split()[1]) // 1024
                    break
    except (OSError, ValueError):
        pass
    for mx in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            with open(mx) as f:
                v = f.read().strip()
            if v != "max" and 0 < int(v) < 1 << 50:
                hw["limit_mb"] = int(v) // 1048576
                break
        except (OSError, ValueError):
            continue
    try:
        hw["disk_free_mb"] = shutil.disk_usage(config.DATA_DIR if os.path.isdir(config.DATA_DIR) else "/").free // 1048576
    except OSError:
        pass
    try:
        with open("/proc/loadavg") as f:
            hw["load1"] = float(f.read().split()[0])
    except (OSError, ValueError):
        pass
    STATE["hw"], STATE["hw_at"] = hw, now
    return hw


def base_tier(hw):
    """只看硬件:内存不足 1.5GB 或 CPU 少于 2 核 → 轻量;内存不足 3GB 或 CPU 少于 4 核 → 标准;其余高性能。"""
    cpu, mem = hw.get("cpu") or 1, hw.get("mem_mb")
    if mem is None:
        return "standard", ["读不到主机内存,按标准档运行"]
    if cpu < 2 or mem < 1536:
        return "light", [f"主机内存 {mem} MB / {cpu} 核,按轻量档运行"]
    if cpu < 4 or mem < 3072:
        return "standard", [f"主机内存 {mem} MB / {cpu} 核,按标准档运行"]
    return "high", [f"主机内存 {mem} MB / {cpu} 核,可以运行高性能档"]


def pressure(hw, mem_press, slow_ms):
    """当前压力导致要降几档,以及原因。"""
    steps, why = 0, []
    if mem_press is not None and mem_press > 0.9:
        steps += 1
        why.append(f"容器内存已用 {int(mem_press * 100)}%")
    if hw.get("load1") is not None and hw["load1"] > (hw.get("cpu") or 1) * 1.5:
        steps += 1
        why.append(f"系统负载 {hw['load1']:.1f} 偏高(CPU {hw.get('cpu')} 核)")
    if slow_ms is not None and slow_ms > 150:
        steps += 1
        why.append(f"连接明细单次采集耗时 {int(slow_ms)} ms")
    if hw.get("disk_free_mb") is not None and hw["disk_free_mb"] < 1024:
        steps += 1
        why.append(f"数据盘只剩 {hw['disk_free_mb']} MB")
    return min(2, steps), why


def evaluate(now, mem_press=None):
    """每 60 秒由采集循环调用一次,决定当前档位。返回当前档位。"""
    if now - STATE["eval_at"] < 60 and STATE["since"]:
        return STATE["tier"]
    STATE["eval_at"] = now
    hw = read_hw(now)
    if CFG["tier"] != "auto":
        if STATE["tier"] != CFG["tier"]:
            STATE.update(tier=CFG["tier"], since=now, cand="", reasons=[f"已手动固定为{TIER_NAME[CFG['tier']]}档"])
        STATE["since"] = STATE["since"] or now
        STATE["reasons"] = [f"已手动固定为{TIER_NAME[CFG['tier']]}档"]
        return STATE["tier"]
    base, why = base_tier(hw)
    ms = sorted(SLOW)[len(SLOW) // 2] if len(SLOW) >= 3 else None
    steps, pw = pressure(hw, mem_press, ms)
    want = ORDER[max(0, ORDER.index(base) - steps)]
    STATE["reasons"] = why + pw
    if not STATE["since"]:                       # 第一次:直接采用,不等门槛
        STATE.update(tier=want, since=now, cand="")
        return want
    if want == STATE["tier"]:
        STATE["cand"] = ""
        return STATE["tier"]
    if STATE["cand"] != want:
        STATE["cand"], STATE["cand_since"] = want, now
        return STATE["tier"]
    if now - STATE["cand_since"] >= 300 and now - STATE["since"] >= 600:
        log(f"连接监控档位 {TIER_NAME[STATE['tier']]} → {TIER_NAME[want]}:{'、'.join(STATE['reasons'])}")
        STATE.update(tier=want, since=now, cand="")
    return STATE["tier"]


# ---------------------------------------------------------------- 分钟历史
def _new_agg():
    return {"conns": 0, "tcp": 0, "udp": 0, "new": 0, "closed": 0, "syn": 0, "unrep": 0, "n": 0}


def record(now, dstat, ct_dev, rows, rcol):
    """每次连接明细刷新后调用:累计当前窗口;窗口翻页时写库。rows = 当前明细,rcol = 取字段的下标表。"""
    p = params()
    res = p["res"] * 60
    b = int(now // res) * res
    global _bucket
    if _bucket and b != _bucket and _agg:
        flush(_bucket, rows, rcol, now)
    _bucket = b
    for dev, d in dstat.items():
        a = _agg.setdefault(dev, _new_agg())
        a["n"] += 1
        a["conns"] = max(a["conns"], d["conns"])
        a["tcp"] = max(a["tcp"], d["tcp"])
        a["udp"] = max(a["udp"], d["udp"])
        a["new"] += d["new"]
        a["closed"] += d["closed"]
        c = ct_dev.get(dev) or {}
        a["syn"] = max(a["syn"], (c.get("states") or {}).get("SYN_SENT", 0))
        a["unrep"] = max(a["unrep"], c.get("tcp_unreplied", 0))
    # 异常前的环形缓冲
    keep = max(4, int(p["pre"] / max(1, p["every"])) + 3)
    for dev, d in dstat.items():
        r = RING.get(dev)
        if r is None or r.maxlen != keep:
            r = RING[dev] = collections.deque(r or (), maxlen=keep)
        c = ct_dev.get(dev) or {}
        r.append((int(now), d["conns"], d["tcp"], d["udp"], d["new"], d["closed"], (c.get("states") or {}).get("SYN_SENT", 0), c.get("tcp_unreplied", 0)))
    for dev in [k for k, r in RING.items() if k not in dstat and r and now - r[-1][0] > 600]:
        del RING[dev]


def _tops(rows, rcol, dev):
    dst, ports, nodes = {}, {}, {}
    for r in rows:
        if r[rcol["dev"]] != dev:
            continue
        k = r[rcol["host"]] or r[rcol["dst"]] or "?"
        dst[k] = dst.get(k, 0) + 1
        pk = f"{r[rcol['dport']] or '?'}/{r[rcol['proto']] or '?'}"
        ports[pk] = ports.get(pk, 0) + 1
        nodes[r[rcol["node"]]] = nodes.get(r[rcol["node"]], 0) + 1
    top = lambda d: [[k, c] for k, c in sorted(d.items(), key=lambda x: -x[1])[:3]]
    return {"d": top(dst), "p": top(ports), "n": top(nodes)}


def flush(bucket, rows, rcol, now):
    """把上一个窗口的汇总写进 conn_dev_min。出错只记录。"""
    global _agg
    agg, _agg = _agg, {}
    if not agg:
        return
    try:
        from . import db
        con = db.open_db()
        try:
            data = []
            for dev, a in agg.items():
                if a["conns"] == 0 and a["closed"] == 0:
                    continue
                data.append((int(bucket), dev, a["conns"], a["tcp"], a["udp"], a["new"], a["closed"], a["syn"], a["unrep"],
                             json.dumps(_tops(rows, rcol, dev), ensure_ascii=False, separators=(",", ":"))))
            with con:
                con.executemany("INSERT OR REPLACE INTO conn_dev_min(ts,dev,conns,tcp,udp,new,closed,syn,unrep,top) VALUES(?,?,?,?,?,?,?,?,?,?)", data)
            STATE["last_flush"], STATE["flush_n"] = int(now), STATE["flush_n"] + len(data)
            if now - STATE["prune_at"] > 3600:
                STATE["prune_at"] = now
                prune(con, now)
        finally:
            con.close()
        STATE["err"] = ""
    except Exception as e:
        STATE["err"] = f"{type(e).__name__}: {e}"[:120]


# ---------------------------------------------------------------- 预算与清理
def storage(con):
    # 按实际内容长度统计(每行另加固定字段和索引开销约 90 字节),比固定估算准
    mn, mb = con.execute("SELECT COUNT(*), COALESCE(SUM(length(top)+length(dev)),0) FROM conn_dev_min").fetchone()
    ev, eb = con.execute("SELECT COUNT(*), COALESCE(SUM(length(title)+length(evidence)+length(diag)+length(dev)+length(kind)),0) FROM conn_event").fetchone()
    sn, sb = con.execute("SELECT COUNT(*), COALESCE(SUM(size),0) FROM conn_snap").fetchone()
    est = mb + mn * 90 + eb + ev * 120 + sb
    return {"minute_rows": mn, "events": ev, "snaps": sn, "snap_bytes": sb, "est_bytes": est, "budget_bytes": CFG["budget_mb"] * 1048576,
            "min_row_bytes": int(mb / mn + 90) if mn else 0}


def prune(con, now):
    """按档位保留天数清理;超出预算先清最老的快照,再缩短历史;磁盘不足时进一步收缩。"""
    p = params()
    hist_days, ev_days = p["hist"], p["events"]
    hw = read_hw(now)
    low = hw.get("disk_free_mb") is not None and hw["disk_free_mb"] < 1024
    if low:
        hist_days = max(1, hist_days // 2)
        STATE["storage_note"] = f"数据盘只剩 {hw['disk_free_mb']} MB,历史保留缩短为 {hist_days} 天,快照暂停写入"
    else:
        STATE["storage_note"] = ""
    with con:
        con.execute("DELETE FROM conn_dev_min WHERE ts<?", (int(now) - hist_days * 86400,))
        old = [r[0] for r in con.execute("SELECT id FROM conn_event WHERE ts_start<?", (int(now) - ev_days * 86400,))]
        for i in old:
            con.execute("DELETE FROM conn_snap WHERE event_id=?", (i,))
            con.execute("DELETE FROM conn_event WHERE id=?", (i,))
    st = storage(con)
    budget = st["budget_bytes"]
    if st["est_bytes"] > budget or (low and st["snap_bytes"]):
        # 1) 清最老的快照(保留事件摘要)
        target = budget * 0.5 if not low else 0
        with con:
            for i, sz in con.execute("SELECT event_id, size FROM conn_snap ORDER BY ts ASC").fetchall():
                if st["snap_bytes"] <= target and st["est_bytes"] <= budget:
                    break
                con.execute("DELETE FROM conn_snap WHERE event_id=?", (i,))
                st["snap_bytes"] -= sz
                st["est_bytes"] -= sz
        # 2) 还超就缩短历史
        d = hist_days
        while st["est_bytes"] > budget and d > 1:
            d -= 1
            with con:
                n = con.execute("DELETE FROM conn_dev_min WHERE ts<?", (int(now) - d * 86400,)).rowcount
            st["est_bytes"] -= n * (st.get("min_row_bytes") or 250)
        STATE["storage_note"] = (STATE["storage_note"] + ";" if STATE["storage_note"] else "") + f"新增数据超出 {CFG['budget_mb']} MB 预算,已清理旧快照 / 缩短历史"
    return st


# ---------------------------------------------------------------- 事件与快照
def _compact(rows, rcol, dev, now, n):
    out = []
    for r in rows:
        if r[rcol["dev"]] != dev:
            continue
        out.append([r[rcol["proto"]], r[rcol["host"]] or r[rcol["dst"]] or "", r[rcol["dport"]], r[rcol["node"]], r[rcol["state"]],
                    int(now - r[rcol["start"]]) if r[rcol["start"]] else None, r[rcol["up"]] + r[rcol["down"]], r[rcol["link"]]])
        if len(out) >= n:
            break
    return out


def trigger(dev, kind, level, title, evidence, now=None, rows=None, rcol=None, diag=None):
    """记录一条异常事件(同一设备同一类型进行中只记一条,后续触发只更新)。返回事件 id;出错返回 0。"""
    now = now or time.time()
    try:
        with _lock:
            a = ACTIVE.get((dev, kind))
            from . import db
            con = db.open_db()
            try:
                if a:
                    a["last"] = now
                    rank = {"unknown": 0, "attention": 1, "suspect": 2}
                    if rank.get(level, 0) > rank.get(a["level"], 0):
                        a["level"] = level
                    with con:
                        con.execute("UPDATE conn_event SET level=?, evidence=?, diag=? WHERE id=?",
                                    (a["level"], json.dumps(evidence, ensure_ascii=False), json.dumps(diag or {}, ensure_ascii=False), a["id"]))
                    return a["id"]
                p = params()
                # 刚结束不久(15 分钟内)的同类事件又出现:接着原来的事件记,不另开一条,避免一台设备反复抖动刷出一串事件
                prev = con.execute("SELECT id,level FROM conn_event WHERE dev=? AND kind=? AND status='closed' AND ts_end>=? ORDER BY id DESC LIMIT 1",
                                   (dev, kind, int(now) - 900)).fetchone()
                if prev:
                    lv = level if {"unknown": 0, "attention": 1, "suspect": 2}.get(level, 0) > {"unknown": 0, "attention": 1, "suspect": 2}.get(prev[1], 0) else prev[1]
                    with con:
                        con.execute("UPDATE conn_event SET ts_end=0, status='open', level=?, evidence=?, diag=? WHERE id=?",
                                    (lv, json.dumps(evidence, ensure_ascii=False), json.dumps(diag or {}, ensure_ascii=False), prev[0]))
                    ACTIVE[(dev, kind)] = {"id": prev[0], "dev": dev, "kind": kind, "level": lv, "start": now, "last": now, "post_until": now,
                                           "pre": [], "at": None, "post": [], "done": True}
                    return prev[0]
                with con:
                    cur = con.execute("INSERT INTO conn_event(ts_start,ts_end,dev,kind,level,title,evidence,diag,status) VALUES(?,?,?,?,?,?,?,?,?)",
                                      (int(now), 0, dev, kind, level, title[:200], json.dumps(evidence, ensure_ascii=False), json.dumps(diag or {}, ensure_ascii=False), "open"))
                eid = cur.lastrowid
            finally:
                con.close()
            snap_at = None
            if rows is not None and rcol is not None:
                snap_at = {"ts": int(now), "rows": _compact(rows, rcol, dev, now, p["snap_rows"]) if p["snap_rows"] else [],
                           "tops": _tops(rows, rcol, dev)}
            ACTIVE[(dev, kind)] = {"id": eid, "dev": dev, "kind": kind, "level": level, "start": now, "last": now, "post_until": now + p["post"],
                                   "pre": [list(x) for x in RING.get(dev, ())], "at": snap_at, "post": [], "done": False}
            return eid
    except Exception as e:
        STATE["err"] = f"事件记录出错 {type(e).__name__}: {e}"[:120]
        return 0


def tick(now, dstat, ct_dev):
    """每次刷新后调用:给进行中的事件追加「异常后」采样;窗口结束写快照;长时间没有再触发的事件自动结束。"""
    if not ACTIVE:
        return
    try:
        with _lock:
            for key, a in list(ACTIVE.items()):
                dev = a["dev"]
                if not a["done"]:
                    r = RING.get(dev)
                    if r and r[-1][0] >= now - 1 and (not a["post"] or a["post"][-1][0] != r[-1][0]):
                        a["post"].append(list(r[-1]))
                    if now >= a["post_until"]:
                        _write_snap(a)
                        a["done"] = True
                if now - a["last"] >= 300 and a["done"]:
                    _close(a, now)
                    del ACTIVE[key]
    except Exception as e:
        STATE["err"] = f"事件跟踪出错 {type(e).__name__}: {e}"[:120]


def resolve(dev, kind, now=None):
    """检测到恢复正常时由调用方结束事件(快照没写完会先写)。"""
    now = now or time.time()
    with _lock:
        a = ACTIVE.pop((dev, kind), None)
        if a:
            if not a["done"]:
                _write_snap(a)
                a["done"] = True
            _close(a, now)


def _close(a, now):
    from . import db
    con = db.open_db()
    try:
        with con:
            con.execute("UPDATE conn_event SET ts_end=?, status='closed' WHERE id=?", (int(now), a["id"]))
    finally:
        con.close()


def _write_snap(a):
    hw = read_hw()
    if hw.get("disk_free_mb") is not None and hw["disk_free_mb"] < 1024:
        STATE["snap_skipped"] = "数据盘空间不足,未保存现场快照"
        return
    payload = {"pre": a["pre"], "at": a["at"], "post": a["post"], "cols": ["ts", "conns", "tcp", "udp", "new", "closed", "syn", "unrep"],
               "row_cols": ["proto", "target", "port", "node", "state", "age", "bytes", "link"]}
    s = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    while len(s) > 300_000 and payload["at"] and payload["at"]["rows"]:
        payload["at"]["rows"] = payload["at"]["rows"][:len(payload["at"]["rows"]) // 2]
        s = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    from . import db
    con = db.open_db()
    try:
        with con:
            con.execute("INSERT OR REPLACE INTO conn_snap(event_id,ts,size,payload) VALUES(?,?,?,?)", (a["id"], int(a["start"]), len(s), s))
        STATE["snap_skipped"] = ""
        st = storage(con)
        if st["est_bytes"] > st["budget_bytes"]:
            prune(con, time.time())
    finally:
        con.close()


# ---------------------------------------------------------------- 查询
def trend(con, dev="", minutes=60, now=None, maxpts=240, since=None, until=None):
    """设备(或全网)连接数趋势。点太多时按时间段聚合:连接数取最大,新增 / 关闭取合计。since / until 为自定义时间范围(秒级时间戳)。"""
    now = now or time.time()
    if since:
        until = int(until or now)
        since = int(since)
        if until <= since:
            until = since + 300
        minutes = max(5, min(60 * 24 * 90, (until - since) // 60))
    else:
        minutes = max(5, min(60 * 24 * 30, int(minutes)))
        since, until = int(now) - minutes * 60, int(now) + 60
    if dev:
        rows = con.execute("SELECT ts,conns,tcp,udp,new,closed,syn,unrep FROM conn_dev_min WHERE dev=? AND ts>=? AND ts<=? ORDER BY ts", (dev, since, until)).fetchall()
    else:
        rows = con.execute("SELECT ts,SUM(conns),SUM(tcp),SUM(udp),SUM(new),SUM(closed),SUM(syn),SUM(unrep) FROM conn_dev_min WHERE ts>=? AND ts<=? GROUP BY ts ORDER BY ts", (since, until)).fetchall()
    step = max(1, -(-len(rows) // maxpts)) if rows else 1
    out = []
    for i in range(0, len(rows), step):
        g = rows[i:i + step]
        out.append({"ts": g[0][0], "conns": max(x[1] for x in g), "tcp": max(x[2] for x in g), "udp": max(x[3] for x in g),
                    "new": sum(x[4] for x in g), "closed": sum(x[5] for x in g), "syn": max(x[6] for x in g), "unrep": max(x[7] for x in g)})
    return {"dev": dev, "minutes": minutes, "since": since, "until": until, "res_min": params()["res"], "step": step, "rows": out}


def _ev_row(r):
    return {"id": r[0], "ts_start": r[1], "ts_end": r[2], "dev": r[3], "kind": r[4], "level": r[5], "level_name": LEVELS.get(r[5], r[5]), "title": r[6], "status": r[9]}


def events(con, dev="", hours=24 * 7, limit=100, now=None):
    now = now or time.time()
    sql = "SELECT id,ts_start,ts_end,dev,kind,level,title,evidence,diag,status FROM conn_event WHERE ts_start>=?"
    args = [int(now) - int(hours) * 3600]
    if dev:
        sql += " AND dev=?"
        args.append(dev)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(max(1, min(500, int(limit))))
    return [_ev_row(r) for r in con.execute(sql, args)]


def event_detail(con, eid):
    r = con.execute("SELECT id,ts_start,ts_end,dev,kind,level,title,evidence,diag,status FROM conn_event WHERE id=?", (int(eid),)).fetchone()
    if not r:
        return None
    out = _ev_row(r)
    for k, v in (("evidence", r[7]), ("diag", r[8])):
        try:
            out[k] = json.loads(v or "{}")
        except ValueError:
            out[k] = {}
    s = con.execute("SELECT payload FROM conn_snap WHERE event_id=?", (int(eid),)).fetchone()
    try:
        out["snapshot"] = json.loads(s[0]) if s else None
    except ValueError:
        out["snapshot"] = None
    out["snapshot_pending"] = bool(not s and (r[3], r[4]) in ACTIVE and not ACTIVE[(r[3], r[4])]["done"])
    return out


def system(con):
    p = params()
    out = {"tier": STATE["tier"], "tier_name": TIER_NAME[STATE["tier"]], "forced": CFG["tier"] != "auto", "since": int(STATE["since"]),
           "reasons": list(STATE["reasons"]), "hw": dict(STATE["hw"]), "params": p, "cfg": cfg_out(),
           "last_flush": STATE["last_flush"], "err": STATE["err"], "storage_note": STATE["storage_note"], "snap_skipped": STATE["snap_skipped"],
           "active_events": len(ACTIVE)}
    try:
        out["storage"] = storage(con)
    except Exception:
        out["storage"] = None
    return out
