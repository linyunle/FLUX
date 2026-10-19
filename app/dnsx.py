"""DNS 增强:dnsmasq 日志统计 + 自定义 DNS 服务器探测。(AdGuard Home 在 agh.py)

dnsmasq(OpenWrt 默认的 DNS):面板不改路由器任何设置,只读它通过「系统日志」转发过来的日志。
- 路由器要开 dnsmasq 的查询日志(logqueries),并且面板的「系统日志接收」已开启;没开就只能统计到 dnsmasq 的普通日志(DHCP / 告警等)。
- 查询日志量很大,所以 query / reply / cached / forwarded 这几类行在这里就地汇总成计数,不再逐条存进系统日志表;其余行(DHCP、警告、错误)照常保存。
自定义 DNS 服务器:填 名称 + 地址 + 端口,面板定时发一个真正的 DNS 查询(UDP),记录是否响应、耗时,保留 7 天的小时汇总。
"""
import ipaddress
import json
import random
import re
import socket
import struct
import threading
import time

from . import db
from .util import log, stop

QUERY = re.compile(r"^query\[(\w+)\]\s+(\S+)\s+from\s+(\S+)$")
FWD = re.compile(r"^forwarded\s+(\S+)\s+to\s+(\S+)$")
REPLY = re.compile(r"^(reply|cached|config)\s+(\S+)\s+is\s+(.+)$")
_lock = threading.Lock()
_mem = {"q": 0, "nx": 0, "cached": 0, "fwd": 0, "domain": {}, "client": {}, "upstream": {}, "nx_dom": {}, "type": {}}
STATE = {"last_query": 0, "folded": 0}
CAP = 4000
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def _bump(d, k, n=1):
    if k in d or len(d) < CAP:
        d[k] = d.get(k, 0) + n


def feed(tag, msg, now=None):
    """给系统日志接收线程用:是 dnsmasq 的查询类日志就计数并返回 True(调用方不再存这一行)。"""
    if tag != "dnsmasq":
        return False
    m = QUERY.match(msg)
    if m:
        with _lock:
            _mem["q"] += 1
            _bump(_mem["type"], m.group(1).upper())
            _bump(_mem["domain"], m.group(2).lower()[:120])
            _bump(_mem["client"], m.group(3))
            STATE["last_query"] = int(now or time.time())
            STATE["folded"] += 1
        return True
    m = FWD.match(msg)
    if m:
        with _lock:
            _mem["fwd"] += 1
            _bump(_mem["upstream"], m.group(2))
            STATE["folded"] += 1
        return True
    m = REPLY.match(msg)
    if m:
        with _lock:
            if m.group(1) == "cached":
                _mem["cached"] += 1
            if m.group(3).strip().upper().startswith("NXDOMAIN"):
                _mem["nx"] += 1
                _bump(_mem["nx_dom"], m.group(2).lower()[:120])
            STATE["folded"] += 1
        return True
    return False


def flush(con, now=None):
    """把内存里的计数写进库(按小时 / 按天)。syslog 线程每隔几秒调一次。"""
    now = now or time.time()
    with _lock:
        snap = {k: (dict(v) if isinstance(v, dict) else v) for k, v in _mem.items()}
        for k, v in _mem.items():
            _mem[k] = {} if isinstance(v, dict) else 0
    if not (snap["q"] or snap["fwd"] or snap["cached"] or snap["nx"]):
        return
    hour, day = time.strftime("%Y-%m-%d %H", time.localtime(now)), time.strftime("%Y-%m-%d", time.localtime(now))
    with con:
        con.execute("INSERT INTO dnsq_hour(hour,q,nx,cached,fwd) VALUES(?,?,?,?,?) ON CONFLICT(hour) DO UPDATE SET q=q+excluded.q,nx=nx+excluded.nx,cached=cached+excluded.cached,fwd=fwd+excluded.fwd",
                    (hour, snap["q"], snap["nx"], snap["cached"], snap["fwd"]))
        rows = [(day, kind, k, n) for kind in ("domain", "client", "upstream", "nx_dom", "type") for k, n in snap[kind].items()]
        con.executemany("INSERT INTO dnsq_top(day,kind,k,n) VALUES(?,?,?,?) ON CONFLICT(day,kind,k) DO UPDATE SET n=n+excluded.n", rows)


def prune(con, now=None):
    now = now or time.time()
    with con:
        con.execute("DELETE FROM dnsq_hour WHERE hour<?", (time.strftime("%Y-%m-%d %H", time.localtime(now - 8 * 86400)),))
        con.execute("DELETE FROM dnsq_top WHERE day<?", (time.strftime("%Y-%m-%d", time.localtime(now - 8 * 86400)),))
        con.execute("DELETE FROM dnsq_top WHERE (day,kind,k) IN (SELECT day,kind,k FROM (SELECT day,kind,k, ROW_NUMBER() OVER (PARTITION BY day,kind ORDER BY n DESC) rn FROM dnsq_top) WHERE rn>300)")
        con.execute("DELETE FROM dnsprobe WHERE hour<?", (time.strftime("%Y-%m-%d %H", time.localtime(now - 8 * 86400)),))


def dnsmasq_stats(con, names=None, now=None):
    """dnsmasq 的 24 小时 / 7 天统计;没收到过查询日志时 enabled=False 并给出开启办法。"""
    now = now or time.time()
    h24 = time.strftime("%Y-%m-%d %H", time.localtime(now - 86400))
    r = con.execute("SELECT COALESCE(SUM(q),0),COALESCE(SUM(nx),0),COALESCE(SUM(cached),0),COALESCE(SUM(fwd),0) FROM dnsq_hour WHERE hour>=?", (h24,)).fetchone()
    last = STATE["last_query"] or 0
    if not last:
        x = con.execute("SELECT MAX(hour) FROM dnsq_hour WHERE q>0").fetchone()[0]
        if x:
            last = int(time.mktime(time.strptime(x, "%Y-%m-%d %H")))
    out = {"enabled": bool(last), "last_query": last, "q24": r[0], "nx24": r[1], "cached24": r[2], "fwd24": r[3],
           "nx_rate": round(r[1] * 100 / r[0], 1) if r[0] else 0, "cache_rate": round(r[2] * 100 / r[0], 1) if r[0] else 0}
    day = time.strftime("%Y-%m-%d", time.localtime(now))
    d2 = time.strftime("%Y-%m-%d", time.localtime(now - 86400))

    def top(kind, n=10):
        return [(k, v) for k, v in con.execute("SELECT k,SUM(n) s FROM dnsq_top WHERE kind=? AND day>=? GROUP BY k ORDER BY s DESC LIMIT ?", (kind, d2, n))]
    names = names or {}
    out["top_domains"] = [{"d": k, "n": v} for k, v in top("domain")]
    out["top_nx"] = [{"d": k, "n": v} for k, v in top("nx_dom")]
    out["top_clients"] = [{"ip": k, "name": names.get(k, ""), "n": v} for k, v in top("client")]
    out["upstreams"] = [{"s": k, "n": v} for k, v in top("upstream", 6)]
    out["types"] = [{"t": k, "n": v} for k, v in top("type", 6)]
    ser = {r[0]: r[1] for r in con.execute("SELECT hour,q FROM dnsq_hour WHERE hour>=?", (h24,))}
    out["series"] = [ser.get(time.strftime("%Y-%m-%d %H", time.localtime(now - i * 3600)), 0) for i in range(23, -1, -1)]
    return out


def dnsmasq_lines(con, n=30, level=7):
    """dnsmasq / dnsmasq-dhcp 等相关的普通日志(查询类行已汇总,不在这里)。"""
    rows = con.execute("SELECT ts,sev,tag,msg FROM syslog WHERE (tag LIKE 'dnsmasq%' OR tag LIKE 'odhcpd%') AND sev<=? ORDER BY id DESC LIMIT ?", (level, n)).fetchall()
    return [{"ts": r[0], "sev": r[1], "tag": r[2], "msg": r[3]} for r in rows]


# ---------- 自定义 DNS 服务器 ----------
DEFAULT_CFG = {"servers": [], "domain": "www.baidu.com", "every": 60}


def load_cfg(con):
    c = {"servers": [], "domain": DEFAULT_CFG["domain"], "every": 60}
    try:
        r = con.execute("SELECT v FROM kv WHERE k='dns_cfg'").fetchone()
        d = json.loads(r[0]) if r else {}
    except Exception:
        d = {}
    if isinstance(d, dict):
        c["servers"] = [s for s in (d.get("servers") or []) if isinstance(s, dict) and s.get("host")][:12]
        c["domain"] = str(d.get("domain") or c["domain"])
        c["every"] = max(30, min(3600, int(d.get("every") or 60)))
    return c


def _check_host(h):
    h = str(h or "").strip()
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass
    if not HOST_RE.match(h) or len(h) > 253:
        raise ValueError("地址要填 IP 或域名")
    return h


def save_cfg(con, body):
    out = []
    for i, s in enumerate((body.get("servers") or [])[:12]):
        if not isinstance(s, dict):
            continue
        host = _check_host(s.get("host"))
        try:
            port = int(53 if s.get("port") in (None, "") else s.get("port"))
        except (TypeError, ValueError):
            raise ValueError("端口要填数字")
        if not 1 <= port <= 65535:
            raise ValueError("端口范围 1–65535")
        name = str(s.get("name") or "").strip()[:30] or f"{host}:{port}"
        out.append({"id": str(s.get("id") or "")[:12] or "s%x" % random.randrange(1 << 24), "name": name, "host": host, "port": port})
    if len({(s["host"], s["port"]) for s in out}) != len(out):
        raise ValueError("有重复的服务器(地址 + 端口相同)")
    dom = str(body.get("domain") or DEFAULT_CFG["domain"]).strip().lower()[:100]
    if not HOST_RE.match(dom):
        raise ValueError("测试域名格式不对,例如 www.baidu.com")
    try:
        every = max(30, min(3600, int(body.get("every") or 60)))
    except (TypeError, ValueError):
        raise ValueError("间隔要填数字(秒)")
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES('dns_cfg',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (json.dumps({"servers": out, "domain": dom, "every": every}, ensure_ascii=False),))
    return load_cfg(con)


def build_query(domain, qid=None):
    qid = qid if qid is not None else random.randrange(65536)
    q = b"".join(bytes([len(p)]) + p.encode("idna") for p in domain.strip(".").split(".")) + b"\x00"
    return qid, struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", 1, 1)


def probe_once(host, port, domain, timeout=2.0):
    """发一个 A 查询。返回 (耗时毫秒, 说明);耗时为 None 表示失败。收到任何合法响应都算服务器在工作(NXDOMAIN 也算)。"""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    except OSError as e:
        return None, f"解析不了地址:{e}"
    fam, _, _, _, addr = infos[0]
    qid, pkt = build_query(domain)
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        t = time.perf_counter()
        s.sendto(pkt, addr)
        while True:
            data, src = s.recvfrom(4096)
            if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == qid and data[2] & 0x80:
                ms = (time.perf_counter() - t) * 1000
                rc = data[3] & 15
                return round(ms, 1), {0: "正常", 2: "服务器故障(SERVFAIL)", 3: "域名不存在(NXDOMAIN)", 5: "拒绝(REFUSED)"}.get(rc, f"返回码 {rc}")
    except socket.timeout:
        return None, "超时无响应"
    except OSError as e:
        return None, f"{type(e).__name__}: {e}"
    finally:
        s.close()


LAST = {}      # id -> {ms, note, at}


def probe_all(con, now=None):
    now = now or time.time()
    c = load_cfg(con)
    hour = time.strftime("%Y-%m-%d %H", time.localtime(now))
    live = {s["id"] for s in c["servers"]}
    for k in list(LAST):
        if k not in live:
            LAST.pop(k, None)
    for s in c["servers"]:
        ms, note = probe_once(s["host"], s["port"], c["domain"])
        LAST[s["id"]] = {"ms": ms, "note": note, "at": int(now)}
        with con:
            con.execute("INSERT INTO dnsprobe(hour,sid,n,lost,sum_ms,max_ms) VALUES(?,?,1,?,?,?) ON CONFLICT(hour,sid) DO UPDATE SET n=n+1,lost=lost+excluded.lost,sum_ms=sum_ms+excluded.sum_ms,max_ms=MAX(max_ms,excluded.max_ms)",
                        (hour, s["id"], 0 if ms is not None else 1, ms or 0, ms or 0))


def servers_status(con, now=None):
    now = now or time.time()
    c = load_cfg(con)
    h24 = time.strftime("%Y-%m-%d %H", time.localtime(now - 86400))
    rows = []
    for s in c["servers"]:
        r = con.execute("SELECT COALESCE(SUM(n),0),COALESCE(SUM(lost),0),COALESCE(SUM(sum_ms),0),COALESCE(MAX(max_ms),0) FROM dnsprobe WHERE sid=? AND hour>=?", (s["id"], h24)).fetchone()
        ok = r[0] - r[1]
        ser = {x[0]: (x[1] / max(1, x[2] - x[3])) for x in con.execute("SELECT hour,sum_ms,n,lost FROM dnsprobe WHERE sid=? AND hour>=?", (s["id"], h24))}
        l = LAST.get(s["id"]) or {}
        rows.append({**s, "ms": l.get("ms"), "note": l.get("note", ""), "at": l.get("at", 0), "n24": r[0], "lost24": r[1],
                     "loss_pct": round(r[1] * 100 / r[0], 1) if r[0] else 0, "avg_ms": round(r[2] / ok, 1) if ok else None, "max_ms": round(r[3], 1),
                     "series": [round(ser[k], 1) if k in ser else None for k in (time.strftime("%Y-%m-%d %H", time.localtime(now - i * 3600)) for i in range(23, -1, -1))]})
    return {"servers": rows, "domain": c["domain"], "every": c["every"]}


def test(body):
    """设置页「测试」:不保存,直接试一次。"""
    host = _check_host(body.get("host"))
    try:
        port = int(53 if body.get("port") in (None, "") else body.get("port"))
    except (TypeError, ValueError):
        raise ValueError("端口要填数字")
    dom = str(body.get("domain") or DEFAULT_CFG["domain"]).strip().lower()
    if not HOST_RE.match(dom):
        raise ValueError("测试域名格式不对")
    ms, note = probe_once(host, port, dom)
    return {"ok": ms is not None, "ms": ms, "note": note}


def run():
    con = db.open_db()
    last = 0.0
    last_prune = 0.0
    while not stop.is_set():
        now = time.time()
        try:
            c = load_cfg(con)
            if c["servers"] and now - last >= c["every"]:
                last = now
                probe_all(con, now)
            if now - last_prune > 3600:
                last_prune = now
                prune(con, now)
        except Exception as e:
            log("DNS 探测出错", e)
        stop.wait(5)
