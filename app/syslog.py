"""路由器系统日志收集(可选,默认关闭)。

路由器把系统日志通过 UDP 转发给面板(路由器上只改一条 uci 设置),面板存进自己的 SQLite,
按「保留天数」和「最大条数」自动清理,所以不会往路由器的闪存/硬盘写日志,也不会越攒越多。
- 只接受内网来源(私有地址 / 回环 / 链路本地),WAN 口就算开放了这个端口也进不来。
- 每秒最多入库 300 条,超过的丢弃并计数,防止被日志风暴撑爆。
- UDP 本来就可能丢包,面板重启/容器停止期间的日志也不会补;这是用来排查问题的,不是审计级日志。
- 只读:面板不会改路由器的任何东西。"""
import collections
import ipaddress
import json
import re
import socket
import threading
import time

from . import db
from .util import log, stop

DEFAULT = {"on": False, "port": 5514, "days": 7, "max_rows": 100000}
SEV = ["紧急", "警报", "严重", "错误", "警告", "注意", "信息", "调试"]
RATE = 300
_state = {"bound": 0, "last_rx": 0, "rx": 0, "drop": 0, "bad": 0, "err": "", "pruned": 0, "last_prune": 0, "sys_last": None}
_lock = threading.Lock()

PRI = re.compile(r"^<(\d{1,3})>")
R3164 = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+(\S+)\s+(.*)$", re.S)
R5424 = re.compile(r"^\d\s+\S+\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s+(?:-|\[.*?\])\s*(.*)$", re.S)
FACLV = re.compile(r"^(?:kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|authpriv|ftp|local[0-7])\.(emerg|alert|crit|err|warn|notice|info|debug)\s+", re.I)
TAG = re.compile(r"^([^\s:\[\]]{1,48})(?:\[\d+\])?:\s*(.*)$", re.S)
LVL = {"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warn": 4, "notice": 5, "info": 6, "debug": 7}
# 值得推送的严重情况:内核/文件系统/内存方面的硬故障
CRIT = re.compile(r"out of memory|oom-kill|kernel panic|\boops\b|BUG:|segfault|I/O error|EXT4-fs error|XFS .*error|"
                  r"hung task|call trace|nf_conntrack: table full|Buffer I/O error|ata\d+.*(?:failed|error)", re.I)


def allowed_src(ip):
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local


def parse(data, src):
    """返回 (host, sev, tag, msg);解析不了的整条当消息。"""
    t = data.decode("utf-8", "replace").strip("\x00\r\n ")
    sev, host, tag = 6, src, ""
    m = PRI.match(t)
    if m:
        sev = int(m.group(1)) & 7
        t = t[m.end():]
    m = R5424.match(t) if re.match(r"^\d\s", t) else None
    if m:
        host = m.group(1) if m.group(1) != "-" else src
        tag, t = (m.group(2) if m.group(2) != "-" else ""), m.group(3)
    else:
        m = R3164.match(t)
        if m:
            host, t = m.group(1), m.group(2)
        f = FACLV.match(t)
        if f:
            if not PRI.match(data.decode("utf-8", "replace")):
                sev = LVL.get(f.group(1).lower(), sev)
            t = t[f.end():]
        m = TAG.match(t)
        if m:
            tag, t = m.group(1), m.group(2)
    return host[:64], sev, tag[:48], t.strip()[:1000]


def load_cfg(con):
    c = dict(DEFAULT)
    try:
        r = con.execute("SELECT v FROM kv WHERE k='syslog'").fetchone()
        v = json.loads(r[0]) if r else {}
    except Exception:
        v = {}
    if isinstance(v, dict):
        c["on"] = bool(v.get("on"))
        for k, lo, hi in (("port", 1024, 65535), ("days", 1, 90), ("max_rows", 1000, 1000000)):
            try:
                c[k] = max(lo, min(hi, int(v.get(k, c[k]))))
            except (TypeError, ValueError):
                pass
    return c


def save_cfg(con, body):
    try:
        def num(k, d):
            v = body.get(k)
            return d if v in (None, "") else int(v)
        c = {"on": bool(body.get("on")), "port": num("port", 5514), "days": num("days", 7), "max_rows": num("max_rows", 100000)}
    except (TypeError, ValueError):
        raise ValueError("端口、天数、条数要填数字")
    if not 1024 <= c["port"] <= 65535:
        raise ValueError("端口范围 1024–65535")
    if not 1 <= c["days"] <= 90:
        raise ValueError("保留天数范围 1–90")
    if not 1000 <= c["max_rows"] <= 1000000:
        raise ValueError("最大条数范围 1000–1000000")
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES('syslog',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (json.dumps(c),))
    return load_cfg(con)


def _insert(con, rows):
    if not rows:
        return
    with con:
        con.executemany("INSERT INTO syslog(ts,host,sev,tag,msg) VALUES(?,?,?,?,?)", rows)


def prune(con, cfg, now=None):
    now = now or time.time()
    with con:
        n = con.execute("DELETE FROM syslog WHERE ts<?", (int(now - cfg["days"] * 86400),)).rowcount
        r = con.execute("SELECT MAX(id) FROM syslog").fetchone()[0]
        if r:
            n += con.execute("DELETE FROM syslog WHERE id<=?", (r - cfg["max_rows"],)).rowcount
    _state["pruned"] += max(0, n)
    _state["last_prune"] = int(now)
    return n


def _bind(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.settimeout(1.0)
    return s


def run():
    con = db.open_db()
    sock, port, cfg, last_cfg, last_flush = None, 0, dict(DEFAULT), 0.0, time.time()
    buf, sec, cnt, retry = [], 0, 0, 0.0
    while not stop.is_set():
        now = time.time()
        if now - last_cfg > 5:
            last_cfg = now
            try:
                cfg = load_cfg(con)
            except Exception:
                pass
            want = cfg["port"] if cfg["on"] else 0
            if want != port and (want == 0 or now >= retry):
                if sock:
                    sock.close()
                    sock = None
                port = 0
                _state["bound"] = 0
                if want:
                    try:
                        sock = _bind(want)
                        port = want
                        _state.update(bound=want, err="")
                        log(f"系统日志接收已开启 UDP :{want}")
                    except OSError as e:
                        _state["err"] = f"端口 {want} 绑定失败:{e}"
                        retry = now + 30
                        log("系统日志", _state["err"])
        if not sock:
            stop.wait(1.0)
            continue
        try:
            data, addr = sock.recvfrom(8192)
        except socket.timeout:
            data = None
        except OSError:
            data = None
            stop.wait(1.0)
        if data is not None:
            if int(now) != sec:
                sec, cnt = int(now), 0
            cnt += 1
            if not allowed_src(addr[0]):
                _state["bad"] += 1
            elif cnt > RATE:
                _state["drop"] += 1
            else:
                h, sv, tg, msg = parse(data, addr[0])
                if msg:
                    buf.append((int(now), h, sv, tg, msg))
                    _state["rx"] += 1
                    _state["last_rx"] = int(now)
        if buf and (now - last_flush >= 2 or len(buf) >= 200):
            try:
                _insert(con, buf)
            except Exception as e:
                log("系统日志写库出错", e)
            buf, last_flush = [], now
        if now - _state["last_prune"] > 3600:
            try:
                prune(con, cfg, now)
            except Exception as e:
                log("系统日志清理出错", e)
                _state["last_prune"] = int(now)


def query(con, level=7, q="", n=200, before=0):
    n = max(1, min(1000, int(n)))
    sql, args = "SELECT id,ts,host,sev,tag,msg FROM syslog WHERE sev<=?", [max(0, min(7, int(level)))]
    if before:
        sql += " AND id<?"
        args.append(int(before))
    q = (q or "").strip()[:60]
    if q:
        sql += " AND (msg LIKE ? ESCAPE '\\' OR tag LIKE ? ESCAPE '\\' OR host LIKE ? ESCAPE '\\')"
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        args += [like, like, like]
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(n)
    return [{"id": r[0], "ts": r[1], "host": r[2], "sev": r[3], "lv": SEV[r[3]], "tag": r[4], "msg": r[5]}
            for r in con.execute(sql, args)]


def status(con):
    cfg = load_cfg(con)
    n, lo, hi, sz = con.execute("SELECT COUNT(*),MIN(ts),MAX(ts),SUM(LENGTH(msg)+LENGTH(tag)+LENGTH(host)+40) FROM syslog").fetchone()
    by = {r[0]: r[1] for r in con.execute("SELECT sev,COUNT(*) FROM syslog WHERE ts>=? GROUP BY sev", (int(time.time()) - 86400,))}
    return {"cfg": cfg, "bound": _state["bound"], "err": _state["err"], "rx": _state["rx"], "drop": _state["drop"], "bad": _state["bad"],
            "last_rx": _state["last_rx"], "rows": n or 0, "oldest": lo or 0, "newest": hi or 0, "bytes": sz or 0,
            "pruned": _state["pruned"], "by_sev_24h": {SEV[k]: v for k, v in sorted(by.items())}}


def clear(con):
    with con:
        n = con.execute("DELETE FROM syslog").rowcount
    return {"ok": True, "deleted": n}


def check(con, cfg, now):
    """严重级别(紧急/警报/严重)或命中硬故障关键词的新日志,汇总成一条告警。"""
    from . import alerts
    sc = load_cfg(con)
    if not sc["on"]:
        _state["sys_last"] = None
        return
    mx = con.execute("SELECT COALESCE(MAX(id),0) FROM syslog").fetchone()[0]
    last = _state["sys_last"]
    _state["sys_last"] = mx
    if last is None or mx <= last:
        return
    rows = con.execute("SELECT ts,host,sev,tag,msg FROM syslog WHERE id>? AND id<=? ORDER BY id LIMIT 2000", (last, mx)).fetchall()
    hit = [r for r in rows if r[2] <= 2 or CRIT.search(r[4]) or CRIT.search(r[3] or "")]
    if not hit:
        return
    r = cfg["rules"]["syslog_crit"]
    lines = "\n".join(f"{time.strftime('%H:%M:%S', time.localtime(x[0]))} [{SEV[x[2]]}] {x[3] + ': ' if x[3] else ''}{x[4][:160]}" for x in hit[:5])
    title = f"路由器日志出现 {len(hit)} 条严重信息"
    detail = f"{lines}\n(完整日志在「设置 → 系统日志」)"
    if r["on"] and alerts._allow("syslog_crit", "syslog", r["cool_min"], now):
        alerts.fire(con, cfg, "syslog_crit", "warn", "syslog", title, detail, now)
    else:
        alerts.note(con, "syslog_crit", "syslog", title, detail, level="warn", now=now)
