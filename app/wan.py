"""宽带质量:定时给「默认网关」和几个公共 DNS 发 ICMP 回显(不通过 nikki,走路由器直连),记录延迟和丢包;
同时记录 WAN 掉线/恢复和 WAN 口 IP 变化。用来分清是「宽带/运营商」的问题还是「机场/节点」的问题。
全部只读、只发很小的探测包(每 30 秒每个目标 3 个)。没有 ICMP 权限时退回用 TCP 53 端口的连接耗时。"""
import collections
import fcntl
import os
import socket
import struct
import threading
import time

from .util import log, stop

PROC = os.environ.get("SYS_PROC", "/proc")
EVERY = 30
DEFAULT_TARGETS = ["223.5.5.5", "114.114.114.114"]
SERIES = collections.defaultdict(lambda: collections.deque(maxlen=720))   # 目标 -> (ts, rtt 或 None),约 3 小时
STATE = {"at": 0, "gw": "", "iface": "", "ip": "", "up": None, "mode": "", "down_since": 0, "ip_changed": None}
_lock = threading.Lock()
_flush = {}
_id = os.getpid() & 0xFFFF


def default_route():
    """(网卡, 网关) 读 /proc/net/route;没有默认路由返回 ("", "")。"""
    try:
        with open(PROC + "/net/route") as f:
            next(f)
            for line in f:
                p = line.split()
                if len(p) >= 8 and p[1] == "00000000" and int(p[3], 16) & 2:
                    gw = socket.inet_ntoa(struct.pack("<L", int(p[2], 16)))
                    return p[0], ("" if gw == "0.0.0.0" else gw)
    except Exception:
        pass
    return "", ""


def iface_ip(name):
    if not name:
        return ""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", name[:15].encode()))[20:24])
    except Exception:
        return ""
    finally:
        s.close()


def _csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def icmp_ping(addr, seq, timeout=1.0):
    """返回毫秒或 None;没有权限抛 PermissionError。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    try:
        body = struct.pack("!BBHHH", 8, 0, 0, _id, seq) + b"flux-wanq"
        pkt = struct.pack("!BBHHH", 8, 0, _csum(body), _id, seq) + b"flux-wanq"
        t0 = time.time()
        s.sendto(pkt, (addr, 0))
        while True:
            left = timeout - (time.time() - t0)
            if left <= 0:
                return None
            s.settimeout(left)
            try:
                data, src = s.recvfrom(1024)
            except socket.timeout:
                return None
            ihl = (data[0] & 15) * 4
            if len(data) >= ihl + 8:
                t, _c, _k, pid, ps = struct.unpack("!BBHHH", data[ihl:ihl + 8])
                if t == 0 and pid == _id and ps == seq and src[0] == addr:
                    return round((time.time() - t0) * 1000, 1)
    except OSError as e:
        if isinstance(e, PermissionError):
            raise
        return None
    finally:
        s.close()


def tcp_ping(addr, timeout=1.0, port=53):
    t0 = time.time()
    try:
        c = socket.create_connection((addr, port), timeout=timeout)
        c.close()
        return round((time.time() - t0) * 1000, 1)
    except OSError:
        return None


def probe(addr, seq):
    if STATE["mode"] != "tcp":
        try:
            STATE["mode"] = "icmp"
            return icmp_ping(addr, seq)
        except PermissionError:
            STATE["mode"] = "tcp"
    return tcp_ping(addr)


def sample(targets=None, now=None):
    now = now or time.time()
    iface, gw = default_route()
    ip = iface_ip(iface)
    with _lock:
        was = STATE["up"]
        STATE.update(at=int(now), gw=gw, iface=iface, up=bool(iface))
        if iface and ip and STATE["ip"] and ip != STATE["ip"]:
            STATE["ip_changed"] = {"old": STATE["ip"], "new": ip, "at": int(now)}
        if ip:
            STATE["ip"] = ip
        if was is not False and not iface:
            STATE["down_since"] = int(now)
        if iface:
            STATE["down_since"] = 0
    if not iface:
        for t in list(SERIES):
            SERIES[t].append((now, None))
        return
    tl = ([gw] if gw else []) + [t for t in (targets or DEFAULT_TARGETS) if t != gw]
    for t in tl:
        for i in range(3):
            r = probe(t, (int(now) + i) & 0xFFFF)
            with _lock:
                SERIES[t].append((now + i * 0.3, r))
            if i < 2:
                time.sleep(0.2)


def window(secs=300, now=None):
    """每个目标最近 secs 秒的 {n, lost, avg, max};网关单独标出。"""
    now = now or time.time()
    out = {}
    with _lock:
        for t, d in SERIES.items():
            v = [r for ts, r in d if ts >= now - secs]
            if not v:
                continue
            ok = [r for r in v if r is not None]
            out[t] = {"n": len(v), "lost": len(v) - len(ok), "loss": round((len(v) - len(ok)) * 100 / len(v)),
                      "avg": round(sum(ok) / len(ok), 1) if ok else None, "max": max(ok) if ok else None, "gw": t == STATE["gw"]}
    return out


def flush(con, now=None):
    """把 3 分钟内的新样本按小时汇总进 wanq 表。"""
    now = now or time.time()
    hour = time.strftime("%Y-%m-%d %H", time.localtime(now))
    with _lock:
        rows = []
        for t, d in SERIES.items():
            last = _flush.get(t, 0)
            new = [(ts, r) for ts, r in d if ts > last]
            if not new:
                continue
            _flush[t] = new[-1][0]
            ok = [r for _, r in new if r is not None]
            rows.append((hour, t, len(new), len(new) - len(ok), sum(ok), max(ok) if ok else 0))
    if rows:
        with con:
            con.executemany("INSERT INTO wanq(hour,target,n,lost,sum_rtt,max_rtt) VALUES(?,?,?,?,?,?) ON CONFLICT(hour,target) DO UPDATE SET "
                            "n=n+excluded.n, lost=lost+excluded.lost, sum_rtt=sum_rtt+excluded.sum_rtt, max_rtt=MAX(max_rtt,excluded.max_rtt)", rows)


def hours(con, n=24):
    since = time.strftime("%Y-%m-%d %H", time.localtime(time.time() - n * 3600))
    out = {}
    for h, t, c, lost, s, mx in con.execute("SELECT hour,target,n,lost,sum_rtt,max_rtt FROM wanq WHERE hour>=? ORDER BY hour", (since,)):
        ok = c - lost
        out.setdefault(t, []).append({"hour": h, "n": c, "loss": round(lost * 100 / c) if c else 0, "avg": round(s / ok, 1) if ok else None, "max": mx})
    return out


def snapshot():
    with _lock:
        s = dict(STATE)
    s["targets"] = window()
    return s


def run(get_targets=None):
    from . import db
    con = db.open_db()
    last = 0
    while not stop.is_set():
        try:
            sample(get_targets() if get_targets else None)
            if time.time() - last > 180:
                flush(con)
                last = time.time()
        except Exception as e:
            log("宽带质量探测出错", e)
        stop.wait(EVERY)
