"""设备:IP→MAC(邻居表)、设备命名、导入 uci 静态绑定。"""
import os
import shlex
import socket
import struct
import subprocess
import threading
import time

from . import config
from .util import is_mac, log

LEASES_FILE = os.environ.get("DHCP_LEASES", "/host/tmp/dhcp.leases")  # 可选
NEIGH_FILE = os.environ.get("NEIGH_FILE", "")  # 仅测试用:`ip neigh` 文本

RTM_NEWNEIGH, RTM_GETNEIGH, NLMSG_DONE, NLMSG_ERROR = 28, 30, 3, 2
NDA_DST, NDA_LLADDR = 1, 2
NUD_INCOMPLETE, NUD_FAILED = 0x01, 0x20


# ---------------------------------------------------------------- 邻居表
def _fmt_ip(family, raw):
    try:
        return socket.inet_ntop(family, raw)
    except (ValueError, OSError):
        return ""


NUD_FRESH = 0x02 | 0x08 | 0x10   # REACHABLE / DELAY / PROBE:内核最近确认过这台设备在线(STALE 不算)


def parse_neigh_dump(buf, fresh=None):
    """解析 netlink RTM_GETNEIGH 的回包,返回 {ip: mac};传入 fresh(set)时,把「最近确认在线」的 MAC 也放进去。"""
    out, off = {}, 0
    while off + 16 <= len(buf):
        ln, typ, _flags, _seq, _pid = struct.unpack_from("=IHHII", buf, off)
        if ln < 16 or off + ln > len(buf):
            break
        if typ == NLMSG_DONE:
            break
        if typ == RTM_NEWNEIGH and ln >= 16 + 12:
            family, _p1, _p2, _ifi, state, _fl, _type = struct.unpack_from("=BBHiHBB", buf, off + 16)
            if not state & (NUD_FAILED | NUD_INCOMPLETE) and family in (socket.AF_INET, socket.AF_INET6):
                ip = mac = None
                a, end = off + 16 + 12, off + ln
                while a + 4 <= end:
                    alen, atype = struct.unpack_from("=HH", buf, a)
                    if alen < 4:
                        break
                    val = buf[a + 4:a + alen]
                    t = atype & 0x3FFF
                    if t == NDA_DST:
                        ip = _fmt_ip(family, val)
                    elif t == NDA_LLADDR and len(val) == 6:
                        mac = ":".join(f"{b:02x}" for b in val)
                    a += (alen + 3) & ~3
                if ip and mac and mac != "00:00:00:00:00:00":
                    out[ip] = mac
                    if fresh is not None and state & NUD_FRESH:
                        fresh.add(mac)
        off += (ln + 3) & ~3
    return out


def _netlink_neigh(fresh=None):
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
    s.settimeout(3)
    try:
        s.bind((0, 0))
        hdr = struct.pack("=IHHII", 16 + 12, RTM_GETNEIGH, 0x01 | 0x300, 1, 0)
        s.send(hdr + struct.pack("=BBHiHBB", 0, 0, 0, 0, 0, 0, 0))
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
            # 看最后一条是不是 DONE
            off, done = 0, False
            while off + 16 <= len(data):
                ln, typ = struct.unpack_from("=IH", data, off)
                if ln < 16:
                    break
                if typ in (NLMSG_DONE, NLMSG_ERROR):
                    done = True
                    break
                off += (ln + 3) & ~3
            if done:
                break
        return parse_neigh_dump(data, fresh)
    finally:
        s.close()


def parse_ip_neigh(text, fresh=None):
    out = {}
    for line in text.splitlines():
        p = line.split()
        if len(p) >= 4 and "lladdr" in p:
            mac = p[p.index("lladdr") + 1].lower()
            if is_mac(mac) and mac != "00:00:00:00:00:00" and p[-1] not in ("FAILED", "INCOMPLETE"):
                out[p[0]] = mac
                if fresh is not None and p[-1] in ("REACHABLE", "DELAY", "PROBE"):
                    fresh.add(mac)
    return out


def read_proc_arp():
    out = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                p = line.split()
                if len(p) >= 4 and is_mac(p[3].lower()) and p[3] != "00:00:00:00:00:00":
                    out[p[0]] = p[3].lower()
    except OSError:
        pass
    return out


def read_neigh(fresh=None):
    """{ip: mac}。顺序:netlink(IPv4+IPv6)→ `ip neigh` → /proc/net/arp(仅 IPv4)。
    传入 fresh(set)时,内核最近确认在线(REACHABLE/DELAY/PROBE)的 MAC 会被加进去(/proc/net/arp 没有状态,不加)。"""
    if NEIGH_FILE:
        try:
            with open(NEIGH_FILE, encoding="utf-8") as f:
                return parse_ip_neigh(f.read(), fresh)
        except OSError:
            return {}
    try:
        r = _netlink_neigh(fresh)
        if r:
            return r
    except Exception:
        pass
    try:
        r = parse_ip_neigh(subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=4).stdout, fresh)
        if r:
            return r
    except Exception:
        pass
    return read_proc_arp()


# ---------------------------------------------------------------- uci 静态绑定
def parse_uci_text(text):
    """支持两种粘贴格式:`uci show dhcp` 输出,和 /etc/config/dhcp 原文。
    返回 [{"name":..., "mac":[...], "ip":[...]}](只含 host 段)。"""
    secs, order = {}, []

    def sec(k):
        if k not in secs:
            secs[k] = {"type": "", "opts": {}}
            order.append(k)
        return secs[k]

    cur = None
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("config "):  # 配置文件格式
            try:
                p = shlex.split(s)
            except ValueError:
                cur = None
                continue
            cur = f"_c{len(order)}"
            sec(cur)["type"] = p[1] if len(p) > 1 else ""
            continue
        if s.startswith(("option ", "list ")) and cur:
            try:
                p = shlex.split(s)
            except ValueError:
                continue
            if len(p) >= 3:
                secs[cur]["opts"].setdefault(p[1], []).extend(p[2:])
            continue
        if "=" in s and s.startswith("dhcp."):  # uci show 格式
            left, _, right = s.partition("=")
            parts = left.split(".")
            if len(parts) == 2:
                sec(parts[1])["type"] = right.strip("'\"")
            elif len(parts) == 3:
                try:
                    vals = shlex.split(right)
                except ValueError:
                    vals = [right.strip("'\"")]
                sec(parts[1])["opts"].setdefault(parts[2], []).extend(vals)
    out = []
    for k in order:
        if secs[k]["type"] != "host":
            continue
        o = secs[k]["opts"]
        name = (o.get("name") or [""])[0]
        macs = [m.lower() for v in o.get("mac", []) for m in v.split() if is_mac(m.lower())]
        ips = [i for v in o.get("ip", []) for i in v.split()]
        if name and (macs or ips):
            out.append({"name": name, "mac": macs, "ip": ips})
    return out


# ---------------------------------------------------------------- 邻居缓存 + 名字
class Neigh:
    """IP→MAC 缓存,线程内使用。"""

    def __init__(self, con):
        self.map = {r[0]: r[1] for r in con.execute("SELECT ip, mac FROM ipmap")}
        self.dirty = {}
        self.at = 0.0
        self.miss = {}

    def refresh(self, force=False):
        now = time.time()
        if now - self.at < (3 if force else 30):
            return
        self.at = now
        for ip, mac in read_neigh().items():
            if self.map.get(ip) != mac:
                self.map[ip] = mac
                self.dirty[ip] = mac

    def key(self, ip):
        """设备主键:有 MAC 用 MAC,没有就用 IP。"""
        ip = (ip or "").strip()
        if not ip:
            return "unknown"
        mac = self.map.get(ip)
        if mac:
            return mac
        self.refresh()
        if time.time() - self.miss.get(ip, 0) > 60:
            self.miss[ip] = time.time()
            self.refresh(force=True)
        return self.map.get(ip) or ip


class Names:
    """名字:库里的 devices 表(页面改名/导入)优先,其次 DHCP 租约主机名。"""

    def __init__(self):
        self.leases_mac, self.leases_ip = {}, {}
        self.mt = "x"
        self.checked = 0.0
        self.lock = threading.Lock()

    def _leases(self):
        with self.lock:
            if time.time() - self.checked < 15:
                return
            self.checked = time.time()
            try:
                m = os.stat(LEASES_FILE).st_mtime
            except OSError:
                m = None
            if m == self.mt:
                return
            self.mt = m
            self.leases_mac, self.leases_ip = {}, {}
            if m is None:
                return
            try:
                with open(LEASES_FILE, encoding="utf-8") as f:
                    for line in f:
                        p = line.split()
                        if len(p) >= 4 and p[3] != "*":
                            self.leases_mac[p[1].lower()] = p[3]
                            self.leases_ip[p[2]] = p[3]
            except OSError:
                pass

    def label(self, key, ips, stored):
        """stored = devices 表 {dev: name}"""
        self._leases()
        k = key.lower()
        if k in stored:
            return stored[k]
        for ip in ips:
            if ip in stored:
                return stored[ip]
        if key in local_ips() or any(i in local_ips() for i in ips):
            return "路由器本机"
        if k in self.leases_mac:
            return self.leases_mac[k]
        for ip in list(ips) + [key]:
            if ip in self.leases_ip:
                return self.leases_ip[ip]
        return ""


_LOCAL = {"t": 0.0, "v": frozenset()}


def local_ips():
    """路由器自己的所有 IP(v4 读 fib_trie,v6 读 if_inet6)。容器是 host 网络,看到的就是路由器本机。60 秒缓存。"""
    if time.time() - _LOCAL["t"] < 60:
        return _LOCAL["v"]
    base = os.environ.get("SYS_PROC", "/proc")
    out = set()
    try:
        with open(base + "/net/fib_trie") as f:
            last = ""
            for line in f:
                t = line.strip()
                if t.startswith(("|--", "+--")) and "|--" in t:
                    last = t.split("|--", 1)[1].strip()
                elif "/32 host LOCAL" in t and last:
                    out.add(last)
    except OSError:
        pass
    try:
        with open(base + "/net/if_inet6") as f:
            for line in f:
                h = line.split()[0]
                if len(h) == 32:
                    out.add(socket.inet_ntop(socket.AF_INET6, bytes.fromhex(h)))
    except (OSError, ValueError):
        pass
    _LOCAL.update(t=time.time(), v=frozenset(out))
    return _LOCAL["v"]


NAMES = Names()


def stored_names(con):
    return {k.lower(): v for k, v in con.execute("SELECT dev, name FROM devices")}


def rename(con, dev, name):
    dev = (dev or "").strip().lower()
    name = (name or "").strip()[:60]
    if not dev:
        raise ValueError("缺少设备")
    with con:
        if name:
            con.execute("INSERT INTO devices(dev,name) VALUES(?,?) ON CONFLICT(dev) DO UPDATE SET name=excluded.name",
                        (dev, name))
        else:
            con.execute("DELETE FROM devices WHERE dev=?", (dev,))


def import_uci(con, text):
    hosts = parse_uci_text(text)
    n = 0
    with con:
        for h in hosts:
            keys = h["mac"] or h["ip"]
            for k in keys:
                con.execute("INSERT INTO devices(dev,name) VALUES(?,?) ON CONFLICT(dev) DO UPDATE SET name=excluded.name",
                            (k.lower(), h["name"][:60]))
                n += 1
    log(f"导入设备别名 {n} 条")
    return {"hosts": len(hosts), "entries": n}


def ips_by_dev(con):
    out = {}
    for ip, mac in con.execute("SELECT ip, mac FROM ipmap ORDER BY seen DESC"):
        out.setdefault(mac, []).append(ip)
    for mac in out:
        out[mac].sort(key=lambda x: (":" in x))  # IPv4 在前
    return out
