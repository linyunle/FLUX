"""IP → 国家 / ASN。纯标准库的 MMDB(MaxMind DB)读取器 + 可选的在线下载(DB-IP Lite,CC BY 4.0)。

数据库文件放在 data/geoip/ 下,名字里带 country / asn 的 .mmdb 都认(DB-IP Lite、MaxMind GeoLite2 都行)。
没有数据库时一切照常,只是「目的地国家」那块是空的。
"""
import gzip
import ipaddress
import os
import socket
import struct
import threading
import time
import urllib.request

from . import config
from .util import log

MARK = b"\xab\xcd\xefMaxMind.com"
BASE = os.environ.get("GEO_BASE", "https://download.db-ip.com/free")


class MMDB:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.buf = f.read()
        i = self.buf.rfind(MARK)
        if i < 0:
            raise ValueError("不是 MMDB 文件")
        self.meta, _ = self._dec(i + len(MARK), i + len(MARK))
        m = self.meta
        self.nodes = m["node_count"]
        self.rec = m["record_size"]
        self.ipv = m["ip_version"]
        self.node_bytes = self.rec * 2 // 8
        self.tree_size = self.nodes * self.node_bytes
        self.data_start = self.tree_size + 16
        self.v4 = 0
        if self.ipv == 6:  # IPv4 在 IPv6 树里的位置:前 96 位都是 0
            n = 0
            for _ in range(96):
                if n >= self.nodes:
                    break
                n = self._rec(n, 0)
            self.v4 = n

    # ---- 解码
    def _dec(self, p, base):
        b = self.buf
        ctrl = b[p]
        p += 1
        t = ctrl >> 5
        if t == 1:  # 指针
            sz = (ctrl >> 3) & 3
            v = ctrl & 7
            if sz == 0:
                ptr = (v << 8) | b[p]
                p += 1
            elif sz == 1:
                ptr = ((v << 16) | (b[p] << 8) | b[p + 1]) + 2048
                p += 2
            elif sz == 2:
                ptr = ((v << 24) | (b[p] << 16) | (b[p + 1] << 8) | b[p + 2]) + 526336
                p += 3
            else:
                ptr = int.from_bytes(b[p:p + 4], "big")
                p += 4
            val, _ = self._dec(base + ptr, base)
            return val, p
        if t == 0:
            t = b[p] + 7
            p += 1
        size = ctrl & 31
        if size == 29:
            size = 29 + b[p]
            p += 1
        elif size == 30:
            size = 285 + int.from_bytes(b[p:p + 2], "big")
            p += 2
        elif size == 31:
            size = 65821 + int.from_bytes(b[p:p + 3], "big")
            p += 3
        if t == 2:
            return b[p:p + size].decode("utf-8", "replace"), p + size
        if t == 3:
            return struct.unpack(">d", b[p:p + 8])[0], p + 8
        if t == 4:
            return bytes(b[p:p + size]), p + size
        if t in (5, 6, 9, 10):
            return int.from_bytes(b[p:p + size], "big"), p + size
        if t == 7:
            d = {}
            for _ in range(size):
                k, p = self._dec(p, base)
                d[k], p = self._dec(p, base)
            return d, p
        if t == 11:
            out = []
            for _ in range(size):
                v, p = self._dec(p, base)
                out.append(v)
            return out, p
        if t == 14:
            return bool(size), p
        if t == 15:
            return struct.unpack(">f", b[p:p + 4])[0], p + 4
        raise ValueError(f"未知数据类型 {t}")

    def _rec(self, n, bit):
        b, o = self.buf, n * self.node_bytes
        r = self.rec
        if r == 24:
            o += bit * 3
            return int.from_bytes(b[o:o + 3], "big")
        if r == 28:
            if bit == 0:
                return ((b[o + 3] & 0xF0) << 20) | int.from_bytes(b[o:o + 3], "big")
            return ((b[o + 3] & 0x0F) << 24) | int.from_bytes(b[o + 4:o + 7], "big")
        o += bit * 4
        return int.from_bytes(b[o:o + 4], "big")

    def get(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        bits = int(a)
        if a.version == 4:
            n, total, node = 32, 32, self.v4 if self.ipv == 6 else 0
        else:
            if self.ipv == 4:
                return None
            n, total, node = 128, 128, 0
        for i in range(total):
            if node >= self.nodes:
                break
            node = self._rec(node, (bits >> (n - 1 - i)) & 1)
        if node == self.nodes:
            return None
        if node < self.nodes:
            return None
        off = node - self.nodes - 16 + self.tree_size + 16
        val, _ = self._dec(off, self.tree_size + 16)
        return val


# ---------------------------------------------------------------- 数据库管理
_lock = threading.RLock()
_db = {"country": None, "asn": None}
_cache = {}
DL = {"running": False, "msg": "", "at": 0}


def dir_():
    return os.path.join(config.DATA_DIR, "geoip")


def _find(kind):
    d = dir_()
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return ""
    for n in names:
        if n.lower().endswith(".mmdb") and kind in n.lower() and not n.endswith(".tmp"):
            return os.path.join(d, n)
    return ""


def load():
    with _lock:
        _cache.clear()
        for kind in ("country", "asn"):
            _db[kind] = None
            p = _find(kind)
            if p:
                try:
                    _db[kind] = MMDB(p)
                except Exception as e:
                    log("读取 GeoIP 库失败", p, e)


def status():
    out = {"dir": dir_(), "download": dict(DL), "base": BASE}
    for kind in ("country", "asn"):
        m = _db[kind]
        out[kind] = ({"file": os.path.basename(m.path), "built": time.strftime("%Y-%m-%d", time.gmtime(m.meta.get("build_epoch", 0))),
                      "type": m.meta.get("database_type", ""), "size": len(m.buf)} if m else None)
    return out


def available():
    return bool(_db["country"] or _db["asn"])


def _rec_cc(r):
    if not isinstance(r, dict):
        return ""
    for k in ("country", "registered_country"):
        v = r.get(k)
        if isinstance(v, dict) and v.get("iso_code"):
            return str(v["iso_code"]).upper()
    return ""


def lookup(ip):
    """(国家码, ASN 文字) ;查不到给空串。带缓存。"""
    with _lock:
        v = _cache.get(ip)
        if v is not None:
            return v
        cc, asn = "", ""
        try:
            if _db["country"]:
                cc = _rec_cc(_db["country"].get(ip))
            if _db["asn"]:
                r = _db["asn"].get(ip)
                if isinstance(r, dict) and r.get("autonomous_system_number"):
                    asn = f"AS{r['autonomous_system_number']} {r.get('autonomous_system_organization', '')}".strip()[:60]
        except Exception:
            pass
        if len(_cache) > 20000:
            _cache.clear()
        _cache[ip] = (cc, asn)
        return cc, asn


def _fetch(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "FLUX"})
    with urllib.request.urlopen(req, timeout=60) as r:
        raw = r.read(80 * 1024 * 1024)
    data = gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw
    if MARK not in data:
        raise ValueError("下载的文件不是 MMDB")
    tmp = dest + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    MMDB(tmp)  # 能读才替换
    os.replace(tmp, dest)


def _download():
    try:
        os.makedirs(dir_(), exist_ok=True)
        t = time.time()
        for kind in ("country", "asn"):
            err = None
            for back in range(3):  # 本月没发布就退回上个月
                lt = time.localtime(t - back * 31 * 86400)
                url = f"{BASE}/dbip-{kind}-lite-{time.strftime('%Y-%m', lt)}.mmdb.gz"
                DL["msg"] = f"下载 {kind}…"
                try:
                    _fetch(url, os.path.join(dir_(), f"dbip-{kind}-lite.mmdb"))
                    err = None
                    break
                except Exception as e:
                    err = e
            if err:
                raise err
        load()
        DL["msg"] = "完成"
    except Exception as e:
        DL["msg"] = f"失败:{type(e).__name__}: {e}"[:160]
        log("GeoIP 下载失败", e)
    DL["running"] = False
    DL["at"] = int(time.time())


def start_download():
    if DL["running"]:
        return False
    DL.update(running=True, msg="开始下载…")
    threading.Thread(target=_download, name="geo-dl", daemon=True).start()
    return True
