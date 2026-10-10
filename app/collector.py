"""采集:定时读 mihomo 的 /connections,算增量,按 天/设备/节点/策略组/规则/目标 累加。

方向:upload = 发往外网(库里 up),download = 从外网收到(down)。
精度:短于一个采样周期的连接看不到;连接关闭前最后一个周期的字节会丢;
      启动后第一次采样只记基线。
"""
import os
import time
import urllib.error

from . import config, db, devices
from .util import api_call, host_of, log, stop

PROC_NET_DEV = os.environ.get("PROC_NET_DEV", "/proc/net/dev")
WAN_IFACES = [x.strip() for x in os.environ.get("WAN_IFACE", "").split(",") if x.strip()]
BUILTIN_TYPES = {"direct", "reject", "rejectdrop", "compatible", "pass", "dns"}

COLLECTOR = None


class Collector:
    def __init__(self, con):
        global COLLECTOR
        COLLECTOR = self
        self.con = con
        self.seen = {}
        self.baseline_done = False
        self.buf, self.hbuf, self.wbuf, self.whbuf = {}, {}, {}, {}
        self.groups = {}      # 组名 -> (now, [成员])
        self.ptype = {}       # 名字 -> 类型
        self.nodes = {}       # 叶子节点 -> {type, delay}
        self.proxies_at = 0.0
        self.last_flush = time.time()
        self.last_poll_t = 0.0
        self.neigh = devices.Neigh(con)
        self.nodeinfo = {}
        self.ndirty = set()
        self.wan_last, self.wan_warned = {}, False
        self.live = {"at": 0, "nodes": {}, "clients": {}}
        self.status = {"ok": False, "error": "尚未连接", "last_ok": 0, "rev": -1}
        self.conf_rev = config.get()["rev"]
        self.mihomo_version = ""

    # ---- /proxies:策略组、节点类型、延迟
    def refresh_proxies(self, force=False):
        if not force and time.time() - self.proxies_at < 60:
            return
        try:
            proxies = api_call("/proxies").get("proxies", {})
        except Exception as e:
            log("读取 /proxies 失败(沿用旧缓存):", e)
            self.proxies_at = time.time() - 45
            return
        groups, ptype, nodes = {}, {}, {}
        for n, p in proxies.items():
            if not isinstance(p, dict):
                continue
            t = str(p.get("type") or "")
            ptype[n] = t
            if isinstance(p.get("all"), list):
                groups[n] = (p.get("now") or "", [str(x) for x in p["all"]])
            elif t.lower() not in BUILTIN_TYPES:
                hist = p.get("history") or []
                delay = int(hist[-1].get("delay") or 0) if hist and isinstance(hist[-1], dict) else None
                nodes[n] = {"type": t, "delay": delay}
        self.groups, self.ptype, self.nodes, self.proxies_at = groups, ptype, nodes, time.time()

    def leaf(self, chains):
        name = str(chains[0]) if chains else ""
        seen = set()
        while name in self.groups and name not in seen:
            seen.add(name)
            now, members = self.groups[name]
            nxt = now or (members[0] if members else "")
            if not nxt or nxt == name:
                break
            name = nxt
        return name or "UNKNOWN"

    @staticmethod
    def is_probe(m):
        return (str(m.get("inboundName") or "") == config.PROBE_LISTENER
                or str(m.get("inboundPort") or "") == str(config.PROBE_PORT))

    # ---- 一次采样
    def poll(self):
        t0 = time.time()
        data = api_call("/connections")
        self.refresh_proxies()
        conns = data.get("connections") or []
        elapsed = max(1.0, t0 - self.last_poll_t) if self.last_poll_t else config.INTERVAL
        self.last_poll_t = t0
        lt = time.localtime()
        day, hour = time.strftime("%Y-%m-%d", lt), time.strftime("%Y-%m-%d %H", lt)
        alive = set()
        live_n, live_c = {}, {}
        for c in conns:
            cid = c.get("id")
            if not cid:
                continue
            m = c.get("metadata") or {}
            if self.is_probe(m):  # 出口探测自己的连接不计入
                continue
            alive.add(cid)
            chains = c.get("chains") or []
            node = self.leaf(chains)
            client = self.neigh.key(str(m.get("sourceIP") or ""))
            ln = live_n.setdefault(node, [0, 0, 0])
            lc = live_c.setdefault(client, [0, 0, 0])
            ln[0] += 1
            lc[0] += 1
            if node not in ("DIRECT", "UNKNOWN") and not node.startswith("REJECT"):
                remote = host_of(str(m.get("remoteDestination") or ""))
                if remote and self.nodeinfo.get(node, (None, ""))[1] != remote:
                    self.nodeinfo[node] = (self.ptype.get(node, ""), remote)
                    self.ndirty.add(node)
            up, down = int(c.get("upload") or 0), int(c.get("download") or 0)
            last = self.seen.get(cid)
            self.seen[cid] = (up, down)
            if not self.baseline_done:
                continue
            if last is None:
                du, dd = up, down
            else:
                du, dd = up - last[0], down - last[1]
                if du < 0:
                    du = up
                if dd < 0:
                    dd = down
            if du <= 0 and dd <= 0:
                continue
            for arr in (ln, lc):
                arr[1] += du
                arr[2] += dd
            host = (str(m.get("host") or "").strip().lower() or str(m.get("sniffHost") or "").strip().lower()
                    or str(m.get("destinationIP") or "").strip() or "unknown")
            grp = str(chains[-1]) if chains else ""
            r, p = str(c.get("rule") or ""), str(c.get("rulePayload") or "")
            rule = ((r + "," + p) if p else r)[:80] or "unknown"
            a = self.buf.setdefault((day, client, node, grp, rule, host), [0, 0])
            a[0] += du
            a[1] += dd
            h = self.hbuf.setdefault((hour, client, node), [0, 0])
            h[0] += du
            h[1] += dd
        for cid in [k for k in self.seen if k not in alive]:
            del self.seen[cid]
        self.baseline_done = True
        self.live = {
            "at": int(t0),
            "nodes": {k: {"conns": v[0], "up_rate": v[1] / elapsed, "down_rate": v[2] / elapsed} for k, v in live_n.items()},
            "clients": {k: {"conns": v[0], "up_rate": v[1] / elapsed, "down_rate": v[2] / elapsed} for k, v in live_c.items()},
        }

    # ---- WAN 实际流量(可选,用来对账)
    def poll_wan(self):
        if not WAN_IFACES:
            return
        cur = {}
        try:
            with open(PROC_NET_DEV) as f:
                for line in f:
                    if ":" not in line:
                        continue
                    name, rest = line.split(":", 1)
                    if name.strip() in WAN_IFACES:
                        parts = rest.split()
                        cur[name.strip()] = (int(parts[0]), int(parts[8]))
        except OSError as e:
            if not self.wan_warned:
                log("读取 WAN 计数失败:", e)
                self.wan_warned = True
            return
        if not cur and not self.wan_warned:
            log(f"找不到 WAN_IFACE={','.join(WAN_IFACES)} 对应的网卡")
            self.wan_warned = True
        lt = time.localtime()
        day, hour = time.strftime("%Y-%m-%d", lt), time.strftime("%Y-%m-%d %H", lt)
        for n, (rx, tx) in cur.items():
            last = self.wan_last.get(n)
            self.wan_last[n] = (rx, tx)
            if last is None:
                continue
            drx = rx - last[0] if rx >= last[0] else rx
            dtx = tx - last[1] if tx >= last[1] else tx
            for store, key in ((self.wbuf, day), (self.whbuf, hour)):
                a = store.setdefault(key, [0, 0])
                a[0] += dtx
                a[1] += drx

    # ---- 落库
    def maybe_flush(self):
        if time.time() - self.last_flush >= config.FLUSH:
            self.flush()

    def flush(self):
        self.last_flush = time.time()
        buf, hbuf, wbuf, whbuf = self.buf, self.hbuf, self.wbuf, self.whbuf
        ipd, nd = self.neigh.dirty, set(self.ndirty)
        if not (buf or hbuf or wbuf or whbuf or ipd or nd):
            return
        self.buf, self.hbuf, self.wbuf, self.whbuf = {}, {}, {}, {}
        self.neigh.dirty = {}
        self.ndirty = set()
        now = int(time.time())
        try:
            with self.con:
                self.con.executemany(
                    "INSERT INTO traffic(day,client,node,grp,rule,host,up,down) VALUES(?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(day,client,node,grp,rule,host) DO UPDATE SET up=up+excluded.up, down=down+excluded.down",
                    [(*k, v[0], v[1]) for k, v in buf.items()])
                self.con.executemany(
                    "INSERT INTO hourly(hour,client,node,up,down) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(hour,client,node) DO UPDATE SET up=up+excluded.up, down=down+excluded.down",
                    [(*k, v[0], v[1]) for k, v in hbuf.items()])
                self.con.executemany(
                    "INSERT INTO wan(day,up,down) VALUES(?,?,?) ON CONFLICT(day) DO UPDATE SET up=up+excluded.up, down=down+excluded.down",
                    [(k, v[0], v[1]) for k, v in wbuf.items()])
                self.con.executemany(
                    "INSERT INTO wan_hourly(hour,up,down) VALUES(?,?,?) ON CONFLICT(hour) DO UPDATE SET up=up+excluded.up, down=down+excluded.down",
                    [(k, v[0], v[1]) for k, v in whbuf.items()])
                self.con.executemany(
                    "INSERT INTO ipmap(ip,mac,seen) VALUES(?,?,?) ON CONFLICT(ip) DO UPDATE SET mac=excluded.mac, seen=excluded.seen",
                    [(ip, mac, now) for ip, mac in ipd.items()])
                for node in nd:
                    typ, remote = self.nodeinfo.get(node, ("", ""))
                    self.con.execute(
                        "INSERT INTO nodeinfo(node,type,remote,seen) VALUES(?,?,?,?) ON CONFLICT(node) DO UPDATE SET "
                        "type=excluded.type, geo=CASE WHEN nodeinfo.remote IS excluded.remote THEN nodeinfo.geo ELSE NULL END, "
                        "geo_at=CASE WHEN nodeinfo.remote IS excluded.remote THEN nodeinfo.geo_at ELSE NULL END, "
                        "remote=excluded.remote, seen=excluded.seen", (node, typ, remote, now))
        except Exception as e:
            for src, dst in ((buf, self.buf), (hbuf, self.hbuf), (wbuf, self.wbuf), (whbuf, self.whbuf)):
                for k, v in src.items():
                    a = dst.setdefault(k, [0, 0])
                    a[0] += v[0]
                    a[1] += v[1]
            self.neigh.dirty.update(ipd)
            self.ndirty |= nd
            log("写库失败,稍后重试:", e)

    def prune(self):
        day_cut = time.strftime("%Y-%m-%d", time.localtime(time.time() - config.KEEP_DAYS * 86400))
        hour_cut = time.strftime("%Y-%m-%d %H", time.localtime(time.time() - config.HOUR_KEEP_DAYS * 86400))
        with self.con:
            self.con.execute("DELETE FROM traffic WHERE day < ?", (day_cut,))
            self.con.execute("DELETE FROM wan WHERE day < ?", (day_cut,))
            self.con.execute("DELETE FROM hourly WHERE hour < ?", (hour_cut,))
            self.con.execute("DELETE FROM wan_hourly WHERE hour < ?", (hour_cut,))
            self.con.execute("DELETE FROM ipmap WHERE seen < ?", (int(time.time()) - 30 * 86400,))
        log(f"已清理 {day_cut} 之前的明细")

    def on_conf_change(self):
        """页面里改了连接设置:丢掉增量基线,下一轮重新建立。"""
        self.flush()
        self.seen.clear()
        self.baseline_done = False
        self.proxies_at = 0.0
        self.last_poll_t = 0.0
        self.status["error"] = "连接设置已更新,重新连接中"

    def run(self):
        last_prune = 0.0
        fail_logged = False
        while not stop.is_set():
            rev = config.get()["rev"]
            if rev != self.conf_rev:
                self.conf_rev = rev
                self.on_conf_change()
            try:
                self.poll()
                self.status.update(ok=True, error="", last_ok=int(time.time()))
                if fail_logged:
                    log("API 已恢复")
                    fail_logged = False
            except urllib.error.HTTPError as e:
                msg = "密钥不对(401)" if e.code == 401 else f"API 返回 {e.code}"
                self.status.update(ok=False, error=msg)
                if not fail_logged:
                    log(msg)
                    fail_logged = True
            except Exception as e:
                self.status.update(ok=False, error=f"连不上 API:{e}")
                if not fail_logged:
                    log("连不上 API:", e)
                    fail_logged = True
            try:
                self.poll_wan()
            except Exception as e:
                log("WAN 计数异常:", e)
            self.maybe_flush()
            if time.time() - last_prune > 6 * 3600:
                try:
                    self.prune()
                except Exception as e:
                    log("清理失败:", e)
                last_prune = time.time()
            stop.wait(config.INTERVAL)
        self.flush()
