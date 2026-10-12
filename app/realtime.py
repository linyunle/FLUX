"""实时速度:每隔几秒读一次 mihomo 的 /connections,按连接算增量,
分成 直连 / 代理 两组速度,并统计连接数、活跃设备、活跃节点。最近 10 分钟留在内存里。"""
import collections
import os
import time

from . import collector, config
from .util import api_call, log, stop

INTERVAL = max(1, min(10, int(os.environ.get("REALTIME_SEC", "2") or 2)))
# (时间戳, 直连上, 直连下, 代理上, 代理下, 总连接, 直连连接, 代理连接)
SAMPLES = collections.deque(maxlen=600)
LIVE = {"at": 0, "clients": {}, "nodes": {}}
# (时间戳, mihomo 进程内存, 系统已用, 系统总量),字节
MEM = collections.deque(maxlen=600)


def host_mem():
    """读 /proc/meminfo(host 网络模式的容器里看到的就是路由器自己的内存)"""
    try:
        m = {}
        with open("/proc/meminfo") as f:
            for ln in f:
                k, _, v = ln.partition(":")
                m[k] = int(v.split()[0]) * 1024
        tot = m.get("MemTotal", 0)
        avail = m.get("MemAvailable", m.get("MemFree", 0) + m.get("Buffers", 0) + m.get("Cached", 0))
        return max(0, tot - avail), tot
    except Exception:
        return 0, 0
STATE = {"ok": False, "error": ""}


def kind(node, ptype):
    t = (ptype.get(node, "") or "").lower()
    if t == "direct" or node == "DIRECT":
        return "direct"
    if t in ("reject", "rejectdrop") or node.startswith("REJECT"):
        return "reject"
    return "proxy"


def run():
    seen, last_t, rev = {}, 0.0, -1
    fail_logged = False
    while not stop.is_set():
        c = config.get()
        if c["rev"] != rev:
            rev, seen, last_t = c["rev"], {}, 0.0
        try:
            col = collector.COLLECTOR
            t0 = time.time()
            data = api_call("/connections", timeout=8)
            conns = data.get("connections") or []
            elapsed = max(0.5, t0 - last_t) if last_t else INTERVAL
            ptype = dict(col.ptype) if col else {}
            tot = {"direct": [0, 0], "proxy": [0, 0]}
            cnt = {"direct": 0, "proxy": 0}
            lc, ln = {}, {}
            new_seen, first = {}, not last_t
            for cn in conns:
                cid = cn.get("id")
                if not cid:
                    continue
                m = cn.get("metadata") or {}
                chains = cn.get("chains") or []
                node = col.leaf(chains) if col else (str(chains[0]) if chains else "UNKNOWN")
                k = kind(node, ptype)
                ip = str(m.get("sourceIP") or "")
                client = (col.neigh.key(ip) if col else ip)
                up, down = int(cn.get("upload") or 0), int(cn.get("download") or 0)
                new_seen[cid] = (up, down)
                last = seen.get(cid)
                if first:
                    du = dd = 0
                elif last is None:
                    du, dd = up, down
                else:
                    du, dd = up - last[0], down - last[1]
                    du = up if du < 0 else du
                    dd = down if dd < 0 else dd
                grp = "direct" if k == "direct" else "proxy"
                if k != "reject":
                    tot[grp][0] += du
                    tot[grp][1] += dd
                    cnt[grp] += 1
                for store, key in ((lc, client), (ln, node)):
                    a = store.setdefault(key, [0, 0, 0])
                    a[0] += 1
                    a[1] += du
                    a[2] += dd
            seen, last_t = new_seen, t0
            hu, ht = host_mem()
            MEM.append((t0, int(data.get("memory") or 0), hu, ht))
            if not first:
                SAMPLES.append((t0, tot["direct"][0] / elapsed, tot["direct"][1] / elapsed,
                                tot["proxy"][0] / elapsed, tot["proxy"][1] / elapsed,
                                len(conns), cnt["direct"], cnt["proxy"]))
            conv = lambda d: {k: {"conns": v[0], "up_rate": v[1] / elapsed, "down_rate": v[2] / elapsed} for k, v in d.items()}
            LIVE.update(at=int(t0), clients=conv(lc), nodes=conv(ln))
            STATE.update(ok=True, error="")
            if fail_logged:
                log("实时速度已恢复")
                fail_logged = False
        except Exception as e:
            STATE.update(ok=False, error=f"{type(e).__name__}: {e}"[:120])
            if not fail_logged:
                log("实时速度读取失败(会自动重试):", e)
                fail_logged = True
        stop.wait(INTERVAL)
