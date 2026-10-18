"""路由器自身的运行状态:CPU / 负载 / 内存 / 温度 / 连接跟踪 / 网卡收发与丢包 / 磁盘 / 运行时长。
容器是 host 网络,读 /proc 和 /sys 看到的就是路由器本机。全部只读,每次采样只读几个小文件。
读不到的项(例如没有温度传感器)会直接缺省,页面上不显示。"""
import collections
import glob
import json
import os
import re
import threading
import time

from . import config, realtime

PROC = os.environ.get("SYS_PROC", "/proc")
SYSFS = os.environ.get("SYS_SYSFS", "/sys")
# (时间戳, CPU%, 内存已用, 连接跟踪数, 最高温度, 总下行B/s, 总上行B/s)
SERIES = collections.deque(maxlen=600)
STATE = {"at": 0, "cpu": None, "load": None, "ncpu": os.cpu_count() or 1, "mem": None, "uptime": 0, "temps": [],
         "ct": None, "ifaces": [], "disk": None, "disks": []}
_lock = threading.Lock()
_last = {"cpu": None, "net": None, "t": 0.0}
SKIP_IF = ("lo", "veth", "docker", "br-", "ifb", "bonding_masters")


def _rd(path):
    with open(path) as f:
        return f.read()


def _cpu():
    try:
        v = [int(x) for x in _rd(PROC + "/stat").split("\n", 1)[0].split()[1:]]
    except Exception:
        return None
    idle = v[3] + (v[4] if len(v) > 4 else 0)
    tot = sum(v[:8]) if len(v) >= 8 else sum(v)
    last, _last["cpu"] = _last["cpu"], (idle, tot)
    if not last or tot <= last[1]:
        return None
    return round(max(0.0, min(100.0, (1 - (idle - last[0]) / (tot - last[1])) * 100)), 1)


def _temps():
    out = []
    for p in sorted(glob.glob(SYSFS + "/class/thermal/thermal_zone*/temp")):
        try:
            v = int(_rd(p).strip())
            name = ""
            try:
                name = _rd(os.path.dirname(p) + "/type").strip()
            except OSError:
                pass
            out.append({"name": name or os.path.basename(os.path.dirname(p)), "c": round(v / 1000 if abs(v) > 200 else v, 1)})
        except Exception:
            continue
    if not out:
        for p in sorted(glob.glob(SYSFS + "/class/hwmon/hwmon*/temp*_input")):
            try:
                out.append({"name": os.path.basename(os.path.dirname(p)), "c": round(int(_rd(p).strip()) / 1000, 1)})
            except Exception:
                continue
    return [t for t in out if -40 < t["c"] < 150]


def _ct():
    try:
        n = int(_rd(PROC + "/sys/net/netfilter/nf_conntrack_count").strip())
        m = int(_rd(PROC + "/sys/net/netfilter/nf_conntrack_max").strip())
        return {"n": n, "max": m, "pct": round(n * 100 / m, 1) if m else None}
    except Exception:
        return None


def _net(now):
    try:
        lines = _rd(PROC + "/net/dev").split("\n")[2:]
    except Exception:
        return []
    cur = {}
    for ln in lines:
        name, _, rest = ln.partition(":")
        name = name.strip()
        f = rest.split()
        if not name or len(f) < 16 or name.startswith(SKIP_IF):
            continue
        cur[name] = [int(f[0]), int(f[2]), int(f[3]), int(f[8]), int(f[10]), int(f[11])]  # rxB rxErr rxDrop txB txErr txDrop
    last, _last["net"] = _last["net"], (now, cur)
    if not last:
        return []
    dt = max(0.5, now - last[0])
    out = []
    for k, c in cur.items():
        o = last[1].get(k)
        if not o:
            continue
        d = [x - y if x >= y else 0 for x, y in zip(c, o)]
        out.append({"name": k, "down": d[0] / dt, "up": d[3] / dt, "errs": d[1] + d[4], "drops": d[2] + d[5],
                    "tot_errs": c[1] + c[4], "tot_drops": c[2] + c[5]})
    out.sort(key=lambda r: -(r["down"] + r["up"]))
    return out[:8]


def _disk():
    try:
        st = os.statvfs(config.DATA_DIR if os.path.isdir(config.DATA_DIR) else "/")
        tot, free = st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
        return {"total": tot, "free": free, "pct": round((tot - free) * 100 / tot, 1) if tot else None}
    except Exception:
        return None


REAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "vfat", "exfat", "ntfs", "ntfs3", "fuseblk", "overlay", "zfs", "jfs", "ubifs"}
SKIP_MP = ("/proc", "/sys", "/dev", "/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/run", "/var/run", "/var/lib/docker")


def _stat(mp):
    st = os.statvfs(mp)
    tot, free = st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
    return st, tot, free


def _disks():
    """所有挂载的硬盘/分区的空间。容器里只能看到挂进来的盘:要看路由器上别的硬盘,
    在 compose 里加一行 `- /mnt:/host/mnt:ro,rslave`(只读),或用环境变量 DISK_PATHS=名称=路径,名称=路径 指定。"""
    out, seen = [], set()

    def add(name, mp, fs):
        try:
            st, tot, free = _stat(mp)
        except OSError:
            return
        if tot < 64 * 1048576:
            return
        key = (getattr(st, "f_fsid", 0), st.f_blocks)
        if key in seen:
            return
        seen.add(key)
        out.append({"name": name, "mp": mp, "fs": fs, "total": tot, "free": free, "pct": round((tot - free) * 100 / tot, 1)})

    for it in (os.environ.get("DISK_PATHS") or "").split(","):
        n, _, p = it.partition("=")
        if n.strip() and p.strip():
            add(n.strip(), p.strip(), "")
    d = config.DATA_DIR if os.path.isdir(config.DATA_DIR) else "/"
    add("面板数据所在盘", d, "")
    try:
        lines = _rd(PROC + "/mounts").splitlines()
    except OSError:
        lines = []
    for ln in lines:
        f = ln.split()
        if len(f) < 3:
            continue
        mp, fs = f[1].replace("\\040", " "), f[2]
        if fs not in REAL_FS or mp.startswith(SKIP_MP) or (fs == "overlay" and mp != "/"):
            continue
        label = mp[5:] if mp.startswith("/host/") else mp
        add("容器根(Docker 所在盘)" if mp == "/" else label or "/", mp, fs)
    return out[:12]


def sample():
    now = time.time()
    cpu = _cpu()
    load = None
    try:
        load = [float(x) for x in _rd(PROC + "/loadavg").split()[:3]]
    except Exception:
        pass
    used, total = realtime.host_mem()
    up = 0
    try:
        up = int(float(_rd(PROC + "/uptime").split()[0]))
    except Exception:
        pass
    temps, ct, ifs = _temps(), _ct(), _net(now)
    if now - _last["t"] > 30 or STATE["disk"] is None:
        _last["t"], disk = now, _disk()
        try:
            disks = _disks()
        except Exception:
            disks = STATE["disks"]
    else:
        disk, disks = STATE["disk"], STATE["disks"]
    with _lock:
        STATE.update(at=int(now), cpu=cpu if cpu is not None else STATE["cpu"], load=load, mem={"used": used, "total": total} if total else None,
                     uptime=up, temps=temps, ct=ct, ifaces=ifs, disk=disk, disks=disks)
        if cpu is not None:
            SERIES.append((now, cpu, used, ct["n"] if ct else 0, max((t["c"] for t in temps), default=0),
                           sum(i["down"] for i in ifs), sum(i["up"] for i in ifs)))


TEMP_SRC = {"v": "auto", "at": 0.0}
CPU_RE = re.compile(r"cpu|soc|core|package|ap\d|mt7|bcm|ipq", re.I)


def temp_src(con=None):
    """主温度读哪个传感器:auto = 名字像 CPU / SoC 的优先,没有就取最高;max = 所有传感器的最高值;其它 = 指定传感器名。"""
    if con is not None and time.time() - TEMP_SRC["at"] > 20:
        try:
            r = con.execute("SELECT v FROM kv WHERE k='temp_src'").fetchone()
            TEMP_SRC["v"] = (json.loads(r[0]) if r else "auto") or "auto"
        except Exception:
            pass
        TEMP_SRC["at"] = time.time()
    return TEMP_SRC["v"]


def save_temp_src(con, v):
    v = str(v or "auto")[:60]
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES('temp_src',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (json.dumps(v),))
    TEMP_SRC.update(v=v, at=time.time())
    return v


def pick_temp(temps, src="auto"):
    """返回 (主温度, 用的哪个传感器)。"""
    if not temps:
        return None, ""
    if src not in ("auto", "max"):
        for t in temps:
            if t["name"] == src:
                return t["c"], t["name"]
    if src == "auto":
        cands = [t for t in temps if CPU_RE.search(t["name"])]
        if cands:
            t = max(cands, key=lambda x: x["c"])
            return t["c"], t["name"]
    t = max(temps, key=lambda x: x["c"])
    return t["c"], t["name"]


def snapshot(secs=120, src="auto"):
    now = time.time()
    with _lock:
        s = dict(STATE)
        rows = [r for r in SERIES if r[0] >= now - secs]
    s["series"] = [[round(r[0], 1), r[1], r[2], r[3], r[4]] for r in rows]
    s["tmax"] = max((t["c"] for t in s["temps"]), default=None)
    s["tmain"], s["tmain_name"] = pick_temp(s["temps"], src)
    s["temp_src"] = src
    return s
