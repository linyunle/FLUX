"""路由器内核的 TCP 计数(/proc/net/snmp)。容器是 host 网络,读到的就是路由器本机的数字:
nikki(mihomo)本机收发的 TCP 段、重传段、复位。注意它不含被直接转发(不经过本机)的流量,也分不出设备/应用。"""
import collections
import threading
import time

SNMP = "/proc/net/snmp"
SERIES = collections.deque(maxlen=600)   # (时间戳, 发出段, 重传段, 发出RST, 收到段)
HOURLY = {}                              # "YYYY-MM-DD HH" -> [发出段, 重传段, RST]
STATE = {"ok": False}
_lock = threading.Lock()
_last = None


def _read():
    with open(SNMP) as f:
        lines = [ln.split() for ln in f if ln.startswith("Tcp:")]
    if len(lines) < 2:
        return None
    d = dict(zip(lines[0][1:], lines[1][1:]))
    return int(d["OutSegs"]), int(d["RetransSegs"]), int(d.get("OutRsts", 0)), int(d["InSegs"])


def sample():
    global _last
    try:
        cur = _read()
    except Exception:
        cur = None
    if cur is None:
        STATE["ok"] = False
        return
    STATE["ok"] = True
    now = time.time()
    last, _last = _last, cur
    if last is None:
        return
    d = [c - l if c >= l else 0 for c, l in zip(cur, last)]
    SERIES.append((now, *d))
    hour = time.strftime("%Y-%m-%d %H", time.localtime(now))
    with _lock:
        a = HOURLY.setdefault(hour, [0, 0, 0])
        a[0] += d[0]
        a[1] += d[1]
        a[2] += d[2]


def pop_hourly():
    with _lock:
        out = dict(HOURLY)
        HOURLY.clear()
    return out


def push_back(h):
    with _lock:
        for k, v in h.items():
            a = HOURLY.setdefault(k, [0, 0, 0])
            for i in range(3):
                a[i] += v[i]
