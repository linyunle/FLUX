"""设备上线 / 离线记录与提醒。

在线证据(任一即可):内核邻居表里该设备最近确认过在线(REACHABLE/DELAY/PROBE),或刚刚有连接经过 nikki。
超过「离线判定」分钟都没有证据才算离线(手机省电断 Wi-Fi 几分钟不算);再出现就是上线。
所有设备的在线状态和最后在线时间都会记下来(设备页可看);上线/离线事件只对「关注」的设备(或规则里选了所有设备)记进时间线并推送。"""
import json
import time

from . import alerts, devices, realtime
from .util import is_mac

_s = {"st": None, "start": time.time(), "saved": 0}
LEARN = 120   # 面板刚启动的头两分钟只记状态不出事件,避免重启后一堆「上线」


def _kv(con, k, d):
    try:
        r = con.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
        return json.loads(r[0]) if r else d
    except Exception:
        return d


def _put(con, k, v):
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, json.dumps(v, ensure_ascii=False)))


def watch_list(con):
    v = _kv(con, "dev_watch", [])
    return [str(x) for x in v][:500] if isinstance(v, list) else []


def set_watch(con, key, on):
    key = str(key or "").strip()
    if not key or len(key) > 64:
        raise ValueError("设备标识不对")
    w = [x for x in watch_list(con) if x != key]
    if on:
        w.append(key)
    _put(con, "dev_watch", w[-500:])
    return {"ok": True, "watch": bool(on)}


def evidence(now=None):
    fresh = set()
    neigh = devices.read_neigh(fresh)
    out = set(fresh)
    for key in list(realtime.LIVE["clients"]):
        if is_mac(key):
            out.add(key)
        elif key in neigh:
            out.add(neigh[key])
    return out


def _fmt_dur(sec):
    sec = int(sec)
    if sec < 3600:
        return f"{max(1, sec // 60)} 分钟"
    if sec < 86400:
        return f"{sec // 3600} 小时 {sec % 3600 // 60} 分钟"
    return f"{sec // 86400} 天 {sec % 86400 // 3600} 小时"


def check(con, cfg, now, ev=None):
    st = _s["st"]
    if st is None:
        st = _s["st"] = _kv(con, "presence", {})
        if not isinstance(st, dict):
            st = _s["st"] = {}
    ev = evidence(now) if ev is None else ev
    ro, rf = cfg["rules"]["dev_online"], cfg["rules"]["dev_offline"]
    grace = rf["grace_min"] * 60
    watch = set(watch_list(con))
    learning = now - _s["start"] < LEARN
    changed = False
    events = []
    for mac in ev:
        e = st.get(mac)
        if not e:
            st[mac] = {"on": True, "since": int(now), "last": int(now)}
            changed = True
        else:
            if not e["on"]:
                events.append(("on", mac, now - e["since"]))
                e.update(on=True, since=int(now))
                changed = True
            e["last"] = int(now)
    for mac, e in st.items():
        if e["on"] and mac not in ev and now - e["last"] >= grace:
            e.update(on=False, since=e["last"])
            events.append(("off", mac, e["last"]))
            changed = True
    cache = None
    for kind, mac, x in events:
        if learning:
            continue
        rule = ro if kind == "on" else rf
        if not (mac in watch or rule["all"] >= 1):
            continue
        cache = cache or alerts._dev_names(con)
        name = alerts._dev_label(con, mac, cache)
        ips = [i for i in cache[0].get(mac, []) if ":" not in i][:2]
        tail = (f"(IP {'、'.join(ips)})" if ips else "")
        k = "dev_online" if kind == "on" else "dev_offline"
        if kind == "on":
            title, detail = f"设备上线:{name}", f"{name}{tail}重新连上了网络,上次离线了 {_fmt_dur(x)}。"
        else:
            title, detail = f"设备离线:{name}", f"{name}{tail}已经 {_fmt_dur(now - x)}没有出现(最后在线 {time.strftime('%m-%d %H:%M', time.localtime(x))})。"
        if rule["on"] and alerts._allow(k, mac, rule["cool_min"], now):
            alerts.fire(con, cfg, k, "info" if kind == "on" else "warn", mac, title, detail, now)
        else:
            alerts.note(con, k, mac, title, detail, now=now)
    if changed or now - _s["saved"] > 300:
        _put(con, "presence", st)
        _s["saved"] = now


def status(con):
    st = _s["st"] if _s["st"] is not None else _kv(con, "presence", {})
    watch = set(watch_list(con))
    cache = alerts._dev_names(con)
    rows = []
    for mac, e in st.items():
        rows.append({"key": mac, "name": alerts._dev_label(con, mac, cache), "on": e["on"], "since": e["since"], "last": e["last"], "watch": mac in watch})
    rows.sort(key=lambda r: (not r["on"], r["name"].lower()))
    return {"rows": rows, "watch": sorted(watch)}
