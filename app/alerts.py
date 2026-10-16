"""告警:规则引擎 + 推送渠道。

每隔几十秒检查一次现成的数据(实时连接、节点测速、TCP 重传、历史小时流量),触发就:
1. 写进 alerts 表(页面「告警」里能看),
2. 按配置推送到 Bark / Telegram / 企业微信 / 飞书 / ntfy / 通用 Webhook。
配置(规则阈值、推送渠道)放在数据库 kv 表的 alert_cfg 里;渠道里的密钥不会通过接口原样返回。
"""
import copy
import json
import statistics
import threading
import time
import urllib.parse
import urllib.request

from . import collector, config, db, devices, groups, netstat, realtime, sysinfo
from .util import is_mac, log, stop

KINDS = {
    "new_device": "新设备",
    "traffic_spike": "流量突增",
    "node_down": "节点故障",
    "node_up": "节点恢复",
    "retrans_high": "重传率偏高",
    "conn_many": "连接数异常",
    "api_down": "nikki 失联",
    "api_up": "nikki 恢复",
    "quota": "套餐用量",
    "sys_conntrack": "连接跟踪占用高",
    "sys_temp": "路由器温度高",
    "sys_disk": "磁盘空间不足",
    "sys_mem": "路由器内存紧张",
    "report": "周报",
    "group_policy": "分组白名单",
    "node_degrade": "节点变差",
    "geo_new": "新目的地国家",
    "quota_forecast": "套餐预计超额",
    "quota_expire": "套餐到期",
    "audit": "设置变更",
    "boot": "面板启动",
    "router_reboot": "路由器重启",
}
LEVELS = ("bad", "warn", "info", "ok", "note")

# 规则默认值:on 是否启用,其余是阈值;cool_min 同一对象两次告警之间至少隔多少分钟
DEFAULT_RULES = {
    "new_device": {"on": True},
    "traffic_spike": {"on": True, "min_mb": 1024, "factor": 5, "cool_min": 180},
    "node_down": {"on": True, "fails": 3, "cool_min": 60},
    "retrans_high": {"on": True, "pct": 5, "cool_min": 30},
    "conn_many": {"on": True, "count": 500, "cool_min": 60},
    "api_down": {"on": True, "after_sec": 120, "cool_min": 30},
    "quota": {"on": True, "pct": 80, "cool_min": 1440},
    "group_policy": {"on": True, "cool_min": 1440},
    "node_degrade": {"on": True, "drop": 20, "cool_min": 1440},
    "geo_new": {"on": True, "min_mb": 50, "cool_min": 1440},
    "quota_forecast": {"on": True, "cool_min": 1440},
    "quota_expire": {"on": True, "days": 7, "cool_min": 720},
    "sys_conntrack": {"on": True, "pct": 85, "cool_min": 60},
    "sys_temp": {"on": True, "c": 85, "cool_min": 60},
    "sys_disk": {"on": True, "pct": 90, "cool_min": 1440},
    "sys_mem": {"on": True, "pct": 92, "cool_min": 120},
}
# 阈值范围(防止填出离谱的值)
LIMITS = {"min_mb": (0.1, 1048576), "factor": (1.2, 1000), "cool_min": (1, 10080), "fails": (1, 50),
          "pct": (0.5, 100), "count": (10, 100000), "after_sec": (30, 86400), "c": (30, 120), "drop": (5, 90), "days": (1, 90)}
CHANNEL_TYPES = {"bark": "Bark", "telegram": "Telegram", "wecom": "企业微信机器人", "feishu": "飞书机器人",
                 "ntfy": "ntfy", "webhook": "通用 Webhook(JSON)"}
DEFAULT_CFG = {"rules": DEFAULT_RULES, "channels": [], "quiet": {"on": False, "start": "23:00", "end": "07:00"}}

_lock = threading.RLock()
_cool = {}       # (kind, key) -> 上次触发时间
_down = set()    # 当前判定为故障的节点
_api_bad_since = 0.0
_api_fired = False
_state = {"seeded": False, "start": 0.0}


# ---------------------------------------------------------------- 配置
def _num(v, name, default):
    lo, hi = LIMITS[name]
    try:
        x = float(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, x))


def _hhmm(v, default):
    try:
        h, m = str(v).split(":")
        h, m = int(h), int(m)
        if 0 <= h < 24 and 0 <= m < 60:
            return f"{h:02d}:{m:02d}"
    except ValueError:
        pass
    return default


def _norm_channel(c, old=None):
    t = str(c.get("type") or "")
    if t not in CHANNEL_TYPES:
        raise ValueError("不支持的推送类型")
    out = {"id": str(c.get("id") or "")[:20] or f"c{int(time.time() * 1000) % 10**9}", "type": t,
           "name": (str(c.get("name") or "").strip() or CHANNEL_TYPES[t])[:30], "on": bool(c.get("on", True))}
    old = old or {}
    if t == "telegram":
        tok = str(c.get("token") or "").strip() or old.get("token", "")
        chat = str(c.get("chat") or "").strip() or old.get("chat", "")
        if not tok or not chat:
            raise ValueError(f"「{out['name']}」需要填 Bot Token 和 Chat ID")
        out.update(token=tok[:200], chat=chat[:60])
    else:
        url = str(c.get("url") or "").strip() or old.get("url", "")
        pr = urllib.parse.urlparse(url)
        if pr.scheme not in ("http", "https") or not pr.netloc or len(url) > 500:
            raise ValueError(f"「{out['name']}」的地址要以 http:// 或 https:// 开头")
        out["url"] = url
    return out


def _mask(c):
    m = {k: v for k, v in c.items() if k not in ("url", "token", "chat")}
    if c["type"] == "telegram":
        m["has_secret"] = bool(c.get("token"))
        m["hint"] = "Chat " + c.get("chat", "")
    else:
        pr = urllib.parse.urlparse(c.get("url", ""))
        m["has_secret"] = bool(c.get("url"))
        m["hint"] = f"{pr.scheme}://{pr.netloc}/…" if pr.netloc else ""
    return m


def load_cfg(con):
    cfg = copy.deepcopy(DEFAULT_CFG)
    try:
        r = con.execute("SELECT v FROM kv WHERE k='alert_cfg'").fetchone()
        d = json.loads(r[0]) if r else {}
    except Exception:
        d = {}
    for k, base in DEFAULT_RULES.items():
        sv = (d.get("rules") or {}).get(k) or {}
        for f in base:
            if f == "on":
                cfg["rules"][k]["on"] = bool(sv.get("on", base["on"]))
            elif f in sv:
                cfg["rules"][k][f] = _num(sv[f], f, base[f])
    cfg["channels"] = [c for c in (d.get("channels") or []) if isinstance(c, dict) and c.get("type") in CHANNEL_TYPES]
    q = d.get("quiet") or {}
    cfg["quiet"] = {"on": bool(q.get("on")), "start": _hhmm(q.get("start"), "23:00"), "end": _hhmm(q.get("end"), "07:00")}
    return cfg


def save_cfg(con, body):
    """body: {rules, channels, quiet}。渠道里密钥留空 = 沿用已保存的同 id 渠道。"""
    cur = load_cfg(con)
    old = {c["id"]: c for c in cur["channels"]}
    cfg = copy.deepcopy(DEFAULT_CFG)
    for k, base in DEFAULT_RULES.items():
        sv = (body.get("rules") or {}).get(k) or {}
        for f in base:
            if f == "on":
                cfg["rules"][k]["on"] = bool(sv.get("on", cur["rules"][k]["on"]))
            else:
                cfg["rules"][k][f] = _num(sv.get(f, cur["rules"][k][f]), f, base[f])
    chans = []
    for c in (body.get("channels") or [])[:10]:
        if isinstance(c, dict):
            chans.append(_norm_channel(c, old.get(str(c.get("id") or ""))))
    cfg["channels"] = chans
    q = body.get("quiet") or {}
    cfg["quiet"] = {"on": bool(q.get("on")), "start": _hhmm(q.get("start"), "23:00"), "end": _hhmm(q.get("end"), "07:00")}
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES('alert_cfg',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                    (json.dumps(cfg, ensure_ascii=False),))
    return cfg


def public_cfg(con):
    cfg = load_cfg(con)
    learn_left = 0
    if _state["start"]:
        learn_left = max(0, int(_state["start"] + config.ALERT_LEARN - time.time()))
    return {"rules": cfg["rules"], "channels": [_mask(c) for c in cfg["channels"]], "quiet": cfg["quiet"],
            "kinds": KINDS, "types": CHANNEL_TYPES, "learn_left": learn_left}


# ---------------------------------------------------------------- 推送
def _post(url, data, headers=None, timeout=8):
    h = {"Content-Type": "application/json", "User-Agent": "FLUX"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        r.read(2048)
        return r.status


def send(ch, title, body, kind="test", level="info"):
    """向一个渠道发一条。成功返回 None,失败返回原因文字。"""
    text = f"{title}\n{body}".strip()
    try:
        t = ch["type"]
        if t == "telegram":
            url = f"https://api.telegram.org/bot{ch['token']}/sendMessage"
            _post(url, json.dumps({"chat_id": ch["chat"], "text": text}).encode())
        elif t == "bark":
            _post(ch["url"], json.dumps({"title": title, "body": body, "group": "FLUX"}, ensure_ascii=False).encode())
        elif t == "wecom":
            _post(ch["url"], json.dumps({"msgtype": "text", "text": {"content": text}}, ensure_ascii=False).encode())
        elif t == "feishu":
            _post(ch["url"], json.dumps({"msg_type": "text", "content": {"text": text}}, ensure_ascii=False).encode())
        elif t == "ntfy":
            _post(ch["url"], text.encode(), {"Content-Type": "text/plain; charset=utf-8", "Title": urllib.parse.quote(title)})
        else:
            _post(ch["url"], json.dumps({"source": "FLUX", "kind": kind, "level": level, "title": title, "text": body,
                                          "time": time.strftime("%F %T")}, ensure_ascii=False).encode())
        return None
    except Exception as e:
        msg = f"{type(e).__name__}: {e}"
        # 报错里可能带地址里的密钥,统一抹掉
        for secret in (ch.get("url"), ch.get("token")):
            if secret:
                msg = msg.replace(secret, "…")
        return msg[:120]


def test_channel(con, body):
    """测试发送。body 可带完整渠道(没保存也能测),密钥留空时沿用同 id 已保存的。"""
    old = {c["id"]: c for c in load_cfg(con)["channels"]}
    c = body.get("channel") or {}
    ch = _norm_channel(c, old.get(str(c.get("id") or "")))
    err = send(ch, "FLUX 测试消息", "收到这条说明推送渠道配置正确。", "test", "info")
    return {"ok": err is None, "error": err or ""}


# ---------------------------------------------------------------- 触发
def _in_quiet(cfg, now):
    q = cfg["quiet"]
    if not q["on"]:
        return False
    lt = time.localtime(now)
    cur = lt.tm_hour * 60 + lt.tm_min
    s = int(q["start"][:2]) * 60 + int(q["start"][3:])
    e = int(q["end"][:2]) * 60 + int(q["end"][3:])
    return (s <= cur < e) if s <= e else (cur >= s or cur < e)


def _allow(kind, key, mins, now):
    with _lock:
        last = _cool.get((kind, key), 0)
        if now - last < mins * 60:
            return False
        _cool[(kind, key)] = now
        if len(_cool) > 2000:
            for k in [k for k, v in _cool.items() if now - v > 86400]:
                _cool.pop(k, None)
        return True


def fire(con, cfg, kind, level, key, title, detail, now=None):
    now = now or time.time()
    chans = [c for c in cfg["channels"] if c.get("on", True)]
    if _in_quiet(cfg, now):
        sent = "静默时段,只记录"
    elif not chans:
        sent = "没有配置推送渠道"
    else:
        ok, bad = [], []
        for c in chans:
            err = send(c, f"[FLUX] {title}", detail, kind, level)
            (bad if err else ok).append(c["name"] + (f"({err})" if err else ""))
        sent = ("已推送:" + "、".join(ok) if ok else "") + (";" if ok and bad else "") + ("失败:" + "、".join(bad) if bad else "")
    with con:
        con.execute("INSERT INTO alerts(ts,kind,level,key,title,detail,sent) VALUES(?,?,?,?,?,?,?)",
                    (int(now), kind, level, key, title, detail, sent))
        con.execute("DELETE FROM alerts WHERE id NOT IN (SELECT id FROM alerts ORDER BY id DESC LIMIT 2000)")
    log("告警", kind, title)


def note(con, kind, key, title, detail="", level="note", now=None):
    """只记录到时间线,不推送、不算未读。"""
    with con:
        con.execute("INSERT INTO alerts(ts,kind,level,key,title,detail,sent) VALUES(?,?,?,?,?,?,?)",
                    (int(now or time.time()), kind, level, key, title, detail, "仅记录"))
        con.execute("DELETE FROM alerts WHERE id NOT IN (SELECT id FROM alerts ORDER BY id DESC LIMIT 2000)")


def _dev_names(con):
    return devices.ips_by_dev(con), devices.stored_names(con)


def _dev_label(con, key, cache=None):
    ips, stored = cache or _dev_names(con)
    ipl = ips.get(key, [] if is_mac(key) else [key])
    return devices.NAMES.label(key, ipl, stored) or next((i for i in ipl if ":" not in i), "") or key


def _fmt(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


# ---- 各条规则
def check_new_device(con, cfg, now):
    st = _state
    known = {r[0] for r in con.execute("SELECT client FROM known_dev")}
    if not st["seeded"]:
        with con:
            con.execute("INSERT OR IGNORE INTO known_dev(client, first) SELECT DISTINCT client, ? FROM hourly WHERE client != ''", (int(now),))
            con.execute("INSERT OR IGNORE INTO known_dev(client, first) SELECT DISTINCT client, ? FROM traffic WHERE client != ''", (int(now),))
        known = {r[0] for r in con.execute("SELECT client FROM known_dev")}
        st["seeded"] = True
    learning = now - st["start"] < config.ALERT_LEARN
    cache = None
    for key, v in list(realtime.LIVE["clients"].items()):
        if not key or key in known or key.startswith(("127.", "::1", "fe80")):
            continue
        with con:
            con.execute("INSERT OR IGNORE INTO known_dev(client, first) VALUES(?,?)", (key, int(now)))
        known.add(key)
        if learning or not cfg["rules"]["new_device"]["on"]:
            continue
        cache = cache or _dev_names(con)
        name = _dev_label(con, key, cache)
        ips = cache[0].get(key, [])
        fire(con, cfg, "new_device", "info", key, f"发现新设备:{name}",
             f"标识 {key}" + (f",IP {'、'.join(ips[:3])}" if ips else "") + "。如果不认识,检查一下 Wi-Fi 密码或 DHCP 列表。", now)


def _baseline(con, client, hour_now, now):
    """本设备「同一钟点」的历史均值(最近 14 天里别的日子),样本不够时退回前 24 小时的中位数。"""
    cutoff = time.strftime("%Y-%m-%d %H", time.localtime(now - 14 * 86400))
    rows = con.execute("SELECT hour, SUM(up+down) FROM hourly WHERE client=? AND hour>=? AND hour<? GROUP BY hour",
                       (client, cutoff, hour_now)).fetchall()
    hod = hour_now[11:13]
    same = [b for h, b in rows if h[11:13] == hod and h[:10] != hour_now[:10]]
    if len(same) >= 3:
        return statistics.fmean(same), len(same), "同时段均值"
    recent = sorted(rows)[-24:]
    vals = [b for _, b in recent if b > 0]
    if len(vals) >= 3:
        return statistics.median(vals), len(vals), "近 24 小时中位数"
    return 0.0, len(vals), "暂无基线"


def check_traffic_spike(con, cfg, now):
    r = cfg["rules"]["traffic_spike"]
    hour_now = time.strftime("%Y-%m-%d %H", time.localtime(now))
    min_b = r["min_mb"] * 1048576
    cache = None
    for client, b in con.execute("SELECT client, SUM(up+down) FROM hourly WHERE hour=? AND client!='' GROUP BY client", (hour_now,)).fetchall():
        if b < min_b:
            continue
        base, n, how = _baseline(con, client, hour_now, now)
        if base and b < base * r["factor"]:
            continue
        if not _allow("traffic_spike", client, r["cool_min"], now):
            continue
        cache = cache or _dev_names(con)
        name = _dev_label(con, client, cache)
        why = f"平时这个钟点约 {_fmt(base)}({how},{n} 个样本),已是 {b / base:.1f} 倍" if base else f"还没有历史基线,按绝对阈值 {_fmt(min_b)} 判断"
        fire(con, cfg, "traffic_spike", "warn", client, f"流量突增:{name}", f"这一小时已用 {_fmt(b)},{why}。", now)


def check_nodes(con, cfg, now):
    c = collector.COLLECTOR
    if not c:
        return
    r = cfg["rules"]["node_down"]
    cutoff = time.strftime("%Y-%m-%d %H", time.localtime(now - 6 * 3600))
    used = {x[0] for x in con.execute("SELECT DISTINCT node FROM hourly WHERE hour>=?", (cutoff,))}
    used |= {now_ for now_, _ in c.groups.values() if now_}
    for node, info in dict(c.nodes).items():
        fails = int(info.get("fails") or 0)
        if fails >= r["fails"] and node in used:
            if node not in _down and _allow("node_down", node, r["cool_min"], now):
                _down.add(node)
                fire(con, cfg, "node_down", "bad", node, f"节点故障:{node}",
                     f"nikki 对它的延迟测试已连续失败 {fails} 次(类型 {info.get('type') or '?'}),正在使用它的设备可能打不开网站。", now)
            else:
                _down.add(node)
        elif fails == 0 and node in _down:
            _down.discard(node)
            if _allow("node_up", node, 1, now):
                fire(con, cfg, "node_up", "ok", node, f"节点恢复:{node}", f"延迟测试恢复正常({info.get('delay')} ms)。", now)


def check_retrans(con, cfg, now):
    r = cfg["rules"]["retrans_high"]
    w = [x for x in list(netstat.SERIES) if x[0] >= now - 300]
    out, rt = sum(x[1] for x in w), sum(x[2] for x in w)
    if out < 2000:
        return
    rate = rt / out * 100
    if rate >= r["pct"] and _allow("retrans_high", "tcp", r["cool_min"], now):
        fire(con, cfg, "retrans_high", "warn", "tcp", f"TCP 重传率偏高:{rate:.1f}%",
             f"最近 5 分钟路由器发出 {out} 个 TCP 段,其中 {rt} 个是重传(阈值 {r['pct']:g}%)。可能是上游链路拥塞、丢包或某个节点质量差;这是路由器整体口径,不分设备。", now)


def check_conns(con, cfg, now):
    r = cfg["rules"]["conn_many"]
    cache = None
    for key, v in list(realtime.LIVE["clients"].items()):
        if v["conns"] >= r["count"] and _allow("conn_many", key, r["cool_min"], now):
            cache = cache or _dev_names(con)
            name = _dev_label(con, key, cache)
            fire(con, cfg, "conn_many", "warn", key, f"连接数异常:{name}",
                 f"这台设备此刻有 {v['conns']} 个并发连接(阈值 {int(r['count'])})。常见原因:BT/PT 下载、扫描类软件、被入侵的设备。", now)


def check_api(con, cfg, now):
    global _api_bad_since, _api_fired
    r = cfg["rules"]["api_down"]
    c = collector.COLLECTOR
    ok = (c.status.get("ok") if c else True) or not c
    if ok:
        if _api_fired:
            _api_fired = False
            fire(con, cfg, "api_up", "ok", "api", "nikki 已恢复连接", "面板重新连上了 nikki 的 API,统计继续。", now)
        _api_bad_since = 0.0
        return
    if not _api_bad_since:
        _api_bad_since = now
    if now - _api_bad_since >= r["after_sec"] and not _api_fired and _allow("api_down", "api", r["cool_min"], now):
        _api_fired = True
        fire(con, cfg, "api_down", "bad", "api", "nikki 失联",
             f"面板已有 {int((now - _api_bad_since) // 60)} 分钟连不上 nikki 的 API:{(c.status.get('error') if c else '')}。这段时间的流量不会被统计。", now)


def check_sys(con, cfg, now):
    s = sysinfo.STATE
    up = s.get("uptime") or 0
    last = _state.get("uptime")
    _state["uptime"] = up
    if last and up and up + 30 < last:
        note(con, "router_reboot", "reboot", "路由器重启过", f"运行时间从 {last // 3600} 小时回到了 {up // 60} 分钟,说明路由器刚重启(或断电)过。", level="warn", now=now - up)
    r = cfg["rules"]
    ct = s.get("ct")
    if r["sys_conntrack"]["on"] and ct and ct.get("pct") is not None and ct["pct"] >= r["sys_conntrack"]["pct"] and _allow("sys_conntrack", "ct", r["sys_conntrack"]["cool_min"], now):
        fire(con, cfg, "sys_conntrack", "warn", "ct", f"连接跟踪占用 {ct['pct']:.0f}%",
             f"路由器当前有 {ct['n']} 条连接跟踪记录,上限 {ct['max']}(阈值 {r['sys_conntrack']['pct']:g}%)。满了以后新连接会被丢弃,表现为网页突然打不开。常见原因:BT/PT、扫描、被入侵的设备。", now)
    tm = max((t["c"] for t in s.get("temps") or []), default=None)
    if r["sys_temp"]["on"] and tm is not None and tm >= r["sys_temp"]["c"] and _allow("sys_temp", "temp", r["sys_temp"]["cool_min"], now):
        fire(con, cfg, "sys_temp", "warn", "temp", f"路由器温度 {tm:.0f}℃",
             f"最高温度传感器读数 {tm:.1f}℃(阈值 {r['sys_temp']['c']:g}℃)。检查散热、通风,或是否长时间满载。", now)
    d = s.get("disk")
    if r["sys_disk"]["on"] and d and d.get("pct") is not None and d["pct"] >= r["sys_disk"]["pct"] and _allow("sys_disk", "disk", r["sys_disk"]["cool_min"], now):
        fire(con, cfg, "sys_disk", "warn", "disk", f"磁盘已用 {d['pct']:.0f}%",
             f"面板数据所在的磁盘已用 {d['pct']:.1f}%,剩余 {d['free'] // 1048576} MB(阈值 {r['sys_disk']['pct']:g}%)。", now)
    m = s.get("mem")
    if r["sys_mem"]["on"] and m and m["total"] and m["used"] * 100 / m["total"] >= r["sys_mem"]["pct"] and _allow("sys_mem", "mem", r["sys_mem"]["cool_min"], now):
        fire(con, cfg, "sys_mem", "warn", "mem", f"路由器内存已用 {m['used'] * 100 // m['total']}%",
             f"已用 {m['used'] // 1048576} MB / 共 {m['total'] // 1048576} MB(阈值 {r['sys_mem']['pct']:g}%,已扣除缓存)。内存持续偏高可能是某个服务泄漏,可到「内存使用」卡片看趋势。", now)


def check_degrade(con, cfg, now):
    from . import advisor
    advisor.check_degrade(con, cfg, now)


def check_geo_new(con, cfg, now):
    from . import advisor
    advisor.check_geo_new(con, cfg, now)


def check_providers(con, cfg, now):
    from . import providers
    providers.sample(con, now)


def check_forecast(con, cfg, now):
    from . import advisor
    advisor.check_quota_forecast(con, cfg, now)


def check_quota_expire(con, cfg, now):
    from . import insight
    insight.check_quota_expire(con, cfg, now)


def check_quota(con, cfg, now):
    from . import insight
    insight.check_quota(con, cfg, now)


CHECKS = [("new_device", check_new_device), ("traffic_spike", check_traffic_spike), ("node_down", check_nodes),
          ("retrans_high", check_retrans), ("conn_many", check_conns), ("api_down", check_api), ("quota", check_quota)] + [("sys", check_sys), ("group_policy", groups.check), ("node_degrade", check_degrade), ("geo_new", check_geo_new), ("quota_forecast", check_forecast), ("quota_expire", check_quota_expire), ("prov", check_providers)]


def evaluate(con, now=None):
    now = now or time.time()
    if not _state["start"]:
        _state["start"] = now
        r = con.execute("SELECT v FROM kv WHERE k='alert_start'").fetchone()
        if r:
            _state["start"] = float(r[0])  # 重启不重新进入「学习期」
        else:
            with con:
                con.execute("INSERT INTO kv(k,v) VALUES('alert_start',?)", (str(now),))
    cfg = load_cfg(con)
    for kind, fn in CHECKS:
        if kind in cfg["rules"] and kind != "new_device" and not cfg["rules"][kind]["on"]:
            continue
        try:
            fn(con, cfg, now)
        except Exception as e:
            log("告警检查出错", kind, e)


def run():
    con = db.open_db()
    try:
        note(con, "boot", "boot", f"面板启动 {config.VERSION}", "容器重启或更新后会记一条;配合下面的「路由器重启」可以区分是面板重启还是路由器重启。")
    except Exception:
        pass
    stop.wait(5)
    while not stop.is_set():
        try:
            evaluate(con)
        except Exception as e:
            log("告警引擎出错", e)
        try:
            from . import insight
            insight.maybe_push_report(con)
        except Exception as e:
            log("周报出错", e)
        stop.wait(config.ALERT_EVAL)


# ---------------------------------------------------------------- 给页面用
def list_events(con, kind="", limit=50, before=0):
    q, a = "SELECT id,ts,kind,level,key,title,detail,sent FROM alerts WHERE 1=1", []
    if kind:
        q += " AND kind=?"
        a.append(kind)
    if before:
        q += " AND id<?"
        a.append(before)
    rows = con.execute(q + " ORDER BY id DESC LIMIT ?", a + [max(1, min(200, limit))]).fetchall()
    return [dict(zip(("id", "ts", "kind", "level", "key", "title", "detail", "sent"), r)) for r in rows]


def seen_ts(con):
    r = con.execute("SELECT v FROM kv WHERE k='alert_seen'").fetchone()
    return int(float(r[0])) if r else 0


def unread(con):
    return con.execute("SELECT COUNT(*) FROM alerts WHERE ts>? AND level IN ('bad','warn','info')", (seen_ts(con),)).fetchone()[0]


def mark_seen(con):
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES('alert_seen',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (str(time.time()),))


def counts(con, since):
    out = {x: 0 for x in LEVELS}
    for lv, n in con.execute("SELECT level, COUNT(*) FROM alerts WHERE ts>=? GROUP BY level", (int(since),)):
        out[lv] = n
    return out


def baseline_table(con, now=None, limit=12):
    """每台设备:这一小时已用 / 平时同钟点均值,方便一眼看出谁偏离了平时。"""
    now = now or time.time()
    hour_now = time.strftime("%Y-%m-%d %H", time.localtime(now))
    since = time.strftime("%Y-%m-%d %H", time.localtime(now - 24 * 3600))
    top = con.execute("SELECT client, SUM(up+down) s FROM hourly WHERE hour>=? AND client!='' GROUP BY client ORDER BY s DESC LIMIT ?", (since, limit)).fetchall()
    cache = _dev_names(con)
    cur = {c: b for c, b in con.execute("SELECT client, SUM(up+down) FROM hourly WHERE hour=? GROUP BY client", (hour_now,))}
    out = []
    for client, s24 in top:
        base, n, how = _baseline(con, client, hour_now, now)
        b = cur.get(client, 0)
        out.append({"key": client, "name": _dev_label(con, client, cache), "now": b, "base": round(base), "samples": n, "how": how,
                    "ratio": round(b / base, 2) if base else None, "last24": s24})
    return out
