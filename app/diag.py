"""自检 + 诊断包。
自检:对面板自己的运行状态、数据一致性、配置做一遍检查,把「看起来不对劲」的地方列出来(很多 bug 会先在这里露出来)。
诊断包:版本、配置摘要、节点/订阅状态、最近告警、面板日志、前端报错、自检结果打成一个 JSON;默认把 IP/MAC/设备名打码,不含任何密码或 Token。"""
import os
import platform
import re
import sys
import threading
import time

from . import agh, airports, alerts, config, devices, panellog, probe, providers, sysinfo, wan

STARTED = time.time()
MAC = re.compile(r"\b([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b")
NUM = re.compile(r"\d+")


def _web():
    from . import web
    return web


def _f(level, title, detail=""):
    return {"level": level, "title": title, "detail": detail}


def _kv(con, k, d=None):
    from .insight import _kv_get
    return _kv_get(con, k, d)


def _rss_mb():
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) // 1024
    except Exception:
        pass
    return None


def selfcheck(con, now=None):
    now = now or time.time()
    out = []
    w = _web()
    c = w.collector.COLLECTOR
    st = dict(c.status) if c else {}
    if not c or not st.get("ok"):
        out.append(_f("bad", "面板连不上 nikki", f"{st.get('error') or '采集器未启动'}。检查「设置 → 连接」里的地址和密码。"))
    live_at = w.live()["at"]
    if live_at and now - live_at > 20:
        out.append(_f("warn", "实时采集停了", f"实时数据已经 {int(now - live_at)} 秒没有更新,设备页/实时速度会停住。看面板日志里有没有「实时速度读取失败」。"))
    names = {t.name for t in threading.enumerate()}
    for n, label in (("realtime", "实时采集"), ("alerts", "告警引擎"), ("wanq", "宽带质量探测")):
        if n not in names:
            out.append(_f("bad", f"{label}线程不在了", "这个后台线程已经退出,重启容器能恢复;请把诊断包发给我看原因。"))
    try:
        r = con.execute("PRAGMA quick_check(1)").fetchone()
        if r and r[0] != "ok":
            out.append(_f("bad", "数据库自检没通过", str(r[0])[:200] + "。先备份设置,再考虑删除 data/traffic.db 重建。"))
    except Exception as e:
        out.append(_f("warn", "数据库自检出错", str(e)))
    d = sysinfo.STATE.get("disk")
    if d and d.get("pct") is not None:
        if d["pct"] >= 95:
            out.append(_f("bad", "面板数据盘快满了", f"已用 {d['pct']}%,剩余 {d['free'] // 1048576} MB。数据库写不进去会丢统计。"))
        elif d["pct"] >= 85:
            out.append(_f("warn", "面板数据盘空间偏紧", f"已用 {d['pct']}%。"))
    if time.localtime(now).tm_year < 2024:
        out.append(_f("warn", "系统时间不对", "年份早于 2024,统计的日期会错乱;检查路由器时间/NTP。"))
    rss = _rss_mb()
    if rss and rss > 400:
        out.append(_f("warn", "面板占用内存偏高", f"{rss} MB。若还在增长,可能有内存泄漏,请把诊断包发给我。"))
    ac = alerts.load_cfg(con)
    if not any(ch.get("on", True) for ch in ac["channels"]):
        out.append(_f("info", "没有配置推送渠道", "所有告警只会记录在「告警」页,不会推送到手机。"))
    # 日志里重复出现的错误
    seen = {}
    for line in panellog.tail(800):
        if re.search(r"出错|失败|Traceback|错误|Error", line):
            k = NUM.sub("#", line[20:])[:120]
            seen[k] = seen.get(k, 0) + 1
    for k, n in sorted(seen.items(), key=lambda x: -x[1])[:5]:
        if n >= 3:
            out.append(_f("warn", f"日志里重复出现 {n} 次:{k[:60]}", "不一定是 bug(例如 nikki 重启期间连不上),但持续出现就值得看。"))
    ce = panellog.client_errors()
    for e in ce[:5]:
        out.append(_f("bad", f"页面脚本报错({e['n']} 次):{e['msg'][:80]}", "这是浏览器里的 JavaScript 报错,通常会让某张卡片显示不出来。请把诊断包发给我。"))
    # 数据一致性
    since = time.strftime("%Y-%m-%d", time.localtime(now - 7 * 86400))
    tot = noc = 0
    for node, s in con.execute("SELECT node, SUM(up+down) FROM traffic WHERE day>=? GROUP BY node", (since,)):
        if node in airports.SPECIAL or node in ("DIRECT", "REJECT"):
            continue
        tot += s or 0
        if w.airport_of(node) == airports.NONE:
            noc += s or 0
    if tot and noc * 100 / tot >= 20:
        out.append(_f("warn", "有不少流量归不到机场", f"近 7 天 {round(noc * 100 / tot)}% 的代理流量落在「未分类」节点上。到「设置 → 机场归类」补规则,套餐用量和机场统计才准。"))
    used = {r[0] for r in con.execute("SELECT DISTINCT node FROM hourly WHERE hour>=?", (time.strftime("%Y-%m-%d %H", time.localtime(now - 86400)),))} - airports.SPECIAL - {"DIRECT", "REJECT"}
    scored = {r[0] for r in con.execute("SELECT DISTINCT node FROM qoe WHERE hour>=?", (time.strftime("%Y-%m-%d %H", time.localtime(now - 86400)),))}
    if len(used) >= 3 and len(used & scored) * 2 < len(used):
        out.append(_f("info", "多数在用的节点没有测速评分", f"最近 24 小时用到 {len(used)} 个节点,只有 {len(used & scored)} 个有测速数据。开启「设置 → 节点测速」后评分会覆盖在用的节点。"))
    q = _kv(con, "quota", {}) or {}
    nodes = w.all_nodes()
    aps = {w.airport_of(n) for n in nodes}
    off = providers.official()
    for ap in q:
        if ap not in aps and ap not in off:
            out.append(_f("warn", f"套餐「{ap}」对不上任何机场", "机场名和「机场归类」/订阅名都不一致,这条套餐不会有用量。"))
    wn = wan.snapshot()
    if wn["at"] and wn["up"] is False:
        out.append(_f("bad", "宽带现在是断的", "路由器没有默认路由。"))
    elif not wn["at"] and now - STARTED > 120:
        out.append(_f("warn", "宽带质量没有数据", "探测线程没有产出样本。看面板日志里「宽带质量探测出错」。"))
    elif wn["at"] and wn["mode"] == "tcp":
        out.append(_f("info", "宽带质量在用 TCP 探测", "容器没有 ICMP 权限,退回用 TCP 53 的连接耗时,丢包判断会粗一些。"))
    for t, v in (wn.get("targets") or {}).items():
        if v.get("silent"):
            out.append(_f("info", f"{t} 不回应 ICMP", "这个探测目标从没回应过(被运营商或对方屏蔽),不参与丢包判断。可以忽略。"))
        elif v.get("gw") and v["n"] >= 12 and v["loss"] >= 20:
            out.append(_f("info", f"到网关的 ICMP 丢包 {v['loss']}%", "运营商常对 PPPoE 对端的 ICMP 限速,不一定是真丢包。对照「TCP 重传率」和「告警」里的 TCP 重传提醒来判断线路是否真的有问题。"))
    try:
        for p in providers.fetch():
            at = providers.parse_ts(p["updated"])
            if at and p["has_info"] and now - at > 72 * 3600:
                out.append(_f("warn", f"订阅「{p['name']}」{int((now - at) // 86400)} 天没更新", "官方用量/到期数据会停在旧值;到 nikki 里手动更新一次看报什么错。"))
    except Exception:
        pass
    named = devices.stored_names(con)
    un = [k for k in w.realtime.LIVE["clients"] if k not in named][:50]
    if len(un) >= 5:
        out.append(_f("info", f"{len(un)} 台设备还没起名字", "到设备页点名字旁边的 ✎ 起个名,告警和统计更好认。"))
    lv = {"bad": 0, "warn": 1, "info": 2}
    out.sort(key=lambda f: lv.get(f["level"], 3))
    if not out:
        out.append(_f("ok", "没有发现问题", "自检的各项都正常。"))
    return out


def _names(con):
    try:
        return sorted({str(v) for v in devices.stored_names(con).values() if v}, key=len, reverse=True)
    except Exception:
        return []


def mask_text(t, names=()):
    t = MAC.sub(lambda m: ":".join(m.group(0).replace("-", ":").split(":")[:3]) + ":**:**:**", str(t))
    t = IPV4.sub(lambda m: f"{m.group(1)}.{m.group(2)}.*.*", t)
    for i, n in enumerate(names):
        if len(n) >= 2:
            t = t.replace(n, f"设备{i + 1}")
    return t


def bundle(con, full=False, now=None):
    now = now or time.time()
    w = _web()
    names = [] if full else _names(con)
    m = (lambda s: str(s)) if full else (lambda s: mask_text(s, names))
    ac = alerts.load_cfg(con)
    a = agh.load_cfg(con)
    q = _kv(con, "quota", {}) or {}
    cf = config.get()
    c = w.collector.COLLECTOR
    try:
        pv = providers.status(con)
    except Exception as e:
        pv = {"ok": False, "error": str(e)}
    for r in pv.get("rows", []):
        r.pop("cmp", None)
    counts = {}
    for t in ("traffic", "hourly", "app_hourly", "qoe", "alerts", "ipmap", "wanq", "dns"):
        try:
            counts[t] = con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        except Exception:
            counts[t] = None
    try:
        dbsize = os.path.getsize(config.DB_PATH)
    except OSError:
        dbsize = None
    ev = [{"time": time.strftime("%F %T", time.localtime(e["ts"])), "kind": e["kind"], "level": e["level"], "title": m(e["title"]),
           "detail": m(e["detail"]), "sent": e["sent"]} for e in alerts.list_events(con, limit=60)]
    return {
        "flux_diag": 1, "created": time.strftime("%F %T", time.localtime(now)), "masked": not full,
        "version": config.VERSION, "python": sys.version.split()[0], "platform": platform.platform(),
        "process_uptime_sec": int(now - STARTED), "rss_mb": _rss_mb(),
        "selfcheck": selfcheck(con, now),
        "nikki": {"api": cf["api"] if full else mask_text(cf["api"]), "has_secret": bool(cf["secret"]), "status": dict(c.status) if c else None},
        "config": {
            "rules": {k: v for k, v in ac["rules"].items()}, "quiet": ac["quiet"],
            "channels": [{"type": ch.get("type"), "on": ch.get("on", True)} for ch in ac["channels"]],
            "agh": {"configured": bool(a["url"]), "on": a["on"], "has_user": bool(a["user"]), "has_pass": bool(a["pass"])},
            "quota": q, "probe": probe.load_cfg(con), "airport_rules_lines": len(airports.rules_text().splitlines()),
            "interval": config.INTERVAL, "keep_days": config.KEEP_DAYS, "hour_keep_days": config.HOUR_KEEP_DAYS,
            "wan_iface_env": list(w.collector.WAN_IFACES),
        },
        "providers": pv.get("rows"),
        "nodes": [{"name": n, "type": v.get("type"), "delay": v.get("delay"), "fails": v.get("fails")} for n, v in (c.nodes.items() if c else [])][:400],
        "sys": {k: v for k, v in sysinfo.snapshot(60).items() if k != "series"},
        "wan": wan.snapshot(),
        "db": {"size_bytes": dbsize, "rows": counts},
        "threads": sorted(t.name for t in threading.enumerate()),
        "alerts_recent": ev,
        "client_errors": panellog.client_errors(),
        "log": [m(x) for x in panellog.tail(300)],
    }
