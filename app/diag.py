"""自检 + 诊断包。
自检:对面板自己的运行状态、数据一致性、配置做一遍检查,把「看起来不对劲」的地方列出来(很多 bug 会先在这里露出来)。
诊断包:版本、配置摘要、节点/订阅状态、最近告警、面板日志、前端报错、自检结果打成一个 JSON;默认把 IP/MAC/设备别名打码,不含任何密码或 Token。"""
import hashlib
import os
import platform
import re
import sys
import threading
import time

from . import tidy, netstat, agh, dnsx, nikkilog, airports, alerts, config, devices, panellog, probe, providers, sysinfo, syslog, ups, expiry, dockerapi, wan, listen

STARTED = time.time()
MAC = re.compile(r"\b([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b")
NUM = re.compile(r"\d+")


def _web():
    from . import web
    return web


def _f(level, title, detail="", act=None):
    """act = {"label": 按钮文字, "url": POST 接口, "body": 请求体}:前端在这一项旁边显示一个按钮。"""
    d = {"level": level, "title": title, "detail": detail}
    if act:
        d["act"] = act
    return d


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
        out.append(_f("bad", "面板连不上 nikki", f"{st.get('error') or '采集器未启动'}。检查「设置 → 内核连接」里的地址和密码。"))
    live_at = w.live()["at"]
    if live_at and now - live_at > 20:
        out.append(_f("warn", "实时采集停了", f"实时数据已经 {int(now - live_at)} 秒没有更新,设备页/实时速度会停住。看面板日志里有没有「实时速度读取失败」。"))
    try:
        from . import nodegeo
        ng = nodegeo.summary(con)
        if ng["cn"]:
            out.append(_f("warn", f"{ng['cn']} 个节点的服务器登记在中国大陆", "节点名写的是境外,但服务器 IP 登记在中国大陆(重点关注):" + "、".join(x["node"] for x in ng["rows"] if x["level"] == "high" and not x["ignored"])[:160] + "。到「安全 → 回看 → 节点所在地」查看详情。"))
    except Exception:
        pass
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
    for i, d in enumerate(sysinfo.STATE.get("disks") or ([dict(sysinfo.STATE["disk"], name="面板数据盘")] if sysinfo.STATE.get("disk") else [])):
        if d.get("pct") is None:
            continue
        try:
            if alerts.disk_rule(alerts.load_cfg(con), d.get("mp") or "")[0]:
                continue
        except Exception:
            pass
        if d["pct"] >= 95:
            out.append(_f("bad", f"「{d['name']}」快满了", f"已用 {d['pct']}%,剩余 {d['free'] // 1048576} MB。" + ("数据库写不进去会丢统计。" if i == 0 else "")))
        elif d["pct"] >= 85:
            out.append(_f("warn", f"「{d['name']}」空间偏紧", f"已用 {d['pct']}%。"))
    try:
        sc = syslog.load_cfg(con)
        if sc["on"] and syslog._state["err"]:
            out.append(_f("warn", "系统日志接收没起来", syslog._state["err"] + "。换一个端口,或看看是不是被别的程序占用了。"))
        else:
            sl = syslog.silence(con)
            if sl:
                out.append(_f(sl["level"], sl["title"], sl["detail"]))
        if syslog._state["drop"]:
            out.append(_f("info", f"系统日志已丢弃 {syslog._state['drop']} 条", "短时间内日志太多(每秒超过 300 条),超出的被丢弃了。多半是某个服务在狂刷日志,值得去看看是谁。"))
        if dockerapi.load_cfg(con)["on"] and dockerapi.STATE["ok"] is False:
            out.append(_f("warn", "读不到 Docker 容器信息", dockerapi.STATE["err"]))
        if ups.load_cfg(con)["on"] and ups.STATE["ok"] is False:
            out.append(_f("warn", "读不到 UPS", ups.STATE["err"]))
        for t, v in list(expiry.STATE["certs"].items()) + list(expiry.STATE["domains"].items()):
            if v.get("days") is not None and v["days"] <= 14:
                out.append(_f("warn", f"{t} {'已过期' if v['days'] < 0 else str(v['days']) + ' 天后到期'}", "证书或域名快到期了,记得续期。"))
    except Exception:
        pass
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
        if re.search(r"出错|失败|Traceback|错误|Error", line) and not re.search(r"[:,]\s*0 个超时/失败", line):   # 「节点探测完成…0 个超时/失败」是正常日志
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
        out.append(_f("warn", "有不少流量归不到机场", f"近 7 天 {round(noc * 100 / tot)}% 的代理流量落在「未分类」节点上。到「设置 → 订阅归类」补规则,套餐用量和机场统计才准。"))
    used = {r[0] for r in con.execute("SELECT DISTINCT node FROM hourly WHERE hour>=?", (time.strftime("%Y-%m-%d %H", time.localtime(now - 86400)),))} - airports.SPECIAL - {"DIRECT", "REJECT"}
    scored = {r[0] for r in con.execute("SELECT DISTINCT node FROM qoe WHERE hour>=?", (time.strftime("%Y-%m-%d %H", time.localtime(now - 86400)),))}
    if len(used) >= 3 and len(used & scored) * 2 < len(used):
        out.append(_f("info", "多数在用的节点没有测速评分", f"最近 24 小时用到 {len(used)} 个节点,只有 {len(used & scored)} 个有测速数据。开启「设置 → 节点探测」后评分会覆盖在用的节点。"))
    q = _kv(con, "quota", {}) or {}
    nodes = w.all_nodes()
    aps = {w.airport_of(n) for n in nodes}
    off = providers.official()
    for ap in q:
        if ap not in aps and ap not in off:
            out.append(_f("warn", f"套餐「{ap}」对不上任何机场", "机场名和「订阅归类」/订阅名都不一致,这条套餐不会有用量。"))
    wn = wan.snapshot()
    if wn["at"] and wn["up"] is False:
        out.append(_f("bad", "宽带现在是断的", "路由器没有默认路由。"))
    elif not wn["at"] and now - STARTED > 120:
        out.append(_f("warn", "宽带质量没有数据", "探测线程没有产出样本。看面板日志里「宽带质量探测出错」。"))
    elif wn["at"] and wn["mode"] == "tcp":
        out.append(_f("info", "宽带质量在用 TCP 探测", "容器没有 ICMP 权限,退回用 TCP 53 的连接耗时,丢包判断会粗一些。"))
    # 近 15 分钟 TCP 重传率:够样本且正常(< 2%)时,网关 ICMP 丢包基本是运营商限速,不再提示;偏高才当作真问题
    seg = [x for x in list(netstat.SERIES) if x[0] >= now - 900]
    out_seg, rt_seg = sum(x[1] for x in seg), sum(x[2] for x in seg)
    rt_rate = rt_seg * 100 / out_seg if out_seg >= 2000 else None
    for t, v in (wn.get("targets") or {}).items():
        if v.get("silent"):
            out.append(_f("info", f"{t} 不回应 ICMP", "这个探测目标从没回应过(被运营商或对方屏蔽),不参与丢包判断。可以忽略。"))
        elif v.get("gw") and v["n"] >= 12 and v["loss"] >= 20:
            if rt_rate is None:
                out.append(_f("info", f"到网关的 ICMP 丢包 {v['loss']}%", "运营商常对 PPPoE 对端的 ICMP 限速,不一定是真丢包。对照「TCP 重传率」和「告警」里的 TCP 重传提醒来判断线路是否真的有问题。"))
            elif rt_rate >= 2:
                out.append(_f("warn", f"到网关丢包 {v['loss']}%,TCP 重传率也偏高({rt_rate:.1f}%)", "两项同时异常,线路很可能真的有问题:检查光猫 / 网线 / PPPoE 拨号,必要时联系运营商。"))
    try:
        muted = set(tidy.sub_muted(con))
        for p in providers.fetch():
            at = providers.parse_ts(p["updated"])
            if p["name"] in muted:
                continue
            if at and p["has_info"] and now - at > 72 * 3600:
                out.append(_f("warn", f"订阅「{p['name']}」{int((now - at) // 86400)} 天没更新", "官方用量/到期数据会停在旧值;到 nikki 里手动更新一次看报什么错。已经不用这个订阅的话,可以停用提醒(「订阅长时间没更新」告警和这条自检都不再提它)。",
                              {"label": "不再提醒这个订阅", "url": "/api/submute", "body": {"name": p["name"], "on": True}}))
        if muted:
            out.append(_f("info", f"已停用 {len(muted)} 个订阅的「没更新」提醒", "、".join(sorted(muted))[:120],
                          {"label": "全部恢复提醒", "url": "/api/submute", "body": {"clear": True}}))
    except Exception:
        pass
    named = devices.stored_names(con)
    un = [k for k in w.realtime.LIVE["clients"] if k not in named][:50]
    if len(un) >= 5:
        out.append(_f("info", f"{len(un)} 台设备还没起名字", "到设备页点名字旁边的 ✎ 起个名,告警和统计更好认。"))
    try:
        ls = listen.status()
        if ls["fallback_from"]:
            out.append(_f("warn", f"面板端口 {ls['fallback_from']} 被占用,现在用的是 {ls['current']['port']}", "「设置 → 内核连接 → 面板自己的访问地址和端口」里改成一个固定的空闲端口,避免每次重启地址变化。"))
    except Exception:
        pass
    try:
        if ups.STATE.get("onbatt_since"):
            out.append(_f("bad", "UPS 正在用电池供电", "市电断了,看「设置 → 电源与到期监控」里的电量和预计续航。"))
        if dockerapi.load_cfg(con)["on"] and dockerapi.STATE["ok"]:
            rows = (dockerapi._cache["v"] or {}).get("rows") or []
            bad = [r["name"] for r in rows if r["state"] == "restarting" or "unhealthy" in (r.get("status") or "")]
            if bad:
                out.append(_f("warn", f"{len(bad)} 个容器状态异常:{'、'.join(bad[:5])}", "在「容器」页看状态和日志。"))
        if syslog.load_cfg(con)["on"]:
            n = con.execute("SELECT COUNT(*) FROM syslog WHERE ts>=? AND sev<=3", (int(now) - 86400,)).fetchone()[0]
            if n >= 5:
                top = con.execute("SELECT tag,COUNT(*) FROM syslog WHERE ts>=? AND sev<=3 GROUP BY tag ORDER BY 2 DESC LIMIT 1", (int(now) - 86400,)).fetchone()
                out.append(_f("warn", f"最近 24 小时路由器有 {n} 条 error 及以上的日志", f"最多的来源是「{top[0]}」({top[1]} 条)。到「路由器日志」页看内容;诊断包里附了最近的明细。"))
    except Exception:
        pass
    try:
        rb = con.execute("SELECT COUNT(*) FROM alerts WHERE kind='router_reboot' AND ts>=?", (int(now) - 86400,)).fetchone()[0]
        if rb >= 2:
            hint = ""
            try:
                r = con.execute("SELECT msg FROM syslog WHERE ts>=? AND sev<=3 AND tag='kernel' AND (msg LIKE '%I/O error, dev %' OR msg LIKE '%EXT4-fs error%') ORDER BY ts DESC LIMIT 1", (int(now) - 86400,)).fetchone()
                m = re.search(r"dev (sd[a-z]+)|device (sd[a-z]+)", r[0]) if r else None
                n = con.execute("SELECT COUNT(*) FROM syslog WHERE ts>=? AND tag='kernel' AND (msg LIKE '%I/O error, dev %' OR msg LIKE '%EXT4-fs error%')", (int(now) - 86400,)).fetchone()[0] if r else 0
                if m:
                    dv = m.group(1) or m.group(2)
                    mpl = sysinfo.dev_map().get(re.match(r"sd[a-z]+", dv).group(0)) if re.match(r"sd[a-z]+", dv) else None
                    hint = f"同时内核有 {n} 条磁盘错误({dv}{'，现在挂载的是 ' + '、'.join(mpl[:2]) if mpl else ''}),很可能是这块硬盘或它的 USB 连接出了问题(之前就有过因此重启)。可以先把它拔掉、不在开机时挂载,观察是否还重启。"
            except Exception:
                pass
            out.append(_f("bad" if rb >= 4 else "warn", f"最近 24 小时路由器重启了 {rb} 次", hint or "看「告警」时间线里的「路由器重启」,再对照路由器日志里重启前的最后几条;常见原因是硬盘 / USB 故障、供电或过热。"))
    except Exception:
        pass
    try:
        ac = agh.load_cfg(con)
        d = agh._cache.get("data") or {}
        if ac["url"] and ac["on"] and d.get("configured") and d.get("ok") is False:
            out.append(_f("warn", "读不到 AdGuard Home", f"{d.get('error') or '连接失败'}。「设置 → DNS 解析」里检查地址和账号。"))
        for s in dnsx.servers_status(con, now)["servers"]:
            if s["at"] and s["ms"] is None:
                out.append(_f("warn", f"DNS 服务器「{s['name']}」没有响应", f"{s['note']}(近 24 小时丢包 {s['loss_pct']}%)。看「安全」页的 DNS 卡片。"))
            elif s["n24"] >= 20 and s["loss_pct"] >= 20:
                out.append(_f("warn", f"DNS 服务器「{s['name']}」丢包 {s['loss_pct']}%", "近 24 小时有不少探测没得到回应。"))
        dm = dnsx.dnsmasq_stats(con, {}, now)
        if dm["q24"] >= 200 and dm["nx_rate"] >= 30:
            out.append(_f("info", f"dnsmasq 的 NXDOMAIN 比例偏高({dm['nx_rate']}%)", "说明很多查询的域名不存在;看「安全」页 DNS 卡片里「查不到的域名」,常见原因是 IPv6 / 搜索域 / 某个设备在乱查。"))
        if syslog.load_cfg(con)["on"] and not dm["enabled"] and not (ac["url"] and ac["on"]):
            out.append(_f("info", "没有 DNS 查询统计", "没接 AdGuard Home,也没收到 dnsmasq 的查询日志。在「设置 → DNS 解析」里看开启办法(路由器开 dnsmasq 查询日志,面板只读)。"))
    except Exception:
        pass
    try:
        nl = nikkilog.status(con)
        if nl["cfg"]["on"]:
            e24 = sum(v for k, v in nl["by_24h"].items() if k.endswith(":错误"))
            if e24 >= 10:
                tm = nikkilog.top_messages(con, int(now) - 86400, 1, 3)   # 只在「错误」里挑最多的,不被直连超时这类警告顶替
                out.append(_f("warn", f"最近 24 小时 nikki 日志有 {e24} 条错误", (f"最多的是:{tm[0]['example'][:90]}(×{tm[0]['n']})。" if tm else "") + "到「设置 → 内核与插件日志」查看;诊断包里附了汇总和最近的明细。"))
            nz = tidy.noise(con, int(now) - 86400)
            names = devices.stored_names(con)
            for x in [r for r in nz["rows"] if not r["ignored"] and r["n"] >= 30][:3]:
                who = names.get(x["src"].lower()) or x["src"]
                out.append(_f("info", f"「{who}」24 小时内直连 {x['host']} 失败 {x['n']} 次",
                              "同一设备反复连同一个地址超时,多半是它自己的云服务暂时不通或被屏蔽,不是面板的问题;会把 nikki 日志顶满。确认没问题可以忽略这一项(只是不再提醒,不影响日志)。",
                              {"label": "忽略这一项", "url": "/api/noise/ignore", "body": {"key": x["key"], "on": True}}))
            ig = [r for r in nz["rows"] if r["ignored"]]
            if ig:
                out.append(_f("info", f"已忽略 {len(ig)} 项设备直连失败", "、".join(f"{r['src']}→{r['host']}" for r in ig[:3]),
                              {"label": "全部恢复提醒", "url": "/api/noise/ignore", "body": {"clear": True}}))
            if not nl["rows"] and not nl["mode"]["core"] and not nl["mode"]["app"]:
                out.append(_f("info", "还没有收到 nikki 日志", "启动后需要一会儿;如果一直没有,看「设置 → 内核与插件日志」里的提示(要在 compose 里只读挂载 /var/log/nikki)。"))
    except Exception:
        pass
    try:
        from . import auth, health
        if not auth.enabled():
            out.append(_f("warn", "面板没有设置访问密码", "同一局域网的任何人都能打开面板、看到每台设备访问的域名并修改设置。到「设置 → 安全与访问」设置访问密码。"))
        for c_ in health.checks(con):
            if c_["level"] == "bad" and c_["name"] in ("数据目录可写", "数据目录磁盘", "后台任务"):
                out.append(_f("bad", c_["name"] + "异常", c_["detail"] + (";" + c_["hint"] if c_["hint"] else "")))
            elif c_["level"] == "warn" and c_["name"] in ("数据目录磁盘", "数据库大小", "系统时间"):
                out.append(_f("warn", c_["name"] + "需要注意", c_["detail"] + (";" + c_["hint"] if c_["hint"] else "")))
    except Exception:
        pass
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


def domain_masker():
    """域名 → 代号(域名#xxxxxx)。每个诊断包用一把随机盐,同一个域名在包里是同一个代号(统计 / 排行仍然成立),
    但看不出访问了什么,也没法拿常见域名列表去撞。"""
    salt = os.urandom(8)
    seen = {}

    def f(d):
        d = str(d or "").strip().lower().rstrip(".")
        if not d or d in ("", "-"):
            return d
        if d not in seen:
            seen[d] = "域名#" + hashlib.sha1(salt + d.encode()).hexdigest()[:6]
        return seen[d]
    return f


DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
NOT_DOMAIN = {"yaml", "yml", "json", "log", "txt", "conf", "so", "sh", "go", "py", "mmdb", "db", "dat", "js", "html", "css", "png", "ipk", "tgz", "gz", "zip", "lua", "sock", "pid"}


def mask_domains(t, mk):
    """文本里像域名的片段换成代号(mk 是 domain_masker() 返回的函数);config.yaml 这类文件名不动。"""
    def f(m):
        s = m.group(0)
        return s if s.rsplit(".", 1)[-1].lower() in NOT_DOMAIN else mk(s)
    return DOMAIN_RE.sub(f, str(t))


def mask_text(t, names=()):
    t = MAC.sub(lambda m: ":".join(m.group(0).replace("-", ":").split(":")[:3]) + ":**:**:**", str(t))
    t = IPV4.sub(lambda m: f"{m.group(1)}.{m.group(2)}.*.*", t)
    for i, n in enumerate(names):
        if len(n) >= 2:
            t = t.replace(n, f"设备{i + 1}")
    return t


def _ext(con, m, full, now, logs=False, dom=False):
    """路由器日志 / UPS / 到期 / 容器 / 监听地址 的详细诊断(默认打码;不含容器日志、环境变量、密码)。"""
    out = {}
    # ---- 路由器日志
    try:
        st = syslog.status(con)
        cfg = st.pop("cfg")
        since = int(now) - 86400
        tags = [{"tag": r[0], "n": r[1], "worst": syslog.SEV[r[2]]} for r in con.execute(
            "SELECT tag,COUNT(*),MIN(sev) FROM syslog WHERE ts>=? GROUP BY tag ORDER BY COUNT(*) DESC LIMIT 15", (since,))]
        hourly = {time.strftime("%m-%d %H", time.localtime(r[0] * 3600)): r[1] for r in con.execute(
            "SELECT ts/3600,COUNT(*) FROM syslog WHERE ts>=? AND sev<=3 GROUP BY ts/3600 ORDER BY 1", (since,))}
        recent = [{"time": time.strftime("%m-%d %H:%M:%S", time.localtime(r["ts"])), "lv": r["lv"], "tag": r["tag"], "msg": m(r["msg"])[:220]}
                  for r in syslog.query(con, level=4, n=60)]
        out["syslog"] = dict(st, cfg=cfg, top_tags_24h=tags, error_per_hour_24h=hourly, recent_warn_and_above=recent)
        if logs:      # 勾选「包含日志明细」:最近 300 条(任何级别),已打码
            out["syslog"]["recent_all_levels"] = [f"{time.strftime('%m-%d %H:%M:%S', time.localtime(r['ts']))} [{r['lv']}] {m(r['tag'])}: {m(r['msg'])[:240]}"
                                                  for r in syslog.query(con, level=7, n=300)]
    except Exception as e:
        out["syslog"] = {"error": f"{type(e).__name__}: {e}"}
    # ---- DNS:AdGuard 日志 / dnsmasq 日志与统计 / 自定义 DNS 服务器
    try:
        dmask = domain_masker() if dom else (lambda d: m(d))
        ag = agh.diag_info(con)
        if ag.get("querylog"):
            ag["querylog"]["recent"] = [dict(r, client=m(r["client"]), d=dmask(r["d"])) for r in ag["querylog"]["recent"]]
        ag["url"] = m(ag.get("url", ""))
        dm = dnsx.dnsmasq_stats(con, {}, now)
        for k in ("top_clients",):
            dm[k] = [{"ip": m(r["ip"]), "n": r["n"]} for r in dm[k]]
        dm["top_domains"], dm["top_nx"] = [{"d": dmask(r["d"]), "n": r["n"]} for r in dm["top_domains"][:10]], [{"d": dmask(r["d"]), "n": r["n"]} for r in dm["top_nx"][:10]]
        dm["recent_lines"] = [f"{time.strftime('%m-%d %H:%M:%S', time.localtime(r['ts']))} [{syslog.SEV[r['sev']]}] {r['tag']}: {m(r['msg'])[:220]}" for r in dnsx.dnsmasq_lines(con, 60 if logs else 30)]
        sv = dnsx.servers_status(con, now)
        out["dns"] = {"domains_masked": bool(dom), "adguard": ag, "dnsmasq": dm, "custom_servers": {"domain": sv["domain"], "every_sec": sv["every"],
                      "servers": [{"name": s["name"], "addr": m(f"{s['host']}:{s['port']}"), "ms": s["ms"], "note": s["note"], "loss_pct_24h": s["loss_pct"], "avg_ms_24h": s["avg_ms"], "samples_24h": s["n24"]} for s in sv["servers"]]}}
    except Exception as e:
        out["dns"] = {"error": f"{type(e).__name__}: {e}"}
    # ---- nikki 内核 / 插件日志
    try:
        st = nikkilog.status(con)
        cfg = st.pop("cfg")
        dm2 = domain_masker() if dom else None
        mm = (lambda x: mask_domains(m(x), dm2)) if dom else m
        since = int(now) - 86400
        fmt = lambda r: f"{time.strftime('%m-%d %H:%M:%S', time.localtime(r['ts']))} [{r['lv']}] {mm(r['msg'])[:240]}"
        out["nikki_log"] = dict(st, cfg={k: cfg[k] for k in ("on", "level", "days", "max_rows", "dir_eff")},
                                top_warn_error_24h=[dict(x, example=mm(x["example"])) for x in nikkilog.top_messages(con, since)],
                                noise_top=[{"src": m(r["src"]), "host": mm(r["host"]), "n": r["n"], "ignored": r["ignored"]} for r in tidy.noise(con, since)["rows"][:8]],
                                recent_core_warn_and_above=[fmt(r) for r in nikkilog.query(con, "core", 4, "", 60)],
                                recent_plugin=[fmt(r) for r in nikkilog.query(con, "app", 7, "", 60)])
        if logs:
            out["nikki_log"]["recent_all_levels"] = {s_: [fmt(r) for r in nikkilog.query(con, s_, 7, "", 300)] for s_ in ("core", "app")}
    except Exception as e:
        out["nikki_log"] = {"error": f"{type(e).__name__}: {e}"}
    # ---- 健康检查与访问安全(只有开关状态,没有任何密码 / 令牌)
    try:
        from . import auth, health
        out["health"] = [{"name": c["name"], "level": c["level"], "detail": m(c["detail"])} for c in health.checks(con)]
        out["access"] = {"password_set": auth.enabled(), "viewer_account": auth.has_viewer(), "allow_nets_set": bool(os.environ.get("ALLOW_NETS")),
                         "trusted_proxies_extra": bool(os.environ.get("TRUSTED_PROXIES")), "page_token": bool(config.PAGE_TOKEN)}
        out["auto_backups"] = [{"name": b["name"], "size": b["size"]} for b in health.listing()]
    except Exception as e:
        out["health"] = {"error": f"{type(e).__name__}: {e}"}
    # ---- 订阅更新相关的 nikki 日志(排查订阅长时间没更新)
    try:
        from . import nikkilog as _nk
        out["sub_update_log"] = [f"{time.strftime('%m-%d %H:%M:%S', time.localtime(t))} {m(x)[:240]}" for t, x in _nk.provider_errors(con, "", 30)]
    except Exception as e:
        out["sub_update_log"] = {"error": f"{type(e).__name__}: {e}"}
    # ---- 关联分析(本周对比 / 故障时间线 / 无线事件)
    try:
        from . import analysis
        cp = analysis.compare(con)
        tl = analysis.timeline(con, 72)
        wf = analysis.wifi(con, 24)
        out["analysis"] = {"compare_notes": [x["text"] for x in cp["notes"]], "traffic_delta_pct": cp["traffic"]["delta_pct"], "retrans": cp["retrans"], "wan": cp["wan"],
                           "nodes_worse": cp["nodes_worse"], "timeline_marks": tl["marks"], "wifi": {"available": wf["available"], "flap": wf.get("flap", []), "lines": wf["lines"]}}
    except Exception as e:
        out["analysis"] = {"error": f"{type(e).__name__}: {e}"}
    # ---- 更新检查(为什么没提示新版本:看 error / latest / 仓库是否绑定)
    try:
        from . import update
        u = update.check()
        out["update"] = {k: u.get(k) for k in ("current", "latest", "newer", "enabled", "error")}
    except Exception as e:
        out["update"] = {"error": f"{type(e).__name__}: {e}"}
    # ---- UPS
    try:
        uc = ups.load_cfg(con)
        ser = [r for r in list(ups.SERIES) if r[1] is not None]
        sm = None
        if ser:
            col = lambda i: [r[i] for r in ser if r[i] is not None]
            rng = lambda v: {"min": min(v), "max": max(v), "avg": round(sum(v) / len(v), 1)} if v else None
            sm = {"samples": len(ser), "minutes": int((ser[-1][0] - ser[0][0]) // 60), "charge": rng(col(1)), "load": rng(col(2)), "runtime_sec": rng(col(3)), "input_v": rng(col(4))}
        evs = [{"time": time.strftime("%F %T", time.localtime(e["ts"])), "kind": e["kind"], "level": e["level"], "title": e["title"], "detail": m(e["detail"])}
               for k in ("ups_onbatt", "ups_low", "ups_lost") for e in alerts.list_events(con, kind=k, limit=15)]
        evs.sort(key=lambda e: e["time"], reverse=True)
        out["ups"] = {"cfg": {"on": uc["on"], "host": m(uc["host"]), "port": uc["port"], "name": uc["name"]}, "ok": ups.STATE["ok"], "err": ups.STATE["err"],
                      "read_age_sec": int(now - ups.STATE["at"]) if ups.STATE["at"] else None, "info": ups.STATE["info"],
                      "onbatt_since": ups.STATE["onbatt_since"] or None, "series_3h": sm, "recent_events": evs[:20]}
    except Exception as e:
        out["ups"] = {"error": f"{type(e).__name__}: {e}"}
    # ---- 到期
    try:
        ec = expiry.load_cfg(con)
        expiry._restore(con)
        nm = (lambda t, i, k: t) if full else (lambda t, i, k: f"{k}{i + 1}")
        out["expiry"] = {"cfg_counts": {"certs": len(ec["certs"]), "domains": len(ec["domains"])}, "checked_age_sec": int(now - expiry.STATE["at"]) if expiry.STATE["at"] else None,
                         "certs": [{"name": nm(t, i, "证书"), "days": v.get("days"), "trusted": v.get("trusted"), "issuer": v.get("issuer"), "err": v.get("err")} for i, (t, v) in enumerate(expiry.STATE["certs"].items())],
                         "domains": [{"name": nm(t, i, "域名"), "days": v.get("days"), "err": v.get("err")} for i, (t, v) in enumerate(expiry.STATE["domains"].items())]}
    except Exception as e:
        out["expiry"] = {"error": f"{type(e).__name__}: {e}"}
    # ---- 容器
    try:
        dc = dockerapi.load_cfg(con)
        d = {"cfg": {"on": dc["on"], "url": m(dc["url"]), "control": dc["control"], "control_password_set": dockerapi.control_ok()},
             "ok": dockerapi.STATE["ok"], "err": dockerapi.STATE["err"], "n": dockerapi.STATE["n"]}
        if dc["on"]:
            snap = dockerapi.snapshot(con)
            rows = snap.get("rows") or []
            d["summary"] = {"running": sum(1 for r in rows if r["state"] == "running"), "total": len(rows),
                            "not_running": [r["name"] for r in rows if r["state"] != "running"], "unhealthy": [r["name"] for r in rows if "unhealthy" in (r.get("status") or "")],
                            "restarting": [r["name"] for r in rows if r["state"] == "restarting"]}
            d["containers"] = [{"name": r["name"], "image": r["image"], "state": r["state"], "status": r["status"], "cpu": r["cpu"], "mem": r["mem"], "mem_limit": r["mem_limit"],
                                "ports": r["ports"], "net": r["net"], "project": r["project"], "locked": r["locked"]} for r in rows][:80]
        evs = [{"time": time.strftime("%F %T", time.localtime(e["ts"])), "kind": e["kind"], "level": e["level"], "title": e["title"], "detail": m(e["detail"])}
               for e in alerts.list_events(con, limit=200) if e["kind"] in ("docker_down", "docker_unhealthy") or (e["kind"] == "audit" and e["key"] == "docker")]
        d["recent_events"] = evs[:25]
        out["docker"] = d
    except Exception as e:
        out["docker"] = {"error": f"{type(e).__name__}: {e}"}
    # ---- 目的地国家 / ASN Top(近 7 天;只含国家码和 ASN 名,不含域名和 IP)
    try:
        from . import insight
        g = insight.geo_summary(con, 7)
        out["geo_top"] = {"days": 7, "available": g["available"], "known_pct": round(g["known"] * 100 / g["all"], 1) if g["all"] else None,
                          "note": "只统计能看到真实目的地的流量(直连等),代理流量只能看到节点所在国",
                          "countries": [{"cc": x["cc"], "bytes": x["bytes"]} for x in g["by_cc"][:15]], "asn": [{"asn": x["asn"], "bytes": x["bytes"]} for x in g["by_asn"][:10]]}
    except Exception as e:
        out["geo_top"] = {"error": f"{type(e).__name__}: {e}"}
    # ---- 节点登记地与节点名地区不符(只读判断)
    try:
        from . import nodegeo
        ng = nodegeo.summary(con)
        out["node_geo"] = {"note": "登记地=节点服务器 IP 在 GeoIP 库里的国家;不符多半是中转 / CDN,登记在中国大陆(CN)的标重点关注",
                           "cn_registered": ng["cn"], "mismatch_other": ng["mid"], "cdn_like": ng["low"], "ignored": ng["ignored"],
                           "nodes": [{"node": x["node"], "name_region": x["name_cc"], "registered": x["reg_cc"], "asn": x["asn"], "server": m(x["remote"]),
                                      "level": x["level"], "ignored": x["ignored"]} for x in ng["rows"][:60]]}
    except Exception as e:
        out["node_geo"] = {"error": f"{type(e).__name__}: {e}"}
    # ---- 磁盘 / 监听 / 功能开关
    try:
        out["disks"] = sysinfo.snapshot(1).get("disks")
    except Exception:
        out["disks"] = None
    try:
        ls = listen.status()
        out["listen"] = {"current": ls["current"], "env": ls["env"], "fallback_from": ls["fallback_from"], "pending": bool(ls["pending"]), "last_msg": ls["msg"]}
    except Exception:
        out["listen"] = None
    return out


def bundle(con, full=False, now=None, logs=False, dom=False):
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
    for t in ("traffic", "hourly", "app_hourly", "qoe", "alerts", "ipmap", "wanq", "dns", "syslog"):
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
        "ext": _ext(con, m, full, now, logs, dom),
        "features": {"syslog": syslog.load_cfg(con)["on"], "ups": ups.load_cfg(con)["on"], "docker": dockerapi.load_cfg(con)["on"],
                     "expiry": bool(expiry.load_cfg(con)["certs"] or expiry.load_cfg(con)["domains"])},
        "db": {"size_bytes": dbsize, "rows": counts},
        "threads": sorted(t.name for t in threading.enumerate()),
        "alerts_recent": ev,
        "client_errors": panellog.client_errors(),
        "log": [m(x) for x in panellog.tail(300)],
    }
