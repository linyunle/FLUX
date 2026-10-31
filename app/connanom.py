"""v0.52(P3):设备连接行为基线 + 异常判定 + 规则式诊断。

- 基线:每台设备按「一天中的小时」统计历史并发连接(P50 / P95)、新增速率 P95、UDP 占比、常见目标;
  历史不足(新设备)时不假装有基线,改用更保守的固定门槛,并把可信度标成「低」。轻量档只算整体基线。
- 判定:14 种信号,各有权重;连续 2 次检查都成立才算,避免一个毛刺就报警;
  级别:正常 / 需要关注 / 高度可疑 / 无法判断。可信度低、又缺少连接表佐证时给「无法判断」,不硬下结论。
- 诊断:每个事件带 现象 / 关键证据 / 可能原因 / 证据不足项 / 结论 / 建议排查方向。相关性不等于因果,文字里明确写。
只读,不改任何设置;任何异常只记在 STATE["err"]。
"""
import time

from . import connhist

STATE = {"on": True, "err": "", "checks": 0, "base_at": 0.0, "base_devs": 0, "at": 0.0}
BASE = {}          # dev -> 基线
LEVEL = {}         # dev -> 最近一次判定 {level, conf, score, signals, at}
PENDING = []       # 新出现的「高度可疑」事件,交给告警模块推送
NOTES = []         # 新开的「需要关注 / 无法判断」事件,只写时间线、不推送
_streak = {}       # dev -> 连续成立次数
_clear = {}        # dev -> 开始恢复正常的时间
_emit = {}         # dev -> 上次写事件的 (level, 时间)
_todo = []         # 待重算基线的设备
COMMON_PORTS = {"80", "443", "53", "853", "8080", "8443"}

SIG = {
    "sudden_growth": ("连接数突然增长", 2), "sustained_high": ("连接数持续偏高", 2), "new_rate": ("新建连接速率过高", 2),
    "close_rate": ("关闭连接速率过高", 1), "short_conns": ("大量短连接", 2), "long_unreleased": ("大量长时间未释放的连接", 1),
    "proto_drift": ("TCP / UDP 比例偏离平时", 1), "many_ips": ("目标 IP 数量异常多", 2), "many_domains": ("目标域名数量异常多", 1),
    "port_focus": ("端口高度集中", 1), "new_targets": ("出现平时没有的目标", 1), "failures": ("握手失败 / 无回应连接多", 2),
    "node_anom": ("无回应连接集中在某个节点", 1), "habit_dev": ("明显偏离这台设备平时的习惯", 1),
}
CAUSE = {
    "sudden_growth": "某个应用刚启动或批量发起连接(下载、同步、扫描)",
    "sustained_high": "BT / PT 下载、持续同步、监控类应用,或设备异常",
    "new_rate": "短时间内大量新建连接(扫描、爬取、重试风暴)",
    "close_rate": "大量连接被快速关闭或被对端重置",
    "short_conns": "连接建立后很快结束:常见于端口扫描、DNS 风暴、频繁重试",
    "long_unreleased": "连接泄漏(程序没有关闭连接)或长连接类应用(下载 / 推送)",
    "proto_drift": "UDP 占比明显变化:QUIC / 视频通话 / P2P / DNS 异常都会出现",
    "many_ips": "访问的目标分散:P2P、扫描、CDN 大量分发",
    "many_domains": "访问的域名很多:爬取、广告 / 追踪请求、批量检测",
    "port_focus": "几乎都连同一个非常见端口:专用服务或定向扫描 / 攻击",
    "new_targets": "出现平时没有访问过的目标:新应用,或设备被使用方式改变",
    "failures": "目标不可达、被防火墙或节点丢弃、节点故障",
    "node_anom": "该节点出口异常或线路故障,导致握手无回应",
    "habit_dev": "与这台设备同一时段的历史相比明显偏高",
}
ADVICE = {
    "sudden_growth": "在设备上查看刚启动的程序;对照「连接明细」里数量最多的目标",
    "sustained_high": "确认是否有下载 / 同步任务;必要时在设备上暂停相应程序后观察连接数是否回落",
    "new_rate": "看事件快照里的 Top 目标和端口;确认设备是否在批量访问同一类地址",
    "close_rate": "对照「失败 / 无回应」证据,检查节点和线路是否稳定",
    "short_conns": "看 Top 目标是否集中在少数地址 / 端口;排查设备上是否有扫描或重试逻辑的程序",
    "long_unreleased": "到连接明细按「持续时间」排序,找出最久的连接属于哪个应用",
    "proto_drift": "按 UDP 筛选连接明细,看目标端口(443 多为 QUIC,53 为 DNS)",
    "many_ips": "按目标 IP 看分布;若是 P2P 类应用属正常现象",
    "many_domains": "按域名看分布,确认是否为浏览器 / 广告类请求",
    "port_focus": "确认该端口对应的服务是否你预期的",
    "new_targets": "确认这些目标是否你认识的服务",
    "failures": "按「状态」筛选「无回应 / 正在连接」,查看目标和节点;必要时切换节点对比",
    "node_anom": "到节点页看该节点延迟和丢包,尝试切换节点",
    "habit_dev": "对比该设备平时同一时段的连接趋势",
}


def _pct(v, q):
    if not v:
        return 0
    v = sorted(v)
    return v[min(len(v) - 1, int(len(v) * q))]


def compute_base(con, dev, now):
    """用历史分钟数据算基线;lite=轻量档只算整体。"""
    p = connhist.params()
    rows = con.execute("SELECT ts,conns,tcp,udp,new,top FROM conn_dev_min WHERE dev=? AND ts>=?", (dev, int(now) - p["hist"] * 86400)).fetchall()
    if not rows:
        BASE[dev] = {"n": 0, "days": 0, "all": None, "hours": {}, "udp": None, "hosts": set(), "at": now}
        return
    lite = p["baseline"] == "lite"
    by_h, allc, alln = {}, [], []
    tcp = udp = 0
    hosts = {}
    for ts, c, t, u, n, top in rows:
        allc.append(c); alln.append(n); tcp += t; udp += u
        if not lite:
            by_h.setdefault(time.localtime(ts).tm_hour, []).append((c, n))
        if top and len(hosts) < 400:
            try:
                import json
                for k, _ in json.loads(top).get("d", [])[:2]:
                    hosts[k] = hosts.get(k, 0) + 1
            except ValueError:
                pass
    hours = {h: (len(v), _pct([x[0] for x in v], .5), _pct([x[0] for x in v], .95), _pct([x[1] for x in v], .95)) for h, v in by_h.items()}
    span = (rows[-1][0] - rows[0][0]) / 86400 if len(rows) > 1 else 0
    BASE[dev] = {"n": len(rows), "days": round(span, 1), "all": (len(rows), _pct(allc, .5), _pct(allc, .95), _pct(alln, .95)), "hours": hours,
                 "udp": (udp / (tcp + udp)) if tcp + udp else None, "hosts": {k for k, c in hosts.items() if c >= 3}, "at": now}


def refresh_base(now, devs):
    """每次最多重算 3 台设备;全部轮完后 30 分钟再来一轮。"""
    global _todo
    if not _todo:
        if now - STATE["base_at"] < 1800:
            return
        _todo = [d for d in devs]
        STATE["base_at"] = now
    if not _todo:
        return
    from . import db
    con = db.open_db(readonly=True)
    try:
        for _ in range(3):
            if not _todo:
                break
            compute_base(con, _todo.pop(), now)
    finally:
        con.close()
    STATE["base_devs"] = len(BASE)


def ref(dev, now):
    """返回 (p50, p95, new95, 可信度, 说明)。没有可靠基线时 p95 为 None。"""
    b = BASE.get(dev)
    if not b or not b["all"] or b["all"][0] < 60:
        return None, None, None, "low", "这台设备历史数据不足(新设备或刚开启),使用更保守的固定门槛,结论可信度低"
    h = b["hours"].get(time.localtime(now).tm_hour)
    if h and h[0] >= 30:
        return h[1], h[2], h[3], ("high" if b["days"] >= 3 else "medium"), f"对比这台设备同一小时的历史({h[0]} 个分钟样本)"
    a = b["all"]
    return a[1], a[2], a[3], "medium" if b["days"] >= 1 else "low", f"对比这台设备整体历史({a[0]} 个分钟样本)"


def detect(dev, now, rows, ct_ok):
    """返回 (signals, insufficient, 基线说明, 可信度)。rows = 这台设备的当前连接明细。"""
    r = list(connhist.RING.get(dev, ()))
    sig, miss = [], []
    if len(r) < 3:
        return [], ["采样点不足 3 个"], "", "low"
    p50, p95, new95, conf, why = ref(dev, now)
    cur = r[-1]
    conns, tcp, udp = cur[1], cur[2], cur[3]
    span = max(1, cur[0] - r[0][0])
    prior = [x for x in r if cur[0] - x[0] >= 20 and cur[0] - x[0] <= 90]
    hi = max(150, 1.5 * p95 + 20) if p95 is not None else 400
    new_hi = max(150, 3 * (new95 or 0) / max(1, connhist.params()["res"])) if p95 is not None else 600

    def add(i, ev):
        sig.append({"id": i, "name": SIG[i][0], "weight": SIG[i][1], "evidence": ev})
    if prior:
        pm = min(x[1] for x in prior)
        if conns >= 3 * max(pm, 10) and conns - pm >= 100:
            add("sudden_growth", f"连接数从约 {pm} 升到 {conns}(不到 90 秒内)")
    five = [x for x in r if cur[0] - x[0] <= 300]
    if len(five) >= 3 and cur[0] - five[0][0] >= 240 and all(x[1] >= hi for x in five):
        add("sustained_high", f"最近 {int((cur[0] - five[0][0]) / 60)} 分钟连接数一直 ≥ {int(hi)}(当前 {conns})")
    minute = [x for x in r if cur[0] - x[0] <= 60]
    new_pm = sum(x[4] for x in minute)
    close_pm = sum(x[5] for x in minute)
    if new_pm >= new_hi:
        add("new_rate", f"最近 1 分钟新建 {new_pm} 个连接(门槛 {int(new_hi)})")
    if close_pm >= new_hi:
        add("close_rate", f"最近 1 分钟关闭 {close_pm} 个连接(门槛 {int(new_hi)})")
    if new_pm >= max(120, new_hi * 0.6) and conns < new_pm / 2:
        add("short_conns", f"1 分钟新建 {new_pm} 个但当前只剩 {conns} 个:大量连接很快结束")
    if rows:
        old = sum(1 for x in rows if x[1] and now - x[1] > 3600)
        if old >= 100:
            add("long_unreleased", f"{old} 个连接已持续超过 1 小时")
        ips = {x[2] for x in rows if x[2]}
        if len(ips) >= 200:
            add("many_ips", f"当前连向 {len(ips)} 个不同的真实目标 IP")
        hosts = {x[3] for x in rows if x[3]}
        if len(hosts) >= 150:
            add("many_domains", f"当前访问 {len(hosts)} 个不同域名")
        if len(rows) >= 100:
            pc = {}
            for x in rows:
                pc[x[4]] = pc.get(x[4], 0) + 1
            pt, pn = max(pc.items(), key=lambda y: y[1])
            if pt and pt not in COMMON_PORTS and pn / len(rows) >= 0.8:
                add("port_focus", f"{int(pn * 100 / len(rows))}% 的连接都去往非常见端口 {pt}")
            b = BASE.get(dev)
            if b and b["hosts"] and conf != "low":
                hc = {}
                for x in rows:
                    if x[3]:
                        hc[x[3]] = hc.get(x[3], 0) + 1
                if hc:
                    ht, hn = max(hc.items(), key=lambda y: y[1])
                    if ht not in b["hosts"] and hn / len(rows) >= 0.5:
                        add("new_targets", f"一半以上连接去往 {ht},平时这台设备不常访问")
    b = BASE.get(dev)
    if b and b["udp"] is not None and conf != "low" and conns >= 50 and tcp + udp:
        us = udp / (tcp + udp)
        if abs(us - b["udp"]) > 0.4:
            add("proto_drift", f"UDP 占比 {int(us * 100)}%,平时约 {int(b['udp'] * 100)}%")
    elif conf == "low":
        miss.append("没有可靠的历史基线,无法判断 TCP / UDP 比例和目标是否偏离习惯")
    if ct_ok:
        bad = max(cur[6], cur[7])           # 两者描述的是同一类 TCP 连接,取大不相加;UDP 没回应不算
        if bad >= max(30, 0.3 * tcp):
            add("failures", f"TCP 正在握手 {cur[6]} 个、TCP 对端无回应 {cur[7]} 个(当前 TCP 共 {tcp} 个;UDP 没回应很常见,不计入)")
        if rows:
            un = {}
            tot = 0
            for x in rows:
                if x[5] == "无回应":
                    un[x[6]] = un.get(x[6], 0) + 1
                    tot += 1
            if tot >= 20:
                nd, nn = max(un.items(), key=lambda y: y[1])
                if nn / tot >= 0.8:
                    add("node_anom", f"{nn}/{tot} 个无回应连接都走节点「{nd}」")
    else:
        miss.append("读不到路由器连接表,握手失败 / 无回应类证据无法判断")
    if p95 is not None and conns > 2 * p95 + 20 and conns >= 100:
        add("habit_dev", f"当前 {conns} 个连接,这台设备{why.replace('对比这台设备', '')}的 P95 是 {p95}")
    return sig, miss, why, conf


def grade(sig, conf, ct_ok):
    score = sum(s["weight"] for s in sig)
    if score == 0:
        return "normal", 0
    if conf == "low" and not ct_ok and score < 5:
        return "unknown", score
    if score >= 5 or (score >= 4 and conf != "low"):
        return "suspect", score
    return "attention", score


def diagnose(dev_name, level, sig, miss, why, conf, conns):
    names = "、".join(s["name"] for s in sig) or "无"
    causes = []
    for s in sig:
        c = CAUSE[s["id"]]
        if c not in causes:
            causes.append(c)
    advice = []
    for s in sig:
        a = ADVICE[s["id"]]
        if a not in advice:
            advice.append(a)
    concl = {"suspect": "多项指标同时偏离,且证据较充分,建议尽快核对。", "attention": "有指标偏离,但不足以判断为故障或攻击,建议观察。",
             "unknown": "信息不足(缺少历史基线和连接表佐证),无法判断是否异常。"}.get(level, "未发现异常。")
    return {"phenomenon": f"{dev_name} 当前 {conns} 个并发连接;出现:{names}。", "evidence": [s["evidence"] for s in sig],
            "causes": causes[:5], "insufficient": list(miss),
            "conclusion": concl + "以上原因只是常见情形,同时出现不等于因果关系,需要结合设备上的实际应用确认。",
            "advice": advice[:5], "confidence": conf, "baseline": why}


def check(now, dstat, ct_dev, rows, rcol, ct_ok, label=None):
    """每次连接明细刷新后调用。"""
    if not STATE["on"]:
        return
    try:
        STATE["at"] = now
        STATE["checks"] += 1
        refresh_base(now, list(dstat))
        by = {}
        for x in rows:
            by.setdefault(x[rcol["dev"]], []).append(x)
        for dev, d in dstat.items():
            if d["conns"] < 20 and (dev, "conn_anom") not in connhist.ACTIVE:
                LEVEL.pop(dev, None)
                _streak.pop(dev, None)
                continue
            mine = [[None, x[rcol["start"]], x[rcol["dst"]], x[rcol["host"]], x[rcol["dport"]], _state(x, rcol), x[rcol["node"]]]
                    for x in by.get(dev, [])]
            sig, miss, why, conf = detect(dev, now, mine, ct_ok)
            level, score = grade(sig, conf, ct_ok)
            LEVEL[dev] = {"level": level, "conf": conf, "score": score, "signals": [s["id"] for s in sig], "at": int(now), "why": why}
            if level == "normal":
                _streak[dev] = 0
                t0 = _clear.setdefault(dev, now)
                if now - t0 >= 120 and (dev, "conn_anom") in connhist.ACTIVE:
                    connhist.resolve(dev, "conn_anom", now)
                    _emit.pop(dev, None)
                continue
            _clear.pop(dev, None)
            _streak[dev] = _streak.get(dev, 0) + 1
            if _streak[dev] < 2:
                continue
            last = _emit.get(dev)
            if last and last[0] == level and now - last[1] < 30:
                continue
            nm = label(dev) if label else _label(dev)
            dg = diagnose(nm, level, sig, miss, why, conf, d["conns"])
            title = f"{connhist.LEVELS.get(level, level)}:" + "、".join(s["name"] for s in sig[:3])
            eid = connhist.trigger(dev, "conn_anom", level, title, {"signals": sig, "score": score, "conns": d["conns"], "conf": conf}, now,
                                   [x for x in rows if x[rcol["dev"]] == dev] if not last else None, rcol if not last else None, dg)
            if eid and (not last or (last[0] != "suspect" and level == "suspect")):
                if level == "suspect":
                    PENDING.append({"id": eid, "dev": dev, "title": title, "diag": dg})
                    del PENDING[:-50]
                elif connhist.LAST["new"]:
                    NOTES.append({"id": eid, "dev": dev, "title": title, "diag": dg})
                    del NOTES[:-50]
            _emit[dev] = (level, now)
        for dev in [k for k in LEVEL if k not in dstat]:
            LEVEL.pop(dev, None)
        STATE["err"] = ""
    except Exception as e:
        STATE["err"] = f"{type(e).__name__}: {e}"[:120]


def _state(x, rcol):
    return "无回应" if x[rcol["unrep"]] and x[rcol["proto"]] == "tcp" else x[rcol["state"]]


def _label(dev):
    try:
        from . import alerts, db
        con = db.open_db(readonly=True)
        try:
            return alerts._dev_label(con, dev)
        finally:
            con.close()
    except Exception:
        return dev


def overview():
    out = {"normal": 0, "attention": 0, "suspect": 0, "unknown": 0}
    for v in LEVEL.values():
        out[v["level"]] = out.get(v["level"], 0) + 1
    return out
