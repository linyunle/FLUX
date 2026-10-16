"""给管理员的建议:节点评分、新目的地国家、套餐预计超额。都是只读判断,面板只提示,不会改任何配置。"""
import datetime
import time

from . import alerts, insight


def _hour(t):
    return time.strftime("%Y-%m-%d %H", time.localtime(t))


def _score(n, sd, sq, f):
    """0~100:延迟 40% + 超时率 40% + 波动 20%。测速不足 10 次不评分。"""
    tests = n + f
    if tests < 10:
        return None
    avg = sd / n if n else None
    fail = f / tests
    if avg is None:
        return {"score": 0, "avg": None, "jitter": None, "fail": round(fail, 4), "tests": tests}
    jit = max(0.0, sq / n - avg * avg) ** 0.5
    c = lambda x: max(0.0, min(1.0, x))
    s = 40 * c(1 - (avg - 80) / 420) + 40 * c(1 - fail / 0.2) + 20 * c(1 - jit / max(avg, 50))
    return {"score": round(s), "avg": round(avg), "jitter": round(jit), "fail": round(fail, 4), "tests": tests}


def node_scores(con, now=None):
    now = now or time.time()
    h_now, h_24, h_8d = _hour(now), _hour(now - 24 * 3600), _hour(now - 8 * 24 * 3600)
    q = "SELECT node, SUM(n), SUM(sum_d), SUM(sum_sq), SUM(fails) FROM qoe WHERE hour>=? AND hour<=? GROUP BY node"
    cur = {r[0]: _score(*r[1:]) for r in con.execute(q, (h_24, h_now))}
    base = {r[0]: _score(*r[1:]) for r in con.execute("SELECT node, SUM(n), SUM(sum_d), SUM(sum_sq), SUM(fails) FROM qoe WHERE hour>=? AND hour<? GROUP BY node", (h_8d, h_24))}
    used = {r[0]: r[1] or 0 for r in con.execute("SELECT node, SUM(up+down) FROM hourly WHERE hour>=? GROUP BY node", (_hour(now - 48 * 3600),))}
    w = insight._web()
    rows = []
    for node, c in cur.items():
        if not c:
            continue
        b = base.get(node)
        delta = (c["score"] - b["score"]) if b else None
        tips = []
        if c["fail"] >= 0.1:
            tips.append(f"近 24 小时测速超时率 {c['fail'] * 100:.0f}%,线路不稳")
        if c["avg"] is not None and c["avg"] >= 300:
            tips.append(f"平均延迟 {c['avg']} ms 偏高")
        if delta is not None and delta <= -20:
            tips.append(f"比过去一周平时低 {-delta} 分")
        if tips and used.get(node, 0) > 0:
            tips.append("正在被使用:可考虑在策略组里换节点或降低它的优先级")
        rows.append({"node": node, "airport": w.airport_of(node), **c, "base": b["score"] if b else None, "delta": delta,
                     "used": used.get(node, 0), "level": "bad" if c["score"] < 50 else "warn" if c["score"] < 70 else "ok",
                     "advice": ";".join(tips)})
    rows.sort(key=lambda r: (r["score"], r["node"]))
    return rows


def check_degrade(con, cfg, now):
    r = cfg["rules"]["node_degrade"]
    for x in node_scores(con, now):
        if x["used"] < 1024 * 1024 or x["base"] is None or x["score"] >= 70:
            continue
        if x["base"] - x["score"] >= r["drop"] and alerts._allow("node_degrade", x["node"], r["cool_min"], now):
            alerts.fire(con, cfg, "node_degrade", "warn", x["node"], f"节点变差:{x['node']}",
                        f"评分 {x['score']}(过去一周平时 {x['base']})。{x['advice']}。", now)


def check_geo_new(con, cfg, now):
    r = cfg["rules"]["geo_new"]
    today = time.strftime("%Y-%m-%d", time.localtime(now))
    since = time.strftime("%Y-%m-%d", time.localtime(now - 30 * 86400))
    days = con.execute("SELECT COUNT(DISTINCT day) FROM geo WHERE day>=? AND day<?", (since, today)).fetchone()[0]
    if days < 5:   # 历史太短,谈不上「新」
        return
    seen = {c for (c,) in con.execute("SELECT cc FROM geo WHERE day>=? AND day<? GROUP BY cc HAVING SUM(up+down)>0", (since, today))}
    for cc, b in con.execute("SELECT cc, SUM(up+down) FROM geo WHERE day=? GROUP BY cc", (today,)):
        if cc and cc not in seen and (b or 0) >= r["min_mb"] * 1048576 and alerts._allow("geo_new", cc, r["cool_min"], now):
            alerts.fire(con, cfg, "geo_new", "info", cc, f"出现新的目的地国家:{cc}",
                        f"今天有 {b / 1048576:.0f} MB 流量去往 {cc},过去 30 天没有去过这个国家。可能是新的服务/CDN,也可能是异常设备,到「安全」页的目的地分布里看是谁。只统计能看到真实目的地的流量(直连等)。", now)


def check_quota_forecast(con, cfg, now):
    r = cfg["rules"]["quota_forecast"]
    for q in insight.quota_status(con):
        if not (q["known"] and q["over"] and q["pct"] >= 30 and q["pct"] < 100):
            continue
        if alerts._allow("quota_forecast", q["airport"] + q["start"], r["cool_min"] * 30, now):
            alerts.fire(con, cfg, "quota_forecast", "warn", q["airport"], f"套餐预计超额:{q['airport']}",
                        f"本周期已用 {q['pct']}%,按近 7 天速度预计 {q['exhaust']} 用完,早于重置日 {q['end']}。可以适当减少大流量下载,或换别的机场分担。", now)
