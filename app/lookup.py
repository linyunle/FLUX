"""域名查询:一个域名「会怎么走」(按规则推算)和「实际怎么走的」(历史记录 + 当前连接 + 实时 DNS 查询)。

面板对 nikki / AdGuard 只读:这里只调只读接口(/rules /proxies /connections /dns/query、AGH 的 check_host)。
规则推算只能展开 Domain / DomainSuffix / DomainKeyword / DomainRegex 四类静态规则;规则集 / GEOSITE 面板读不到内容,
遇到时只能标出「前面有这些规则集可能先命中」,真正命中哪条以「实际路由」(历史记录里的规则)为准。
"""
import re
import time
import urllib.parse

from . import agh, collector
from .util import api_call, log

_HOST = re.compile(r"^[a-z0-9._\-一-鿿:\[\]]{1,253}$")
_IPLIT = re.compile(r"^[0-9a-f:.]+$")


def clean(h):
    h = str(h or "").strip().lower().rstrip(".")
    h = re.sub(r"^[a-z]+://", "", h).split("/")[0]
    if h.count(":") == 1:          # host:port
        h = h.split(":")[0]
    if not h or not _HOST.match(h):
        raise ValueError("请输入域名,例如 github.com")
    return h


def _norm(t):
    return re.sub(r"[^a-z]", "", str(t or "").lower())


def _match(r, host):
    """True / False / None(无法在面板里判断)"""
    t, pl = _norm(r.get("type")), str(r.get("payload") or "").lower()
    if t in ("match", "final"):
        return True
    if t == "domain":
        return host == pl
    if t == "domainsuffix":
        return host == pl or host.endswith("." + pl)
    if t == "domainkeyword":
        return pl in host
    if t == "domainregex":
        try:
            return bool(re.search(pl, host))
        except re.error:
            return None
    if t in ("geosite", "ruleset"):
        return None
    return False     # IP / 端口 / 进程等规则,对「只知道域名」的查询不适用


def _chain(target):
    """策略组 → 当前选中 → … → 节点;返回 [名字, ...]"""
    c = collector.COLLECTOR
    names, seen, cur = [], set(), target
    groups = dict(c.groups) if c else {}
    while cur and cur not in seen:
        seen.add(cur)
        names.append(cur)
        g = groups.get(cur)
        if not g:
            break
        now, members = g
        cur = now or (members[0] if members else "")
    return names


def _kind(node):
    c = collector.COLLECTOR
    t = (c.ptype.get(node, "") if c else "").lower()
    if node == "DIRECT" or t == "direct":
        return "直连"
    if node.startswith("REJECT") or t in ("reject", "rejectdrop"):
        return "拒绝"
    return "代理"


def _step(n, title, tag, main, sub="", details=None, level=""):
    return {"n": n, "title": title, "tag": tag, "main": main, "sub": sub, "details": details or [], "level": level}


def lookup(con, host):
    host = clean(host)
    is_ip = bool(_IPLIT.match(host)) and (":" in host or host.replace(".", "").isdigit())
    out = {"host": host, "is_ip": is_ip, "errors": []}
    c = collector.COLLECTOR

    # ---- 历史记录(面板自己统计的真实连接)
    exact = True
    rows = con.execute("SELECT rule, grp, node, SUM(up+down), COUNT(DISTINCT client), MIN(day), MAX(day) FROM traffic WHERE host=? GROUP BY rule, grp, node "
                       "ORDER BY SUM(up+down) DESC LIMIT 8", (host,)).fetchall()
    if not rows and not is_ip:
        exact = False
        rows = con.execute("SELECT rule, grp, node, SUM(up+down), COUNT(DISTINCT client), MIN(day), MAX(day) FROM traffic WHERE host LIKE ? ESCAPE '\\' GROUP BY rule, grp, node "
                           "ORDER BY SUM(up+down) DESC LIMIT 8", ("%." + host.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_"),)).fetchall()
    hist = [{"rule": r[0], "group": r[1], "node": r[2], "bytes": r[3] or 0, "devices": r[4], "first": r[5], "last": r[6]} for r in rows]
    out["history"] = {"exact": exact, "rows": hist}
    dnsrows = [{"ip": ip, "mode": md, "last": last} for ip, md, last in
               con.execute("SELECT ip, mode, last FROM dns WHERE host=? ORDER BY last DESC LIMIT 6", (host,))]

    # ---- nikki 规则列表
    rules = []
    try:
        rules = (api_call("/rules", timeout=8) or {}).get("rules") or []
    except Exception as e:
        out["errors"].append(f"读取 nikki 规则列表失败:{type(e).__name__}")
    unknown, first = [], None
    if not is_ip:
        for i, r in enumerate(rules):
            m = _match(r, host)
            if m is None:
                unknown.append({"index": i + 1, "rule": f"{r.get('type')},{r.get('payload')}", "proxy": str(r.get("proxy") or "")})
            elif m:
                first = {"index": i + 1, "type": str(r.get("type") or ""), "payload": str(r.get("payload") or ""), "proxy": str(r.get("proxy") or "")}
                break
    obs = hist[0] if hist else None
    obs_idx = None
    if obs and rules:
        for i, r in enumerate(rules):
            key = (str(r.get("type") or "") + "," + str(r.get("payload") or "")) if r.get("payload") else str(r.get("type") or "")
            if key[:80] == obs["rule"]:
                obs_idx = i + 1
                break

    # ======== 推算
    calc = [_step(1, "发起访问", "IP" if is_ip else "域名", host, "终端来源 IP / 端口未指定")]
    if dnsrows:
        modes = sorted({d["mode"] or "?" for d in dnsrows})
        fake = any(d["mode"] == "fake-ip" for d in dnsrows)
        calc.append(_step(2, "DNS 解析", "按历史推算", "fake-ip(代理 DNS 返回占位地址)" if fake and modes == ["fake-ip"] else "、".join(modes),
                          "记录里出现过的解析方式;" + ("全部走 nikki DNS" if modes == ["fake-ip"] else "有连接没走 fake-ip,可能是设备自带 DNS / DoH"),
                          [f"{d['ip'] or '(fake-ip,无真实 IP)'} · {d['mode']} · {time.strftime('%m-%d %H:%M', time.localtime(d['last']))}" for d in dnsrows]))
    else:
        calc.append(_step(2, "DNS 解析", "无记录", "面板没记录过这个域名的解析方式", "第一次被访问后才会有"))
    if is_ip:
        calc.append(_step(3, "规则匹配", "IP", "IP 地址按 IP 类规则匹配(IP-CIDR / GEOIP 等)", "面板只推算域名规则,请看右边实际路由"))
    elif first:
        det = [f"第 {u['index']} 条 {u['rule']} → {u['proxy']}" for u in unknown[:8]]
        sure = not unknown
        calc.append(_step(3, "规则匹配", f"第 {first['index']} 条", f"{first['type']} {first['payload']}" if first["payload"] else first["type"],
                          ("前面没有需要展开的规则集,按顺序确定命中这条。" if sure else
                           f"前面还有 {len(unknown)} 条规则集 / GEOSITE 面板读不到内容,可能先命中它们;以实际路由为准。"),
                          det, "" if sure else "warn"))
    else:
        calc.append(_step(3, "规则匹配", "未知", "没有找到静态规则能命中", "可能由规则集 / GEOSITE 命中,看实际路由", [f"第 {u['index']} 条 {u['rule']} → {u['proxy']}" for u in unknown[:8]], "warn"))
    target = (first or {}).get("proxy") or (obs and obs["group"]) or ""
    if not first and unknown and not obs:
        target = ""
    if obs_idx and obs and not first:
        target = next((str(r.get("proxy") or "") for i, r in enumerate(rules) if i + 1 == obs_idx), target)
    if target:
        ch = _chain(target)
        leaf = ch[-1]
        d = c.nodes.get(leaf, {}) if c else {}
        calc.append(_step(4, "最终出口", _kind(leaf), " → ".join(ch),
                          (f"当前延迟 {d['delay']} ms" if d.get("delay") else "") + ((" · 已连续 %d 次测速失败" % d["fails"]) if d.get("fails") else ""), [], "warn" if d.get("fails") else ""))
        out["leaf"] = leaf
    else:
        calc.append(_step(4, "最终出口", "未知", "无法推算", "规则集命中的目标要看实际路由"))
    out["calc"] = {"title": "规则路由", "badge": "按规则推算", "steps": calc}

    # ======== 实际
    real = []
    n_all = sum(h["bytes"] for h in hist)
    if hist:
        real.append(_step(1, "访问记录", "域名" if exact else "含子域名", host + ("" if exact else "(未直接访问过,下面是它的子域名)"),
                          f"{hist[0]['first']} ~ {hist[0]['last']} · 共 {_bytes(n_all)} · {max(h['devices'] for h in hist)} 台设备"))
    else:
        real.append(_step(1, "访问记录", "无", "面板里没有这个域名的访问记录", "只能看上面的推算"))
    # DNS 实查
    try:
        t0 = time.time()
        q = api_call("/dns/query?" + urllib.parse.urlencode({"name": host, "type": "A"}), timeout=6) or {}
        ms = int((time.time() - t0) * 1000)
        ans = [a.get("data") for a in (q.get("Answer") or []) if a.get("data")]
        fake = any(str(a).startswith(("198.18.", "198.19.")) for a in ans)
        real_step = _step(2, "DNS 解析", f"{ms} ms", ("FakeIP " if fake else "") + ("、".join(ans[:4]) if ans else "没有返回地址"),
                          "nikki 实时查询" + (" · 返回占位地址,说明这个域名走代理 DNS" if fake else ""), [], "" if ans else "warn")
    except Exception as e:
        real_step = _step(2, "DNS 解析", "失败", f"nikki DNS 查询失败:{type(e).__name__}", "只读查询,没有改动任何设置", [], "warn")
    # AGH
    try:
        cfg = agh.load_cfg(con)
        if cfg.get("url"):
            r = agh._req(cfg, "/control/filtering/check_host?name=" + urllib.parse.quote(host), timeout=5)
            reason = str(r.get("reason") or "")
            blocked = reason.startswith("Filtered") and reason != "FilteredSafeSearch"
            real_step["details"].append(("AdGuard Home:会拦截 · " + (r.get("rule") or reason)) if blocked else "AdGuard Home:不拦截")
            if blocked:
                real_step["level"] = "warn"
    except Exception:
        pass
    real.append(real_step)
    # 当前连接
    live = []
    try:
        for cn in (api_call("/connections", timeout=8) or {}).get("connections") or []:
            m = cn.get("metadata") or {}
            h = str(m.get("host") or m.get("sniffHost") or "").lower()
            if h == host or (not is_ip and h.endswith("." + host)):
                live.append({"chain": list(reversed(cn.get("chains") or [])), "rule": f"{cn.get('rule')},{cn.get('rulePayload')}" if cn.get("rulePayload") else str(cn.get("rule") or ""),
                             "type": str(m.get("type") or ""), "dns": str(m.get("dnsMode") or ""), "src": str(m.get("sourceIP") or "")})
    except Exception as e:
        out["errors"].append(f"读取当前连接失败:{type(e).__name__}")
    out["live"] = live[:6]
    if live:
        types = sorted({x["type"] for x in live if x["type"]})
        real.append(_step(3, "当前连接", f"{len(live)} 条", "进入 nikki:" + ("、".join(types) or "?"),
                          "入口类型来自 nikki 连接记录", [f"{x['src']} · {x['dns'] or '?'} · " + " → ".join(x["chain"]) for x in live[:4]]))
    else:
        real.append(_step(3, "当前连接", "无", "现在没有到这个域名的活动连接", "有连接时这里会显示入口类型和链路"))
    # 命中的规则
    if obs:
        det = [f"{h['rule']} → {h['group'] or '-'} → {h['node']}  ({_bytes(h['bytes'])})" for h in hist[:5]]
        real.append(_step(4, "规则匹配", "连接记录" + (f" · 第 {obs_idx} 条" if obs_idx else ""), obs["rule"] or "(未记录)",
                          "来自面板统计的真实连接,这是实际命中的规则", det))
        leafs = obs["node"]
        real.append(_step(5, "最终出口", _kind(leafs), " → ".join(x for x in (obs["group"], leafs) if x) or leafs,
                          f"{_bytes(obs['bytes'])} · {obs['devices']} 台设备 · 最近 {obs['last']}"))
        if out.get("leaf") and out["leaf"] != leafs and exact:
            real[-1]["sub"] += f" · 与推算的出口不同(推算:{out['leaf']}),策略组可能切换过"
            real[-1]["level"] = "warn"
        out["real_node"] = leafs
    else:
        real.append(_step(4, "规则匹配", "无", "没有连接记录", ""))
        real.append(_step(5, "最终出口", "未知", "没有连接记录", "访问一次后再来查"))
    out["real"] = {"title": "实际路由", "badge": "来自真实连接" if obs else "暂无记录", "steps": real}
    return out


def probe(body):
    """通过指定节点对这个域名做一次延迟测试(nikki 自己发请求,和「节点探测」是同一个接口)。"""
    host = clean(body.get("host"))
    node = str(body.get("node") or "")[:120]
    c = collector.COLLECTOR
    if not node or not c or node not in c.nodes:
        raise ValueError("节点不存在")
    q = urllib.parse.urlencode({"url": f"https://{host}/", "timeout": 6000})
    try:
        r = api_call(f"/proxies/{urllib.parse.quote(node, safe='')}/delay?{q}", timeout=9) or {}
        return {"ok": True, "delay": int(r.get("delay") or 0), "node": node}
    except Exception as e:
        log("域名实测失败", e)
        return {"ok": False, "node": node, "error": f"{type(e).__name__}"}


def _bytes(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
