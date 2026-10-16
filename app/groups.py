"""设备分组 + 分组白名单。
- 分组:给设备贴标签(IoT / 手机 / 电脑 / 访客 / 自定义),存在 kv: dev_groups。
- 白名单:某个分组可以设「允许访问的域名」(按后缀匹配,example.com 也含 a.example.com)。
  组里的设备访问了名单之外的域名,就告警一次(同一设备同一域名 24 小时内不重复)。只看域名,不看 IP;
  走代理的流量看不到真实目的地时以 mihomo 记录的域名为准,没有域名的连接不判断。
- 「学习」:把某分组最近 7 天实际访问过的域名(合并到主域名)列出来,一键填成白名单草稿,再人工删减。"""
import ipaddress
import json
import time

DEFAULT_GROUPS = ["IoT", "手机", "电脑", "访客"]
_prev = {}   # (day, dev, host) -> 累计字节
_seeded = {"day": ""}


def _get(con, k, default):
    try:
        r = con.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
        return json.loads(r[0]) if r else default
    except Exception:
        return default


def _put(con, k, v):
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, json.dumps(v, ensure_ascii=False)))


def dev_groups(con):
    d = _get(con, "dev_groups", {})
    return {str(k): str(v) for k, v in d.items() if isinstance(d, dict) and v} if isinstance(d, dict) else {}


def set_group(con, dev, group):
    dev = (dev or "").strip().lower()
    group = (group or "").strip()[:20]
    if not dev:
        raise ValueError("缺少设备")
    d = dev_groups(con)
    if group:
        d[dev] = group
    else:
        d.pop(dev, None)
    if len(d) > 2000:
        raise ValueError("分组太多")
    _put(con, "dev_groups", d)
    return d


def _norm_domains(v):
    items = v if isinstance(v, list) else str(v or "").replace(",", "\n").split("\n")
    out = []
    for x in items:
        x = str(x).strip().lower().lstrip("*.").strip()
        if x and "/" not in x and " " not in x and len(x) <= 100 and x not in out:
            out.append(x)
    return out[:300]


def policy(con):
    d = _get(con, "group_policy", {})
    out = {}
    if isinstance(d, dict):
        for g, v in d.items():
            if isinstance(v, dict):
                out[str(g)[:20]] = {"on": bool(v.get("on")), "allow": _norm_domains(v.get("allow"))}
    return out


def save_policy(con, group, on, allow):
    group = (group or "").strip()[:20]
    if not group:
        raise ValueError("缺少分组名")
    p = policy(con)
    p[group] = {"on": bool(on), "allow": _norm_domains(allow)}
    _put(con, "group_policy", p)
    return p[group]


def names(con):
    used = sorted(set(dev_groups(con).values()) | set(policy(con)))
    return used + [g for g in DEFAULT_GROUPS if g not in used]


def allowed(host, allow):
    h = host.lower().rstrip(".")
    return any(h == a or h.endswith("." + a) for a in allow)


def _is_ip(h):
    try:
        ipaddress.ip_address(h.strip("[]"))
        return True
    except ValueError:
        return False


SLD = {"co", "com", "net", "org", "gov", "edu", "ac"}


def base_domain(host):
    parts = host.lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    n = 3 if len(parts[-1]) == 2 and parts[-2] in SLD else 2
    return ".".join(parts[-n:])


def learn(con, group, days=7):
    devs = [d for d, g in dev_groups(con).items() if g == group]
    if not devs:
        return []
    since = time.strftime("%Y-%m-%d", time.localtime(time.time() - days * 86400))
    q = ",".join("?" * len(devs))
    agg = {}
    for host, b in con.execute(f"SELECT host, SUM(up+down) FROM traffic WHERE day>=? AND client IN ({q}) GROUP BY host", [since, *devs]):
        if not host or host == "unknown" or _is_ip(host):
            continue
        d = base_domain(host)
        agg[d] = agg.get(d, 0) + (b or 0)
    return [{"domain": d, "bytes": b} for d, b in sorted(agg.items(), key=lambda kv: -kv[1])[:200]]


def check(con, cfg, now):
    """给告警引擎调用:有白名单的分组里,设备访问了名单之外的域名就告警。第一次只记账不告警。"""
    from . import alerts
    r = cfg["rules"].get("group_policy") or {}
    if not r.get("on", True):
        return
    pol = {g: v for g, v in policy(con).items() if v["on"] and v["allow"]}
    if not pol:
        return
    grp = dev_groups(con)
    day = time.strftime("%Y-%m-%d", time.localtime(now))
    seeded = _seeded["day"] == day
    if not seeded:
        for k in [k for k in _prev if k[0] != day]:
            del _prev[k]
    by_group = {}
    for dev, g in grp.items():
        if g in pol:
            by_group.setdefault(g, []).append(dev)
    cache = None
    for g, devs in by_group.items():
        q = ",".join("?" * len(devs))
        for dev, host, b in con.execute(f"SELECT client, host, SUM(up+down) FROM traffic WHERE day=? AND client IN ({q}) GROUP BY client, host", [day, *devs]):
            if not host or host == "unknown" or _is_ip(host):
                continue
            b = b or 0
            key = (day, dev, host)
            old = _prev.get(key, 0)
            _prev[key] = b
            if not seeded or b <= old or allowed(host, pol[g]["allow"]):
                continue
            if alerts._allow("group_policy", f"{dev}|{base_domain(host)}", r.get("cool_min", 1440), now):
                cache = cache or alerts._dev_names(con)
                name = alerts._dev_label(con, dev, cache)
                alerts.fire(con, cfg, "group_policy", "warn", dev, f"{name} 访问了白名单之外的域名",
                            f"设备「{name}」(分组 {g})访问了 {host},不在这个分组的白名单里。如果它是正常的,到「设置 → 设备分组」把它加进白名单;不认识就留意这台设备。", now)
    _seeded["day"] = day
