"""节点「登记地」与「节点名地区」对不上的检查(只读判断,面板不会改 nikki 的任何配置)。

登记地 = 节点服务器 IP 在 GeoIP 库里登记的国家;节点名地区 = 节点名里写的地区(香港 / HK / Japan …)。
两者不同,常见原因:中转 / IEPL 专线、CDN 前置、机场名字乱标,也可能是节点被替换。
登记在中国大陆(CN)而名字写的是境外:标「重点关注」——流量实际落在大陆网络,可能被监控或做内容审查。
"""
import json
import re

from . import geo

# 与前端 index.html 里的 NODE_REG 保持同步:(国家码, 中文关键字, 两字母代码, 英文整词)
NODE_REG = [
    ("HK", "香港", "HK", r"Hong\s?Kong"), ("TW", "台湾|台灣|台北|新北", "TW", "Taiwan"), ("JP", "日本|东京|大阪|埼玉", "JP", "Japan|Tokyo|Osaka"),
    ("SG", "新加坡|狮城", "SG", "Singapore"), ("KR", "韩国|韓國|首尔", "KR", "Korea|Seoul"),
    ("US", "美国|美國|洛杉矶|硅谷|圣何塞|西雅图|纽约|芝加哥|达拉斯|凤凰城", "US|USA", r"United\s?States|Los\s?Angeles|Seattle|San\s?Jose|Chicago|Dallas"),
    ("GB", "英国|英國|伦敦", "GB|UK", "London|Britain"), ("DE", "德国|德國|法兰克福", "DE", "Germany|Frankfurt"), ("FR", "法国|法國|巴黎", "FR", "France|Paris"),
    ("NL", "荷兰|荷蘭|阿姆斯特丹", "NL", "Netherlands|Amsterdam"), ("CA", "加拿大|多伦多|温哥华", "CA", "Canada|Toronto|Vancouver"),
    ("AU", "澳大利亚|澳洲|悉尼", "AU", "Australia|Sydney"), ("RU", "俄罗斯|俄羅斯|莫斯科", "RU", "Russia|Moscow"), ("IN", "印度(?!尼西亚)|孟买", "IN", "India|Mumbai"),
    ("IE", "爱尔兰|愛爾蘭", "IE", "Ireland|Dublin"), ("AR", "阿根廷", "AR", "Argentina"), ("IQ", "伊拉克", "IQ", "Iraq"), ("TR", "土耳其", "TR", "Turkey|Istanbul"),
    ("MY", "马来西亚|馬來西亞", "MY", "Malaysia"), ("TH", "泰国|泰國|曼谷", "TH", "Thailand|Bangkok"), ("VN", "越南", "VN", "Vietnam"),
    ("PH", "菲律宾|菲律賓", "PH", "Philippines"), ("ID", "印尼|印度尼西亚", "ID", "Indonesia|Jakarta"), ("BR", "巴西", "BR", "Brazil"), ("MX", "墨西哥", "MX", "Mexico"),
    ("ZA", "南非", "ZA", r"South\s?Africa"), ("AE", "阿联酋|迪拜", "AE|UAE", "Dubai"), ("IT", "意大利", "IT", "Italy|Milan"), ("ES", "西班牙", "ES", "Spain|Madrid"),
    ("SE", "瑞典", "SE", "Sweden"), ("CH", "瑞士", "CH", "Switzerland|Zurich"), ("PL", "波兰|波蘭", "PL", "Poland"), ("UA", "乌克兰", "UA", "Ukraine"),
    ("PK", "巴基斯坦", "PK", "Pakistan"), ("NG", "尼日利亚", "NG", "Nigeria"), ("CN", "中国大陆|大陆|回国", "CN", "China"),
]
_REG = [(cc, re.compile(zh), re.compile(r"(?<![A-Za-z])(?:" + code + r")(?![A-Za-z])"), re.compile(r"(?<![A-Za-z])(?:" + word + r")(?![A-Za-z])", re.I))
        for cc, zh, code, word in NODE_REG]
# 登记在这些 ASN 下的多半是 CDN / 中转前置,名字和登记地对不上很常见
CDN_WORDS = ("cloudflare", "akamai", "fastly", "cloudfront", "gcore", "cdn", "edgio", "stackpath", "bunny")
LV_NAME = {"high": "重点关注", "mid": "需核对", "low": "多半是 CDN / 中转"}
LV_RANK = {"high": 0, "mid": 1, "low": 2}
IGN_KEY = "nodegeo_ignore"
MAX_IGN = 400


def name_cc(name):
    s = str(name or "")
    for cc, zh, code, word in _REG:
        if zh.search(s) or code.search(s) or word.search(s):
            return cc
    return ""


def _kv_get(con, k, d):
    try:
        r = con.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
        return json.loads(r[0]) if r else d
    except Exception:
        return d


def ignored(con):
    v = _kv_get(con, IGN_KEY, [])
    return [str(x) for x in v][:400] if isinstance(v, list) else []


def set_ignore(con, node, on):
    node = str(node or "")[:120]
    lst = ignored(con)
    if on and node and node not in lst:
        lst.append(node)
    if not on:
        lst = [x for x in lst if x != node]
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (IGN_KEY, json.dumps(lst, ensure_ascii=False)))
    return lst


def set_ignore_server(con, remote, on):
    """忽略 / 恢复「共用同一个入口地址」的全部节点(中转机场常见:几十个节点同一个入口 IP)。返回影响的节点数。"""
    remote = str(remote or "")
    if not remote:
        return 0
    names = [n for (n,) in con.execute("SELECT node FROM nodeinfo WHERE remote=?", (remote,))][:200]
    lst = ignored(con)
    if on:
        lst += [n for n in names if n not in lst]
    else:
        lst = [x for x in lst if x not in names]
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (IGN_KEY, json.dumps(lst[:400], ensure_ascii=False)))
    return len(names)


def level_of(ncc, rcc, asn):
    """名字地区 ncc 与登记地 rcc 不同时的级别;相同或判断不了给 None。"""
    if not ncc or not rcc or ncc == rcc:
        return None
    if rcc == "CN":
        return "high"
    low = (asn or "").lower()
    if any(w in low for w in CDN_WORDS):
        return "low"
    return "mid"


def _why(lv, ncc, rcc, asn, ccn):
    nm, rg = ccn(ncc), ccn(rcc)
    if lv == "high":
        return (f"节点名写的是{nm},但服务器 IP 登记在中国大陆。这类节点的流量实际落在大陆网络,可能被监控或审查,"
                "也可能是机场把大陆中转当成境外节点卖。建议向机场核实,或在 nikki / 订阅里停用这个节点。")
    if lv == "low":
        return f"节点名写的是{nm},服务器 IP 登记在{rg}({asn}),这是 CDN / 中转前置的常见现象,通常不是问题,留意即可。"
    return (f"节点名写的是{nm},服务器 IP 登记在{rg}。可能是中转 / IEPL 专线、机场名字乱标,也可能是节点被换了。"
            "如果你对这个节点的出口有要求(例如解锁某地服务),建议核实;不放心可以在 nikki / 订阅里停用。")


CCN = {"CN": "中国大陆", "HK": "香港", "TW": "台湾", "JP": "日本", "SG": "新加坡", "KR": "韩国", "US": "美国", "GB": "英国", "DE": "德国", "FR": "法国", "NL": "荷兰",
       "CA": "加拿大", "AU": "澳大利亚", "RU": "俄罗斯", "IN": "印度", "IE": "爱尔兰", "AR": "阿根廷", "IQ": "伊拉克", "TR": "土耳其", "MY": "马来西亚", "TH": "泰国",
       "VN": "越南", "PH": "菲律宾", "ID": "印尼", "BR": "巴西", "MX": "墨西哥", "ZA": "南非", "AE": "阿联酋", "IT": "意大利", "ES": "西班牙", "SE": "瑞典", "CH": "瑞士",
       "PL": "波兰", "UA": "乌克兰", "PK": "巴基斯坦", "NG": "尼日利亚"}


def ccn(cc):
    return CCN.get(cc, cc or "未知")


def scan(con, with_ok=False):
    """逐个节点比较。返回按级别排序的列表;with_ok=True 时把一致的也带上(level 为空)。"""
    ign = set(ignored(con))
    out = []
    try:
        rows = con.execute("SELECT node, remote FROM nodeinfo WHERE remote IS NOT NULL AND remote != ''").fetchall()
    except Exception:
        rows = []
    for node, remote in rows:
        rcc, asn = geo.lookup(remote)
        ncc = name_cc(node)
        lv = level_of(ncc, rcc, asn)
        if not lv and not with_ok:
            continue
        out.append({"node": node, "name_cc": ncc, "reg_cc": rcc, "asn": asn, "remote": remote, "level": lv, "level_name": LV_NAME.get(lv, ""),
                    "ignored": node in ign, "why": _why(lv, ncc, rcc, asn, ccn) if lv else ""})
    cnt = {}
    for r in out:
        cnt[r["remote"]] = cnt.get(r["remote"], 0) + 1
    for r in out:
        r["shared"] = cnt[r["remote"]]
    out.sort(key=lambda r: (LV_RANK.get(r["level"], 9), r["ignored"], r["node"]))
    return out


def summary(con):
    rows = scan(con)
    act = [r for r in rows if not r["ignored"]]
    return {"total": len(rows), "cn": sum(1 for r in act if r["level"] == "high"), "mid": sum(1 for r in act if r["level"] == "mid"),
            "low": sum(1 for r in act if r["level"] == "low"), "ignored": len(rows) - len(act), "rows": rows}


def api(con):
    s = summary(con)
    s["available"] = geo.available()
    s["all_nodes"] = len(con.execute("SELECT 1 FROM nodeinfo WHERE remote IS NOT NULL AND remote != ''").fetchall())
    return s


def check_alert(con, cfg, now):
    """告警:登记地与节点名对不上的节点。「只提醒大陆」开着时,只管登记在中国大陆的。"""
    from . import alerts
    r = cfg["rules"].get("node_geo")
    if not r or not r.get("on") or not geo.available():
        return
    for x in scan(con):
        if x["ignored"] or x["level"] == "low" or (r.get("cn") and x["level"] != "high"):
            continue
        if not alerts._allow("node_geo", x["node"], r["cool_min"], now):
            continue
        high = x["level"] == "high"
        alerts.fire(con, cfg, "node_geo", "warn" if high else "info", x["node"],
                    f"{'【重点关注】' if high else ''}节点「{x['node']}」登记地与名称不符",
                    f"节点名地区:{ccn(x['name_cc'])};服务器 IP 登记地:{ccn(x['reg_cc'])}({x['asn'] or '未知 ASN'})。{x['why']}"
                    "到「安全 → 回看 → 节点所在地」查看详情,可选择忽略。", now)
