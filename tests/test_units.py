import socket, struct, sys, os, time, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import devices


def nl_neigh(family, ip, mac, state=0x02):
    dst = socket.inet_pton(family, ip)
    attrs = struct.pack("=HH", 4 + len(dst), 1) + dst
    attrs += b"\0" * (-len(dst) % 4)
    attrs += struct.pack("=HH", 4 + 6, 2) + bytes.fromhex(mac.replace(":", "")) + b"\0\0"
    body = struct.pack("=BBHiHBB", family, 0, 0, 2, state, 0, 0) + attrs
    return struct.pack("=IHHII", 16 + len(body), 28, 2, 1, 0) + body


def test_netlink():
    buf = (nl_neigh(socket.AF_INET, "192.168.1.10", "aa:bb:cc:dd:ee:01")
           + nl_neigh(socket.AF_INET6, "fd00::10", "aa:bb:cc:dd:ee:01")
           + nl_neigh(socket.AF_INET, "192.168.1.99", "aa:bb:cc:dd:ee:09", state=0x20)  # FAILED 要忽略
           + struct.pack("=IHHII", 16, 3, 2, 1, 0))
    r = devices.parse_neigh_dump(buf)
    assert r == {"192.168.1.10": "aa:bb:cc:dd:ee:01", "fd00::10": "aa:bb:cc:dd:ee:01"}, r


def test_uci():
    show = """dhcp.@host[0]=host
dhcp.@host[0].name='iphone'
dhcp.@host[0].mac='AA:BB:CC:DD:EE:01'
dhcp.@host[0].ip='192.168.1.10'
dhcp.@host[1]=host
dhcp.@host[1].name='tv'
dhcp.@host[1].ip='192.168.1.30'
dhcp.lan=dhcp
dhcp.lan.start='100'
"""
    h = devices.parse_uci_text(show)
    assert h == [{"name": "iphone", "mac": ["aa:bb:cc:dd:ee:01"], "ip": ["192.168.1.10"]},
                 {"name": "tv", "mac": [], "ip": ["192.168.1.30"]}], h
    conf = "config dnsmasq\n\toption x '1'\nconfig host\n\toption name 'nas'\n\toption mac 'aa:bb:cc:dd:ee:02'\n\toption ip '192.168.1.5'\n"
    assert devices.parse_uci_text(conf)[0]["name"] == "nas"


def test_ip_neigh_text():
    t = "192.168.1.10 dev br-lan lladdr aa:bb:cc:dd:ee:01 REACHABLE\nfe80::1 dev br-lan lladdr aa:bb:cc:dd:ee:02 STALE\n192.168.1.7 dev br-lan  FAILED\n"
    assert devices.parse_ip_neigh(t) == {"192.168.1.10": "aa:bb:cc:dd:ee:01", "fe80::1": "aa:bb:cc:dd:ee:02"}


def test_airports():
    from app import airports as a
    a.set_rules("")
    assert a.of("CF | 香港 01") == "CF" and a.of("SSRDOG ｜ 日本 02") == "SSRDOG" and a.of("牛逼 ｜ 新加坡 01") == "牛逼"
    assert a.of("备用节点") == "未分类" and a.of("UNKNOWN") == "未知"
    assert a.of("直连", "direct") == "直连" and a.of("REJECT", "reject") == "拒绝"
    a.set_rules("备用=自建机场\n# 注释\n香港 01=不该命中")
    assert a.of("备用节点") == "自建机场" and a.of("CF | 香港 01") == "不该命中"  # 规则优先于竖线前缀
    for bad in ("没有等号", "=x", "x="):
        try:
            a.parse_rules(bad); assert False, bad
        except ValueError:
            pass
    a.set_rules("")


def test_alerts():
    import sqlite3, time, tempfile
    from app import alerts, config, db
    # 静默时段(跨零点)
    t = time.mktime((2026, 10, 13, 23, 30, 0, 0, 0, -1))
    q = {"quiet": {"on": True, "start": "23:00", "end": "07:00"}}
    assert alerts._in_quiet(q, t) and alerts._in_quiet(q, t + 5 * 3600) and not alerts._in_quiet(q, t - 8 * 3600)
    assert not alerts._in_quiet({"quiet": {"on": False, "start": "23:00", "end": "07:00"}}, t)
    # 渠道校验:地址和密钥
    for bad in ({"type": "bark", "url": "javascript:1"}, {"type": "nope"}, {"type": "telegram", "token": "x"}):
        try:
            alerts._norm_channel(bad); assert False, bad
        except ValueError:
            pass
    m = alerts._mask(alerts._norm_channel({"type": "bark", "url": "https://api.day.app/SECRETKEY"}))
    assert "SECRETKEY" not in str(m) and m["has_secret"]
    # 基线:同钟点样本够 → 均值;不够 → 近 24 小时中位数
    config.DB_PATH = tempfile.mkdtemp() + "/t.db"; config.DATA_DIR = os.path.dirname(config.DB_PATH)
    con = db.init_db()
    now = time.mktime((2026, 10, 13, 10, 20, 0, 0, 0, -1))
    hn = time.strftime("%Y-%m-%d %H", time.localtime(now))
    with con:
        for d in (10, 11, 12):
            con.execute("INSERT INTO hourly VALUES(?,?,?,?,?)", (f"2026-10-{d} 10", "dev1", "n", 100, 900))
    b, n, how = alerts._baseline(con, "dev1", hn, now)
    assert b == 1000 and n == 3 and how == "同时段均值", (b, n, how)
    assert alerts._baseline(con, "nobody", hn, now)[2] == "暂无基线"
    with con:
        for h in range(5):
            con.execute("INSERT INTO hourly VALUES(?,?,?,?,?)", (f"2026-10-13 0{h}", "dev2", "n", 0, 500 + h))
    b, n, how = alerts._baseline(con, "dev2", hn, now)
    assert how == "近 24 小时中位数" and b == 502, (b, how)


def test_geo():
    import gzip, http.server, tempfile, threading, shutil
    from app import config, geo
    d = os.path.join(os.path.dirname(__file__), "data")
    m = geo.MMDB(os.path.join(d, "country-test.mmdb"))
    assert geo._rec_cc(m.get("89.160.20.112")) == "SE" and geo._rec_cc(m.get("2001:218::1")) == "JP"
    assert m.get("1.2.3.4") is None and m.get("not-an-ip") is None
    a = geo.MMDB(os.path.join(d, "asn-test.mmdb"))
    assert a.get("89.160.20.112")["autonomous_system_number"] == 29518
    # 在线下载:本地假服务器提供 .mmdb.gz
    srv_dir = tempfile.mkdtemp()
    ym = time.strftime("%Y-%m")
    for k in ("country", "asn"):
        with open(os.path.join(d, k + "-test.mmdb"), "rb") as f, gzip.open(os.path.join(srv_dir, f"dbip-{k}-lite-{ym}.mmdb.gz"), "wb") as g:
            g.write(f.read())
    class H(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k): super().__init__(*a, directory=srv_dir, **k)
        def log_message(self, *a): pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
    config.DATA_DIR = tempfile.mkdtemp(); geo.BASE = f"http://127.0.0.1:{srv.server_address[1]}"; geo.GH = "http://127.0.0.1:1"  # GitHub 源不可达 → 回退到 DB-IP
    geo.load(); assert not geo.available()
    assert geo.start_download()
    for _ in range(50):
        if not geo.DL["running"]: break
        time.sleep(0.1)
    assert geo.DL["msg"] == "完成" and geo.available(), geo.DL
    assert geo.lookup("89.160.20.112") == ("SE", "AS29518 Bredband2 AB")
    srv.shutdown()
    # 代理设置:校验 + 密码不外露
    for bad in ("ftp://x", "socks5://127.0.0.1:7891", "http://"):
        try: geo.proxy_set(bad); assert False, bad
        except ValueError: pass
    geo.proxy_set("http://nikki:s3cretpw@127.0.0.1:7890")
    assert geo.proxy_hint() == "http://***@127.0.0.1:7890" and "s3cretpw" not in json.dumps(geo.status())
    assert oct(os.stat(os.path.join(config.DATA_DIR, "geo_proxy.txt")).st_mode & 0o777) == "0o600"
    geo.BASE = "http://127.0.0.1:1"
    geo.proxy_set("http://nikki:s3cretpw@127.0.0.1:1")
    geo.start_download()
    for _ in range(100):
        if not geo.DL["running"]: break
        time.sleep(0.1)
    assert "s3cretpw" not in geo.DL["msg"] and geo.DL["msg"].startswith("失败"), geo.DL  # 经不存在的代理,失败信息里不能带密码
    geo.proxy_set(""); assert geo.proxy_hint() in ("", "环境变量 HTTPS_PROXY")


def test_quota_period():
    import datetime
    from app import insight
    D = datetime.date
    assert insight.period(15, D(2026, 10, 14)) == (D(2026, 9, 15), D(2026, 10, 15))
    assert insight.period(15, D(2026, 10, 15)) == (D(2026, 10, 15), D(2026, 11, 15))
    assert insight.period(31, D(2026, 3, 5)) == (D(2026, 2, 28), D(2026, 3, 31))
    assert insight.period(1, D(2026, 12, 20)) == (D(2026, 12, 1), D(2027, 1, 1))
    assert insight.period(1, D(2026, 1, 1)) == (D(2026, 1, 1), D(2026, 2, 1))


def test_leak_lists():
    from app import insight
    assert insight._in_list("www.bilibili.com", insight.CN_SUFFIX) and insight._in_list("a.b.cn", insight.CN_SUFFIX)
    assert not insight._in_list("notbilibili.com", insight.CN_SUFFIX)
    assert insight._in_list("r1.googlevideo.com", insight.FOREIGN_SUFFIX)


def test_groups():
    from app import groups
    assert groups.base_domain("a.b.apple.com") == "apple.com" and groups.base_domain("x.bbc.co.uk") == "bbc.co.uk"
    assert groups.allowed("a.apple.com", ["apple.com"]) and groups.allowed("apple.com", ["apple.com"])
    assert not groups.allowed("notapple.com", ["apple.com"])
    assert groups._norm_domains("Apple.com\n*.a.org, b.net\n bad/x") == ["apple.com", "a.org", "b.net"]


def test_advisor():
    import sqlite3, time
    from app import advisor, alerts, db
    con = sqlite3.connect(":memory:"); con.executescript(db.SCHEMA)
    now = time.time(); H = lambda back: time.strftime("%Y-%m-%d %H", time.localtime(now - back * 3600))
    for back in range(30, 24 * 6):   # 过去一周:两个节点都正常(100ms,0 失败)
        for node in ("A", "B"):
            con.execute("INSERT INTO qoe VALUES(?,?,?,?,?,?)", (H(back), node, 5, 500.0, 50000.0, 0))
    for back in range(0, 20):        # 最近 24h:B 变差(600ms + 一半超时)
        con.execute("INSERT INTO qoe VALUES(?,?,?,?,?,?)", (H(back), "A", 5, 500.0, 50000.0, 0))
        con.execute("INSERT INTO qoe VALUES(?,?,?,?,?,?)", (H(back), "B", 3, 1800.0, 1100000.0, 3))
        con.execute("INSERT INTO hourly VALUES(?,?,?,?,?)", (H(back), "c1", "B", 1 << 20, 1 << 22))
    rows = {r["node"]: r for r in advisor.node_scores(con, now)}
    assert rows["A"]["score"] >= 85 and rows["B"]["score"] < 50 and rows["B"]["delta"] < -30, rows
    assert rows["B"]["advice"] and rows["B"]["level"] == "bad"
    fired = []
    alerts.fire = lambda con, cfg, kind, level, key, title, detail, now=None: fired.append((kind, key))
    alerts._allow = lambda *a, **k: True
    cfg = {"rules": {"node_degrade": {"drop": 20, "cool_min": 1}, "geo_new": {"min_mb": 1, "cool_min": 1}}}
    advisor.check_degrade(con, cfg, now)
    assert fired == [("node_degrade", "B")], fired
    fired.clear()
    for d in range(1, 8):
        con.execute("INSERT INTO geo VALUES(?,?,?,?,?,?)", (time.strftime("%Y-%m-%d", time.localtime(now - d * 86400)), "US", "x", "direct", 1 << 20, 1 << 20))
    con.execute("INSERT INTO geo VALUES(?,?,?,?,?,?)", (time.strftime("%Y-%m-%d", time.localtime(now)), "US", "x", "direct", 1, 1))
    con.execute("INSERT INTO geo VALUES(?,?,?,?,?,?)", (time.strftime("%Y-%m-%d", time.localtime(now)), "BR", "y", "direct", 3 << 20, 3 << 20))
    advisor.check_geo_new(con, cfg, now)
    assert fired == [("geo_new", "BR")], fired


def test_providers_compare():
    import sqlite3, time
    from app import providers, db, insight
    con = sqlite3.connect(":memory:"); con.executescript(db.SCHEMA)
    now = time.time(); T = lambda h: now - h * 3600
    H = lambda h: time.strftime("%Y-%m-%d %H", time.localtime(T(h)))
    # 三次更新:30h 前、6h 前(+200)、刚刚(+300);第四次读数变小 = 套餐重置
    insight._kv_set(con, "prov_upd", {"X": [[T(30), 100], [T(6), 300], [T(0.1), 600]]})
    for h, v in ((20, 150), (10, 40), (3, 100), (1, 9999)):   # 20h、10h 前在第一段,3h 前在第二段;1h 前超出范围
        con.execute("INSERT INTO hourly(hour,client,node,up,down) VALUES(?,?,?,?,?)", (H(h), "c", "n1", v, 0))
    c = providers.compare(con, "X", ["n1"])
    assert [r["official"] for r in c["rows"]] == [200, 300], c
    assert [r["flux"] for r in c["rows"]] == [190, 100 + 9999], c
    assert providers.parse_ts("2026-10-16T06:16:00.123456789+08:00") > 1e9 and providers.parse_ts("0001-01-01T00:00:00Z") == 0


def test_probe_and_panellog():
    import sqlite3, time
    from app import probe, panellog, db
    con = sqlite3.connect(":memory:"); con.executescript(db.SCHEMA)
    H = time.strftime("%Y-%m-%d %H", time.localtime())
    for n, v in (("A", 500), ("B", 900), ("直连", 5000), ("C", 1)):
        con.execute("INSERT INTO hourly(hour,client,node,up,down) VALUES(?,?,?,?,?)", (H, "c", n, v, 0))
    assert probe.candidates(con, 2) == ["B", "A"]   # 按流量排序,直连不测
    calls = []
    probe.api_call = lambda path, **k: calls.append(path) or {"delay": 1}
    probe._run(["a b", "C"], "https://x/y")
    assert calls[0].startswith("/proxies/a%20b/delay?url=https%3A%2F%2Fx%2Fy") and len(calls) == 2, calls
    assert panellog.short_ua("Mozilla/5.0 (Macintosh; Intel Mac OS X) Chrome/120 Safari/537") == "Mac Chrome"
    assert panellog.short_ua("Mozilla/5.0 (iPhone) Safari/604") == "iPhone Safari"
    panellog.record(con, "192.168.1.9", "curl/8", "login_fail")
    panellog.record(con, "192.168.1.9", "curl/8", "page")
    c = panellog.clients(con)
    assert len(c) == 1 and c[0]["fails"] == 1 and c[0]["n"] == 1, c
    assert con.execute("SELECT COUNT(*) FROM alerts WHERE kind='audit'").fetchone()[0] == 1   # 登录失败记一条;新来源只在第一次(同一次已被失败那条占了)


def test_presence():
    import sqlite3, time, copy
    from app import alerts, db, presence
    con = sqlite3.connect(":memory:"); con.executescript(db.SCHEMA)
    cfg = copy.deepcopy(alerts.DEFAULT_CFG)
    fired = []
    alerts.fire = lambda con_, cfg_, kind, level, key, title, detail, now=None: fired.append((kind, key, title))
    A, B = "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"
    t0 = time.time() - 1000
    presence._s["start"] = t0 - 500          # 已过了启动学习期
    presence.check(con, cfg, t0, ev={A, B})  # 初次见到:静默记为在线
    assert not fired and presence.status(con)["rows"] and all(r["on"] for r in presence.status(con)["rows"])
    presence.check(con, cfg, t0 + 300, ev={A})        # B 才 5 分钟没出现:还没到 10 分钟
    assert not fired
    presence.check(con, cfg, t0 + 700, ev={A})        # B 超过 10 分钟 -> 离线;但没关注,不提醒
    assert not fired and [r["on"] for r in presence.status(con)["rows"] if r["key"] == B] == [False]
    presence.set_watch(con, B, True)
    presence.check(con, cfg, t0 + 800, ev={A, B})     # B 回来 -> 上线,已关注 -> 提醒
    assert [f[0] for f in fired] == ["dev_online"] and fired[0][1] == B, fired
    presence.check(con, cfg, t0 + 900, ev={A})
    presence.check(con, cfg, t0 + 1600, ev={A})       # 再次离线,已关注 -> 提醒
    assert [f[0] for f in fired] == ["dev_online", "dev_offline"], fired
    cfg["rules"]["dev_online"]["on"] = False; cfg["rules"]["dev_online"]["all"] = 1   # 推送开关关掉:只记录不推送;选了所有设备:A 也会被记
    presence.check(con, cfg, t0 + 1700, ev={A, B})    # B 上线:开关关着 -> 只记录
    presence.check(con, cfg, t0 + 3000, ev={B})       # A 离线:离线规则范围还是「只关注的」,A 没关注 -> 不记
    presence.check(con, cfg, t0 + 3100, ev={A, B})    # A 上线:上线规则选了所有设备 -> 记录但不推送
    assert [f[0] for f in fired] == ["dev_online", "dev_offline"], fired
    assert con.execute("SELECT COUNT(*) FROM alerts WHERE kind='dev_online' AND key=?", (A,)).fetchone()[0] == 1
    assert con.execute("SELECT COUNT(*) FROM alerts WHERE kind='dev_offline' AND key=?", (A,)).fetchone()[0] == 0


def test_wan_and_diag():
    import os, tempfile, time, copy, sqlite3
    from app import wan, diag, alerts, providers, db
    d = tempfile.mkdtemp(); os.makedirs(d + "/net")
    open(d + "/net/route", "w").write("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
                                       "eth1\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\neth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n")
    wan.PROC = d
    assert wan.default_route() == ("eth1", "192.168.1.1")
    wan.iface_ip = lambda n: "100.64.1.2" if n == "eth1" else ""
    seq = iter([5.0, 6.0, None, None, None, None, 30.0, None, None])
    wan.probe = lambda addr, s: next(seq, None)
    wan.SERIES.clear()
    now = time.time()
    wan.sample(["223.5.5.5"], now)
    w = wan.window(300, now + 1)
    assert w["192.168.1.1"]["gw"] and w["192.168.1.1"]["lost"] == 1 and w["223.5.5.5"]["loss"] == 100, w
    wan.iface_ip = lambda n: "100.64.9.9"
    wan.sample(["223.5.5.5"], now + 30)
    assert wan.snapshot()["ip_changed"]["new"] == "100.64.9.9"
    os.remove(d + "/net/route"); open(d + "/net/route", "w").write("Iface\tDestination\n")
    wan.sample(["223.5.5.5"], now + 60)
    assert wan.snapshot()["up"] is False and wan.snapshot()["down_since"]
    con = sqlite3.connect(":memory:"); con.executescript(db.SCHEMA)
    wan.flush(con, now + 61); assert con.execute("SELECT COUNT(*) FROM wanq").fetchone()[0] >= 1
    # 打码
    t = diag.mask_text("设备 张三的手机 192.168.1.23 aa:bb:cc:dd:ee:ff 连上了", ["张三的手机"])
    assert "192.168.*.*" in t and "aa:bb:cc:**:**:**" in t and "张三" not in t and "设备1" in t, t
    # 订阅过期提醒
    fired = []
    alerts.fire = lambda con_, cfg_, kind, level, key, title, detail, now=None: fired.append((kind, key))
    providers._cache.update(t=time.time(), v=[{"name": "A", "has_info": True, "updated": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(time.time() - 60 * 3600)),
                                               "used": 1, "total": 2, "expire": 0, "nodes": [], "vehicle": "HTTP"},
                                              {"name": "B", "has_info": True, "updated": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(time.time() - 3600)),
                                               "used": 1, "total": 2, "expire": 0, "nodes": [], "vehicle": "HTTP"}])
    providers.check_stale(con, copy.deepcopy(alerts.DEFAULT_CFG), time.time())
    assert fired == [("sub_stale", "A")], fired


def test_provider_nodes_probe_local():
    import os, tempfile, urllib.error
    from app import probe, devices, airports
    calls = []
    def fake(path, **k):
        calls.append(path)
        if path.startswith("/providers/"):
            raise urllib.error.HTTPError(path, 404, "nf", {}, None)
        if "bad" in path:
            raise urllib.error.HTTPError(path, 504, "to", {}, None)
        return {"delay": 5}
    probe.api_call = fake
    assert probe._test_one("n 1", "https://x/y", "P") == (True, "")
    assert calls[0].startswith("/providers/proxies/P/n%201/healthcheck") and calls[1].startswith("/proxies/n%201/delay"), calls   # 订阅接口 404 -> 退回 /proxies
    assert probe._test_one("bad", "https://x/y", "") == (False, "HTTP 504")
    d = tempfile.mkdtemp(); os.makedirs(d + "/net")
    open(d + "/net/fib_trie", "w").write("Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 192.168.100.1\n        /32 host LOCAL\n     |-- 192.168.100.5\n        /32 link UNICAST\n")
    open(d + "/net/if_inet6", "w").write("20010db8000000000000000000000001 02 40 00 00 eth0\n")
    os.environ["SYS_PROC"] = d; devices._LOCAL["t"] = 0
    assert devices.local_ips() == {"192.168.100.1", "2001:db8::1"}, devices.local_ips()
    assert devices.NAMES.label("2001:db8::1", [], {}) == "路由器本机"


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f(); print("ok", n)
