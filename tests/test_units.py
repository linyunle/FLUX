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


def test_syslog():
    import sqlite3, time, copy, tempfile, os, threading, socket as so
    from app import syslog, alerts, db, config
    h, sv, tg, msg = syslog.parse(b"<30>Oct 17 19:58:00 OpenWrt dnsmasq[123]: DHCPACK(br-lan) 192.168.1.5 aa:bb", "127.0.0.1")
    assert (h, sv, tg) == ("OpenWrt", 6, "dnsmasq") and msg.startswith("DHCPACK"), (h, sv, tg, msg)
    h, sv, tg, msg = syslog.parse(b"<11>Oct  7 19:58:00 R kernel: [12.3] Out of memory: Killed process 1", "1.2.3.4")
    assert sv == 3 and tg == "kernel" and syslog.CRIT.search(msg), (sv, tg, msg)
    h, sv, tg, msg = syslog.parse(b"<14>1 2026-10-17T19:58:00+08:00 host app 12 ID47 - hello world", "1.2.3.4")
    assert (h, sv, tg, msg) == ("host", 6, "app", "hello world"), (h, sv, tg, msg)
    h, sv, tg, msg = syslog.parse(b"Oct 17 19:58:00 OpenWrt daemon.err hostapd: bad thing", "1.2.3.4")
    assert sv == 3 and tg == "hostapd" and msg == "bad thing", (sv, tg, msg)
    assert syslog.parse(b"random text", "9.9.9.9")[3] == "random text"
    assert syslog.allowed_src("192.168.1.5") and syslog.allowed_src("127.0.0.1") and not syslog.allowed_src("8.8.8.8")
    con = sqlite3.connect(":memory:"); con.executescript(db.SCHEMA)
    now = time.time()
    syslog._insert(con, [(int(now - 10 * 86400), "r", 6, "old", "ancient"), (int(now - 5), "r", 6, "a", "hello"), (int(now - 4), "r", 3, "b", "bad_thing 100%")])
    assert len(syslog.query(con, 7)) == 3 and len(syslog.query(con, 3)) == 1 and len(syslog.query(con, 7, "100%")) == 1 and len(syslog.query(con, 7, "_")) == 1
    cfg = syslog.save_cfg(con, {"on": True, "port": 5514, "days": 7, "max_rows": 1000})
    assert syslog.prune(con, cfg, now) == 1 and len(syslog.query(con, 7)) == 2
    for bad in ({"port": 80}, {"days": 0}, {"max_rows": 5}):
        try:
            syslog.save_cfg(con, dict({"on": True, "port": 5514, "days": 7, "max_rows": 1000}, **bad)); assert False
        except ValueError:
            pass
    # 严重日志告警:第一次只记基线;之后出现严重信息才触发
    fired = []
    alerts.fire = lambda con_, cfg_, kind, level, key, title, detail, now=None: fired.append((kind, title))
    acfg = copy.deepcopy(alerts.DEFAULT_CFG)
    syslog._state["sys_last"] = None
    syslog.check(con, acfg, now); assert not fired
    syslog._insert(con, [(int(now), "r", 6, "x", "all fine"), (int(now), "r", 6, "kernel", "EXT4-fs error (device sda1): bad")])
    syslog.check(con, acfg, now + 1)
    assert fired and fired[0][0] == "syslog_crit", fired
    syslog._insert(con, [(int(now), "r", 6, "x", "all fine too")])
    n = len(fired); syslog.check(con, acfg, now + 2); assert len(fired) == n
    c = syslog.save_cfg(con, {"on": True, "port": 5514, "ignore": "crond\nCROND\n  \nnut_onbatt"})
    assert c["ignore"] == ["crond", "nut_onbatt"], c
    syslog._insert(con, [(int(now), "r", 3, "crond", "USER root pid 1 cmd x"), (int(now), "r", 6, "a", "keep nut_onbatt_time"), (int(now), "r", 6, "a", "keep me")])
    assert syslog.purge_ignored(con, c) == 2 and any("keep me" in r["msg"] for r in syslog.query(con, 7)) and not any("crond" in r["tag"] for r in syslog.query(con, 7))
    assert syslog.ignored(c, "CROND", "x") and not syslog.ignored(c, "a", "keep me")
    # 真实收包:开线程监听本机一个端口
    d = tempfile.mkdtemp(); config.DB_PATH = d + "/t.db"; c2 = db.init_db()
    s = so.socket(so.AF_INET, so.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    syslog.save_cfg(c2, {"on": True, "port": port, "days": 3, "max_rows": 5000})
    threading.Thread(target=syslog.run, daemon=True).start()
    for _ in range(40):
        if syslog._state["bound"] == port: break
        time.sleep(0.25)
    assert syslog._state["bound"] == port, syslog._state
    cl = so.socket(so.AF_INET, so.SOCK_DGRAM)
    for i in range(3):
        cl.sendto(f"<30>Oct 17 19:58:0{i} R app[1]: msg {i}".encode(), ("127.0.0.1", port))
    for _ in range(20):
        if len(syslog.query(c2, 7)) >= 3: break
        time.sleep(0.5)
    assert len(syslog.query(c2, 7)) == 3, syslog.query(c2, 7)
    syslog.save_cfg(c2, {"on": False, "port": port, "days": 3, "max_rows": 5000})


def test_ups():
    import sqlite3, time, copy, threading, socket as so
    from app import ups, alerts, db
    state = {"status": "OL CHRG", "charge": "100"}
    srv = so.socket(); srv.setsockopt(so.SOL_SOCKET, so.SO_REUSEADDR, 1); srv.bind(("127.0.0.1", 0)); srv.listen(5); port = srv.getsockname()[1]
    def serve():
        while True:
            try: c, _ = srv.accept()
            except OSError: return
            req = c.recv(200).decode()
            if "NOPE" in req: c.sendall(b"ERR UNKNOWN-UPS\n")
            else:
                c.sendall((f'BEGIN LIST VAR CyberPower\nVAR CyberPower battery.charge "{state["charge"]}"\nVAR CyberPower battery.runtime "1500"\nVAR CyberPower ups.load "23"\n'
                           f'VAR CyberPower ups.status "{state["status"]}"\nVAR CyberPower ups.model "UT650EG"\nVAR CyberPower ups.realpower.nominal "360"\nEND LIST VAR CyberPower\n').encode())
            c.close()
    threading.Thread(target=serve, daemon=True).start()
    v = ups.read("127.0.0.1", port, "CyberPower")
    s = ups.summarize(v)
    assert s["charge"] == 100 and s["runtime"] == 1500 and s["status"] == ["OL", "CHRG"] and s["model"] == "UT650EG" and round(s["watts"]) == 83, s
    try:
        ups.read("127.0.0.1", port, "NOPE"); assert False
    except RuntimeError as e:
        assert "没有这个名字" in str(e)
    con = sqlite3.connect(":memory:"); con.executescript(db.SCHEMA)
    ups.save_cfg(con, {"on": True, "host": "127.0.0.1", "port": port, "name": "CyberPower"})
    fired = []
    alerts.fire = lambda con_, cfg_, kind, level, key, title, detail, now=None: fired.append((kind, level, title))
    cfg = copy.deepcopy(alerts.DEFAULT_CFG); now = time.time()
    ups.check(con, cfg, now); assert not fired and ups.STATE["ok"]
    state.update(status="OB DISCHRG", charge="70"); ups.check(con, cfg, now + 30)
    assert fired == [("ups_onbatt", "bad", "市电断了,UPS 在用电池")], fired
    state.update(status="OB DISCHRG LB", charge="15"); ups.check(con, cfg, now + 60)
    assert fired[-1][0] == "ups_low", fired
    state.update(status="OL CHRG", charge="16"); ups.check(con, cfg, now + 600)
    assert fired[-1] == ("ups_onbatt", "ok", "市电恢复"), fired
    z = so.socket(); z.bind(("127.0.0.1", 0)); dead = z.getsockname()[1]; z.close()
    ups.save_cfg(con, {"on": True, "host": "127.0.0.1", "port": dead, "name": "CyberPower"})   # 换成没人监听的端口,模拟 NUT 停了
    n = len(fired); ups.check(con, cfg, now + 700); assert ups.STATE["ok"] is False and len(fired) == n
    ups.check(con, cfg, now + 700 + 11 * 60); assert fired[-1][0] == "ups_lost", fired
    for bad in ({"name": "a b"}, {"host": "x y"}, {"port": 0}):
        try: ups.save_cfg(con, dict({"host": "h", "port": 3493, "name": "n"}, **bad)); assert False
        except ValueError: pass


def test_expiry_and_disks():
    import sqlite3, time, copy, threading, subprocess, ssl, tempfile, os, socket as so, io, json
    from app import expiry, alerts, db, sysinfo
    d = tempfile.mkdtemp()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", d + "/k.pem", "-out", d + "/c.pem", "-days", "12", "-subj", "/CN=test.local"], check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(d + "/c.pem", d + "/k.pem")
    srv = so.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5); port = srv.getsockname()[1]
    def serve():
        while True:
            try:
                c, _ = srv.accept()
                try: ctx.wrap_socket(c, server_side=True).close()
                except Exception: c.close()
            except OSError: return
    threading.Thread(target=serve, daemon=True).start()
    r = expiry.check_cert(f"127.0.0.1:{port}")
    assert r["trusted"] is False and r["days"] in (11, 12) and r["not_after"], r      # 自签名:读得到到期日,但标记不受信任
    assert expiry.check_cert("127.0.0.1:1")["days"] is None
    class R(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): pass
    _orig_urlopen = expiry.urllib.request.urlopen
    expiry.urllib.request.urlopen = lambda req, timeout=0: R(json.dumps({"events": [{"eventAction": "expiration", "eventDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 20 * 86400 + 60))}]}).encode())
    assert expiry.check_domain("example.com")["days"] == 20
    expiry.urllib.request.urlopen = _orig_urlopen
    con = sqlite3.connect(":memory:"); con.executescript(db.SCHEMA)
    try: expiry.save_cfg(con, {"certs": "bad host!"}); assert False
    except ValueError: pass
    expiry.refresh_async = lambda force=False: True
    c = expiry.save_cfg(con, {"certs": f"https://127.0.0.1:{port}/x\n127.0.0.1:{port}", "domains": "Example.com"})
    assert c["certs"] == [f"127.0.0.1:{port}"] and c["domains"] == ["example.com"], c
    expiry.STATE.update(at=int(time.time()), certs={f"127.0.0.1:{port}": r}, domains={"example.com": {"days": 40, "not_after": time.time() + 40 * 86400}})
    fired = []
    alerts.fire = lambda con_, cfg_, kind, level, key, title, detail, now=None: fired.append((kind, level, key))
    expiry.check(con, copy.deepcopy(alerts.DEFAULT_CFG), time.time())
    assert fired == [("cert_expire", "warn", f"127.0.0.1:{port}")], fired               # 11~12 天 <= 14 天提醒;域名 40 天 > 30 天不提醒
    # 磁盘:读 /proc/mounts,同一块盘去重,小分区忽略
    m = d + "/mounts"
    open(m, "w").write(f"overlay / overlay rw 0 0\n/dev/sdz1 {d} ext4 rw 0 0\n/dev/sdz1 {d} ext4 rw 0 0\ntmpfs /tmp tmpfs rw 0 0\nproc /proc proc rw 0 0\n")
    os.makedirs(d + "/proc_x"); os.rename(m, d + "/proc_x/mounts"); sysinfo.PROC = d + "/proc_x"
    ds = sysinfo._disks()
    assert ds and all(x["total"] > 0 and 0 <= x["pct"] <= 100 for x in ds) and len({(x["mp"]) for x in ds}) == len(ds), ds
    os.environ["DISK_PATHS"] = f"我的盘={d}"
    assert sysinfo._disks()[0]["name"] == "我的盘"
    del os.environ["DISK_PATHS"]


def test_docker():
    import sqlite3, time, copy, sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    import mock_docker
    from app import dockerapi, alerts, db, auth
    srv = mock_docker.start(0 or 19330)
    con = sqlite3.connect(":memory:"); con.executescript(db.SCHEMA)
    url = "http://127.0.0.1:19330"
    for bad in ("unix:///var/run/docker.sock", "http://8.8.8.8:2375", "http://example.com:2375", "http://127.0.0.1:2375/x", "http://u:p@127.0.0.1:2375", "https://127.0.0.1:2375"):
        try: dockerapi.save_cfg(con, {"on": True, "url": bad}); assert False, bad
        except ValueError: pass
    for ok_ in ("http://localhost:2375", "http://docker-proxy:2375", "http://192.168.100.1:2375", "http://127.0.0.1:2375/"):
        dockerapi.save_cfg(con, {"on": True, "url": ok_})
    auth._st.update(hash="", env=False)       # 没有密码时不能开控制
    try: dockerapi.save_cfg(con, {"on": True, "url": url, "control": True}); assert False
    except ValueError as e: assert "访问密码" in str(e)
    dockerapi.save_cfg(con, {"on": True, "url": url})
    assert dockerapi.test({"url": url}) == {"ok": True, "version": "27.0.1", "containers": 4}
    snap = dockerapi.snapshot(con, force=True)
    rows = {r["name"]: r for r in snap["rows"]}
    assert snap["ok"] and set(rows) == {"flux", "navidrome", "lrcapi", "docker-socket-proxy"}, rows.keys()
    n = rows["navidrome"]
    assert n["cpu"] == 40.0 and n["mem"] == 200_000_000 and n["mem_limit"] == 8_000_000_000 and n["rx"] == 1000 and n["ports"] == ["4533→4533/tcp"], n
    assert rows["flux"]["locked"] and rows["docker-socket-proxy"]["locked"] and not n["locked"] and rows["lrcapi"]["cpu"] is None
    assert not snap["control"]["enabled"] and not snap["control"]["password"]
    assert "hello /navidrome line 0" in dockerapi.logs(con, "b" * 12)["text"] and "line 1" in dockerapi.logs(con, "b" * 12)["text"]
    try: dockerapi.logs(con, "../etc"); assert False
    except ValueError: pass
    try: dockerapi.act(con, "b" * 12, "stop"); assert False       # 控制没开
    except ValueError as e: assert "没有开启" in str(e)
    import hashlib
    auth._st.update(hash="x", salt="s", env=False)                # 假装设了密码
    dockerapi.save_cfg(con, {"on": True, "url": url, "control": True})
    assert dockerapi.snapshot(con)["control"]["enabled"]
    for cid in ("a" * 12, "d" * 12):
        try: dockerapi.act(con, cid, "stop"); assert False, cid
        except ValueError as e: assert "不能操作" in str(e), e
        dockerapi._last_act[0] = 0
    for bad in ("kill", "rm", "exec"):
        try: dockerapi.act(con, "b" * 12, bad); assert False
        except ValueError: pass
    dockerapi._last_act[0] = 0
    r = dockerapi.act(con, "b" * 12, "stop", "192.168.1.9"); assert r["name"] == "navidrome" and ("/navidrome", "stop") in mock_docker.STATE["posts"], r
    ev = con.execute("SELECT title,detail FROM alerts WHERE kind='audit'").fetchall()
    assert ev and "停止 navidrome" in ev[-1][0] and "192.168.1.9" in ev[-1][1], ev
    dockerapi._last_act[0] = time.time()
    try: dockerapi.act(con, "b" * 12, "start"); assert False      # 限速
    except ValueError as e: assert "太快" in str(e)
    dockerapi._last_act[0] = 0
    mock_docker.STATE["allow_post"] = False                       # 代理没放行 -> 403 要说清楚
    try: dockerapi.act(con, "b" * 12, "start"); assert False
    except ValueError as e: assert "ALLOW_" in str(e), e
    mock_docker.STATE["allow_post"] = True
    # 告警:容器停了 / 面板自己操作的不告警
    fired = []
    alerts.fire = lambda con_, cfg_, kind, level, key, title, detail, now=None: fired.append((kind, key))
    cfg = copy.deepcopy(alerts.DEFAULT_CFG); t0 = time.time()
    for c in mock_docker.C:
        if c["Names"][0] == "/navidrome": c["State"], c["Status"] = "running", "Up"
    dockerapi._expected.clear(); dockerapi._prev.clear(); dockerapi._poll["t"] = 0
    dockerapi.check(con, cfg, t0); assert not fired
    mock_docker.C[1]["State"], mock_docker.C[1]["Status"] = "exited", "Exited (1) now"
    dockerapi.check(con, cfg, t0 + 30); assert not fired          # 60 秒内不重复检查
    dockerapi.check(con, cfg, t0 + 61); assert fired == [("docker_down", "navidrome")], fired
    mock_docker.C[1]["State"] = "running"; dockerapi.check(con, cfg, t0 + 130)
    dockerapi._expected["navidrome"] = t0 + 190; mock_docker.C[1]["State"] = "exited"
    dockerapi.check(con, cfg, t0 + 200); assert len(fired) == 1, fired   # 面板自己操作过 -> 不告警
    mock_docker.C[2]["Status"] = "Up 1 hour (unhealthy)"; mock_docker.C[2]["State"] = "running"
    dockerapi.check(con, cfg, t0 + 300); dockerapi.check(con, cfg, t0 + 400)
    assert ("docker_unhealthy", "lrcapi") in fired, fired
    auth._st.update(hash="", env=False)


def test_listen_fallback():
    import socket, tempfile
    from app import listen, config
    from http.server import BaseHTTPRequestHandler
    d = tempfile.mkdtemp(); config.DATA_DIR = d
    blocker = socket.socket(); blocker.bind(("127.0.0.1", 0)); blocker.listen(1); port = blocker.getsockname()[1]
    config.LISTEN_HOST, config.LISTEN_PORT = "127.0.0.1", port
    srv = listen.boot(BaseHTTPRequestHandler)
    try:
        st = listen.status()
        assert st["fallback_from"] == port and st["current"]["port"] != port and st["current"]["src"] == "fallback", st
    finally:
        listen._close(srv); blocker.close()
    for bad in ("", "abc", "1.2.3", "999.1.1.1"):
        try: listen.valid_host(bad); assert False, bad
        except ValueError: pass
    for bad in (0, 70000, "x", None):
        try: listen.valid_port(bad); assert False, bad
        except ValueError: pass
    assert listen.valid_host("::") == "::" and listen.valid_port("8099") == 8099


def test_security():
    import tempfile, sqlite3
    from app import auth, config, health, db
    # 代理头:只有受信代理(默认仅本机)的 X-Forwarded-For 才被采信
    os.environ.pop("TRUSTED_PROXIES", None)
    assert auth.client_ip("192.168.1.5", "9.9.9.9", "https") == ("192.168.1.5", False)
    assert auth.client_ip("127.0.0.1", "9.9.9.9, 10.0.0.1", "https") == ("9.9.9.9", True)
    assert auth.client_ip("127.0.0.1", "", "") == ("127.0.0.1", False)
    os.environ["TRUSTED_PROXIES"] = "192.168.1.0/24"
    assert auth.client_ip("192.168.1.5", "9.9.9.9", "") == ("9.9.9.9", False)
    assert auth.client_ip("192.168.2.5", "9.9.9.9", "") == ("192.168.2.5", False)
    os.environ.pop("TRUSTED_PROXIES")
    # 网段限制
    os.environ.pop("ALLOW_NETS", None)
    assert auth.net_allowed("8.8.8.8")
    os.environ["ALLOW_NETS"] = "192.168.0.0/16, fd00::/8"
    assert auth.net_allowed("192.168.100.7") and auth.net_allowed("fd00::5") and not auth.net_allowed("8.8.8.8") and not auth.net_allowed("bad")
    os.environ.pop("ALLOW_NETS")
    # 两档密码与会话
    d = tempfile.mkdtemp(); config.DATA_DIR = d
    for k in ("PANEL_PASSWORD", "PANEL_VIEWER_PASSWORD"):
        os.environ.pop(k, None)
    auth.load()
    try: auth.set_viewer("viewer1"); assert False
    except ValueError: pass
    auth.set_password("admin-pw1"); auth.set_viewer("viewer-pw1")
    assert auth.check_role("admin-pw1") == "a" and auth.check_role("viewer-pw1") == "v" and auth.check_role("x") is None
    try: auth.set_viewer("admin-pw1"); assert False
    except ValueError: pass
    try: auth.set_password("viewer-pw1"); assert False
    except ValueError: pass
    ca, cv = auth.make_cookie("a"), auth.make_cookie("v")
    assert auth.cookie_role(ca) == "a" and auth.cookie_role(cv) == "v" and auth.cookie_role("1.a.bad") is None
    assert auth.cookie_role(cv.replace(".v.", ".a.")) is None          # 不能把只读 Cookie 改成管理员
    auth.set_viewer("viewer-pw2")
    assert auth.cookie_role(cv) is None and auth.cookie_role(ca) == "a"  # 换只读密码只踢掉只读会话
    auth.revoke_all()
    assert auth.cookie_role(ca) is None
    auth.load(); assert auth.has_viewer() and auth.check_role("viewer-pw2") == "v"   # 重启后还在
    cs, cl = auth.make_cookie("a", remember=False), auth.make_cookie("a", remember=True)
    assert auth.cookie_short(cs) and not auth.cookie_short(cl) and auth.cookie_role(cs) == "a"
    assert "Max-Age" not in auth.cookie_header("x", remember=False) and "Max-Age=2592000" in auth.cookie_header("x")
    assert auth.perms() == {"export": False, "edit": False}
    auth.set_perms({"edit": True}); assert auth.perms() == {"export": False, "edit": True}
    auth.load(); assert auth.perms()["edit"] is True                      # 重启后还在
    auth.set_viewer(""); assert auth.perms() == {"export": False, "edit": False}   # 没有只读账号时权限不生效
    assert "Secure" in auth.cookie_header("x", secure=True) and "Secure" not in auth.cookie_header("x")
    # 升级前自动备份:版本变了才备份,只留 3 份,文件权限 600
    d2 = tempfile.mkdtemp(); config.DATA_DIR = d2; config.DB_PATH = os.path.join(d2, "t.db")
    con = db.init_db()
    with con: con.execute("INSERT INTO kv(k,v) VALUES('x','1')")
    config.VERSION = "v9.0.0"
    n1 = health.auto_backup(con)
    assert n1 and oct(os.stat(os.path.join(d2, "backups", n1)).st_mode & 0o777) == "0o600"
    assert health.auto_backup(con) is None                              # 同版本不重复备份
    for i in range(4):
        config.VERSION = f"v9.0.{i + 1}"; time.sleep(1.1); health.auto_backup(con)
    assert len(health.listing()) == 3
    try: health.read_backup("../../etc/passwd"); assert False
    except ValueError: pass
    config.VERSION = "dev"


def test_v030():
    import tempfile
    from app import auth, config, alerts, db, nikkilog
    # 磁盘:忽略 / 单独阈值
    cfg = alerts.load_cfg.__globals__["copy"].deepcopy(alerts.DEFAULT_CFG)
    cfg["disks"] = alerts._norm_disks({"/music": {"ign": True}, "/sdb2": {"pct": "95"}, "/x": {"ign": False, "pct": 500}, "/y": "bad"})
    assert cfg["disks"] == {"/music": {"ign": True, "pct": None}, "/sdb2": {"ign": False, "pct": 95.0}}, cfg["disks"]
    assert alerts.disk_rule(cfg, "/music")[0] and alerts.disk_rule(cfg, "/sdb2") == (False, 95.0) and alerts.disk_rule(cfg, "/data") == (False, cfg["rules"]["sys_disk"]["pct"])
    # 登录锁定重启后还在
    d = tempfile.mkdtemp(); config.DATA_DIR = d
    auth._fails.clear(); auth._lloaded[0] = False
    for _ in range(5): auth.fail("10.1.1.1")
    assert auth.locked("10.1.1.1") and oct(os.stat(os.path.join(d, "lockout.json")).st_mode & 0o777) == "0o600"
    auth._fails.clear(); auth._lloaded[0] = False
    assert auth.locked("10.1.1.1") and not auth.locked("10.1.1.2")
    # 告警冷却落盘
    con = db.open_db() if False else None
    import sqlite3
    c2 = sqlite3.connect(os.path.join(d, "t.db")); c2.execute("CREATE TABLE kv(k TEXT PRIMARY KEY, v TEXT)")
    alerts._cool.clear(); alerts._cool[("sys_disk", "/music")] = time.time(); alerts._cool_saved[0] = ""
    alerts.cool_save(c2); alerts._cool.clear(); alerts.cool_load(c2)
    assert ("sys_disk", "/music") in alerts._cool and time.time() - alerts._cool[("sys_disk", "/music")] < 60
    alerts._cool.clear()


def test_v031():
    import sqlite3, tempfile
    from app import analysis, lookup, config, db
    # 规则推算
    R = lambda t, p: {"type": t, "payload": p}
    assert lookup._match(R("DomainSuffix", "github.com"), "gist.github.com") is True and lookup._match(R("DomainSuffix", "github.com"), "notgithub.com") is False
    assert lookup._match(R("Domain", "a.com"), "b.a.com") is False and lookup._match(R("DomainKeyword", "face"), "m.facebook.com") is True
    assert lookup._match(R("RuleSet", "x"), "a.com") is None and lookup._match(R("GeoIP", "CN"), "a.com") is False and lookup._match(R("Match", ""), "a.com") is True
    assert lookup.clean("HTTPS://GitHub.com:443/x") == "github.com"
    try: lookup.clean("a b"); assert False
    except ValueError: pass
    # 无线事件解析
    d3 = tempfile.mkdtemp(); config.DATA_DIR = d3; config.DB_PATH = os.path.join(d3, "t.db")
    db.init_db(); con = db.open_db(); now = int(time.time())
    for i in range(7):
        con.execute("INSERT INTO syslog(ts,host,sev,tag,msg) VALUES(?,?,?,?,?)", (now - i * 60, "r", 6, "hostapd", "phy0-ap0: AP-STA-DISCONNECTED aa:bb:cc:dd:ee:01"))
        con.execute("INSERT INTO syslog(ts,host,sev,tag,msg) VALUES(?,?,?,?,?)", (now - i * 60, "r", 6, "hostapd", "phy0-ap0: AP-STA-CONNECTED aa:bb:cc:dd:ee:01"))
    con.execute("INSERT INTO syslog(ts,host,sev,tag,msg) VALUES(?,?,?,?,?)", (now, "r", 6, "hostapd", "phy0-ap0: STA aa:bb:cc:dd:ee:02 IEEE 802.11: deauthenticated due to inactivity (timer DEAUTH/REMOVE)"))
    con.commit()
    w = analysis.wifi(con, 24)
    d = {x["mac"]: x for x in w["devices"]}
    assert w["available"] and d["aa:bb:cc:dd:ee:01"]["drops"] == 7 and d["aa:bb:cc:dd:ee:01"]["flap"] and d["aa:bb:cc:dd:ee:02"]["inactive"] == 1, w
    assert analysis.compare(con)["series"]["cur"] == [0] * 7 and len(analysis.timeline(con, 12)["rows"]) == 12


def test_v036():
    import tempfile, time, os
    from app import config, db, syslog, backup, geo
    d = tempfile.mkdtemp(); config.DATA_DIR = d; config.DB_PATH = os.path.join(d, "t.db")
    db.init_db(); con = db.open_db(); now = int(time.time())
    # 归并:数字/MAC/IP 视为同一类
    for i in range(5):
        con.execute("INSERT INTO syslog(ts,host,sev,tag,msg) VALUES(?,?,?,?,?)", (now - i, "r", 3, "kernel", f"phy0: STA aa:bb:cc:dd:ee:0{i} err 0x{i}f at 10.0.0.{i}:22 sector {i}00"))
    con.execute("INSERT INTO syslog(ts,host,sev,tag,msg) VALUES(?,?,?,?,?)", (now, "r", 3, "dnsmasq", "failed to read /etc/hosts"))
    con.commit()
    g = syslog.groups(con, level=3, hours=24)
    assert g["total"] == 6 and len(g["rows"]) == 2 and g["rows"][0]["count"] == 5 and g["rows"][0]["tag"] == "kernel", g
    # 收不到日志的提示:关着不提示;开着但从没收到 → 提示并带 uci 命令
    assert syslog.silence(con) is None
    syslog.save_cfg(con, {"on": True, "port": 5514, "days": 2, "max_rows": 2000})
    con.execute("DELETE FROM syslog"); con.commit()
    syslog._state["last_rx"] = 0; syslog._state["err"] = ""
    t0 = syslog._T0; syslog._T0 = time.time() - 3600
    try:
        sl = syslog.silence(con)
        assert sl and "uci set system" in sl["detail"] and "5514" in sl["detail"], sl
    finally:
        syslog._T0 = t0
    # 新设备:面板首次启动时已有的设备不算,之后才出现的才算
    from app import devices
    now2 = int(time.time())
    con.execute("DELETE FROM known_dev")
    con.executemany("INSERT INTO known_dev(client, first) VALUES(?,?)", [("aa:bb:cc:00:00:01", now2 - 20 * 86400), ("aa:bb:cc:00:00:02", now2 - 20 * 86400),
                                                                          ("aa:bb:cc:00:00:03", now2 - 7200), ("aa:bb:cc:00:00:04", now2 - 20 * 86400), ("2409:8a55:e2d4:8480:b077:e2fb:f2f3:466e", now2 - 600)])
    con.commit()
    nd = devices.new_devices(con, 14)
    assert [x["key"] for x in nd] == ["aa:bb:cc:00:00:03"] and nd[0]["first"] == now2 - 7200, nd
    assert devices.new_devices(con, 1)[0]["key"] == "aa:bb:cc:00:00:03" and devices.new_devices(con, 90) and len(devices.new_devices(con, 90)) == 1
    con.execute("DELETE FROM known_dev"); con.commit(); assert devices.new_devices(con) == []
    # 热力图:平均 vs 中位数、单日视图、保留天数
    import datetime
    from app import insight
    config.HOUR_KEEP_DAYS = 21
    con.execute("DELETE FROM hourly"); today = datetime.date.today()
    cols = [r[1] for r in con.execute("PRAGMA table_info(hourly)")]
    assert "hour" in cols and "up" in cols and "down" in cols and "client" in cols, cols
    ins = lambda hour, up, down: con.execute(f"INSERT INTO hourly({','.join(cols)}) VALUES({','.join('?' * len(cols))})",
                                              [{"hour": hour, "client": "aa:bb:cc:00:00:09", "up": up, "down": down}.get(c, 0 if c in ("up", "down", "conns") else "x") for c in cols])
    for k in range(1, 22):
        d = today - datetime.timedelta(days=k)
        ins(d.strftime("%Y-%m-%d") + " 20", 0, 50e9 if k == 7 else 1e9)
    con.commit()
    wd = (today - datetime.timedelta(days=7)).weekday()
    ha = insight.heatmap(con, None, 21, "avg"); hm = insight.heatmap(con, None, 21, "median")
    assert ha["cells"][wd][20] > 10e9 and hm["cells"][wd][20] <= 2e9 and hm["stat"] == "median", (ha["cells"][wd][20], hm["cells"][wd][20])
    assert ha["samples"][wd] == 3 and insight.heatmap(con, None, 99)["days"] == 21
    dv = insight.heatmap(con, None, 21, "avg", (today - datetime.timedelta(days=7)).isoformat())
    assert dv["hours"][20]["down"] == 50e9 and dv["peak"]["hour"] == 20 and len(dv["hours"]) == 24 and dv["hours"][20]["top"], dv["peak"]
    try: insight.heatmap(con, None, 21, "avg", "bad"); assert False
    except ValueError: pass
    config.DATA_DIR = tempfile.mkdtemp()
    try: config.set_retention(1, 30); assert False
    except ValueError: pass
    try: config.set_retention(40, 30); assert False
    except ValueError: pass
    assert config.set_retention(30, 120) == {"hour_days": 30, "days": 120} and config.HOUR_KEEP_DAYS == 30 and config.KEEP_DAYS == 120
    config.HOUR_KEEP_DAYS, config.KEEP_DAYS = 2, 7; config.load_retention(); assert (config.HOUR_KEEP_DAYS, config.KEEP_DAYS) == (30, 120)
    config.HOUR_KEEP_DAYS, config.KEEP_DAYS = 14, 90
    # 备份:代理地址只在「含密钥」时带上
    geo.proxy_set("http://u:p@127.0.0.1:7890")
    assert "geo_proxy" not in backup.export(con, secrets=False)
    b = backup.export(con, secrets=True); assert b["geo_proxy"] == "http://u:p@127.0.0.1:7890"
    geo.proxy_set(""); assert geo.proxy_get() == ""
    backup.restore(con, b); assert geo.proxy_get() == "http://u:p@127.0.0.1:7890"
    geo.proxy_set("")


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f(); print("ok", n)
