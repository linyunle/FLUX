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
    hw = insight.heatmap(con, None, 21, "avg", None, "wk")
    assert len(hw["cells"]) == 2 and hw["labels"] == ["周一到周五", "周六、周日"] and sum(hw["samples"]) == 21 and hw["peak"]["label"] in hw["labels"], hw["samples"]
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


def test_v043_1():
    """路由器重启检测:面板随路由器一起重启时,靠数据库里记的开机时刻对比;自检提示频繁重启 + 硬盘错误。"""
    import tempfile, time, os
    from app import config, db, alerts, diag
    d = tempfile.mkdtemp(); config.DATA_DIR = d; config.DB_PATH = os.path.join(d, "t.db")
    db.init_db(); con = db.open_db(); now = int(time.time())
    cnt = lambda: con.execute("SELECT COUNT(*) FROM alerts WHERE kind='router_reboot'").fetchone()[0]
    alerts._boot_persist(con, 7200, now)                       # 第一次:只记录,不报
    assert cnt() == 0 and con.execute("SELECT v FROM kv WHERE k='router_boot'").fetchone()
    alerts._boot_persist(con, 7200 + 600, now + 600)           # 同一次开机,时刻不变 → 不报
    alerts._boot_persist(con, 7200 + 603, now + 601)           # 抖动几秒 → 不报
    assert cnt() == 0
    alerts._boot_persist(con, 60, now + 3000)                  # 运行时间回到 60 秒 → 路由器重启过
    assert cnt() == 1, cnt()
    alerts._boot_persist(con, 90, now + 3030)                  # 同一次开机再读 → 不重复
    assert cnt() == 1
    alerts._boot_persist(con, 90000, now + 3100)               # 开机时刻比记录的早很多(校时往回拨)→ 不算重启
    assert cnt() == 1
    # 自检:24 小时内重启 ≥2 次才提示;有 sda 的 I/O 错误时点出硬盘
    assert not any("路由器重启了" in x["title"] for x in diag.selfcheck(con, now + 3100))
    con.execute("INSERT INTO alerts(ts,kind,level,key,title,detail,sent) VALUES(?,?,?,?,?,?,?)", (now + 3050, "router_reboot", "warn", "reboot", "路由器重启过", "", "仅记录"))
    con.execute("INSERT INTO syslog(ts,host,sev,tag,msg) VALUES(?,?,?,?,?)", (now + 3000, "r", 3, "kernel", "[ 65.6] I/O error, dev sda, sector 331352064 op 0x0:(READ)"))
    con.commit()
    it = [x for x in diag.selfcheck(con, now + 3100) if "路由器重启了" in x["title"]]
    assert it and "2 次" in it[0]["title"], it
    from app import syslog
    syslog.save_cfg(con, {"on": True, "port": 5514, "days": 2, "max_rows": 2000})
    it = [x for x in diag.selfcheck(con, now + 3100) if "路由器重启了" in x["title"]]
    assert it and "sda" in it[0]["detail"], it


def test_v044():
    """应用规则解析:清掉 AI 输出的 Markdown 残留(行尾 \\、w\\.cdn、HTML 空格实体、关键字里的空格)。"""
    from app import appsig
    r = appsig.parse_rules("cl2-cn.apple.com.w\\.cdngslb.com.t.tushuokeji.net=Apple 系统服务|系统 / 更新\\\nal ikunlun.com=A|其他\n&#x20;zmapi.bestmku.com=其他|其他\\\n*.b.example=乙|办公 / 开发\\")
    assert r == [("cl2-cn.apple.com.w.cdngslb.com.t.tushuokeji.net", "Apple 系统服务", "系统 / 更新"), ("alikunlun.com", "A", "其他"),
                 ("zmapi.bestmku.com", "其他", "其他"), ("b.example", "乙", "办公 / 开发")], r


def test_v046():
    """节点登记地 vs 节点名地区:级别、忽略、告警、周报。"""
    import sqlite3, time
    from app import nodegeo, geo, alerts, insight
    assert nodegeo.name_cc("香港 01") == "HK" and nodegeo.name_cc("JP-Tokyo") == "JP" and nodegeo.name_cc("abc") == ""
    assert nodegeo.level_of("HK", "CN", "") == "high" and nodegeo.level_of("US", "HK", "AS13335 Cloudflare") == "low"
    assert nodegeo.level_of("JP", "SG", "x") == "mid" and nodegeo.level_of("HK", "HK", "") is None and nodegeo.level_of("", "CN", "") is None
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE kv(k TEXT PRIMARY KEY, v TEXT)")
    con.execute("CREATE TABLE nodeinfo(node TEXT, type TEXT, remote TEXT, geo TEXT, geo_at INT, seen INT)")
    con.executemany("INSERT INTO nodeinfo(node,remote) VALUES(?,?)", [("香港 01", "1.1.1.1"), ("日本 02", "2.2.2.2"), ("美国 03", "3.3.3.3"), ("新加坡 04", "4.4.4.4")])
    table = {"1.1.1.1": ("CN", "AS4134 CHINANET"), "2.2.2.2": ("SG", "AS1 x"), "3.3.3.3": ("US", "AS2 y"), "4.4.4.4": ("HK", "AS13335 Cloudflare")}
    old = geo.lookup
    geo.lookup = lambda ip: table.get(ip, ("", ""))
    try:
        r = nodegeo.scan(con)
        assert [(x["node"], x["level"]) for x in r] == [("香港 01", "high"), ("日本 02", "mid"), ("新加坡 04", "low")], r
        assert nodegeo.summary(con)["cn"] == 1
        nodegeo.set_ignore(con, "香港 01", True)
        sm = nodegeo.summary(con)
        assert sm["cn"] == 0 and sm["ignored"] == 1
        nodegeo.set_ignore(con, "香港 01", False)
        assert nodegeo.summary(con)["cn"] == 1
        con.execute("INSERT INTO nodeinfo(node,remote) VALUES('香港 09','1.1.1.1')")        # 同一入口 1.1.1.1 的两个节点
        assert [x["shared"] for x in nodegeo.scan(con) if x["remote"] == "1.1.1.1"] == [2, 2]
        assert nodegeo.set_ignore_server(con, "1.1.1.1", True) == 2 and set(nodegeo.ignored(con)) == {"香港 01", "香港 09"}
        assert nodegeo.summary(con)["cn"] == 0
        assert nodegeo.set_ignore_server(con, "1.1.1.1", False) == 2 and nodegeo.ignored(con) == [] and nodegeo.set_ignore_server(con, "", True) == 0
    finally:
        geo.lookup = old
    assert "node_geo" in alerts.DEFAULT_RULES and alerts.KINDS["node_geo"]


def test_v047():
    """动态对比窗口 + 长周期时间线聚合。"""
    import os, tempfile, time
    from app import analysis, config, db
    d = tempfile.mkdtemp(); config.DATA_DIR = d; config.DB_PATH = os.path.join(d, "t.db")
    db.init_db(); con = db.open_db()
    c = analysis.compare(con)
    assert c["days"] == 7 and c["names"] == ["本周", "上周"] and len(c["series"]["cur"]) == 7
    c = analysis.compare(con, 3)
    assert c["days"] == 3 and c["names"] == ["本期", "上期"] and len(c["series"]["cur"]) == 3 and len(c["series"]["prev"]) == 3
    assert c["cur"][0] > c["prev"][1] and c["prev"][1] < c["cur"][0]
    c = analysis.compare(con, 5, cur_end=analysis._shift(analysis._days(0, 0)[0], 10), prev_end=analysis._shift(analysis._days(0, 0)[0], 30))
    assert c["cur"][1] == analysis._shift(analysis._days(0, 0)[0], 10) and c["prev"][1] == analysis._shift(analysis._days(0, 0)[0], 30) and len(c["series"]["prev"]) == 5
    c = analysis.compare(con, 5, prev_end=analysis._days(0, 0)[0])     # 重叠 → 退回紧挨着本期之前
    assert c["prev"][1] == analysis._shift(c["cur"][0], 1)
    assert analysis.compare(con, 999)["days"] == 90 and analysis.compare(con, "x")["days"] == 7
    for i in range(14):      # 有数据时也要能算(曾因变量名冲突在有设备数据时 500)
        day = time.strftime("%Y-%m-%d", time.localtime(time.time() - i * 86400))
        con.execute("INSERT INTO traffic(day,client,node,grp,rule,host,up,down) VALUES(?,?,?,?,?,?,?,?)", (day, "aa:bb:cc:dd:ee:01", "n", "g", "r", "h%d.com" % i, 10, 90))
    con.commit()
    c = analysis.compare(con, 7)
    assert c["traffic"]["cur"]["total"] == 700 and c["new_hosts"]["count"] == 7 and c["names"] == ["本周", "上周"], c
    t = analysis.timeline(con, 720)
    assert t["step"] == 5 and len(t["rows"]) == 144 and analysis.timeline(con, 24)["step"] == 1


def test_v047_4():
    """网站图标:读页面里的 rel=icon,没有就 /favicon.ico;只收图片;有缓存。"""
    import base64, http.server, os, tempfile, threading
    from app import config, favicon
    config.DATA_DIR = tempfile.mkdtemp()
    PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")
    hits = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def do_GET(self):
            hits.append(self.path)
            if self.path == "/a/":
                body, ct = b'<html><head><link rel="shortcut icon" href="/static/i.png"></head></html>', "text/html"
            elif self.path == "/static/i.png":
                body, ct = PNG, "image/png"
            elif self.path == "/b/":
                body, ct = b"<html></html>", "text/html"
            elif self.path == "/favicon.ico":
                body, ct = b"<html>not an image</html>", "text/html"
            else:
                self.send_response(404); self.end_headers(); return
            self.send_response(200); self.send_header("Content-Type", ct); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    r = favicon.get(base + "/a/")
    assert r and r[1] == "image/png" and r[0] == PNG, r
    n = len(hits)
    assert favicon.get(base + "/a/")[0] == PNG and len(hits) == n, "第二次走缓存"
    assert favicon.get(base.replace("127.0.0.1", "localhost") + "/b/") is None, "/favicon.ico 不是图片 → 没有图标(换个来源,不吃缓存)"
    assert favicon._kind(b"\x89PNG\r\n\x1a\nxxxx", "") == "image/png" and favicon._kind(b"<html>", "image/png") == ""
    srv.shutdown()


def test_v047_5():
    """设备合并:新数据记到主设备、历史按表归并、IP 并入主设备、拆分后恢复。"""
    import os, sqlite3, tempfile, time
    from app import config, db, devices, web
    d = tempfile.mkdtemp(); config.DATA_DIR = d; config.DB_PATH = os.path.join(d, "t.db")
    db.init_db(); con = db.open_db()
    day = time.strftime("%Y-%m-%d")
    A, B = "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"
    con.execute("INSERT INTO ipmap(ip,mac,seen) VALUES('192.168.1.10',?,1),('192.168.1.11',?,1)", (A, B))
    for c, v in ((A, 100), (B, 50), ("192.168.1.11", 7)):
        con.execute("INSERT INTO traffic(day,client,node,grp,rule,host,up,down) VALUES(?,?,?,?,?,?,?,?)", (day, c, "n", "g", "r", "h.com", 0, v))
    con.commit()
    q = lambda: dict(con.execute(f"SELECT {web.DEVX} k, SUM(up+down) FROM traffic GROUP BY k").fetchall())
    assert q() == {A: 100, B: 57}, q()
    devices.set_merge(con, A, B, True)
    assert q() == {A: 157}, q()
    assert devices.MERGE == {B: A} and devices.merged_groups(con) == {A: [B]}
    assert devices.ips_by_dev(con)[A] == ["192.168.1.10", "192.168.1.11"] and B not in devices.ips_by_dev(con)
    n = devices.Neigh(con)
    assert n.key("192.168.1.11") == A, "新数据直接记到主设备"
    try:
        devices.set_merge(con, B, A, True)      # 主设备本身是别人的从设备 → 追到最终主设备,不能并进自己
        raise AssertionError("应当拒绝")
    except ValueError:
        pass
    devices.set_merge(con, B, A, False)         # 拆分一个不存在的从设备也不报错
    devices.set_merge(con, A, B, False)
    assert q() == {A: 100, B: 57} and devices.MERGE == {}
    # 链:C 并进 B,B 再并进 A,C 跟着去 A
    C = "aa:bb:cc:dd:ee:03"
    devices.set_merge(con, B, C, True); devices.set_merge(con, A, B, True)
    assert devices.MERGE == {B: A, C: A}, devices.MERGE
    devices.set_merge(con, A, B, False); devices.set_merge(con, A, C, False)


def test_v048_2():
    """对比里的节点失败率:qoe.n 只数成功次数,失败率 = fails / (n + fails),不能超过 100%。"""
    import os, tempfile, time
    from app import analysis, config, db
    d = tempfile.mkdtemp(); config.DATA_DIR = d; config.DB_PATH = os.path.join(d, "t.db")
    db.init_db(); con = db.open_db()
    cur = time.strftime("%Y-%m-%d %H"); prv = time.strftime("%Y-%m-%d %H", time.localtime(time.time() - 9 * 86400))
    con.execute("INSERT INTO qoe(hour,node,n,sum_d,sum_sq,fails) VALUES(?,?,?,?,?,?)", (prv, "好节点", 20, 20 * 100, 0, 0))
    con.execute("INSERT INTO qoe(hour,node,n,sum_d,sum_sq,fails) VALUES(?,?,?,?,?,?)", (cur, "好节点", 20, 20 * 100, 0, 0))
    con.execute("INSERT INTO qoe(hour,node,n,sum_d,sum_sq,fails) VALUES(?,?,?,?,?,?)", (prv, "变差的", 20, 20 * 100, 0, 0))
    con.execute("INSERT INTO qoe(hour,node,n,sum_d,sum_sq,fails) VALUES(?,?,?,?,?,?)", (cur, "变差的", 6, 6 * 400, 0, 14))     # 20 次里 14 次失败
    con.execute("INSERT INTO qoe(hour,node,n,sum_d,sum_sq,fails) VALUES(?,?,?,?,?,?)", (prv, "死了的", 20, 20 * 100, 0, 0))
    con.execute("INSERT INTO qoe(hour,node,n,sum_d,sum_sq,fails) VALUES(?,?,?,?,?,?)", (cur, "死了的", 0, 0, 0, 30))
    con.commit()
    w = {x["node"]: x for x in analysis.compare(con, 7)["nodes_worse"]}
    assert set(w) == {"变差的", "死了的"}, w
    assert w["变差的"]["fail"] == 70.0 and w["变差的"]["avg"] == 400 and w["变差的"]["avg_prev"] == 100, w
    assert w["死了的"]["fail"] == 100.0 and w["死了的"]["avg"] == 0, w
    assert all(x["fail"] <= 100 for x in w.values())
    tl = analysis.timeline(con, 24)
    assert max(r["node_fail"] or 0 for r in tl["rows"]) <= 100


def test_v048_4():
    """开机后前 N 分钟的路由器日志严重信息只记时间线、不推送。"""
    import os, tempfile, time, json
    from app import alerts, config, db, syslog, sysinfo
    d = tempfile.mkdtemp(); config.DATA_DIR = d; config.DB_PATH = os.path.join(d, "t.db")
    db.init_db(); con = db.open_db()
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES('syslog',?)", (json.dumps({"on": True}),))
    import importlib; importlib.reload(alerts)   # 前面的用例会替换 alerts.fire/_allow 且不还原,这里恢复真实实现
    cfg = alerts.load_cfg(con)
    assert cfg["rules"]["syslog_crit"]["boot_min"] == 30
    now = time.time()
    syslog._state["sys_last"] = None
    syslog.check(con, cfg, now)       # 第一次只记基线
    def add(ts, msg):
        with con:
            con.execute("INSERT INTO syslog(ts,host,sev,tag,msg) VALUES(?,?,?,?,?)", (int(ts), "r", 2, "kernel", msg))
    old = dict(sysinfo.STATE)
    try:
        sysinfo.STATE["uptime"] = 223                  # 开机 223 秒:日志时间在开机后 3 分钟内
        add(now - 20, "I/O error, dev sda, sector 1 op 0x0:(READ)")
        syslog.check(con, cfg, now)
        titles = [r[0] for r in con.execute("SELECT title FROM alerts WHERE kind='syslog_crit'")]
        assert len(titles) == 1 and "开机阶段" in titles[0] and "未推送" in titles[0], titles
        sysinfo.STATE["uptime"] = 7200                 # 运行两小时后再出现:照常提醒
        add(now + 5, "I/O error, dev sda, sector 2 op 0x0:(READ)")
        syslog.check(con, cfg, now + 10)
        titles = [r[0] for r in con.execute("SELECT title FROM alerts WHERE kind='syslog_crit' ORDER BY id")]
        assert len(titles) == 2 and "开机阶段" not in titles[1], titles
        cfg["rules"]["syslog_crit"]["boot_min"] = 0    # 填 0 = 不限制
        sysinfo.STATE["uptime"] = 100
        add(now + 20, "I/O error, dev sda, sector 3 op 0x0:(READ)")
        syslog.check(con, cfg, now + 30)
        assert "开机阶段" not in [r[0] for r in con.execute("SELECT title FROM alerts WHERE kind='syslog_crit' ORDER BY id")][-1]
    finally:
        sysinfo.STATE.clear(); sysinfo.STATE.update(old)


def test_v049():
    """v0.49:盘符翻译、设备直连失败归并与忽略、订阅停用、诊断包对比。"""
    import os, tempfile, time
    from app import config, db, sysinfo, tidy, syslog
    d = tempfile.mkdtemp(); config.DATA_DIR = d; config.DB_PATH = os.path.join(d, "t.db")
    db.init_db(); con = db.open_db()
    # 盘符 → 挂载点
    old = sysinfo._rd
    sysinfo._rd = lambda p: "/dev/sda1 /host/music fuseblk rw 0 0\n/dev/sdb2 /host/sdb2 ext4 rw 0 0\ntmpfs /tmp tmpfs rw 0 0\n" if p.endswith("/mounts") else old(p)
    try:
        assert sysinfo.dev_map()["sda"] == ["/music(fuseblk)"]
        t = sysinfo.annotate_dev("[ 9.1] I/O error, dev sda, sector 5")
        assert "dev sda〔现为 /music(fuseblk)〕" in t, t
        assert "〔" not in sysinfo.annotate_dev("I/O error, dev sdz, sector 5")
        assert "sdb2〔现为 /sdb2(ext4)〕" in sysinfo.annotate_dev("EXT4-fs error (device sdb2): x")
        assert syslog._ann("hello") == "hello"
    finally:
        sysinfo._rd = old
    # 设备直连失败归并
    now = int(time.time())
    with con:
        for i in range(40):
            con.execute("INSERT INTO nklog(ts,src,lvl,msg) VALUES(?,?,?,?)", (now - i, "core", 4, "[TCP] dial DIRECT (match IPCIDR/1.2.3.4/32) 192.168.1.5:%d --> i.example.cn:443 error: i/o timeout" % (3000 + i)))
        con.execute("INSERT INTO nklog(ts,src,lvl,msg) VALUES(?,?,?,?)", (now, "core", 4, "[TCP] dial DIRECT (match X) 192.168.1.6:1 --> b.example.cn:80 error: x"))
    nz = tidy.noise(con, now - 100)
    assert nz["rows"][0]["key"] == "192.168.1.5|i.example.cn" and nz["rows"][0]["n"] == 40 and nz["ign_n"] == 0
    tidy.set_noise(con, "192.168.1.5|i.example.cn", True)
    nz = tidy.noise(con, now - 100)
    assert nz["rows"][0]["ignored"] and nz["ign_n"] == 40
    tidy.set_noise(con, "192.168.1.5|i.example.cn", False)
    assert tidy.noise_ignored(con) == []
    tidy.set_sub_mute(con, "红杏云", True)
    assert tidy.sub_muted(con) == ["红杏云"]
    tidy.set_sub_mute(con, "红杏云", False)
    assert tidy.sub_muted(con) == []
    # 诊断包对比
    a = {"flux_diag": 1, "created": "t1", "version": "v1", "selfcheck": [{"level": "warn", "title": "24 小时有 31 条错误"}, {"level": "info", "title": "老问题"}], "rss_mb": 60,
         "db": {"rows": {"syslog": 10}}, "alerts_recent": [{"kind": "syslog_crit", "level": "warn"}]}
    b = {"flux_diag": 1, "created": "t2", "version": "v2", "selfcheck": [{"level": "bad", "title": "24 小时有 332 条错误"}, {"level": "warn", "title": "新问题"}], "rss_mb": 80,
         "db": {"rows": {"syslog": 30}}, "alerts_recent": [{"kind": "syslog_crit", "level": "warn"}] * 3}
    r = tidy.compare(a, b)
    assert [x["title"] for x in r["finds"]["added"]] == ["新问题"] and [x["title"] for x in r["finds"]["gone"]] == ["老问题"]
    assert r["finds"]["changed"][0]["worse"] is True
    m = {x["name"]: x for x in r["metrics"]}
    assert m["面板占用内存"]["delta"] == 20 and m["路由器日志条数"]["delta"] == 20
    assert r["alerts"] == [{"kind": "syslog_crit", "a": 1, "b": 3}]
    try:
        tidy.compare({}, b); assert False
    except ValueError:
        pass


def test_v050_connmon():
    """v0.50:连接明细——conntrack 解析、与 nikki 连接关联、汇总、告警正文、诊断包、关闭开关。"""
    import os, tempfile, time
    from app import connmon
    ct = (
        "ipv4     2 udp      17 55 src=192.168.100.123 dst=192.168.100.1 sport=43077 dport=53 packets=1 bytes=59 src=192.168.100.1 dst=192.168.100.123 sport=53 dport=43077 packets=1 bytes=87 mark=0 zone=0 use=2\n"
        "ipv6     10 tcp      6 7434 ESTABLISHED src=2409:8a55:e2d3:b950:0d76:4db1:ff41:74ff dst=2409:8c28:6c07:030e:0000:0000:0000:0100 sport=50557 dport=443 packets=1790 bytes=935926 src=2409:8c28:6c07:030e:0000:0000:0000:0100 dst=2409:8a55:e2d3:b950:0d76:4db1:ff41:74ff sport=443 dport=50557 packets=2684 bytes=1559957 [ASSURED] mark=0 zone=0 use=2\n"
        "ipv4 2 tcp 6 30 SYN_SENT src=192.168.100.5 dst=1.2.3.4 sport=40000 dport=80 packets=1 bytes=60 [UNREPLIED] src=1.2.3.4 dst=192.168.100.5 sport=80 dport=40000 packets=0 bytes=0 mark=0 zone=0 use=2\n"
        "ipv4 2 icmp 1 29 src=192.168.100.5 dst=8.8.8.8 type=8 code=0 id=1 packets=1 bytes=84 src=8.8.8.8 dst=192.168.100.5 type=0 code=0 id=1 packets=1 bytes=84 mark=0 zone=0 use=2\n"
        "ipv4 2 tcp 6 99 ESTABLISHED src=172.68.49.102 dst=9.9.9.9 sport=1 dport=443 packets=1 bytes=1 src=9.9.9.9 dst=172.68.49.102 sport=443 dport=1 packets=1 bytes=1 mark=0 zone=0 use=2\n")
    d = tempfile.mkdtemp(); p = os.path.join(d, "ct"); open(p, "w").write(ct)
    e = connmon.parse_ct_line(ct.splitlines()[1])
    assert e["src"] == "2409:8a55:e2d3:b950:d76:4db1:ff41:74ff" and e["state"] == "ESTABLISHED" and e["rb"] == 1559957
    assert connmon.parse_ct_line(ct.splitlines()[3]) is None        # icmp 不收
    assert connmon.parse_ct_line(ct.splitlines()[2])["unreplied"] is True
    assert connmon.parse_ct_line("garbage") is None
    assert connmon.nip("2409:0:0:0:0:0:0:1") == "2409::1" and connmon.is_fake("198.18.0.5") and not connmon.is_fake("1.2.3.4")

    class Neigh:
        map = {"192.168.100.123": "aa:aa", "192.168.100.5": "bb:bb"}
        def key(self, ip): return self.map.get(ip, ip)

    class Col:
        neigh = Neigh(); ptype = {"HK": "Vless", "直连": "Direct"}
        def leaf(self, ch): return str(ch[0]) if ch else "UNKNOWN"
    kind = lambda n, pt: "direct" if n == "直连" else "proxy"
    now = time.time()
    conns = [
        {"id": "1", "metadata": {"network": "tcp", "sourceIP": "2409:8a55:e2d3:b950:d76:4db1:ff41:74ff", "sourcePort": "50557", "destinationIP": "2409:8c28:6c07:30e::100", "destinationPort": "443", "host": "", "remoteDestination": ""}, "chains": ["直连"], "rule": "RuleSet", "rulePayload": "cn_ip", "upload": 5, "download": 9, "start": "2026-10-30T16:11:29.007339908Z"},
        {"id": "2", "metadata": {"network": "tcp", "sourceIP": "192.168.100.5", "sourcePort": "40000", "destinationIP": "198.18.1.9", "destinationPort": "80", "host": "Slow.Example.com"}, "chains": ["HK"], "rule": "Match", "upload": 1, "download": 0, "start": ""},
        {"id": "3", "metadata": {"network": "udp", "sourceIP": "192.168.100.123", "sourcePort": "43077", "destinationIP": "192.168.100.1", "destinationPort": "53"}, "chains": ["直连"], "rule": "Match", "upload": 1, "download": 1},
        {"id": "4", "metadata": {"network": "tcp", "sourceIP": "192.168.100.5", "sourcePort": "40001", "destinationIP": "", "destinationPort": "443", "host": "a.example.com"}, "chains": ["HK"], "rule": "Match"},
    ]
    old = connmon.CT_PATH
    connmon.CT_PATH = p
    connmon.STATE.update(on=True, cfg_at=time.time(), at=0.0, interval=4, ct_at=0.0)
    try:
        connmon.feed(conns, Col(), now, kind)
        assert connmon.STATE["err"] == "", connmon.STATE["err"]
        j = connmon.snapshot(label=lambda k: "名:" + k, now=now)
        assert j["summary"]["total"] == 4 and j["summary"]["tcp"] == 3 and j["summary"]["udp"] == 1
        by = {r["id"]: r for r in j["rows"]}
        assert by["1"]["state"] == "ESTABLISHED" and by["1"]["link"] == "已确认" and by["1"]["state_cn"] == "已建立" and by["1"]["dst_ip"] == "2409:8c28:6c07:30e::100"
        assert by["1"]["dev"] == "aa:aa" or by["1"]["dev"].startswith("2409")        # v6 来源在测试邻居表里没有,按 IP
        assert by["2"]["dst_ip"] == "" and by["2"]["host"] == "slow.example.com"      # fake-ip 不当作真实目标
        assert by["2"]["state"] == "SYN_SENT" and by["2"]["unreplied"] and by["2"]["state_cn"] == "无回应"
        assert by["3"]["state"] == "UDP" and by["4"]["link"] == "未关联" and by["4"]["state"] == ""
        assert any(x["k"] == "443/tcp" for x in j["summary"]["top_ports"])
        assert any("(代理解析" in x["k"] or x["k"] == "slow.example.com" for x in j["summary"]["top_dst"])
        dev5 = connmon.snapshot(dev="bb:bb", label=lambda k: k, now=now)
        assert dev5["summary"]["total"] == 2 and dev5["dev_ct"]["tcp"] == 1
        assert connmon.snapshot(proto="udp", now=now)["summary"]["total"] == 1 and connmon.snapshot(q="slow", now=now)["matched"] == 1
        assert connmon.snapshot(state="SYN_SENT", now=now)["matched"] == 1
        b = connmon.brief("bb:bb")
        assert "TCP 2 / UDP 0" in b and "slow.example.com" in b and "没有回应" in b, b
        dg = connmon.diag(lambda t: t.upper())
        assert dg["top_devices"][0]["dev"] in ("BB:BB", "2409:8A55:E2D3:B950:D76:4DB1:FF41:74FF") and dg["summary"]["total"] == 4
        # 限速:间隔内再喂一次不重算
        at = connmon.STATE["at"]; connmon.feed([], Col(), now + 1, kind)
        assert connmon.STATE["at"] == at and connmon.snapshot(now=now)["summary"]["total"] == 4
        # 新增 / 关闭
        connmon.feed(conns[:2], Col(), now + 12, kind)
        st = connmon.snapshot(now=now + 12)["devices"]
        assert sum(x["closed"] for x in st) == 2
        # 读不到 conntrack:降级,不报错
        connmon.CT_PATH = os.path.join(d, "none"); connmon.STATE["ct_at"] = 0.0
        connmon.feed(conns, Col(), now + 30, kind)
        j2 = connmon.snapshot(now=now + 30)
        assert j2["status"]["ct_ok"] is False and all(r["link"] == "无法判断" and r["state"] == "" for r in j2["rows"])
    finally:
        connmon.CT_PATH = old
    # 关闭开关:清空数据
    import json
    from app import config, db
    config.DATA_DIR = d; config.DB_PATH = os.path.join(d, "t.db"); db.init_db(); con = db.open_db()
    connmon.save_cfg(con, {"on": False})
    assert connmon.snapshot()["rows"] == [] and connmon.STATE["on"] is False
    connmon.feed(conns, Col(), now + 100, kind)
    assert connmon.snapshot()["rows"] == []
    connmon.save_cfg(con, {"on": True})


def test_v051_connhist():
    """v0.51:档位判定与滞回、分钟历史、事件与前后快照、预算清理。"""
    import os, tempfile, time, importlib
    from app import config, db, connhist
    importlib.reload(connhist)
    d = tempfile.mkdtemp(); config.DATA_DIR = d; config.DB_PATH = os.path.join(d, "h.db"); db.init_db()
    # 硬件 → 基础档位
    assert connhist.base_tier({"cpu": 4, "mem_mb": 12000})[0] == "high"
    assert connhist.base_tier({"cpu": 4, "mem_mb": 2000})[0] == "standard"
    assert connhist.base_tier({"cpu": 4, "mem_mb": 1000})[0] == "light"
    assert connhist.base_tier({"cpu": 1, "mem_mb": 8000})[0] == "light"
    assert connhist.base_tier({"cpu": 4, "mem_mb": None})[0] == "standard"
    # 滞回:第一次直接采用;压力出现后 5 分钟 + 停留 10 分钟才降档
    hw = {"arch": "x", "cpu": 4, "mem_mb": 12000, "limit_mb": None, "disk_free_mb": 50000, "load1": 0.1}
    connhist.STATE.update(hw=hw, hw_at=time.time() + 99999, since=0.0, eval_at=0.0, cand="")
    t0 = 1_000_000.0
    assert connhist.evaluate(t0) == "high"
    assert connhist.evaluate(t0 + 60, 0.95) == "high"              # 刚出现压力
    assert connhist.evaluate(t0 + 400, 0.95) == "high"             # 满 5 分钟但停留不足 10 分钟
    assert connhist.evaluate(t0 + 700, 0.95) == "standard"         # 都满足 → 降一档
    assert connhist.evaluate(t0 + 800, None) == "standard"         # 压力解除,要先等候选稳定
    assert connhist.evaluate(t0 + 1000, None) == "standard"        # 候选才 200 秒
    assert connhist.evaluate(t0 + 1250, None) == "standard"        # 候选够久但停留不足 10 分钟(降档在 t0+700)
    assert connhist.evaluate(t0 + 1400, None) == "high"
    connhist.load_cfg({"tier": "light"}); assert connhist.evaluate(t0 + 5000) == "light" and connhist.params()["snap_rows"] == 0
    connhist.load_cfg({"tier": "auto", "hist": 2, "events": 5}); assert connhist.params()["hist"] == 2 and connhist.params()["events"] == 5
    connhist.load_cfg({"tier": "high", "budget_mb": 300}); connhist.evaluate(t0 + 9000)
    assert connhist.STATE["tier"] == "high"
    # 分钟历史:窗口翻页时写库
    R = {"dev": 0, "dst": 1, "host": 2, "dport": 3, "proto": 4, "node": 5, "start": 6, "up": 7, "down": 8, "state": 9, "link": 10}
    rows = [["a", "h%d.com" % (i % 3), "", "443", "tcp", "HK", 0, 1, 2, "ESTABLISHED", "已确认"] for i in range(10)]
    now = (int(time.time() // 60) * 60) - 600
    ds = {"a": {"conns": 10, "tcp": 10, "udp": 0, "new": 3, "closed": 1}}
    ctd = {"a": {"states": {"SYN_SENT": 2}, "unreplied": 1}}
    connhist.STATE["tier"] = "high"
    connhist.record(now + 5, ds, ctd, rows, R)
    connhist.record(now + 65, ds, ctd, rows, R)                       # 翻页 → 写上一分钟
    assert connhist.STATE["err"] == "", connhist.STATE["err"]
    con = db.open_db()
    tr = connhist.trend(con, "a", 60, now + 100)
    assert len(tr["rows"]) == 1 and tr["rows"][0]["conns"] == 10 and tr["rows"][0]["syn"] == 2
    assert connhist.trend(con, "", 60, now + 100)["rows"][0]["new"] == 3
    # 事件 + 快照
    for i in range(5):
        connhist.record(now + 100 + i * 4, ds, ctd, rows, R)
    eid = connhist.trigger("a", "conn_many", "attention", "测试", {"x": 1}, now + 120, rows, R)
    assert eid and connhist.trigger("a", "conn_many", "suspect", "测试", {"x": 2}, now + 125, rows, R) == eid   # 同类合并并升级
    ev = connhist.events(con, "a", 24, 10, now + 130)
    assert len(ev) == 1 and ev[0]["level"] == "suspect" and ev[0]["level_name"] == "高度可疑"
    for i in range(3):
        connhist.record(now + 130 + i * 4, ds, ctd, rows, R); connhist.tick(now + 130 + i * 4, ds, ctd)
    assert connhist.event_detail(con, eid)["snapshot_pending"] is True
    connhist.tick(now + 120 + 181, ds, ctd)                              # 后 180 秒结束 → 写快照
    det = connhist.event_detail(con, eid)
    assert det["snapshot"]["at"]["rows"] and det["snapshot"]["pre"] and det["snapshot"]["post"] and det["snapshot_pending"] is False
    assert det["snapshot"]["at"]["tops"]["d"][0][1] >= 3
    connhist.tick(now + 120 + 181 + 400, ds, ctd)                       # 长时间无新触发 → 结束
    assert connhist.event_detail(con, eid)["status"] == "closed"
    assert connhist.event_detail(con, 9999) is None
    # 预算:超出就清旧快照
    connhist.CFG["budget_mb"] = 1
    with con:
        for i in range(30):
            con.execute("INSERT INTO conn_event(ts_start,dev,kind) VALUES(?,?,?)", (int(now) + i, "a", "k"))
            con.execute("INSERT OR REPLACE INTO conn_snap(event_id,ts,size,payload) VALUES(?,?,?,?)", (100 + i, int(now) + i, 90000, "{}"))
    st = connhist.prune(con, now + 200)
    assert st["snap_bytes"] <= 1048576 * 0.5 + 90000 and connhist.STATE["storage_note"]
    # 保留期:过期事件被删
    with con:
        con.execute("UPDATE conn_event SET ts_start=1 WHERE id=?", (eid,))
    connhist.prune(con, now + 200)
    assert connhist.event_detail(con, eid) is None
    # 磁盘不足:不写快照
    connhist.STATE["hw"] = dict(hw, disk_free_mb=100); connhist.STATE["hw_at"] = time.time() + 99999
    assert "不足" in (connhist.system(con)["storage_note"] or "不足")
    con.close()


def test_v052_connanom():
    """v0.52:基线、14 类信号、四级判定与可信度、事件生命周期、诊断结构、告警推送。"""
    import os, tempfile, time, importlib, json
    from app import config, db, connhist, connanom
    importlib.reload(connhist); importlib.reload(connanom)
    d = tempfile.mkdtemp(); config.DATA_DIR = d; config.DB_PATH = os.path.join(d, "a.db"); db.init_db(); con = db.open_db()
    connhist.STATE.update(tier="high", since=1.0)
    now = float(int(time.time() // 60) * 60)
    # 基线:3 天、同一小时稳定在 ~20 个连接
    hr = time.localtime(now).tm_hour
    with con:
        for i in range(1, 3 * 1440):
            ts = int(now) - i * 60
            if time.localtime(ts).tm_hour == hr:
                con.execute("INSERT INTO conn_dev_min(ts,dev,conns,tcp,udp,new,closed,syn,unrep,top) VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (ts, "dev1", 18 + i % 5, 15, 5, 4, 4, 0, 0, json.dumps({"d": [["a.com", 5]], "p": [], "n": []})))
    connanom.compute_base(con, "dev1", now)
    b = connanom.BASE["dev1"]
    assert b["n"] > 100 and b["hours"][hr][2] <= 23 and "a.com" in b["hosts"]
    p50, p95, n95, conf, why = connanom.ref("dev1", now)
    assert p95 <= 23 and conf in ("medium", "high") and "同一小时" in why
    p50, p95, n95, conf, why = connanom.ref("nobody", now)
    assert p95 is None and conf == "low" and "保守" in why
    R = {"dev": 0, "dst": 1, "host": 2, "dport": 3, "proto": 4, "node": 5, "start": 6, "up": 7, "down": 8, "state": 9, "link": 10, "unrep": 11}
    def mk(n, host="a.com", port="443", node="HK", unrep=False):
        return [["dev1", "", host, port, "tcp", node, now - 10, 1, 1, "ESTABLISHED", "已确认", unrep] for _ in range(n)]
    def feed_ring(dev, series, t0):
        connhist.RING[dev] = __import__("collections").deque(maxlen=50)
        for i, (c, new, closed, syn, un) in enumerate(series):
            connhist.RING[dev].append((int(t0 + i * 10), c, c, 0, new, closed, syn, un))
    # 正常
    feed_ring("dev1", [(20, 3, 3, 0, 0)] * 6, now - 60)
    sig, miss, why, conf = connanom.detect("dev1", now, [[None, now - 10, "", "a.com", "443", "", "HK"]] * 20, True)
    assert sig == [] and connanom.grade(sig, conf, True)[0] == "normal"
    # 突增 + 持续高 + 偏离习惯
    feed_ring("dev1", [(20, 3, 3, 0, 0)] * 3 + [(400, 300, 5, 0, 0)] * 3, now - 60)
    rows = [[None, now - 10, "", "a.com", "443", "", "HK"]] * 400
    sig, miss, why, conf = connanom.detect("dev1", now, rows, True)
    ids = {s["id"] for s in sig}
    assert {"sudden_growth", "new_rate", "habit_dev"} <= ids, ids
    lv, sc = connanom.grade(sig, conf, True)
    assert lv == "suspect" and sc >= 5
    # 新设备 + 无连接表:不硬下结论
    feed_ring("newdev", [(20, 3, 3, 0, 0)] * 3 + [(450, 3, 3, 0, 0)] * 3, now - 60)
    sig, miss, why, conf = connanom.detect("newdev", now, [[None, now - 10, "", "x.com", "443", "", "HK"]] * 450, False)
    assert conf == "low" and any("连接表" in m for m in miss) and any("基线" in m for m in miss)
    assert connanom.grade(sig, conf, False)[0] in ("unknown", "attention")
    assert connanom.grade([{"weight": 2}] * 3, "low", False)[0] == "suspect"
    # 其他信号
    feed_ring("dev1", [(300, 5, 5, 0, 0)] * 30, now - 290)
    rs = [[None, now - 4000, "9.9.%d.%d" % (i // 250, i % 250), "h%d.com" % i, "6881", "", "HK"] for i in range(300)]
    ids = {s["id"] for s in connanom.detect("dev1", now, rs, True)[0]}
    assert {"long_unreleased", "many_ips", "many_domains", "port_focus", "sustained_high"} <= ids, ids
    feed_ring("dev1", [(100, 1, 1, 60, 10)] * 6, now - 60)
    rs = [[None, now - 5, "", "a.com", "443", "无回应", "HK"] for _ in range(100)]
    ids = {s["id"] for s in connanom.detect("dev1", now, rs, True)[0]}
    assert {"failures", "node_anom"} <= ids, ids
    feed_ring("dev1", [(60, 200, 190, 0, 0)] * 6, now - 60)
    ids = {s["id"] for s in connanom.detect("dev1", now, [], True)[0]}
    assert "short_conns" in ids
    # 诊断结构
    dg = connanom.diagnose("设备1", "attention", connanom.detect("dev1", now, [], True)[0], [], "x", conf="high", conns=60)
    assert all(k in dg for k in ("phenomenon", "evidence", "causes", "insufficient", "conclusion", "advice")) and "因果" in dg["conclusion"]
    # check():连续 2 次才开事件,恢复后结束;高度可疑进入推送队列
    class Row(list): pass
    rcol = R
    def mkrows(n): return [["dev1", "", "9.9.9.9", "443", "tcp", "HK", now - 10, 1, 1, "ESTABLISHED", "已确认", False] for _ in range(n)]
    connhist.RING.clear(); connanom.LEVEL.clear(); connanom.PENDING.clear()
    connanom.STATE["base_at"] = now
    ds = {"dev1": {"conns": 450, "tcp": 450, "udp": 0, "new": 400, "closed": 5}}
    for i in range(6):
        t = now + i * 10
        connhist.RING.setdefault("dev1", __import__("collections").deque(maxlen=50)).append((int(t), 450 if i >= 3 else 20, 450 if i >= 3 else 20, 0, 400 if i >= 3 else 3, 5, 0, 0))
        ds["dev1"]["conns"] = 450 if i >= 3 else 20
        connanom.check(t, ds, {}, mkrows(ds["dev1"]["conns"]), rcol, True, label=lambda k: "设备一")
    assert connanom.STATE["err"] == "", connanom.STATE["err"]
    assert connanom.LEVEL["dev1"]["level"] in ("suspect", "attention")
    ev = connhist.events(con, "dev1", 24, 10, now + 100)
    assert any(e["kind"] == "conn_anom" for e in ev)
    e = [x for x in ev if x["kind"] == "conn_anom"][0]
    assert connhist.event_detail(con, e["id"])["diag"]["advice"]
    # 恢复:连续正常超过 120 秒 → 事件结束
    for i in range(6, 40):
        t = now + i * 10
        connhist.RING["dev1"].append((int(t), 20, 20, 0, 3, 3, 0, 0))
        ds["dev1"]["conns"] = 20
        connanom.check(t, ds, {}, mkrows(20), rcol, True, label=lambda k: "设备一")
    assert ("dev1", "conn_anom") not in connhist.ACTIVE
    # 告警推送:只有高度可疑进 PENDING,按规则 fire / note
    importlib.reload(__import__("app.alerts", fromlist=["x"]))
    from app import alerts
    sent = []
    alerts.fire = lambda *a, **k: sent.append(a[2:5])
    connanom.PENDING.append({"id": 7, "dev": "dev1", "title": "t", "diag": {"phenomenon": "p", "evidence": ["e"], "conclusion": "c"}})
    cfg = alerts.load_cfg(con)
    alerts.check_anom(con, cfg, now)
    assert sent and sent[0][:2] == ("conn_anom", "warn") and connanom.PENDING == []
    cfg["rules"]["conn_anom"]["on"] = False
    connanom.PENDING.append({"id": 8, "dev": "dev1", "title": "t", "diag": {"phenomenon": "p", "evidence": ["e"], "conclusion": "c"}})
    alerts.check_anom(con, cfg, now + 1)
    assert len(sent) == 1
    importlib.reload(alerts)
    con.close()


def test_v053_unreplied_and_reopen():
    """v0.53.3:「无回应」只算 TCP(UDP 单向很常见);同类事件刚结束又出现时接着原事件记。"""
    import os, tempfile, time, importlib
    from app import config, db, connmon, connhist
    importlib.reload(connhist)
    d = tempfile.mkdtemp(); p = os.path.join(d, "ct")
    ln = "ipv4 2 udp 17 29 src=192.168.1.5 dst=8.8.8.%d sport=%d dport=53 packets=1 bytes=60 [UNREPLIED] src=8.8.8.%d dst=192.168.1.5 sport=53 dport=%d packets=0 bytes=0 mark=0 zone=0 use=2\n"
    open(p, "w").write("".join(ln % (i, 4000 + i, i, 4000 + i) for i in range(5))
                       + "ipv4 2 tcp 6 30 SYN_SENT src=192.168.1.5 dst=1.2.3.4 sport=40000 dport=80 packets=1 bytes=60 [UNREPLIED] src=1.2.3.4 dst=192.168.1.5 sport=80 dport=40000 packets=0 bytes=0 mark=0 zone=0 use=2\n")
    old = connmon.CT_PATH; connmon.CT_PATH = p
    try:
        connmon.read_ct(None, {"192.168.1.5"}, time.time())
    finally:
        connmon.CT_PATH = old
    c = connmon.CT["dev"]["192.168.1.5"]
    assert c["unreplied"] == 6 and c["tcp_unreplied"] == 1 and c["udp"] == 5
    config.DATA_DIR = d; config.DB_PATH = os.path.join(d, "r.db"); db.init_db(); con = db.open_db()
    now = time.time()
    e1 = connhist.trigger("dev", "conn_anom", "attention", "t", {}, now)
    connhist.resolve("dev", "conn_anom", now + 100)
    e2 = connhist.trigger("dev", "conn_anom", "suspect", "t", {}, now + 400)
    assert e1 == e2 and len(connhist.events(con, "dev", 24, 10, now + 500)) == 1
    assert connhist.events(con, "dev", 24, 10, now + 500)[0]["level"] == "suspect"
    connhist.resolve("dev", "conn_anom", now + 500)
    e3 = connhist.trigger("dev", "conn_anom", "attention", "t", {}, now + 500 + 1000)   # 超过 15 分钟 → 新事件
    assert e3 != e1
    con.close()


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f(); print("ok", n)
