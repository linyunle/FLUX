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


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f(); print("ok", n)
