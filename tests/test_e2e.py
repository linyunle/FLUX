import json, os, sqlite3, subprocess, sys, tempfile, time, urllib.request, urllib.error
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import mock_mihomo
API_P, PROBE_P, WEB_P = 19090, 18999, 18099
mock_mihomo.start(API_P, PROBE_P)

data = tempfile.mkdtemp()
neigh = os.path.join(data, "neigh.txt")
open(neigh, "w").write("192.168.1.10 dev br lladdr aa:bb:cc:dd:ee:01 REACHABLE\nfd00::10 dev br lladdr aa:bb:cc:dd:ee:01 STALE\n192.168.1.20 dev br lladdr aa:bb:cc:dd:ee:02 REACHABLE\n")
# 旧 v1 库:client 是 IP,hourly 没有设备/节点
today = time.strftime("%Y-%m-%d")
con = sqlite3.connect(os.path.join(data, "traffic.db"))
con.executescript("""CREATE TABLE traffic(day TEXT,client TEXT,node TEXT,host TEXT,up INTEGER,down INTEGER,PRIMARY KEY(day,client,node,host)) WITHOUT ROWID;
CREATE TABLE hourly(hour TEXT PRIMARY KEY,up INTEGER,down INTEGER) WITHOUT ROWID;
CREATE TABLE ipmap(ip TEXT PRIMARY KEY, mac TEXT NOT NULL, seen INTEGER NOT NULL) WITHOUT ROWID;""")
con.execute("INSERT INTO traffic VALUES(?,?,?,?,?,?)", (today, "192.168.1.10", "HK-01", "old.example", 111, 222))
con.execute("INSERT INTO ipmap VALUES('192.168.1.10','aa:bb:cc:dd:ee:01',?)", (int(time.time()),))
con.commit(); con.close()

env = dict(os.environ, DATA_DIR=data, NIKKI_API=f"http://127.0.0.1:{API_P}", NIKKI_SECRET="wrong", INTERVAL_SEC="2", FLUSH_SEC="2",
           LISTEN_HOST="127.0.0.1", LISTEN_PORT=str(WEB_P), NEIGH_FILE=neigh, PROBE_PORT=str(PROBE_P), EGRESS_INTERVAL_H="0",
           EGRESS_ECHO_URL="http://echo.test/ip", APP_VERSION="v0.2.0", GITHUB_REPO="")
proc = subprocess.Popen([sys.executable, "-m", "app"], cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
B = f"http://127.0.0.1:{WEB_P}"


def get(p):
    return json.load(urllib.request.urlopen(B + p, timeout=5))


def post(p, body, origin=None):
    h = {"Content-Type": "application/json"}
    if origin: h["Origin"] = origin
    try:
        return 200, json.load(urllib.request.urlopen(urllib.request.Request(B + p, json.dumps(body).encode(), h), timeout=15))
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def ok(c, msg):
    print(("PASS " if c else "FAIL ") + msg)
    if not c: raise SystemExit(1)

try:
    for _ in range(40):
        try: get("/api/status"); break
        except Exception: time.sleep(0.25)
    time.sleep(3)
    st = get("/api/status")
    ok(not st["conn"]["ok"] and "401" in st["conn"]["error"], "错误密码时状态显示 401")
    ok(post("/api/config", {"api": f"http://127.0.0.1:{API_P}", "secret": "bad"})[0] == 400, "设置页:错误密码被拒绝且不保存")
    ok(post("/api/config", {"api": f"http://127.0.0.1:{API_P}", "secret": "s3cret"}, origin="http://evil.example")[0] == 403, "跨站 POST 被拒")
    c, r = post("/api/config", {"api": f"http://127.0.0.1:{API_P}", "secret": "s3cret"})
    ok(c == 200 and r["version"] == "v1.19.0-mock", "设置页:正确密码验证并保存")
    cp = os.path.join(data, "config.json")
    ok(oct(os.stat(cp).st_mode & 0o777) == "0o600", "config.json 权限 0600")
    time.sleep(9)  # 基线 + 几轮增量 + flush
    st = get("/api/status"); ok(st["conn"]["ok"], "改密码后自动重连成功(无需重启)")
    ok("s3cret" not in json.dumps(st), "status 不泄露密码")
    s = get("/api/summary?by=client")
    keys = {r["key"]: r for r in s["rows"]}
    ok("aa:bb:cc:dd:ee:01" in keys and not any(k in keys for k in ("192.168.1.10", "fd00::10")), "IPv4+IPv6 合并成同一设备(含旧库里的 IP 行)")
    d1 = keys["aa:bb:cc:dd:ee:01"]
    ok(d1["up"] > 111 and sorted(i for i in d1["ips"]) == ["192.168.1.10", "fd00::10"], f"设备流量累加,IP 列表正确 {d1['ips']}")
    ok(get("/api/summary?by=host&q=netflix")["rows"][0]["key"] == "netflix.com", "目标搜索")
    ok(all("api.ip.sb" != r["key"] for r in get("/api/summary?by=host")["rows"]), "探测连接不计入统计")
    ok(get("/api/summary?by=client&dev=aa:bb:cc:dd:ee:02")["rows"][0]["key"] == "aa:bb:cc:dd:ee:02", "按设备筛选")
    g = get("/api/summary?by=group")["rows"]; ok("Proxy" in {r["key"] for r in g}, "策略组维度")
    ru = get("/api/summary?by=rule&group=Proxy")["rows"]; ok(ru and ru[0]["key"] == "RuleSet", "规则维度 + 策略组钻取")
    m = get("/api/modes")["modes"]; ok(m["proxy"]["down"] > 0 and m["direct"]["down"] > 0, "代理/直连分流")
    ok(not any(r["key"] == "aa:bb:cc:dd:ee:02" for r in get("/api/summary?by=client&mode=proxy")["rows"]), "走代理里不含「直连」节点的流量")
    nr = sqlite3.connect(os.path.join(data, "traffic.db")).execute("SELECT type, remote FROM nodeinfo WHERE node='直连'").fetchone()
    ok(nr and nr[0].lower() == "direct" and not nr[1], "直连节点只记类型,不记目标地址")
    ok(get("/api/summary?by=client&mode=direct")["rows"][0]["key"] == "aa:bb:cc:dd:ee:02", "模式筛选")
    h = get("/api/hours?hours=3&dev=aa:bb:cc:dd:ee:01")["hours"]; ok(len(h) == 3 and sum(x["down"] for x in h) > 0, "小时趋势 + 设备筛选")
    dd = get("/api/days?days=3")["days"]; ok(len(dd) == 3 and dd[-1]["down"] > 0, "按天趋势补零")
    # 实时速度 + 节点
    rt = get("/api/realtime"); ok(rt["ok"] and len(rt["samples"]) >= 3 and rt["now"]["down"] >= 5000, f"实时速度流 {len(rt['samples'])} 个点")
    ok(any(d["key"] == "aa:bb:cc:dd:ee:01" for d in rt["devices"]), "实时:活跃设备")
    gr = {r["key"]: r for r in get("/api/summary?by=group")["rows"]}
    ok(gr["Proxy"]["nodes"][0]["node"] == "HK-01" and gr["国内"]["nodes"][0]["node"] == "直连", "策略组实际走的节点")
    rr = get("/api/summary?by=rule&group=Proxy")["rows"]; ok(rr[0]["nodes"][0]["node"] == "HK-01", "规则实际走的节点")
    # 域名清单
    dm = {r["key"]: r for r in get("/api/domains")["rows"]}
    ok({"googlevideo.com", "quark.cn", "youtube.com", "netflix.com", "baidu.com"} <= set(dm), f"域名合并子域名 {sorted(dm)}")
    ok(dm["googlevideo.com"]["subs"] == 2 and dm["googlevideo.com"]["direct"] == 0, "googlevideo 两个子域名合并,去向是代理")
    ok(dm["quark.cn"]["direct"] == dm["quark.cn"]["up"] + dm["quark.cn"]["down"] > 0, "quark.cn 走「直连」节点 → 去向直连")
    raw = {r["key"] for r in get("/api/domains?merge=0")["rows"]}
    ok({"r1.googlevideo.com", "r2.googlevideo.com", "dl.drive.quark.cn"} <= raw, "不合并时显示完整主机名")
    d2 = get("/api/domains?dev=aa:bb:cc:dd:ee:02")["rows"]
    ok({r["key"] for r in d2} == {"baidu.com", "quark.cn"} and all(r["ndev"] == 1 for r in d2), "域名清单按设备筛选")
    ok(all(r["key"] == "quark.cn" for r in get("/api/domains?q=quark")["rows"]), "域名清单搜索")
    ok(dm["youtube.com"]["devs"][0]["key"] == "aa:bb:cc:dd:ee:01", "域名的访问设备")
    # 命名
    ok(post("/api/device", {"dev": "aa:bb:cc:dd:ee:01", "name": "小林的手机"})[0] == 200, "改名")
    ok(post("/api/devices/import", {"text": "dhcp.@host[0]=host\ndhcp.@host[0].name='nas'\ndhcp.@host[0].mac='aa:bb:cc:dd:ee:02'"})[0] == 200, "导入 uci 静态绑定")
    names = {r["key"]: r["name"] for r in get("/api/summary?by=client")["rows"]}
    ok(names["aa:bb:cc:dd:ee:01"] == "小林的手机" and names["aa:bb:cc:dd:ee:02"] == "nas", "名字生效")
    ok(post("/api/devices/import", {"text": "garbage"})[0] == 400, "无效导入给出错误")
    # 出口
    e = get("/api/egress"); ok(e["ready"]["ok"], "探测前提检查通过")
    ok({r["node"]: r["delay"] for r in e["rows"] if r["kind"] == "proxy"} == {"HK-01": 88, "JP-01": 0}, "节点延迟(0=超时)")
    ok({r["node"]: r["kind"] for r in e["rows"]}.get("直连") == "direct", "名叫「直连」的 Direct 节点被识别为直连")
    c, r = post("/api/egress/probe", {}); ok(c == 200 and r["ok"], "开始探测")
    time.sleep(3)
    e = get("/api/egress"); eg = {r["node"]: r.get("egress") for r in e["rows"]}
    ok(eg["HK-01"]["ip"] == "203.0.113.5" and eg["HK-01"]["org"] == "HKT", "HK 出口 IP/运营商(ip.sb 格式)")
    ok(eg["JP-01"]["ip"] == "198.51.100.7" and eg["JP-01"]["org"] == "IIJ" and eg["JP-01"]["asn"] == "2497", "JP 出口(ipwho 格式)")
    ok(mock_mihomo.STATE["probe_sel"] == "HK-01", "探测完还原探测组原选择")
    # 旧库迁移
    ok(sqlite3.connect(os.path.join(data, "traffic.db")).execute("PRAGMA user_version").fetchone()[0] == 3, "数据库升到 v3,旧数据保留")
    ok(urllib.request.urlopen(B + "/").read().startswith(b"<!doctype html>"), "首页可访问")
    ok(urllib.request.urlopen(B + "/health").read() == b"ok", "/health")
finally:
    proc.terminate()
    try: out = proc.communicate(timeout=5)[0]
    except Exception: out = ""
    print("---- 服务日志 ----\n" + out[-1500:])
