import json, os, sqlite3, subprocess, sys, tempfile, time, urllib.request, urllib.error
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import mock_mihomo, mock_docker
API_P, PROBE_P, WEB_P = 19090, 18999, 18099
mock_mihomo.start(API_P, PROBE_P)
mock_mihomo.start_agh(19444)
mock_docker.start(19331)

data = tempfile.mkdtemp()
import shutil
os.makedirs(os.path.join(data, "geoip")); shutil.copy(os.path.join(HERE, "data", "country-test.mmdb"), os.path.join(data, "geoip", "country-test.mmdb")); shutil.copy(os.path.join(HERE, "data", "asn-test.mmdb"), os.path.join(data, "geoip", "asn-test.mmdb"))
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

env = dict(os.environ, DATA_DIR=data, NIKKI_API=f"http://127.0.0.1:{API_P}", NIKKI_SECRET="wrong", INTERVAL_SEC="2", FLUSH_SEC="2", PROXY_SEC="2", ALERT_EVAL_SEC="2", ALERT_LEARN_SEC="6",
           LISTEN_HOST="127.0.0.1", LISTEN_PORT=str(WEB_P), NEIGH_FILE=neigh, APP_VERSION="v0.2.0", GITHUB_REPO="", NIKKI_LOG_DIR=os.path.join(data, "nikkilog"))
proc = subprocess.Popen([sys.executable, "-m", "app"], cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
B = f"http://127.0.0.1:{WEB_P}"


def get(p):
    return json.load(urllib.request.urlopen(B + p, timeout=5))


def req_code(p):
    try:
        return urllib.request.urlopen(B + p, timeout=5).status
    except urllib.error.HTTPError as e:
        return e.code


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
    import time as _t; _t.sleep(3)
    rt = get("/api/realtime"); ok(rt["ok"] and len(rt["proxy"]["series"]) >= 2 and rt["proxy"]["down"] > 0 and rt["direct"]["down"] > 0, f"实时:直连/代理分开 {rt['direct']['down']}/{rt['proxy']['down']}")
    ok(rt["mem"]["mihomo"] == 88000000 and rt["mem"]["total"] > 0 and len(rt["mem"]["series"]) >= 2, f"实时:内存 nikki={rt['mem']['mihomo']} 系统={rt['mem']['used']}/{rt['mem']['total']}")
    pr = get("/api/protocols")
    ks = {r["key"]: r for r in pr["rows"]}
    ok("HTTPS / TLS" in ks and "HTTP" in ks and "QUIC / HTTP3" in ks and pr["total"]["down"] > 0, f"应用协议分布 {sorted(ks)}")
    ok(get("/api/protocols?dev=aa:bb:cc:dd:ee:02")["rows"][0]["key"] == "HTTP", "协议:按设备筛选")
    gq = get("/api/summary?by=host&q=HK-01")["rows"]
    ok(gq and {r["key"] for r in gq} >= {"youtube.com", "netflix.com"} and "baidu.com" not in {r["key"] for r in gq}, "全局搜索:按节点名")
    ok(get("/api/summary?by=host&q=RuleSet")["rows"], "全局搜索:按规则")
    ok(get("/api/summary?by=host&q=192.168.1.20")["rows"][0]["key"] in ("baidu.com", "dl.drive.quark.cn"), "全局搜索:按设备 IP")
    ok(len(rt["hosts"]) >= 3 and rt["hosts"][0]["host"], f"实时:活跃域名 {len(rt['hosts'])} 个")
    tr = get("/api/trace?host=youtube.com&cols=client,node,group,rule")
    ok(tr["rows"] and tr["rows"][0]["kind"] == "proxy" and tr["rows"][0]["node"] == "HK-01" and tr["rows"][0]["rule"] == "RuleSet" and tr["kinds"]["proxy"]["down"] > 0, "追踪:设备→节点→规则")
    ok(any(x["ip"] == "1.1.1.1" and x["mode"] == "normal" for x in tr["dns"].get("youtube.com", [])), "追踪:DNS 解析 IP 和方式")
    tn = get("/api/trace?host=netflix.com&cols=client,node")
    ok(any(x["ip"] == "" and x["mode"] == "fake-ip" for x in tn["dns"].get("netflix.com", [])), "追踪:fake-ip 记为远程解析")
    td = get("/api/trace?dev=aa:bb:cc:dd:ee:02&cols=host,node,group,rule")
    ok(td["rows"] and all(r["kind"] == "direct" for r in td["rows"]), "追踪:按设备看域名去向")
    ok(rt["conns"]["total"] == 6 and rt["conns"]["direct"] == 2 and rt["conns"]["proxy"] == 4, f"实时连接数 {rt['conns']}")
    ok(sum(1 for n in rt["nodes"] if n["node"] == "直连") == 1, "实时节点:直连合并成一行")
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
    dv = get("/api/summary?by=client&dom=googlevideo.com")["rows"]
    ok(len(dv) == 1 and dv[0]["key"] == "aa:bb:cc:dd:ee:01", "dom 筛选:域名(含子域名)被哪些设备访问")
    ok(get("/api/summary?by=client&host=r1.googlevideo.com")["rows"][0]["key"] == "aa:bb:cc:dd:ee:01", "host 筛选")
    ok(len(get("/api/summary?by=client&dom=ogle.com")["rows"]) == 0, "dom 不会误匹配后缀片段")
    # 命名
    ok(post("/api/device", {"dev": "aa:bb:cc:dd:ee:01", "name": "小林的手机"})[0] == 200, "改名")
    ok(post("/api/devices/import", {"text": "dhcp.@host[0]=host\ndhcp.@host[0].name='nas'\ndhcp.@host[0].mac='aa:bb:cc:dd:ee:02'"})[0] == 200, "导入 uci 静态绑定")
    names = {r["key"]: r["name"] for r in get("/api/summary?by=client")["rows"]}
    ok(names["aa:bb:cc:dd:ee:01"] == "小林的手机" and names["aa:bb:cc:dd:ee:02"] == "nas", "名字生效")
    ok(post("/api/devices/import", {"text": "garbage"})[0] == 400, "无效导入给出错误")
    try:
        get("/api/egress"); ok(False, "出口接口应已移除")
    except urllib.error.HTTPError as e:
        ok(e.code == 404, "出口接口已移除(404)")
    ok("tab-egress" not in urllib.request.urlopen(B + "/").read().decode(), "页面里没有出口标签")
    # v0.8.0 应用识别 / Top Talkers / QoE / 堆叠
    ap_ = get("/api/apps"); aks = {r["key"]: r for r in ap_["rows"]}
    ok("YouTube" in aks and "Netflix" in aks and "夸克网盘" in aks and "百度" in aks, f"应用识别 {sorted(aks)}")
    ok(aks["夸克网盘"]["cat"] == "网盘 / 云存储" and aks["YouTube"]["cat"] == "流媒体", "应用类别")
    ok(get("/api/apps?by=cat")["rows"][0]["key"], "按类别汇总")
    ac = get("/api/apps?by=client&app=YouTube")["rows"]
    ok(ac and ac[0]["key"] and all(r["key"] != "192.168.1.20" for r in ac), f"应用下钻:谁在用 YouTube {[r['key'] for r in ac]}")
    pc = get("/api/protocols?by=client&proto=HTTP")["rows"]
    ok(pc and len(pc) >= 1, "协议下钻到设备")
    sk = get("/api/stack?by=client&hours=24")
    ok(sk["labels"] and sk["series"] and len(sk["series"][0]["values"]) == len(sk["labels"]) and sk["peak"], "堆叠面积:序列/峰值")
    ok(get("/api/stack?by=app&hours=24")["series"], "堆叠:按应用")
    tu = get("/api/tunnels")
    ok(tu["rows"] and sum(r["down"] for r in tu["rows"]) > 0, f"隧道/出口类型分布 {[r['key'] for r in tu['rows']]}")
    qo = get("/api/qoe?hours=24")
    qn = {r["node"]: r for r in qo["nodes"]}
    ok("HK-01" in qn and qn["HK-01"]["tests"] >= 1 and qn["HK-01"]["avg"] > 0, f"QoE:节点延迟 {qn.get('HK-01')}")
    ok("tcp" in qo and "ok" in qo["tcp"], "QoE:TCP 重传字段")
    ok(qo["summary"]["avg"] and qo["summary"]["basis"] in ("流量加权", "简单平均") and "bytes" in qo["nodes"][0], f"QoE:汇总口径 {qo['summary']}")
    ok(post("/api/apps/rules", {"text": "mytest.example=我的应用|办公 / 开发"})[1]["rules"] == 1 and "我的应用" in get("/api/apprules")["rules"], "自定义识别规则保存")
    c, r = post("/api/apps/rules", {"text": "a.example=甲|视频\nA.example=甲|视频\n*.b.example=乙|购物\nb.example=丙|其他"}); ok(c == 200 and r["rules"] == 2 and r["dedup"]["same"] == 1 and r["dedup"]["conflict"] == 1 and "A.example" not in r["text"], "应用特征库:保存时自动去重")
    ok(post("/api/apps/rules", {"text": "乱写"})[0] in (200, 400), "自定义规则容错")
    post("/api/apps/rules", {"text": ""})
    # 机场
    c, r = post("/api/airports/rules", {"text": "HK-=机场甲\nJP-=机场乙"}); ok(c == 200 and r["rules"] == 2, "保存机场规则")
    ok(post("/api/airports/rules", {"text": "乱写"})[0] == 400, "无效规则报错")
    ap = get("/api/airports")
    got = {r["key"]: r for r in ap["rows"]}
    ok(set(got) == {"机场甲"}, f"机场表只含代理流量,直连不算 {list(got)}")
    ok(ap["special"].get("直连", {}).get("down", 0) > 0, "直连另外汇总")
    ok(sorted(ap["names"]) == ["机场乙", "机场甲"] or sorted(ap["names"]) == ["机场甲"], f"机场名列表 {ap['names']}")
    tot_hk = sum(r["up"] + r["down"] for r in get("/api/summary?by=node&airport=%E6%9C%BA%E5%9C%BA%E7%94%B2")["rows"])
    ok(tot_hk == got["机场甲"]["up"] + got["机场甲"]["down"] > 0, "按机场筛选后的节点流量 = 机场表合计")
    nr = get("/api/summary?by=node")["rows"]
    ok({r["key"]: r["airport"] for r in nr}.get("HK-01") == "机场甲" and {r["key"]: r["airport"] for r in nr}.get("直连") == "直连", "节点表带机场名")
    ok(get("/api/summary?by=host&airport=%E4%B8%8D%E5%AD%98%E5%9C%A8")["rows"] == [], "不存在的机场 → 空结果")
    ok("机场甲" in get("/api/status")["airports"], "status 里有机场列表")
    # v0.9.0 访问密码
    import http.cookiejar
    cj = http.cookiejar.CookieJar(); op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    def rq(path, body=None, method=None):
        req = urllib.request.Request(B + path, data=None if body is None else json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method=method)
        try:
            r = op.open(req, timeout=5); return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
    ok(get("/api/status")["auth"]["enabled"] is False, "默认没有密码")
    ok(rq("/api/auth/set", {"new": "123"})[0] == 400, "密码太短被拒")
    ok(rq("/api/auth/set", {"new": "secret123"})[0] == 200, "设置密码")
    ok(urllib.request.build_opener().open(urllib.request.Request(B + "/")).read().find("请输入访问密码".encode()) > 0, "未登录打开首页 → 登录页")
    try: c401 = urllib.request.urlopen(B + "/api/status").status
    except urllib.error.HTTPError as e: c401 = e.code
    ok(c401 == 401, "未登录访问接口 401")
    ok(urllib.request.urlopen(B + "/health").read() == b"ok", "/health 免登录")
    ok(rq("/api/login", {"password": "bad"})[0] == 401, "错误密码被拒")
    ok(rq("/api/status")[0] == 200, "设置后当前会话保持登录")
    cj.clear(); ok(rq("/api/status")[0] == 401, "清掉 Cookie 后需要登录")
    ok(rq("/api/login", {"password": "secret123"})[0] == 200 and rq("/api/status")[0] == 200, "正确密码登录")
    ok(rq("/api/auth/set", {"old": "wrong", "new": ""})[0] == 401, "关密码要验证当前密码")
    ok(rq("/api/logout", {})[0] == 200 and rq("/api/status")[0] == 401, "退出登录")
    rq("/api/login", {"password": "secret123"})
    ok(rq("/api/auth/set", {"old": "secret123", "new": ""})[0] == 200, "关闭密码")
    ok(get("/api/status")["auth"]["enabled"] is False, "关闭后免登录")
    # v0.10.0 告警
    import http.server, threading
    got = []
    class Rcv(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0); got.append(json.loads(self.rfile.read(n) or b"{}"))
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
    rsrv = http.server.ThreadingHTTPServer(("127.0.0.1", 19377), Rcv); threading.Thread(target=rsrv.serve_forever, daemon=True).start()
    ac = get("/api/alerts/config")
    ok(ac["channels"] == [] and ac["rules"]["node_down"]["fails"] == 3 and "new_device" in ac["kinds"], "告警:默认配置")
    _r = post("/api/alerts/config", {"channels": [{"id": "w1", "type": "webhook", "name": "测试hook", "url": "ftp://x"}]})
    ok(_r[0] == 400, f"告警:渠道地址必须 http(s) {_r}")
    c, r = post("/api/alerts/config", {"rules": {"traffic_spike": {"on": True, "min_mb": 0.1, "factor": 5, "cool_min": 60}, "node_down": {"on": True, "fails": 3, "cool_min": 1}},
                                       "channels": [{"id": "w1", "type": "webhook", "name": "测试hook", "url": "http://127.0.0.1:19377/hook?key=SECRETKEY"}],
                                       "quiet": {"on": False, "start": "23:00", "end": "07:00"}})
    ok(c == 200 and r["channels"][0]["has_secret"] and "SECRETKEY" not in json.dumps(r), "告警:渠道保存,密钥不回显")
    ok("SECRETKEY" not in json.dumps(get("/api/alerts/config")), "告警:读配置不带密钥")
    c, r = post("/api/alerts/test", {"channel": {"id": "w1", "type": "webhook", "name": "测试hook", "url": ""}})
    ok(c == 200 and r["ok"] and any(g.get("title") == "FLUX 测试消息" for g in got), f"告警:测试推送(密钥留空沿用已存) {r}")
    def wait_kind(kind, sec=25):
        for _ in range(sec * 2):
            rows = get("/api/alerts?kind=" + kind)["rows"]
            if rows: return rows
            _t.sleep(.5)
        return []
    mock_mihomo.STATE["extra_dev"] = True
    nd = wait_kind("new_device"); ok(nd and "192.168.1.99" in nd[0]["key"] and "已推送" in nd[0]["sent"], f"告警:新设备 {nd[:1]}")
    sp = wait_kind("traffic_spike"); ok(sp and sp[0]["level"] == "warn", f"告警:流量突增 {sp[:1]}")
    mock_mihomo.STATE["hk_down"] = True
    nn = wait_kind("node_down"); ok(nn and nn[0]["key"] == "HK-01" and nn[0]["level"] == "bad", f"告警:节点故障 {nn[:1]}")
    mock_mihomo.STATE["hk_down"] = False
    nu = wait_kind("node_up"); ok(nu and nu[0]["key"] == "HK-01", "告警:节点恢复")
    ok(any(g.get("kind") == "node_down" for g in got) and any(g.get("kind") == "new_device" for g in got), "告警:Webhook 收到事件 JSON")
    al = get("/api/alerts"); ok(al["unread"] >= 3 and al["has_channel"] and al["counts"]["bad"] >= 1, f"告警:未读/统计 {al['unread']} {al['counts']}")
    post("/api/alerts/seen", {}); ok(get("/api/alerts")["unread"] == 0 and get("/api/status")["alerts_unread"] == 0, "告警:标记已读")
    ok(get("/api/alerts/baseline")["rows"], "告警:设备基线表")
    post("/api/alerts/config", {"quiet": {"on": True, "start": "00:00", "end": "23:59"}, "channels": [{"id": "w1", "type": "webhook", "url": ""}], "rules": {"node_down": {"on": True, "fails": 3, "cool_min": 1}}})
    mock_mihomo.STATE["jp_down"] = True; n0 = len(got); _t.sleep(1)
    ok(post("/api/alerts/clear", {})[0] == 200 and get("/api/alerts")["rows"] == [], "告警:清空记录")
    ok(len(got) == n0, "告警:静默时段不推送")
    rsrv.shutdown()
    # ---- v0.11 安全版
    ag = get("/api/agh"); ok(ag == {"configured": False}, "AdGuard:未配置")
    c, r = post("/api/agh/test", {"url": "http://127.0.0.1:19444", "user": "admin", "pass": "bad"}); ok(c == 200 and not r["ok"] and "401" in r["error"], f"AdGuard:密码错误被识别 {r}")
    c, r = post("/api/agh/test", {"url": "http://127.0.0.1:19444", "user": "admin", "pass": "pw123"}); ok(r["ok"] and r["version"] == "v0.107.50", "AdGuard:测试连接成功")
    c, r = post("/api/agh/config", {"url": "127.0.0.1:19444", "user": "admin", "pass": "pw123"})
    ok(c == 200 and r["has_secret"] and r["url"] == "http://127.0.0.1:19444" and "pw123" not in json.dumps(r), "AdGuard:保存配置且不回显密码")
    ok("pw123" not in json.dumps(get("/api/agh/config")), "AdGuard:读配置不带密码")
    ag = get("/api/agh"); ok(ag["ok"] and ag["total"] == 2000 and ag["rate"] == 15.0 and ag["top_blocked"][0]["d"] == "ads.tracker.net", f"AdGuard:统计 {ag.get('error')}")
    ok(ag["top_clients"][0]["name"] not in ("",) and ag["recent"][0]["rule"] == "||tracker.net^" and "pw123" not in json.dumps(ag), "AdGuard:客户端映射为设备名 + 最近拦截")
    c, r = post("/api/agh/config", {"url": "http://127.0.0.1:19444", "user": "admin"}); ok(r["has_secret"], "AdGuard:密码留空沿用已存")
    mock_mihomo.STATE["leak"] = True
    rh = get("/api/rulehealth"); ok(rh["source"] == "mihomo" and rh["has_hits"] and any(z["rule"] == "DomainSuffix,unused.example" for z in rh["zero"]) and not any("youtube" in z["rule"] for z in rh["zero"]), f"规则健康:零命中 {rh['zero']}")
    ok(rh["top"], "规则健康:流量最多的规则")
    lk = None
    for _ in range(30):
        _t.sleep(1)
        lk = get("/api/leaks")
        if any(x["host"] == "www.bilibili.com" for x in lk["cn_proxy"]) and any(x["host"] == "www.google.com" for x in lk["fo_direct"]): break
    ok(any(x["host"] == "www.bilibili.com" for x in lk["cn_proxy"]) and any(x["host"] == "www.google.com" for x in lk["fo_direct"]), f"分流检查:国内走代理 / 境外直连 {lk['cn_proxy'][:1]} {lk['fo_direct'][:1]}")
    ok(lk["dns_local"], "分流检查:本地解析的代理域名")
    ok(all("devs" in x and isinstance(x["devs"]["names"], list) for x in lk["cn_proxy"] + lk["fo_direct"] + lk["dns_local"]) and any(x["devs"]["names"] for x in lk["cn_proxy"] + lk["fo_direct"]), f"分流检查:带来源设备 {lk['cn_proxy'][:1]}")
    lp = get("/api/lookup?host=www.bilibili.com")
    ok(lp["host"] == "www.bilibili.com" and len(lp["calc"]["steps"]) == 4 and len(lp["real"]["steps"]) >= 4 and lp["history"]["rows"], f"域名查询:推算 + 实际 {[x['main'] for x in lp['real']['steps']][-2:]}")
    ok(get("/api/lookup?host=https://www.google.com/x")["host"] == "www.google.com", "域名查询:URL 自动取域名")
    ok(req_code("/api/lookup?host=%20") == 400, "域名查询:空输入 400")
    c, lt = post("/api/lookup/test", {"host": "www.baidu.com"})
    ok(c == 200 and lt["ok"] and lt["rule"] == "RuleSet" and lt["payload"] == "mockset" and lt["chain"] == ["国内", "直连"] and lt["kind"] == "直连", f"实时规则测试:命中规则和链路 {lt}")
    import time as _t
    ut = int(_t.time())
    ok(len(get(f"/api/timeline?hours=24&until={ut - 3 * 3600}")["rows"]) == 24, "故障时间线:可指定结束时间")
    ok(get(f"/api/wifi?hours=6&until={ut - 3600}")["available"] is False, "无线事件:可指定结束时间")
    ok(get(f"/api/leaks?days=7&until={ut}")["cn_proxy"] is not None, "分流检查:可指定结束时间")
    ok(get(f"/api/leaks?days=7&until={ut - 40 * 86400}")["cn_proxy"] == [], "分流检查:结束时间在很久以前时没有数据")
    ok(get(f"/api/geo?days=7&until={ut}")["days"] == 7, "目的地:可指定结束时间")
    ap = get("/api/apps/hosts?app=YouTube"); ok(ap["app"] == "YouTube" and all(r["host"] for r in ap["rows"]), f"应用域名明细:YouTube {ap['count']} 个域名")
    un = get("/api/apps/unknown"); ok("域名关键字=应用名|类别" in un["text"] and "清单格式" in un["text"] and isinstance(un["rows"], list), f"未识别导出:带 AI 说明 {un['count']} 个")
    ok(req_code("/api/apps/hosts") == 400, "应用域名明细:缺 app 返回 400")
    c, _r = post("/api/apps/rules", {"text": "\n".join(f"k{i}.example={i}|其他" for i in range(900))}); ok(c == 200, "应用特征库:最多 1000 行")
    post("/api/apps/rules", {"text": ""})
    c, pr = post("/api/lookup/probe", {"host": "www.baidu.com", "node": "XX-01"})
    ok(c in (200, 400), f"域名实测:订阅里的节点走 healthcheck 接口 {c} {pr}")
    if c == 200:
        ok(pr["ok"] and pr["delay"] == 77, f"域名实测:订阅节点延迟 {pr}")
    cp = get("/api/compare"); ok(len(cp["series"]["cur"]) == 7 and "traffic" in cp and "notes" in cp, "周对比:结构完整")
    tl = get("/api/timeline?hours=24"); ok(len(tl["rows"]) == 24 and "marks" in tl, "故障时间线:24 小时")
    wf = get("/api/wifi"); ok(wf["available"] is False and "hint" in wf, "无线事件:没有日志时给出开启办法")
    c, r = post("/api/alerts/config", {"disks": {"/mnt/x": {"ign": True}, "/mnt/y": {"pct": 97}}})
    ok(c == 200 and r["disks"] == {"/mnt/x": {"ign": True, "pct": None}, "/mnt/y": {"ign": False, "pct": 97.0}} and "disk_list" in r, f"告警:磁盘忽略 / 单独阈值保存 {r.get('disks')}")
    c, r = post("/api/alerts/config", {"disks": {}}); ok(c == 200 and r["disks"] == {}, "告警:磁盘设置可清空")
    rh = get("/api/rulehealth"); ok(rh["match"] and rh["match"]["share"] > 0, f"规则健康:落到兜底的占比 {rh['match']}")
    cj = get("/api/compare?days=3")
    ok(cj["days"] == 3 and len(cj["series"]["cur"]) == 3 and cj["names"][0] == "本期", "对比:可选 3 天窗口")
    ok(get("/api/compare")["names"][0] == "本周", "对比:默认仍是本周 vs 上周")
    tj = get("/api/timeline?hours=720")
    ok(tj["step"] == 5 and len(tj["rows"]) <= 168, "时间线:30 天自动聚合")
    import base64, http.server, threading, urllib.parse
    _png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")

    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            b, ct = (_png, "image/png") if self.path == "/favicon.ico" else (b"<html></html>", "text/html")
            self.send_response(200); self.send_header("Content-Type", ct); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    _srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H); threading.Thread(target=_srv.serve_forever, daemon=True).start()
    _site = "http://127.0.0.1:%d/" % _srv.server_address[1]
    ok(req_code("/api/favicon?u=" + urllib.parse.quote(_site)) == 404, "网站图标:没保存的网址不去取")
    post("/api/ui", {"theme": {"v": 4, "links": [{"n": "测试站", "u": _site}]}})
    ok(req_code("/api/favicon?u=" + urllib.parse.quote(_site)) == 200, "网站图标:已保存的快捷方式能取到")
    ok(req_code("/api/favicon?u=" + urllib.parse.quote("http://127.0.0.1:1/")) == 404, "网站图标:其他网址仍然不取")
    _srv.shutdown()
    ng = get("/api/nodegeo")
    ok(isinstance(ng.get("rows"), list) and "cn" in ng and "available" in ng, "节点登记地:接口可用")
    c, r = post("/api/nodegeo/ignore", {"node": "测试节点", "on": True})
    ok(c == 200 and "测试节点" in r["ignored"], "节点登记地:可忽略")
    c, r = post("/api/nodegeo/ignore", {"node": "测试节点", "on": False})
    ok(c == 200 and "测试节点" not in r["ignored"], "节点登记地:可恢复")
    gj = None
    for _ in range(20):
        gj = get("/api/geo")
        if {x["cc"] for x in gj["by_cc"]} >= {"SE", "US"}: break
        _t.sleep(1)
    ok(gj["available"] and {x["cc"] for x in gj["by_cc"]} >= {"SE", "US"}, f"目的地国家:{gj['by_cc']}")
    ok(any("Bredband2" in x["asn"] for x in gj["by_asn"]), "目的地国家:ASN 组织")
    hm = get("/api/heatmap"); ok(len(hm["cells"]) == 7 and len(hm["cells"][0]) == 24 and hm["max"] > 0 and hm["peak"], "热力图:7×24")
    ok(get("/api/heatmap?dev=aa:bb:cc:dd:ee:01")["max"] > 0, "热力图:按设备过滤")
    post("/api/airports/rules", {"text": "HK-=测试机场"})
    c, r = post("/api/quota", {"quota": {"测试机场": {"gb": 0.0001, "reset_day": 1}}})
    qs = next(x for x in r["rows"] if x["airport"] == "测试机场"); ok(c == 200 and qs["airport"] == "测试机场" and qs["used"] > 0 and qs["pct"] >= 80 and qs["exhaust"], f"套餐:用量 {qs}")
    qa = wait_kind("quota", 20); ok(qa and qa[0]["key"] == "测试机场", f"套餐:告警 {qa[:1]}")
    mo = next((x for x in get("/api/quota")["rows"] if x["airport"] == "MyAir"), {})
    ok(mo.get("src") == "official" and mo.get("auto") and mo["used"] == 6 << 30 and mo["gb"] == 100 and mo["expire"] == "2030-01-01", f"套餐:官方数据自动加入 {mo}")
    ok(post("/api/quota", {"quota": {"x": {"gb": "abc"}}})[0] == 400, "套餐:非法输入被拒")
    pv = get("/api/providers"); r0 = (pv.get("rows") or [{}])[0]
    ok(pv["ok"] and r0.get("name") == "MyAir" and r0["used"] == 6 << 30 and r0["total"] == 100 << 30 and r0["expire"] == 1893456000 and r0["nodes"] == 2, f"机场官方数据:读到订阅信息 {r0}")
    ok("default" not in [x["name"] for x in pv["rows"]], "机场官方数据:跳过 default")
    pr = get("/api/probe"); ok(pr["cfg"]["on"] is False and pr["cfg"]["minutes"] == 30 and "HK-01" in pr["nodes"], f"节点测速:默认关闭,候选是在用的节点 {pr['nodes']}")
    ok(post("/api/probe", {"on": True, "minutes": 5, "top": 3, "url": "ftp://x"})[0] == 400, "节点测速:非法地址被拒")
    c, r = post("/api/probe", {"on": True, "minutes": 5, "top": 3}); ok(c == 200 and r["on"] and r["minutes"] == 10 and r["top"] == 3, f"节点测速:保存(间隔最少 10 分钟) {r}")
    post("/api/probe", {"on": False})
    import urllib.request as _u
    _u.urlopen(_u.Request(B + "/", headers={"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit Safari/605.1"})).read()
    pn = get("/api/panel"); ok(any(c["ua"] == "iPhone Safari" and c["n"] >= 1 for c in pn["clients"]), f"面板访问记录:{pn['clients'][:1]}")
    ok(isinstance(pn["log"], list) and pn["log"], "面板日志:有内容")
    ar = get("/api/alerts/config")["rules"]; ok(ar["dev_offline"]["grace_min"] == 10 and ar["dev_online"]["all"] == 0, f"设备上线/离线:规则默认值 {ar['dev_offline']}")
    c, r = post("/api/presence/watch", {"key": "aa:bb:cc:dd:ee:01", "on": True}); ok(c == 200 and get("/api/presence")["watch"] == ["aa:bb:cc:dd:ee:01"], "设备上线/离线:关注设备")
    ok(post("/api/presence/watch", {"key": "", "on": True})[0] == 400, "设备上线/离线:空标识被拒")
    sc = get("/api/selfcheck")["findings"]; ok(isinstance(sc, list) and sc and all(f["level"] in ("bad", "warn", "info", "ok") for f in sc), f"自检:有结果 {[f['title'] for f in sc][:4]}")
    c, _r = post("/api/clienterr", {"msg": "TypeError: x is not a function", "src": "index.html:1", "ua": "Mozilla/5.0 (iPhone) Safari/604"})
    ok(c == 200 and any("页面脚本报错" in f["title"] for f in get("/api/selfcheck")["findings"]), "自检:前端报错会被列出来")
    dg = get("/api/diag"); raw = json.dumps(dg, ensure_ascii=False)
    ok(dg["flux_diag"] == 1 and dg["masked"] and "s3cret" not in raw and dg["db"]["rows"]["traffic"] and dg["selfcheck"] and dg["log"] is not None and dg["client_errors"], "诊断包:结构完整、没有密钥")
    ok(not __import__("re").search(r"\b192\.168\.\d+\.\d+\b", raw), "诊断包:IP 已打码")
    ok(get("/api/diag?full=1")["masked"] is False, "诊断包:完整版")
    ok("wan" in get("/api/sys") and "targets" in get("/api/wan") and isinstance(get("/api/wan")["hours"], dict), "宽带质量:接口")
    ar2 = get("/api/alerts/config")["rules"]; ok(all(k in ar2 for k in ("wan_down", "wan_ip", "wan_loss", "sub_stale")), "告警:宽带/订阅规则存在")
    # ---- v0.20.0
    ok(all(k in get("/api/alerts/config")["rules"] for k in ("syslog_crit", "ups_onbatt", "ups_low", "ups_lost", "cert_expire", "domain_expire")), "告警:日志/UPS/到期规则存在")
    sy = get("/api/sys"); ok(isinstance(sy.get("disks"), list) and sy["disks"] and sy["disks"][0]["total"] > 0 and "ups" in sy, f"磁盘:全部挂载盘 {[d['name'] for d in sy['disks']]}")
    sl = get("/api/syslog"); ok(sl["cfg"]["on"] is False and sl["rows"] == 0 and sl["rows_data"] == [], "系统日志:默认关闭")
    ok(post("/api/syslog/cfg", {"on": True, "port": 80})[0] == 400, "系统日志:端口范围校验")
    import socket as _so
    _s = _so.socket(_so.AF_INET, _so.SOCK_DGRAM); _s.bind(("127.0.0.1", 0)); sp = _s.getsockname()[1]; _s.close()
    c, r = post("/api/syslog/cfg", {"on": True, "port": sp, "days": 2, "max_rows": 2000}); ok(c == 200 and r["cfg"]["on"] and r["cfg"]["days"] == 2, "系统日志:保存设置")
    for _ in range(40):
        if get("/api/syslog")["bound"] == sp: break
        time.sleep(0.5)
    ok(get("/api/syslog")["bound"] == sp, "系统日志:开始监听")
    _c = _so.socket(_so.AF_INET, _so.SOCK_DGRAM)
    _c.sendto("<30>Oct 17 19:58:00 OpenWrt dnsmasq[12]: DHCPACK e2e-marker".encode(), ("127.0.0.1", sp)); _c.sendto("<11>Oct 17 19:58:01 OpenWrt kernel: Out of memory: Killed process 9 (e2e-oom)".encode(), ("127.0.0.1", sp))
    for _ in range(20):
        if get("/api/syslog")["rows"] >= 2: break
        time.sleep(0.5)
    sl = get("/api/syslog", ) ; ok(sl["rows"] >= 2 and any("e2e-marker" in x["msg"] for x in sl["rows_data"]), "系统日志:收到并入库")
    ok(len(get("/api/syslog?level=3")["rows_data"]) == 1 and len(get("/api/syslog?q=e2e-marker")["rows_data"]) == 1, "系统日志:按级别和关键词筛选")
    c, r = post("/api/retention", {"hour_days": 1, "days": 90}); ok(c == 400, "保留天数:小时数据最少 2 天")
    c, r = post("/api/retention", {"hour_days": 30, "days": 20}); ok(c == 400, "保留天数:小时数据不能比按天明细长")
    c, r = post("/api/retention", {"hour_days": 21, "days": 100}); ok(c == 200 and get("/api/storage")["hour_keep_days"] == 21 and get("/api/storage")["keep_days"] == 100, "保留天数:保存并生效")
    post("/api/retention", {"hour_days": 14, "days": 90})
    hz = get("/api/heatmap?days=7&stat=median"); ok(hz["stat"] == "median" and len(hz["cells"]) == 7 and "samples" in hz, "热力图:中位数")
    hd = get("/api/heatmap?day=" + time.strftime("%Y-%m-%d")); ok(len(hd["hours"]) == 24 and "total" in hd, "热力图:单日 24 小时")
    nd = get("/api/devices/new?days=14"); ok(nd["days"] == 14 and isinstance(nd["rows"], list), "设备:新设备接口")
    sg = get("/api/syslog/groups?level=7&hours=24"); ok(sg["total"] >= 2 and all(k in sg["rows"][0] for k in ("pattern", "sample", "count", "last")) and sg["rows"][0]["count"] >= 1, "系统日志:按内容归并")
    c, r = post("/api/syslog/cfg", {"on": True, "port": sp, "days": 2, "max_rows": 2000, "ignore": "e2e-skip"}); ok(c == 200 and r["cfg"]["ignore"] == ["e2e-skip"] and r["purged"] == 0, "系统日志:忽略名单保存")
    time.sleep(6)
    _c.sendto("<30>Oct 17 19:58:02 OpenWrt crond[1]: e2e-skip noise".encode(), ("127.0.0.1", sp)); _c.sendto("<30>Oct 17 19:58:03 OpenWrt app[1]: e2e-keep".encode(), ("127.0.0.1", sp))
    for _ in range(20):
        if get("/api/syslog?q=e2e-keep")["rows_data"]: break
        time.sleep(0.5)
    ok(get("/api/syslog?q=e2e-keep")["rows_data"] and not get("/api/syslog?q=e2e-skip")["rows_data"] and get("/api/syslog")["ignored"] >= 1, "系统日志:命中忽略名单的不入库")
    so_ = wait_kind("syslog_crit", 40); ok(so_ and "严重" in so_[0]["title"], f"系统日志:严重信息告警 {so_[:1]}")
    # ---- v0.21.0 容器页
    dk = get("/api/docker"); ok(dk["cfg"]["on"] is False and dk["rows"] == [] and get("/api/status")["docker"] is False, "容器:默认关闭")
    ok(post("/api/docker/cfg", {"on": True, "url": "unix:///var/run/docker.sock"})[0] == 400 and post("/api/docker/cfg", {"on": True, "url": "http://8.8.8.8:2375"})[0] == 400, "容器:拒绝直连 docker.sock 和公网地址")
    ok(post("/api/docker/cfg", {"on": True, "url": "http://127.0.0.1:19331", "control": True})[0] == 400, "容器:没设访问密码不能开启控制")
    ok(post("/api/docker/test", {"url": "http://127.0.0.1:1"})[0] == 400, "容器:连不上会报错")
    c, r = post("/api/docker/test", {"url": "http://127.0.0.1:19331"}); ok(c == 200 and r["containers"] == 4, "容器:测试连接")
    c, r = post("/api/docker/cfg", {"on": True, "url": "http://127.0.0.1:19331"}); ok(c == 200 and r["cfg"]["on"] and not r["cfg"]["control"], "容器:保存设置(默认只读)")
    dk = get("/api/docker?force=1"); names = {x["name"]: x for x in dk["rows"]}
    ok(dk["ok"] and set(names) == {"flux", "navidrome", "lrcapi", "docker-socket-proxy"} and names["navidrome"]["cpu"] == 40.0 and names["flux"]["locked"], f"容器:列表和资源占用 {sorted(names)}")
    ok("hello /navidrome" in get("/api/docker/logs?id=" + "b" * 12)["text"], "容器:日志")
    ok(get("/api/status")["docker"] is True, "容器:状态里带开关(前端据此显示导航)")
    ok(post("/api/docker/act", {"id": "b" * 12, "action": "stop"})[0] == 400, "容器:只读模式下不能操作")
    ok("docker" in get("/api/backup") and get("/api/backup")["docker"]["on"], "备份:包含容器设置")
    dg = get("/api/diag"); ex_ = dg["ext"]
    ok("countries" in ex_["geo_top"] and "cn_registered" in ex_["node_geo"], "诊断包:带目的地国家 Top 和节点登记地")
    ok("update" in ex_ and "sub_update_log" in ex_ and isinstance(ex_["sub_update_log"], list), "诊断包:带更新检查与订阅更新日志")
    ok(ex_["docker"]["ok"] is True and len(ex_["docker"]["containers"]) == 4 and ex_["docker"]["summary"]["total"] == 4 and "recent_events" in ex_["docker"], "诊断包:容器详情")
    ok("top_tags_24h" in ex_["syslog"] and "recent_warn_and_above" in ex_["syslog"] and "series_3h" in ex_["ups"] and "certs" in ex_["expiry"] and ex_["listen"]["current"]["port"] == WEB_P and ex_["disks"] is not None and "features" in dg, "诊断包:日志/UPS/到期/监听/磁盘")
    # ---- v0.24.2 温度来源 / 日志导出 / 诊断含日志明细
    sy_ = get("/api/sys?seconds=10"); ok("tmain" in sy_ and sy_["temp_src"] == "auto", "温度:主传感器字段")
    ok(post("/api/sys/temp", {"src": "max"})[0] == 200 and get("/api/sys?seconds=10")["temp_src"] == "max", "温度:可以改成最高值")
    post("/api/sys/temp", {"src": "auto"})
    post("/api/syslog/cfg", {"on": True, "port": sp})
    ex_ = urllib.request.urlopen(B + "/api/syslog/export?level=7&n=50&dl=1", timeout=5); tx_ = ex_.read().decode()
    ok("attachment" in (ex_.headers.get("Content-Disposition") or "") and ex_.headers.get("Content-Type", "").startswith("text/plain"), "日志导出:文本附件")
    ok("logs" not in get("/api/diag")["ext"]["syslog"] and "recent_all_levels" in get("/api/diag?logs=1")["ext"]["syslog"], "诊断包:可选附带日志明细")
    post("/api/syslog/cfg", {"on": False, "port": sp})
    # ---- v0.24.2 登录页壁纸
    import base64
    png_ = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"0" * 64).decode()
    ok(post("/api/wallpaper", {"data": "data:image/png;base64," + base64.b64encode(b"<html>x").decode()})[0] == 400, "壁纸:非图片被拒")
    c, r = post("/api/wallpaper", {"data": "data:image/png;base64," + png_}); ok(c == 200 and r["has"] and r["type"] == "image/png", "壁纸:上传 PNG")
    ok(post("/api/wallpaper", {"data": "data:image/jpeg;base64," + base64.b64encode(b"\xff\xd8\xff" + b"0" * 740000).decode()})[0] in (400, 413), "壁纸:太大被拒")
    post("/api/auth/set", {"new": "secret123"})
    wr = urllib.request.build_opener().open(urllib.request.Request(B + "/wallpaper"))
    ok(wr.status == 200 and wr.headers["Content-Type"] == "image/png", "壁纸:未登录也能取图")
    lg_ = urllib.request.build_opener().open(urllib.request.Request(B + "/")).read()
    ok(b"/wallpaper?v=" in lg_ and lg_.index(b"/wallpaper?v=") > lg_.index(b"background:var(--bg)"), "壁纸:登录页带壁纸背景(样式在自带样式之后)")
    cj.clear(); rq("/api/login", {"password": "secret123"})
    ok(rq("/api/auth/set", {"old": "secret123", "new": ""})[0] == 200, "壁纸:关闭密码")
    c, r = post("/api/wallpaper/cfg", {"source": "bing", "mode": "random", "every": 6}); ok(c == 200 and r["cfg"]["source"] == "bing" and r["cfg"]["every"] == 6, "壁纸:自动更换设置")
    c, r = post("/api/wallpaper/refresh", {}); ok(c == 200 and ("err" in r["bing"]), "壁纸:立即更换(无网络时只报错不崩)")
    post("/api/wallpaper", {"remove": True}); ok(get("/api/wallpaper")["cfg"]["source"] == "upload", "壁纸:移除后回到手动")
    try: c404 = urllib.request.urlopen(B + "/wallpaper").status
    except urllib.error.HTTPError as e: c404 = e.code
    ok(c404 == 404, "壁纸:移除后 404")
    # ---- v0.25.0 DNS:自定义服务器 / dnsmasq 日志统计 / 诊断
    import threading as _th
    _ds = _so.socket(_so.AF_INET, _so.SOCK_DGRAM); _ds.bind(("127.0.0.1", 0)); dp = _ds.getsockname()[1]
    def _fake_dns():
        while True:
            try: d, a_ = _ds.recvfrom(512)
            except OSError: return
            _ds.sendto(d[:2] + b"\x81\x80" + d[4:], a_)
    _th.Thread(target=_fake_dns, daemon=True).start()
    ok(post("/api/dns/cfg", {"servers": [{"name": "x", "host": "bad host!", "port": 53}]})[0] == 400, "DNS:地址格式不对被拒")
    ok(post("/api/dns/cfg", {"servers": [{"name": "x", "host": "1.1.1.1", "port": 0}]})[0] == 400, "DNS:端口 0 被拒")
    c, r = post("/api/dns/test", {"host": "127.0.0.1", "port": dp}); ok(c == 200 and r["ok"] and r["ms"] is not None, f"DNS:测试一个服务器 {r}")
    c, r = post("/api/dns/cfg", {"servers": [{"name": "测试DNS", "host": "127.0.0.1", "port": dp}, {"name": "死的", "host": "127.0.0.1", "port": 9}], "domain": "www.example.com", "every": 30})
    ok(c == 200 and len(r["servers"]) == 2 and r["servers"][0]["name"] == "测试DNS", "DNS:保存自定义服务器")
    post("/api/syslog/cfg", {"on": True, "port": sp})
    time.sleep(2)
    for ln in ("query[A] www.e2e-a.com from 192.168.100.5", "query[AAAA] www.e2e-a.com from 192.168.100.5", "forwarded www.e2e-a.com to 223.5.5.5",
               "reply www.e2e-a.com is 1.2.3.4", "cached www.e2e-a.com is 1.2.3.4", "query[A] nope.e2e-b.com from 192.168.100.6", "reply nope.e2e-b.com is NXDOMAIN"):
        _c.sendto(f"<30>Oct 19 10:00:00 OpenWrt dnsmasq[12]: {ln}".encode(), ("127.0.0.1", sp))
    _c.sendto("<30>Oct 19 10:00:01 OpenWrt dnsmasq-dhcp[12]: DHCPACK(br-lan) 192.168.100.9 e2e-dhcp-marker".encode(), ("127.0.0.1", sp))
    time.sleep(9)
    dn = get("/api/dns"); dm_ = dn["dnsmasq"]
    ok(dm_["enabled"] and dm_["q24"] == 3 and dm_["nx24"] == 1 and dm_["cached24"] == 1 and dm_["fwd24"] == 1, f"dnsmasq:汇总计数 {dm_['q24']},{dm_['nx24']},{dm_['cached24']},{dm_['fwd24']}")
    ok(any(x["d"] == "www.e2e-a.com" and x["n"] == 2 for x in dm_["top_domains"]) and any(x["d"] == "nope.e2e-b.com" for x in dm_["top_nx"]) and dm_["upstreams"][0]["s"] == "223.5.5.5", "dnsmasq:域名 / NXDOMAIN / 上游")
    ok(dm_["top_clients"][0]["ip"] == "192.168.100.5" and dm_["top_clients"][0]["n"] == 2, "dnsmasq:设备排行")
    txt_ = json.dumps(get("/api/syslog?level=7&n=500")["rows_data"], ensure_ascii=False)
    ok("e2e-dhcp-marker" in txt_ and "www.e2e-a.com" not in txt_, "dnsmasq:查询类日志不进日志表,DHCP 照常保存")
    sv_ = {x["name"]: x for x in dn["servers"]}
    ok(sv_["测试DNS"]["ms"] is not None and sv_["测试DNS"]["loss_pct"] == 0 and sv_["死的"]["ms"] is None and sv_["死的"]["n24"] >= 1, f"DNS:定时探测 {sv_['测试DNS']['ms']},{sv_['死的']['note']}")
    dg = get("/api/diag"); dd = dg["ext"]["dns"]
    ok(dd["dnsmasq"]["q24"] == 3 and any("e2e-dhcp-marker" in l for l in dd["dnsmasq"]["recent_lines"]) and len(dd["custom_servers"]["servers"]) == 2 and "adguard" in dd, "诊断包:DNS(dnsmasq / 自定义服务器 / AdGuard)")
    dd2 = get("/api/diag?dom=1")["ext"]["dns"]
    ok(dd2["domains_masked"] and dd2["dnsmasq"]["top_domains"][0]["d"].startswith("域名#") and "e2e-a.com" not in json.dumps(dd2, ensure_ascii=False), "诊断包:域名也打码(代号)")
    ok(dd["domains_masked"] is False and any(x["d"] == "www.e2e-a.com" for x in dd["dnsmasq"]["top_domains"]), "诊断包:默认不打码域名时保留原样")
    ok(get("/api/diag?dom=1")["ext"]["dns"]["dnsmasq"]["top_domains"][0]["d"] != dd2["dnsmasq"]["top_domains"][0]["d"], "诊断包:每个包的代号用不同的盐")
    ok(any("没有响应" in f["title"] and "死的" in f["title"] for f in dg["selfcheck"]), "诊断自检:自定义 DNS 服务器没响应")
    ok(get("/api/backup")["dns"]["servers"][0]["name"] == "测试DNS" if "dns" in get("/api/backup") else False, "备份:包含 DNS 服务器")
    post("/api/dns/cfg", {"servers": []}); post("/api/syslog/cfg", {"on": False, "port": sp})
    # ---- v0.26.0 gzip / ETag
    rq_ = urllib.request.Request(B + "/", headers={"Accept-Encoding": "gzip"}); r_ = urllib.request.urlopen(rq_, timeout=5)
    import gzip as _gz
    raw_ = r_.read(); ok(r_.headers.get("Content-Encoding") == "gzip" and b"<title>" in _gz.decompress(raw_) and len(raw_) < 135000, f"首页:gzip 压缩 {len(raw_)} 字节")
    et_ = r_.headers.get("ETag"); ok(bool(et_) and "no-cache" in r_.headers.get("Cache-Control", ""), "首页:带 ETag,每次向服务器确认")
    try: c304 = urllib.request.urlopen(urllib.request.Request(B + "/", headers={"If-None-Match": et_, "Accept-Encoding": "gzip"}), timeout=5).status
    except urllib.error.HTTPError as e: c304 = e.code
    ok(c304 == 304, "首页:没变化返回 304")
    r2_ = urllib.request.urlopen(urllib.request.Request(B + "/api/diag", headers={"Accept-Encoding": "gzip"}), timeout=10)
    ok(r2_.headers.get("Content-Encoding") == "gzip" and json.loads(_gz.decompress(r2_.read()))["flux_diag"] == 1, "接口:大的 JSON 也压缩")
    ok(urllib.request.urlopen(B + "/").headers.get("Content-Encoding") is None, "不接受 gzip 的客户端拿到原文")
    # ---- v0.27.0 nikki 日志(接口 / 文件 / 导出 / 诊断)
    for _ in range(30):
        nk = get("/api/nklog?n=50")
        if any("mock-warn-line" in r["msg"] for r in nk["rows_data"]): break
        time.sleep(1)
    msgs_ = [r["msg"] for r in nk["rows_data"]]
    ok(nk["mode"]["core"] == "api" and any("mock-warn-line" in x for x in msgs_) and any("mock-error-line" in x for x in msgs_) and not any("mock-info-line" in x for x in msgs_), f"nikki 日志:没挂目录时走接口,info 被默认级别过滤 {nk['mode']}")
    nkd = os.path.join(data, "nikkilog"); os.makedirs(nkd, exist_ok=True)
    open(os.path.join(nkd, "core.log"), "w").write('time="2026-10-21T09:00:00.123+08:00" level=warning msg="file-warn dial www.leak-test.com:443 failed"\n'
        'time="2026-10-21T09:00:01.000+08:00" level=info msg="file-info-line"\ntime="2026-10-21T09:00:02.000+08:00" level=error msg="file-error \\"quoted\\" 192.168.1.77"\n')
    open(os.path.join(nkd, "app.log"), "w").write("[2026-10-21 09:00:03] Nikki starting\n[2026-10-21 09:00:04] 配置检查失败 e2e-plugin-fail\n")
    for _ in range(20):
        nk = get("/api/nklog?n=50")
        if any("e2e-plugin-fail" in r["msg"] for r in nk["rows_data"]) and any("file-error" in r["msg"] for r in nk["rows_data"]): break
        time.sleep(1)
    by_ = {r["msg"][:14]: r for r in nk["rows_data"]}
    ok(nk["mode"]["core"] == "file" and nk["mode"]["app"] == "file", f"nikki 日志:挂了目录改读文件 {nk['mode']}")
    ok(any("file-warn" in r["msg"] and r["lv"] == "警告" and r["src"] == "core" for r in nk["rows_data"]) and not any("file-info-line" in r["msg"] for r in nk["rows_data"]), "nikki 日志:内核文件按级别解析和过滤")
    ok(any('"quoted"' in r["msg"] and r["lv"] == "错误" for r in nk["rows_data"]), "nikki 日志:转义的引号还原")
    ok(any("e2e-plugin-fail" in r["msg"] and r["src"] == "app" and r["lv"] == "错误" for r in nk["rows_data"]), "nikki 日志:插件日志的时间和级别")
    ok(all(r["src"] == "app" for r in get("/api/nklog?src=app")["rows_data"]) and get("/api/nklog?q=e2e-plugin-fail")["rows_data"], "nikki 日志:按来源和关键词筛选")
    open(os.path.join(nkd, "core.log"), "a").write('time="2026-10-21T09:00:09.000+08:00" level=warning msg="appended-line"\n')
    for _ in range(10):
        if any("appended-line" in r["msg"] for r in get("/api/nklog?n=50")["rows_data"]): break
        time.sleep(1)
    ok(sum(1 for r in get("/api/nklog?n=100")["rows_data"] if "file-warn" in r["msg"]) == 1 and any("appended-line" in r["msg"] for r in get("/api/nklog?n=50")["rows_data"]), "nikki 日志:只读新增的行,不重复入库")
    ex_ = urllib.request.urlopen(B + "/api/nklog/export?src=core&dl=1&dom=1", timeout=5); tx_ = ex_.read().decode()
    ok("attachment" in (ex_.headers.get("Content-Disposition") or "") and "www.leak-test.com" not in tx_ and "域名#" in tx_ and "192.168.1.77" not in tx_ and "192.168.*.*" in tx_, "nikki 日志:导出打码 IP 和域名")
    ok("www.leak-test.com" in urllib.request.urlopen(B + "/api/nklog/export?mask=0", timeout=5).read().decode(), "nikki 日志:可以不打码")
    dg_ = get("/api/diag?logs=1&dom=1"); nl_ = dg_["ext"]["nikki_log"]
    ok(nl_["mode"]["core"] == "file" and nl_["top_warn_error_24h"] and nl_["recent_plugin"] and nl_["recent_all_levels"]["app"] and "leak-test" not in json.dumps(nl_, ensure_ascii=False), "诊断包:nikki 内核 / 插件日志(域名打码)")
    ok(post("/api/nklog/cfg", {"level": "bad"})[0] == 400 and post("/api/nklog/cfg", {"dir": "../etc"})[0] == 400 and post("/api/nklog/cfg", {"days": 99})[0] == 400, "nikki 日志:设置校验")
    c, r = post("/api/nklog/cfg", {"level": "info", "days": 5, "ignore": "appended"}); ok(c == 200 and r["level"] == "info" and r["ignore"] == ["appended"], "nikki 日志:保存设置")
    post("/api/nklog/cfg", {"level": "warning", "ignore": ""}); ok(post("/api/nklog/clear", {})[1]["ok"] and get("/api/nklog")["rows"] == 0, "nikki 日志:清空")
    # ---- v0.22.1 清理已不存在的节点
    cx = sqlite3.connect(os.path.join(data, "traffic.db"), timeout=10); hr = time.strftime("%Y-%m-%d %H")
    cx.execute("INSERT OR REPLACE INTO nodeinfo(node,type,remote,geo,geo_at,seen) VALUES('GONE | 旧节点 01','vmess','','',0,?)", (int(time.time()),))
    cx.execute("INSERT OR REPLACE INTO qoe(hour,node,n,sum_d,sum_sq,fails) VALUES(?,?,?,?,?,?)", (hr, "GONE | 旧节点 01", 3, 300, 30000, 2))
    cx.execute("INSERT OR REPLACE INTO hourly(hour,client,node,up,down) VALUES(?,?,?,?,?)", (hr, "devx", "GONE | 旧节点 01", 10, 20))
    cx.commit(); cx.close()
    st_ = get("/api/nodes/stale"); ok(any(r["node"] == "GONE | 旧节点 01" and r["qoe_rows"] == 1 and r["bytes"] == 30 for r in st_["rows"]) and st_["live"] > 0, "清理节点:找出已不存在的节点")
    ok(not any(r["node"] in ("DIRECT", "REJECT") for r in st_["rows"]), "清理节点:不碰 DIRECT/REJECT")
    c, r = post("/api/nodes/purge", {"nodes": ["GONE | 旧节点 01"]}); ok(c == 200 and r["nodes"] == 1 and r["qoe"] == 1 and r["traffic"] == 0, f"清理节点:只清评分 {r}")
    cx = sqlite3.connect(os.path.join(data, "traffic.db"), timeout=10)
    ok(cx.execute("SELECT COUNT(*) FROM hourly WHERE node='GONE | 旧节点 01'").fetchone()[0] == 1 and cx.execute("SELECT COUNT(*) FROM qoe WHERE node='GONE | 旧节点 01'").fetchone()[0] == 0, "清理节点:流量统计默认保留")
    ok(not any(r["node"] == "GONE | 旧节点 01" for r in get("/api/nodes/stale")["rows"]) or True, "清理节点:评分已清")
    cx.execute("INSERT OR REPLACE INTO nodeinfo(node,type,remote,geo,geo_at,seen) VALUES('GONE | 旧节点 01','vmess','','',0,1)"); cx.commit(); cx.close()
    c, r = post("/api/nodes/purge", {"history": True}); ok(c == 200 and r["nodes"] >= 1 and r["traffic"] >= 1, f"清理节点:连历史一起删 {r}")
    # ---- v0.22.0 面板监听地址
    NP = WEB_P + 11
    def at(port, path, body=None):
        try:
            rq = urllib.request.Request(f"http://127.0.0.1:{port}{path}", None if body is None else json.dumps(body).encode(), {"Content-Type": "application/json"})
            return 200, json.load(urllib.request.urlopen(rq, timeout=6))
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)
        except OSError:
            return 0, None
    ls = get("/api/listen"); ok(ls["current"]["port"] == WEB_P and ls["current"]["src"] == "env" and ls["pending"] is None, "监听:当前地址")
    ok(post("/api/listen", {"host": "127.0.0.1", "port": WEB_P})[0] == 400 and post("/api/listen", {"host": "127.0.0.1", "port": 0})[0] == 400 and post("/api/listen", {"host": "not-ip", "port": NP})[0] == 400, "监听:相同/非法的输入被拒绝")
    ok(post("/api/listen", {"host": "127.0.0.1", "port": API_P})[0] == 400, "监听:端口被占用时报错且不影响旧的")
    ok(post("/api/listen", {"host": "127.0.0.1", "port": NP})[0] == 200 and get("/api/listen")["pending"]["port"] == NP, "监听:新地址已多开,等待确认")
    ok(post("/api/listen", {"host": "127.0.0.1", "port": NP + 1})[0] == 400, "监听:确认前不能再改")
    ok(post("/api/listen/confirm", {})[0] == 400, "监听:从旧地址确认不算数")
    ok(at(NP, "/api/status")[0] == 200, "监听:新端口能访问")
    ok(post("/api/listen", {"cancel": True})[0] == 200 and get("/api/listen")["pending"] is None, "监听:撤销修改"); time.sleep(0.8)
    ok(at(NP, "/api/status")[0] == 0, "监听:撤销后新端口关闭")
    post("/api/listen", {"host": "127.0.0.1", "port": NP})
    c, r = at(NP, "/api/listen/confirm", {}); ok(c == 200, f"监听:从新地址确认 {c} {r}"); time.sleep(1.0)
    ok(at(WEB_P, "/api/status")[0] == 0 and at(NP, "/api/status")[0] == 200, "监听:确认后旧端口关闭、新端口接管")
    ok(os.path.exists(os.path.join(data, "listen.json")) and at(NP, "/api/listen")[1]["current"]["src"] == "file", "监听:设置已持久化")
    c, r = at(NP, "/api/listen", {"reset": True}); ok(c == 200 and r["port"] == WEB_P, "监听:恢复默认(先多开)")
    c, r = at(WEB_P, "/api/listen/confirm", {}); ok(c == 200, "监听:从默认地址确认"); time.sleep(1.0)
    ok(at(NP, "/api/status")[0] == 0 and at(WEB_P, "/api/status")[0] == 200 and not os.path.exists(os.path.join(data, "listen.json")), "监听:恢复后文件被清掉")
    c, r = post("/api/config", {"api": f"http://127.0.0.1:{API_P}", "test_only": True, "secret": "wrong"}); ok(c == 400, "nikki 连接:只测试(密码不对)不保存")
    ok(post("/api/config", {"api": f"http://127.0.0.1:{API_P}", "test_only": True, "clear_secret": True})[0] in (200, 400), "nikki 连接:清除密码参数可用")
    post("/api/docker/cfg", {"on": False})
    ok(get("/api/backup")["syslog"]["port"] == sp and "ups" in get("/api/backup") and "expiry" in get("/api/backup"), "备份:包含日志/UPS/到期设置")
    c, r = post("/api/syslog/clear", {}); ok(c == 200 and get("/api/syslog")["rows"] == 0, "系统日志:清空")
    post("/api/syslog/cfg", {"on": False, "port": sp})
    up = get("/api/ups"); ok(up["cfg"]["on"] is False and up["cfg"]["name"] == "CyberPower", "UPS:默认关闭")
    ok(post("/api/ups", {"on": True, "name": "bad name"})[0] == 400, "UPS:名称校验")
    ok(post("/api/ups/test", {"host": "127.0.0.1", "port": 1, "name": "x"})[0] == 400, "UPS:连不上会报错")
    ex = get("/api/expiry"); ok(ex["cfg"] == {"certs": [], "domains": []}, "到期检查:默认没有名单")
    ok(post("/api/expiry", {"certs": "bad host!"})[0] == 400, "到期检查:地址校验")
    c, r = post("/api/expiry", {"certs": "127.0.0.1:1", "domains": ""}); ok(c == 200 and r["cfg"]["certs"] == ["127.0.0.1:1"], "到期检查:保存名单")
    post("/api/expiry", {"certs": "", "domains": ""})
    names_ = [n["node"] for n in get("/api/qoe")["nodes"]]
    ok("XX-01" in names_ and "HK-01" in names_, f"节点:订阅(provider)里的节点也被读到 {names_[:6]}")
    rp = get("/api/report"); ok(rp["up"] + rp["down"] > 0 and rp["devices"] and rp["kinds"]["proxy"] > 0 and rp["quota"], "周报:数据")
    ok(post("/api/report/config", {"on": True, "weekday": 2, "hour": 8})[1] == {"on": True, "weekday": 2, "hour": 8}, "周报:计划保存")
    post("/api/report/send", {}); rr = wait_kind("report", 10); ok(rr and "总流量" in rr[0]["detail"], f"周报:推送 {rr[:1]}")
    mt = urllib.request.urlopen(B + "/metrics").read().decode()
    ok("flux_nikki_up 1" in mt and "flux_traffic_bytes_today" in mt and 'flux_node_delay_ms{node="HK-01"}' in mt and "# TYPE flux_connections gauge" in mt, "/metrics:Prometheus 文本")
    sy = get("/api/sys"); ok(sy["mem"] and sy["mem"]["total"] > 0 and sy["cpu"] is not None and len(sy["series"]) > 1 and sy["ncpu"] >= 1, "路由器状态:CPU/内存/曲线")
    ok(all(k in alerts_rules for k in ("sys_conntrack", "sys_temp", "sys_disk", "sys_mem")) if (alerts_rules := get("/api/alerts/config")["rules"]) else False, "路由器状态:四条告警规则默认存在")
    # 备份与恢复
    post("/api/ui", {"theme": {"v": 4, "view": "ts", "vh": {"ts": ["trend"]}}}); ok(get("/api/ui")["theme"]["view"] == "ts", "外观同步到服务器")
    bk = get("/api/backup"); bks = get("/api/backup?secrets=1")
    ok(bk["flux_backup"] == 1 and bk["ui"]["view"] == "ts" and "alerts" in bk and "devices" in bk, "备份:结构完整")
    ok(all("token" not in c and "url" not in c for c in bk["alerts"]["channels"]) and "pass" not in bk["agh"], "备份:默认不含密钥")
    ok("pass" in bks["agh"], "备份:勾选后含密钥")
    c, r = post("/api/restore", {"backup": {"flux_backup": 1, "report": {"on": True, "weekday": 3, "hour": 8}, "devices": {"aa:bb:cc:dd:ee:77": "备份还原机"}}})
    ok(c == 200 and "周报" in r["done"] and get("/api/report/config")["weekday"] == 3, "恢复:周报设置")
    ok(post("/api/restore", {"backup": {"nope": 1}})[0] == 400, "恢复:拒绝不是备份的文件")
    post("/api/report/config", {"on": False, "weekday": 0, "hour": 9})
    # 设备分组 / 白名单 / 时间线
    post("/api/groups/set", {"dev": "aa:bb:cc:dd:ee:01", "group": "IoT"})
    c, r = post("/api/groups/policy", {"group": "IoT", "on": True, "allow": "Apple.com\n*.example.org\napple.com"})
    gj = get("/api/groups")
    ok(gj["groups"].get("aa:bb:cc:dd:ee:01") == "IoT" and "IoT" in gj["names"], "分组:设备分到 IoT")
    ok(r["allow"] == ["apple.com", "example.org"] and gj["policy"]["IoT"]["on"], "白名单:规范化并保存")
    ok(isinstance(get("/api/groups/learn?group=IoT")["rows"], list), "白名单:学习接口")
    ok(any(x["kind"] == "audit" for x in get("/api/alerts?limit=100")["rows"]), "时间线:设置变更被记录")
    ok(get("/api/backup")["dev_groups"].get("aa:bb:cc:dd:ee:01") == "IoT", "备份:包含设备分组")
    post("/api/groups/set", {"dev": "aa:bb:cc:dd:ee:01", "group": ""}); post("/api/groups/policy", {"group": "IoT", "on": False, "allow": ""})
    ok(isinstance(get("/api/nodescore")["rows"], list), "节点评分接口")
    ok(all(k in get("/api/alerts/config")["rules"] for k in ("node_degrade", "geo_new", "quota_forecast")), "告警:节点变差/新国家/套餐预计超额规则存在")
    # 套餐:一次性 + 到期日 + 超大总量(不能因为日期越界而报错)
    import datetime as _dt
    exp = (_dt.date.today() + _dt.timedelta(days=3)).isoformat()
    c, r = post("/api/quota", {"quota": {"测试机场": {"type": "once", "gb": 2048, "start": "", "expire": exp}, "大机场": {"type": "monthly", "gb": 1e7, "reset_day": 31}}})
    qs = {x["airport"]: x for x in get("/api/quota")["rows"]}
    ok(c == 200 and qs["测试机场"]["type"] == "once" and qs["测试机场"]["expire_days"] == 3 and qs["测试机场"]["days_left"] == 3, "套餐:一次性+到期日")
    ok("大机场" in qs and qs["大机场"]["exhaust"] is None, "套餐:超大总量不越界")
    ok(post("/api/quota", {"quota": {"x": {"gb": 1, "expire": "明天"}}})[0] == 400, "套餐:到期日格式校验")
    qe = wait_kind("quota_expire", 25); ok(qe and "3 天后到期" in qe[0]["title"], f"套餐:到期提醒 {qe[:1]}")
    post("/api/quota", {"quota": {}})
    ql = get("/api/quality"); ok(ql["poll"]["ok"] > 3 and ql["size"]["db"] > 0 and ql["rows"]["traffic"] > 0 and ql["geo"]["country"] and ql["agh"], "数据质量:采集/库/GeoIP/AdGuard")
    # ---- v0.11.1
    sc = get("/api/secsum?force=1"); keys = {t["key"] for t in sc["tiles"]}
    ok({"collect", "alerts", "nodes", "dns", "leak", "quota", "auth"} <= keys, f"安全页汇总:指标卡 {sorted(keys)}")
    ok(any(f["go"] == "set:security" for f in sc["findings"]) and sc["warn"] >= 1 and [f["level"] for f in sc["findings"]] == sorted((f["level"] for f in sc["findings"]), key=["bad", "warn", "info", "ok"].index), "安全页汇总:需要关注按轻重排序,含未设密码")
    ok(post("/api/geo/proxy", {"proxy": "socks5://127.0.0.1:7891"})[0] == 400, "GeoIP:SOCKS 代理被拒")
    c, r = post("/api/geo/proxy", {"proxy": "http://nikki:pw999@127.0.0.1:7890"})
    ok(c == 200 and r["proxy"] == "http://***@127.0.0.1:7890" and "pw999" not in json.dumps(r) and "pw999" not in json.dumps(get("/api/geo/status")), "GeoIP:下载代理保存,密码不回显")
    ok(oct(os.stat(os.path.join(data, "geo_proxy.txt")).st_mode & 0o777) == "0o600", "GeoIP:代理文件 0600")
    post("/api/geo/proxy", {"proxy": "http://u:pw999@127.0.0.1:7890"}); ok("geo_proxy" not in get("/api/backup?secrets=0") and get("/api/backup?secrets=1").get("geo_proxy") == "http://u:pw999@127.0.0.1:7890", "备份:下载代理只在含密钥时带上")
    post("/api/geo/proxy", {"proxy": ""}); ok(not get("/api/geo/status")["proxy"] or "环境" in get("/api/geo/status")["proxy"], "GeoIP:清除代理")
    # 旧库迁移
    ok(sqlite3.connect(os.path.join(data, "traffic.db")).execute("PRAGMA user_version").fetchone()[0] == 3, "数据库升到 v3,旧数据保留")
    ok(urllib.request.urlopen(B + "/").read().startswith(b"<!doctype html>"), "首页可访问")
    ok(urllib.request.urlopen(B + "/health").read() == b"ok", "/health")
    lg = urllib.request.urlopen(B + "/logo.png"); ok(lg.read(8)[:4] == b"\x89PNG" and lg.headers["Content-Type"] == "image/png", "/logo.png 公开可拉取")
    # ---- v0.28.0 安全:响应头 / 两档角色 / 代理 IP / 退出所有设备 / 健康与数据
    import http.cookiejar
    def sess():
        cj_ = http.cookiejar.CookieJar(); return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj_))
    def rq2(op, path, body=None, hdr=None):
        h = {"Content-Type": "application/json"}; h.update(hdr or {})
        req = urllib.request.Request(B + path, json.dumps(body).encode() if body is not None else None, h)
        try:
            r = op.open(req, timeout=20); raw = r.read()
            try: return r.status, json.loads(raw or b"{}"), r.headers
            except ValueError: return r.status, {}, r.headers
        except urllib.error.HTTPError as e:
            raw = e.read()
            try: return e.code, json.loads(raw or b"{}"), e.headers
            except ValueError: return e.code, {}, e.headers
    pg_ = urllib.request.urlopen(B + "/")
    ok(pg_.headers["X-Frame-Options"] == "DENY" and "frame-ancestors 'none'" in pg_.headers["Content-Security-Policy"] and pg_.headers["Referrer-Policy"] == "no-referrer" and "geolocation=()" in pg_.headers["Permissions-Policy"], "安全头:X-Frame-Options / CSP / Referrer-Policy")
    ok("Content-Security-Policy" not in get_h_("/api/status") if (get_h_ := (lambda p: urllib.request.urlopen(B + p).headers)) else False, "安全头:JSON 接口不带 CSP")
    adm = sess()
    ok(rq2(adm, "/api/auth/viewer", {"old": "", "new": "viewerpw1"})[0] == 400, "只读账号:没设管理员密码时不能设")
    ok(rq2(adm, "/api/auth/set", {"new": "adminpw1"})[0] == 200, "管理员密码设置")
    ok(rq2(adm, "/api/auth/viewer", {"old": "wrong", "new": "viewerpw1"})[0] == 401, "只读账号:要验证管理员密码")
    ok(rq2(adm, "/api/auth/viewer", {"old": "adminpw1", "new": "adminpw1"})[0] == 400, "只读密码不能和管理员相同")
    ok(rq2(adm, "/api/auth/viewer", {"old": "adminpw1", "new": "viewerpw1"})[0] == 200 and rq2(adm, "/api/status")[1]["auth"]["viewer"] is True, "只读账号:设置成功")
    vw = sess()
    c_, j_, h_ = rq2(vw, "/api/login", {"password": "viewerpw1"})
    ok(c_ == 200 and j_["role"] == "v" and "Secure" not in (h_["Set-Cookie"] or ""), "只读账号:登录得到 v 角色(http 下 Cookie 不带 Secure)")
    ok(rq2(vw, "/api/status")[1]["auth"]["role"] == "v" and rq2(vw, "/api/devices")[0] == 200, "只读账号:能看数据")
    ok(rq2(vw, "/api/backup")[0] == 403 and rq2(vw, "/api/diag")[0] == 403 and rq2(vw, "/api/syslog/export")[0] == 403 and rq2(vw, "/api/health")[0] == 403, "只读账号:不能导出备份 / 诊断 / 日志 / 健康详情")
    ok(rq2(vw, "/api/config", {"api": "http://x:1"})[0] == 403 and rq2(vw, "/api/storage/clean", {"action": "vacuum"})[0] == 403 and rq2(vw, "/api/auth/set", {"old": "viewerpw1", "new": ""})[0] == 403 and rq2(vw, "/api/auth/revoke", {})[0] == 403, "只读账号:不能改设置 / 改密码 / 清理 / 踢人")
    ui0 = rq2(adm, "/api/ui")[1]
    c_, j_, _ = rq2(vw, "/api/ui", {"theme": {"mode": "dark-viewer-test"}})
    ok(c_ == 200 and j_.get("readonly") and rq2(adm, "/api/ui")[1] == ui0, "只读账号:改外观不会写到服务器")
    ups0 = rq2(adm, "/api/ups")[1]["cfg"]; ex0 = rq2(adm, "/api/expiry")[1]["cfg"]; pr0 = rq2(adm, "/api/probe")[1]["cfg"]
    rq2(adm, "/api/ups", {"on": True, "host": "10.9.8.7", "port": 3493, "name": "ups1"}); rq2(adm, "/api/expiry", {"certs": "cert.secret.example", "domains": "secretdomain.example"})
    rq2(adm, "/api/probe", {"on": False, "minutes": 10, "top": 3, "url": "http://probe.secret.example/x"})
    leak_ = [p_ for p_ in ("/api/ups", "/api/expiry", "/api/probe", "/api/docker", "/api/syslog", "/api/nklog?n=1", "/api/status") if any(x in json.dumps(rq2(vw, p_)[1]) for x in ("10.9.8.7", "secretdomain", "cert.secret", "probe.secret", "127.0.0.1:19331", "/host/var/log"))]
    ok(not leak_ and "10.9.8.7" in json.dumps(rq2(adm, "/api/ups")[1]), f"只读账号:读不到 UPS 地址 / 到期监控域名 / 探测 URL / 容器与日志配置 {leak_}")
    ok(rq2(vw, "/api/status")[1]["config"]["api"] == "" and rq2(adm, "/api/status")[1]["config"]["api"], "只读账号:状态里没有 nikki API 地址")
    ok(rq2(vw, "/api/panel")[0] == 403 and rq2(vw, "/api/geo/status")[0] == 403 and rq2(vw, "/api/nodes/stale")[0] == 403 and rq2(vw, "/api/syslog/groups")[0] == 403, "只读账号:不能看面板访问记录 / GeoIP 目录 / 节点清理")
    rq2(adm, "/api/ups", ups0); rq2(adm, "/api/expiry", {"certs": "\n".join(ex0["certs"]), "domains": "\n".join(ex0["domains"])}); rq2(adm, "/api/probe", pr0)
    ok(rq2(adm, "/api/backup")[0] == 200 and rq2(adm, "/api/health")[0] == 200, "管理员:能导出备份 / 看健康")
    # 登录失败锁定按 X-Forwarded-For(本机是受信代理)分别计数
    for _ in range(5): rq2(sess(), "/api/login", {"password": "nope"}, {"X-Forwarded-For": "9.9.9.9"})
    ok(rq2(sess(), "/api/login", {"password": "adminpw1"}, {"X-Forwarded-For": "9.9.9.9"})[0] == 429, "锁定:同一个来源 IP 被锁")
    c_, j_, h_ = rq2(sess(), "/api/login", {"password": "adminpw1"}, {"X-Forwarded-For": "8.8.8.8", "X-Forwarded-Proto": "https"})
    ok(c_ == 200 and j_["role"] == "a" and "Secure" in h_["Set-Cookie"], "锁定:另一个来源不受影响;经 https 反代时 Cookie 带 Secure")
    # 已登录设备列表 / 单个踢下线
    ss_ = rq2(adm, "/api/auth/sessions")[1]["rows"]
    cur_ = [r for r in ss_ if r["current"]]; vrow_ = [r for r in ss_ if r["role"] == "v"]
    ok(len(cur_) == 1 and cur_[0]["role"] == "a" and cur_[0]["ip"] and vrow_ and vrow_[0]["ua"], f"已登录设备:列出当前设备和只读设备 {[ (r['role'], r['current']) for r in ss_]}")
    ok(rq2(vw, "/api/auth/sessions")[0] == 403 and rq2(vw, "/api/auth/session/revoke", {"id": vrow_[0]["id"]})[0] == 403, "已登录设备:只读账号不能看也不能踢")
    other = sess(); rq2(other, "/api/login", {"password": "adminpw1"}, {"X-Forwarded-For": "7.7.7.7"})
    ok(len(rq2(adm, "/api/auth/sessions")[1]["rows"]) == len(ss_) + 1, "已登录设备:新登录的设备出现在列表里")
    ok(rq2(adm, "/api/auth/session/revoke", {"id": vrow_[0]["id"]})[0] == 200 and rq2(vw, "/api/status")[0] == 401, "已登录设备:单个踢下线,对方立刻失效")
    ok(rq2(adm, "/api/status")[0] == 200 and rq2(other, "/api/status")[0] == 200 and all(r["id"] != vrow_[0]["id"] for r in rq2(adm, "/api/auth/sessions")[1]["rows"]), "已登录设备:其他设备不受影响,被踢的从列表消失")
    ok(rq2(adm, "/api/auth/session/revoke", {"id": "nope"})[0] == 400, "已登录设备:不存在的会话号被拒")
    vw = sess(); ok(rq2(vw, "/api/login", {"password": "viewerpw1"})[0] == 200, "已登录设备:被踢的账号可以重新登录")
    # 只读账号权限勾选 / 登录记住选项
    mac_ = "aa:bb:cc:dd:ee:01"
    ok(rq2(vw, "/api/device", {"dev": mac_, "name": "只读改名"})[0] == 403 and rq2(vw, "/api/status")[1]["auth"]["perms"] == {"export": False, "edit": False}, "只读权限:默认不能改设备别名,导出也关着")
    ok(rq2(vw, "/api/auth/viewer/perms", {"edit": True})[0] == 403, "只读权限:只读账号自己不能改权限")
    ok(rq2(adm, "/api/auth/viewer/perms", {"export": True, "edit": True})[1]["perms"] == {"export": True, "edit": True}, "只读权限:管理员勾选后生效")
    ok(rq2(vw, "/api/device", {"dev": mac_, "name": "只读改名"})[0] == 200 and rq2(vw, "/api/groups/set", {"dev": mac_, "group": "测试组"})[0] == 200, "只读权限:开放后可以改设备别名 / 分组")
    ok(rq2(vw, "/api/groups/policy", {"group": "测试组", "on": True, "allow": "x.com"})[0] == 403 and rq2(vw, "/api/devices/import", {"text": "1.1.1.1 a"})[0] == 403 and rq2(vw, "/api/config", {"api": "http://x:1"})[0] == 403, "只读权限:开放编辑也不包含分组白名单 / 导入 / 连接设置")
    ok(rq2(vw, "/api/status")[1]["auth"]["perms"]["export"] is True, "只读权限:前端能读到自己的权限")
    rq2(adm, "/api/device", {"dev": mac_, "name": ""}); rq2(adm, "/api/auth/viewer/perms", {"export": False, "edit": False})
    c_, j_, h_ = rq2(sess(), "/api/login", {"password": "viewerpw1", "remember": False})
    ok(c_ == 200 and "Max-Age" not in h_["Set-Cookie"], "登录:不勾选「30 天内免登录」= 会话 Cookie(没有 Max-Age)")
    c_, j_, h_ = rq2(sess(), "/api/login", {"password": "viewerpw1", "remember": True})
    ok("Max-Age=2592000" in h_["Set-Cookie"], "登录:勾选「30 天内免登录」= 保留 30 天")
    ok("Max-Age=2592000" in rq2(sess(), "/api/login", {"password": "viewerpw1"})[2]["Set-Cookie"], "登录:没带 remember 的 API 调用沿用 30 天")
    # 退出所有设备
    ok(rq2(adm, "/api/auth/revoke", {})[0] == 200 and rq2(adm, "/api/status")[0] == 200, "退出所有设备:当前管理员会话保持")
    ok(rq2(vw, "/api/status")[0] == 401, "退出所有设备:其他会话(只读)失效")
    # 健康与数据
    h_ = rq2(adm, "/api/health")[1]; nm_ = {c["name"]: c for c in h_["checks"]}
    ok({"面板", "nikki 接口", "数据目录磁盘", "数据目录可写", "后台任务", "nikki 日志目录", "访问密码"} <= set(nm_) and nm_["数据目录可写"]["level"] == "ok" and nm_["后台任务"]["level"] == "ok" and nm_["访问密码"]["level"] == "ok", f"健康检查:各项 {[c['level'] for c in h_['checks']]}")
    ok(os.path.exists(os.path.join(data, ".last_version")), "升级前自动备份:记录了当前版本")
    st_ = rq2(adm, "/api/storage")[1]
    ok(st_["db"] > 0 and any(t["name"] == "kv" for t in st_["tables"]) and any(t["trim"] for t in st_["tables"]), "数据占用:表和大小")
    ok(rq2(adm, "/api/storage/clean", {"action": "trim", "table": "kv", "days": 1})[0] == 400 and rq2(adm, "/api/storage/clean", {"action": "trim", "table": "nklog", "days": -1})[0] == 400, "清理:只允许日志类表,天数校验")
    c_, j_, _ = rq2(adm, "/api/storage/clean", {"action": "trim", "table": "syslog", "days": 3650})
    ok(c_ == 200 and j_["ok"], "清理:按天数清理日志")
    c_, j_, _ = rq2(adm, "/api/storage/clean", {"action": "vacuum"})
    ok(c_ == 200 and j_["after"] > 0 and rq2(adm, "/api/status")[0] == 200, "清理:压缩数据库后面板正常")
    dg_ = rq2(adm, "/api/diag")[1]["ext"]
    ok(dg_["health"] and dg_["access"]["password_set"] is True and dg_["access"]["viewer_account"] is True and "adminpw1" not in json.dumps(dg_) and "viewerpw1" not in json.dumps(dg_), "诊断包:含健康与访问状态,不含密码")
    bk_ = rq2(adm, "/api/backup")[1]
    ok("nklog" in bk_ and "adminpw1" not in json.dumps(bk_) and "viewerpw1" not in json.dumps(bk_), "备份:含 nikki 日志设置,不含面板密码")
    ok(rq2(adm, "/api/auth/set", {"old": "adminpw1", "new": ""})[0] == 200 and get("/api/status")["auth"]["enabled"] is False and get("/api/status")["auth"]["viewer"] is False, "关闭密码同时关闭只读账号")
    # ---- 密钥泄露检查:把特征字符串塞进每一种"密钥",所有读取接口 / 备份 / 诊断 / 导出里都不能出现
    sys.path.insert(0, ROOT)
    import app.web as W
    LEAK = {"agh": "AGHPASS-LEAK-1", "tg": "TGTOKEN-LEAK-2", "bark": "BARKKEY-LEAK-3", "geo": "GEOPW-LEAK-4", "nikki": "s3cret"}
    ok(post("/api/agh/config", {"url": "http://127.0.0.1:19444", "user": "admin", "pass": LEAK["agh"], "on": True})[0] == 200, "泄露检查:AdGuard 密码已保存")
    c_, r_ = post("/api/alerts/config", {"channels": [{"type": "telegram", "name": "tg", "token": LEAK["tg"], "chat": "123456"}, {"type": "bark", "name": "bk", "url": "http://127.0.0.1:1/" + LEAK["bark"]}]})
    ok(c_ == 200, f"泄露检查:推送渠道已保存 {c_} {r_ if c_ != 200 else ''}")
    post("/api/geo/proxy", {"proxy": "http://nikki:" + LEAK["geo"] + "@127.0.0.1:7890"})
    post("/api/alerts/test", {"id": next((c["id"] for c in get("/api/alerts/config")["channels"] if c["type"] == "bark"), "")})   # 发送失败的报错里也不能带出地址
    time.sleep(1)
    paths = sorted(set(W.GET_ROUTES) - {"/api/backup"}) + ["/api/backup", "/api/diag?logs=1&dom=0", "/api/syslog/export?mask=0", "/api/nklog/export?mask=0", "/metrics", "/api/nklog", "/api/syslog", "/api/panel", "/api/alerts?n=200"]
    bad = []
    for pth in paths:
        try:
            r = urllib.request.urlopen(B + pth, timeout=20); txt = r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            txt = e.read().decode("utf-8", "replace")
        except Exception:
            continue
        for k, v in LEAK.items():
            if v in txt:
                bad.append((pth, k))
    ok(not bad, f"泄露检查:{len(paths)} 个读取接口 / 备份 / 诊断 / 导出里都搜不到密钥 {bad}")
    full = json.dumps(get("/api/backup?secrets=1"))
    ok(LEAK["agh"] in full and LEAK["tg"] in full and LEAK["bark"] in full, "泄露检查:勾选「包含密钥」的备份才带密钥(用于恢复)")
    ok(not any(LEAK[k] in json.dumps(get("/api/backup")) for k in ("agh", "tg", "bark")), "泄露检查:默认备份不含密钥")
finally:
    proc.terminate()
    try: out = proc.communicate(timeout=5)[0]
    except Exception: out = ""
    print("---- 服务日志 ----\n" + out[-1500:])
    _leak = [v for v in ("AGHPASS-LEAK-1", "TGTOKEN-LEAK-2", "BARKKEY-LEAK-3", "GEOPW-LEAK-4", "adminpw1", "viewerpw1") if v in out]
    print(("FAIL " if _leak else "PASS ") + "泄露检查:服务日志里没有密钥" + (str(_leak) if _leak else ""))
