"""生成 README 用的演示截图(模拟的 nikki / AdGuard / Docker,不含任何真实数据):python3 tests/docshots.py"""
import json, math, os, random, sqlite3, subprocess, sys, tempfile, time, urllib.request
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import mock_mihomo, mock_docker
mock_mihomo.start(19297, 18992); mock_mihomo.start_agh(19444); mock_docker.start(19331)
mock_mihomo.STATE["leak"] = True
data = tempfile.mkdtemp(); neigh = data + "/n"
open(neigh, "w").write("192.168.1.10 dev br lladdr aa:bb:cc:dd:ee:01 REACHABLE\nfd00::10 dev br lladdr aa:bb:cc:dd:ee:01 STALE\n192.168.1.20 dev br lladdr aa:bb:cc:dd:ee:02 REACHABLE\n")
env = dict(os.environ, DATA_DIR=data, NIKKI_API="http://127.0.0.1:19297", NIKKI_SECRET="s3cret", INTERVAL_SEC="2", FLUSH_SEC="2",
           LISTEN_HOST="127.0.0.1", LISTEN_PORT="18222", NEIGH_FILE=neigh, APP_VERSION=open(os.path.join(ROOT, "VERSION")).read().strip())
# 演示里宽带探测改用本机回环,避免沙箱出不去公网时概览出现红色「不通」(只影响截图,不改程序默认)
BOOT = "import runpy, app.wan as w; w.DEFAULT_TARGETS = ['127.0.0.1']; runpy.run_module('app', run_name='__main__')"
p = subprocess.Popen([sys.executable, "-c", BOOT], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
B = "http://127.0.0.1:18222"
OUT = os.path.join(ROOT, "docs", "img"); os.makedirs(OUT, exist_ok=True)


def post(path, body):
    urllib.request.urlopen(urllib.request.Request(B + path, json.dumps(body).encode(), {"Content-Type": "application/json"}))



def seed_demo():
    """预填演示用的历史数据:两周的小时流量(让热力图有规律可看)和几台"新设备"。全是编造的。"""
    con = sqlite3.connect(os.path.join(data, "traffic.db"), timeout=30)
    rnd = random.Random(7)
    now = time.time()
    macs = {"aa:bb:cc:dd:ee:01": 1.0, "aa:bb:cc:dd:ee:02": 2.2}
    for d in range(14, -1, -1):
        for h in range(24):
            t = now - d * 86400
            lt = time.localtime(t)
            hour = time.strftime("%Y-%m-%d ", lt) + "%02d" % h
            wk = lt.tm_wday >= 5
            # 晚上 19-23 点最忙;周末白天也有流量;凌晨几乎没有
            base = 0.04 + 0.9 * math.exp(-((h - 21) ** 2) / 8) + (0.45 * math.exp(-((h - 14) ** 2) / 18) if wk else 0.22 * math.exp(-((h - 9) ** 2) / 6))
            for m, k in macs.items():
                v = base * k * rnd.uniform(0.6, 1.4) * 6e7
                if d == 5 and h == 22 and m.endswith("02"):
                    v *= 14            # 一次大下载,用来演示「中位数」不被带偏
                con.execute("INSERT OR REPLACE INTO hourly(hour,client,node,up,down) VALUES(?,?,?,?,?)", (hour, m, "香港 01", int(v * .12), int(v)))
    # known_dev:一条很早的记录当"首次启动时已有的设备",之后才出现的才算新设备
    con.execute("INSERT OR REPLACE INTO known_dev(client,first) VALUES(?,?)", ("aa:bb:cc:dd:ee:01", int(now - 40 * 86400)))
    con.execute("INSERT OR REPLACE INTO known_dev(client,first) VALUES(?,?)", ("aa:bb:cc:dd:ee:02", int(now - 40 * 86400)))
    for i, (mac, ip, ago) in enumerate([("aa:bb:cc:dd:ee:11", "192.168.1.31", 2 * 3600), ("aa:bb:cc:dd:ee:12", "192.168.1.32", 7 * 3600),
                                        ("aa:bb:cc:dd:ee:13", "192.168.1.33", 30 * 3600), ("aa:bb:cc:dd:ee:14", "192.168.1.34", 5 * 86400)]):
        con.execute("INSERT OR REPLACE INTO known_dev(client,first) VALUES(?,?)", (mac, int(now - ago)))
        con.execute("INSERT OR REPLACE INTO ipmap(ip,mac,seen) VALUES(?,?,?)", (ip, mac, int(now)))
    con.commit(); con.close()


try:
    time.sleep(20)
    seed_demo()
    post("/api/device", {"dev": "aa:bb:cc:dd:ee:01", "name": "小林的手机"})
    post("/api/device", {"dev": "aa:bb:cc:dd:ee:02", "name": "客厅电视"})
    post("/api/device", {"dev": "aa:bb:cc:dd:ee:13", "name": "书房平板"})
    post("/api/agh/config", {"url": "127.0.0.1:19444", "user": "admin", "pass": "pw123"})
    post("/api/docker/cfg", {"on": True, "url": "http://127.0.0.1:19331"})
    post("/api/auth/set", {"new": "demo-pass-123"})
    time.sleep(6)
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        br = pw.chromium.launch(**({"executable_path":os.environ.get("CHROMIUM_PATH","/opt/pw-browsers/chromium")} if os.path.exists(os.environ.get("CHROMIUM_PATH","/opt/pw-browsers/chromium")) else {}), args=["--no-sandbox"])
        # 登录页(未登录状态)
        pg = br.new_context(viewport={"width": 1280, "height": 760}).new_page()
        pg.goto(B + "/"); pg.wait_for_timeout(1200); pg.screenshot(path=f"{OUT}/login.png")
        for scheme in ("light", "dark"):
            ctx = br.new_context(viewport={"width": 1280, "height": 860}, color_scheme=scheme); pg = ctx.new_page()
            pg.goto(B + "/"); pg.wait_for_timeout(800)
            pg.fill("#p", "demo-pass-123"); pg.click("#b"); pg.wait_for_timeout(3500)
            pg.evaluate("TH.viz.style='wave';TH.trend.style='smooth';themeChanged(true)"); pg.wait_for_timeout(2500)
            go = lambda t: (pg.evaluate(f"S.tab='{t}';showTab();refresh()"), pg.wait_for_timeout(3500))
            go("overview"); pg.screenshot(path=f"{OUT}/overview{'-dark' if scheme == 'dark' else ''}.png")
            if scheme == "light":
                pg.click("#glCfg"); pg.wait_for_timeout(600); pg.screenshot(path=f"{OUT}/status-popover.png", clip={"x": 0, "y": 0, "width": 1280, "height": 520})
                pg.keyboard.press("Escape"); pg.evaluate("document.getElementById('glPop')&&document.getElementById('glPop').remove()")
            if scheme == "dark":
                continue
            go("nodes"); pg.screenshot(path=f"{OUT}/nodes.png")
            go("devices"); pg.wait_for_timeout(1500); pg.screenshot(path=f"{OUT}/devices.png")
            nd = pg.query_selector("#newDevCard")
            if nd and nd.is_visible():
                nd.screenshot(path=f"{OUT}/devices-new.png")
            else:
                print("警告:新设备卡没有出现")
            go("rules"); pg.fill("#rtIn", "www.baidu.com"); pg.click("#rtGo"); pg.wait_for_timeout(3500); pg.screenshot(path=f"{OUT}/rules.png")
            go("domains"); pg.fill("#lkpIn", "www.bilibili.com"); pg.click("#lkpGo"); pg.wait_for_timeout(3500); pg.screenshot(path=f"{OUT}/lookup.png")
            go("security"); pg.wait_for_timeout(2500); pg.evaluate("secTab('ov',true)"); pg.wait_for_timeout(500); pg.screenshot(path=f"{OUT}/security.png")
            pg.evaluate("secTab('dns',true)"); pg.wait_for_timeout(800); pg.screenshot(path=f"{OUT}/security-dns.png")
            pg.evaluate("secTab('diag',true)"); pg.wait_for_timeout(800); pg.screenshot(path=f"{OUT}/analysis.png")
            pg.evaluate("secTab('rv',true)"); pg.wait_for_timeout(2500); pg.screenshot(path=f"{OUT}/heatmap.png")
            pg.evaluate("secTab('ov',true)")
            go("alerts"); pg.screenshot(path=f"{OUT}/alerts.png")
            go("docker"); pg.screenshot(path=f"{OUT}/docker.png")
            pg.evaluate("openSettings('look')"); pg.wait_for_timeout(3000); pg.screenshot(path=f"{OUT}/settings.png")
        for scheme in ("light", "dark"):
            ctx = br.new_context(viewport={"width": 390, "height": 800}, device_scale_factor=2, color_scheme=scheme); pm = ctx.new_page()
            pm.goto(B + "/"); pm.wait_for_timeout(800); pm.fill("#p", "demo-pass-123"); pm.click("#b"); pm.wait_for_timeout(3500)
            pm.screenshot(path=f"{OUT}/mobile-{scheme}.png")
        br.close()
    print("截图已更新:", sorted(os.listdir(OUT)))
finally:
    p.terminate()
