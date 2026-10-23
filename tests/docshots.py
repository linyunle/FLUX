"""生成 README 用的演示截图(模拟的 nikki / AdGuard / Docker,不含任何真实数据):python3 tests/docshots.py"""
import json, os, subprocess, sys, tempfile, time, urllib.request
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import mock_mihomo, mock_docker
mock_mihomo.start(19297, 18992); mock_mihomo.start_agh(19444); mock_docker.start(19331)
mock_mihomo.STATE["leak"] = True
data = tempfile.mkdtemp(); neigh = data + "/n"
open(neigh, "w").write("192.168.1.10 dev br lladdr aa:bb:cc:dd:ee:01 REACHABLE\nfd00::10 dev br lladdr aa:bb:cc:dd:ee:01 STALE\n192.168.1.20 dev br lladdr aa:bb:cc:dd:ee:02 REACHABLE\n")
env = dict(os.environ, DATA_DIR=data, NIKKI_API="http://127.0.0.1:19297", NIKKI_SECRET="s3cret", INTERVAL_SEC="2", FLUSH_SEC="2",
           LISTEN_HOST="127.0.0.1", LISTEN_PORT="18222", NEIGH_FILE=neigh, APP_VERSION=open(os.path.join(ROOT, "VERSION")).read().strip())
p = subprocess.Popen([sys.executable, "-m", "app"], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
B = "http://127.0.0.1:18222"
OUT = os.path.join(ROOT, "docs", "img"); os.makedirs(OUT, exist_ok=True)


def post(path, body):
    urllib.request.urlopen(urllib.request.Request(B + path, json.dumps(body).encode(), {"Content-Type": "application/json"}))


try:
    time.sleep(20)
    post("/api/device", {"dev": "aa:bb:cc:dd:ee:01", "name": "小林的手机"})
    post("/api/device", {"dev": "aa:bb:cc:dd:ee:02", "name": "客厅电视"})
    post("/api/agh/config", {"url": "127.0.0.1:19444", "user": "admin", "pass": "pw123"})
    post("/api/docker/cfg", {"on": True, "url": "http://127.0.0.1:19331"})
    post("/api/auth/set", {"new": "demo-pass-123"})
    time.sleep(6)
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        br = pw.chromium.launch(executable_path="/opt/pw-browsers/chromium", args=["--no-sandbox"])
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
            if scheme == "dark":
                continue
            go("nodes"); pg.screenshot(path=f"{OUT}/nodes.png")
            go("devices"); pg.screenshot(path=f"{OUT}/devices.png")
            go("rules"); pg.fill("#rtIn", "www.baidu.com"); pg.click("#rtGo"); pg.wait_for_timeout(3500); pg.screenshot(path=f"{OUT}/rules.png")
            go("domains"); pg.fill("#lkpIn", "www.bilibili.com"); pg.click("#lkpGo"); pg.wait_for_timeout(3500); pg.screenshot(path=f"{OUT}/lookup.png")
            go("security"); pg.wait_for_timeout(2500); pg.screenshot(path=f"{OUT}/security.png")
            pg.evaluate("window.scrollTo(0, 1500)"); pg.wait_for_timeout(1500); pg.screenshot(path=f"{OUT}/analysis.png")
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
