import os, subprocess, sys, tempfile, time, json, urllib.request
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import mock_mihomo
mock_mihomo.start(19091, 18998)
data = tempfile.mkdtemp(); neigh = data + "/n"
open(neigh, "w").write("192.168.1.10 dev br lladdr aa:bb:cc:dd:ee:01 REACHABLE\nfd00::10 dev br lladdr aa:bb:cc:dd:ee:01 STALE\n192.168.1.20 dev br lladdr aa:bb:cc:dd:ee:02 REACHABLE\n")
env = dict(os.environ, DATA_DIR=data, NIKKI_API="http://127.0.0.1:19091", NIKKI_SECRET="s3cret", INTERVAL_SEC="2", FLUSH_SEC="2",
           LISTEN_HOST="127.0.0.1", LISTEN_PORT="18098", NEIGH_FILE=neigh, APP_VERSION="v0.2.0")
p = subprocess.Popen([sys.executable, "-m", "app"], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
B = "http://127.0.0.1:18098"
try:
    time.sleep(10)
    urllib.request.urlopen(urllib.request.Request(B + "/api/device", json.dumps({"dev": "aa:bb:cc:dd:ee:01", "name": "小林的手机"}).encode(), {"Content-Type": "application/json"}))
    urllib.request.urlopen(urllib.request.Request(B + "/api/airports/rules", json.dumps({"text": "HK-=机场甲\nJP-=机场乙"}).encode(), {"Content-Type": "application/json"}))
    time.sleep(4)
    from playwright.sync_api import sync_playwright
    out = os.path.join(HERE, "shots"); os.makedirs(out, exist_ok=True)
    with sync_playwright() as pw:
        br = pw.chromium.launch(executable_path="/opt/pw-browsers/chromium", args=["--no-sandbox"])
        for scheme, w, h in (("light", 1100, 900), ("dark", 1100, 900), ("light", 390, 800)):
            pg = br.new_page(viewport={"width": w, "height": h}, color_scheme=scheme)
            errs = []
            pg.on("console", lambda m: errs.append(m.text) if m.type == "error" else None)
            pg.on("pageerror", lambda e: errs.append(str(e)))
            pg.goto(B + "/"); pg.wait_for_timeout(1500)
            nav = lambda k: (pg.click(f'.navi[data-k="{k}"]'), pg.wait_for_timeout(1000))
            for tab in ("overview", "airports", "nodes", "devices", "domains", "rules", "settings"):
                nav(tab)
                pg.screenshot(path=f"{out}/{scheme}-{w}-{tab}.png", full_page=True)
            nav("airports"); pg.click("#apTbl tbody tr"); pg.wait_for_timeout(600)
            nav("nodes"); pg.screenshot(path=f"{out}/{scheme}-{w}-airport-filtered-nodes.png", full_page=True)
            pg.click("#chips b"); pg.wait_for_timeout(300)
            if w > 500 and scheme == "light":
                nav("overview"); pg.click("#devBtn"); pg.wait_for_timeout(500)
                pg.screenshot(path=f"{out}/light-{w}-devdropdown.png"); pg.keyboard.press("Escape")
                nav("settings")
                for k in ("conn", "airport", "devices"):
                    pg.click(f'#setNav button[data-k="{k}"]'); pg.wait_for_timeout(500)
                    pg.screenshot(path=f"{out}/light-{w}-set-{k}.png")
            if w > 500:
                nav("settings"); pg.click('#setNav button[data-k="look"]'); pg.wait_for_timeout(300)
                for k in ("ocean", "violet", "graphite", "rose", "forest"):
                    pg.click(f'#lkPreset button[data-k="{k}"]'); pg.wait_for_timeout(250)
                    nav("overview"); pg.screenshot(path=f"{out}/{scheme}-{w}-theme-{k}.png")
                    nav("settings")
                pg.click('#lkDens button[data-k="compact"]'); pg.click('#lkWidth button[data-k="f"]'); pg.click('#lkRad button[data-k="l"]'); pg.click('#lkFont button[data-k="l"]')
                pg.click('#lkCards button[data-k="hosts"][data-d="-1"]'); pg.click('#lkCards input[data-k="rtdev"]')
                pg.select_option('#lkCards select[data-k="rtd"][data-f="w"]', "6"); pg.select_option('#lkCards select[data-k="rtp"][data-f="w"]', "6"); pg.select_option('#lkCards select[data-k="rt"][data-f="w"]', "12")
                pg.click('#lkTStyle button[data-k="area"]'); pg.click('#lkSplit'); pg.wait_for_timeout(300)
                nav("overview"); pg.screenshot(path=f"{out}/{scheme}-{w}-layout.png", full_page=True)
                for st in ("line", "group", "bars"):
                    pg.click(f'#tStyle button[data-k="{st}"]'); pg.wait_for_timeout(200); pg.locator("#trendCard").screenshot(path=f"{out}/{scheme}-{w}-trend-{st}.png")
                if scheme == "light":
                    nav("devices"); pg.click("#devTbl tbody tr"); pg.wait_for_timeout(1500); pg.screenshot(path=f"{out}/light-{w}-device-detail.png", full_page=True)
                    pg.click("#ddFilter"); pg.wait_for_timeout(1500); pg.screenshot(path=f"{out}/light-{w}-overview-onedev.png", full_page=True)
                    pg.evaluate("window.scrollTo(0, 400)"); pg.wait_for_timeout(300)
                    top = pg.evaluate("document.querySelector('#tiles').getBoundingClientRect().top")
                    print("滚动后统计卡片 top =", top); pg.screenshot(path=f"{out}/light-{w}-sticky.png")
                    pg.evaluate("window.scrollTo(0, 0)"); pg.click("#devBtn"); pg.click("#devClear"); pg.keyboard.press("Escape")
                print("localStorage:", pg.evaluate("localStorage.getItem('nt.theme.v1')"))
                nav("settings"); pg.click("#lkReset"); pg.wait_for_timeout(200)
            if w <= 500:
                pg.click("#btnMode"); pg.wait_for_timeout(300)
            overflow = pg.evaluate("document.documentElement.scrollWidth > window.innerWidth")
            print(scheme, w, "errors:", errs, "横向溢出:", overflow)
            pg.close()
        br.close()
finally:
    p.terminate()
