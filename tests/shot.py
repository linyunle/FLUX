import os, subprocess, sys, tempfile, time, json, urllib.request
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import mock_mihomo
mock_mihomo.start(19091, 18998)
data = tempfile.mkdtemp(); neigh = data + "/n"
open(neigh, "w").write("192.168.1.10 dev br lladdr aa:bb:cc:dd:ee:01 REACHABLE\nfd00::10 dev br lladdr aa:bb:cc:dd:ee:01 STALE\n192.168.1.20 dev br lladdr aa:bb:cc:dd:ee:02 REACHABLE\n")
env = dict(os.environ, DATA_DIR=data, NIKKI_API="http://127.0.0.1:19091", NIKKI_SECRET="s3cret", INTERVAL_SEC="2", FLUSH_SEC="2",
           LISTEN_HOST="127.0.0.1", LISTEN_PORT="18098", NEIGH_FILE=neigh, PROBE_PORT="18998", EGRESS_INTERVAL_H="0",
           EGRESS_ECHO_URL="http://echo.test/ip", APP_VERSION="v0.2.0")
p = subprocess.Popen([sys.executable, "-m", "app"], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
B = "http://127.0.0.1:18098"
try:
    time.sleep(10)
    urllib.request.urlopen(urllib.request.Request(B + "/api/egress/probe", b"{}", {"Content-Type": "application/json"}))
    urllib.request.urlopen(urllib.request.Request(B + "/api/device", json.dumps({"dev": "aa:bb:cc:dd:ee:01", "name": "小林的手机"}).encode(), {"Content-Type": "application/json"}))
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
            for tab in ("overview", "egress", "devices", "rules"):
                pg.click(f'.tab[data-k="{tab}"]'); pg.wait_for_timeout(1200)
                pg.screenshot(path=f"{out}/{scheme}-{w}-{tab}.png", full_page=True)
            if w > 500 and scheme == "light":
                pg.click('.tab[data-k="overview"]'); pg.click("#devBtn"); pg.wait_for_timeout(500)
                pg.screenshot(path=f"{out}/light-{w}-devdropdown.png")
                pg.keyboard.press("Escape"); pg.click("#btnSet"); pg.wait_for_timeout(500)
                pg.screenshot(path=f"{out}/light-{w}-settings.png")
            overflow = pg.evaluate("document.documentElement.scrollWidth > window.innerWidth")
            print(scheme, w, "errors:", errs, "横向溢出:", overflow)
            pg.close()
        br.close()
finally:
    p.terminate()
