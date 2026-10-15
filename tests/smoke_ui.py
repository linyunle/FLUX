"""浏览器冒烟测试(需要 playwright + chromium):打开「安全」页,各卡片都有内容、控制台没有报错。"""
import os, subprocess, sys, tempfile, time, shutil
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT+'/tests')
import mock_mihomo
mock_mihomo.start(19091, 18998); mock_mihomo.start_agh(19445); mock_mihomo.STATE["leak"]=True
data=tempfile.mkdtemp(); neigh=data+"/n"
os.makedirs(data+"/geoip"); shutil.copy(ROOT+"/tests/data/country-test.mmdb",data+"/geoip/"); shutil.copy(ROOT+"/tests/data/asn-test.mmdb",data+"/geoip/")
open(neigh,"w").write("192.168.1.10 dev br lladdr aa:bb:cc:dd:ee:01 REACHABLE\n")
env=dict(os.environ,DATA_DIR=data,NIKKI_API="http://127.0.0.1:19091",NIKKI_SECRET="s3cret",INTERVAL_SEC="2",FLUSH_SEC="2",PROXY_SEC="2",LISTEN_HOST="127.0.0.1",LISTEN_PORT="18101",NEIGH_FILE=neigh,APP_VERSION="v0.11.5")
p=subprocess.Popen([sys.executable,"-m","app"],cwd=ROOT,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)

try:
    time.sleep(25)
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        br=pw.chromium.launch(executable_path="/opt/pw-browsers/chromium",args=["--no-sandbox"])
        pg=br.new_page(viewport={"width":1200,"height":1000}); msgs=[]
        pg.on("pageerror",lambda e: msgs.append("ERR "+str(e))); pg.on("console",lambda m: msgs.append(m.type+" "+m.text) if m.type in("warning","error") else None)
        pg.goto("http://127.0.0.1:18101/"); pg.wait_for_timeout(2000)
        import json
        pg.evaluate("fetch('/api/agh/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:'http://127.0.0.1:19445',user:'admin',pass:'pw123'})})"); pg.wait_for_timeout(500)
        pg.evaluate("S.tab='security';showTab();refresh()"); pg.wait_for_timeout(3000);         bad = [m for m in msgs if "favicon" not in m and "ERR_" not in m and "Failed to load resource" not in m]
        for sel in ("#secTiles", "#secFinds", "#aghBody", "#lkBody", "#geoBody", "#hmBody", "#qBody"):
            assert pg.inner_text(sel).strip(), "安全页卡片内容为空:" + sel
        assert not bad, bad
        pg.evaluate("S.tab='overview';showTab();refresh()"); pg.wait_for_timeout(3500)
        assert pg.inner_text("#sysTiles").strip(), "路由器状态卡片为空"
        # 外观设置:刷新后要还在;浏览器清空后要从服务器取回
        pg.evaluate("applyView('ts');TH.vh.ts=['trend'];TH.hide=['trend'];themeChanged(true)"); pg.wait_for_timeout(2500)
        pg.reload(); pg.wait_for_timeout(2500)
        assert pg.evaluate("TH.view")=="ts" and pg.evaluate("TH.vh.ts&&TH.vh.ts.includes('trend')"), "刷新后外观设置丢了"
        pg.evaluate("localStorage.removeItem('nt.theme.v1')"); pg.reload(); pg.wait_for_timeout(3500)
        assert pg.evaluate("TH.view")=="ts", "浏览器清空后没有从服务器取回外观设置"
        pg.evaluate("S.set='backup';openSettings('backup')"); pg.wait_for_timeout(1200)
        with pg.expect_download() as dl: pg.click("#bkDl")
        import json as _j; bk=_j.load(open(dl.value.path())); assert bk["flux_backup"]==1 and bk["ui"]["view"]=="ts", "备份下载内容不对"
        pg.once("dialog", lambda d: d.accept()); pg.set_input_files("#bkFile", dl.value.path()); pg.wait_for_timeout(1000)
        assert "已恢复" in pg.inner_text("#bkMsg"), pg.inner_text("#bkMsg")
        # 设置 → 概览卡片:取消 / 重新勾选要真的生效(点名字也行),预设按钮也要生效
        pg.evaluate("openSettings('look')"); pg.wait_for_timeout(800)
        pg.locator('#lkCards label[for=lkc_alertc]').click(); pg.wait_for_timeout(400)
        assert pg.evaluate("TH.hide.includes('alertc')"), "取消勾选没进 TH.hide"
        pg.evaluate("S.tab='overview';showTab();refresh()"); pg.wait_for_timeout(600)
        assert pg.evaluate("getComputedStyle(document.querySelector('#alertCard')).display")=="none", "取消勾选后卡片还在"
        pg.evaluate("openSettings('look')"); pg.wait_for_timeout(600)
        pg.locator('#lkCards input[data-k=alertc]').click(); pg.wait_for_timeout(400)
        pg.evaluate("S.tab='overview';showTab();refresh()"); pg.wait_for_timeout(600)
        assert pg.evaluate("getComputedStyle(document.querySelector('#alertCard')).display")!="none", "重新勾选后卡片没出现"
        pg.evaluate("openSettings('look')"); pg.wait_for_timeout(600)
        pg.locator('#lkView button').nth(1).click(); pg.wait_for_timeout(400)
        assert pg.evaluate("TH.hide.includes('apps')"), "预设「总览」没生效"
        pg.locator('#lkView button').nth(0).click(); pg.wait_for_timeout(400)
        assert pg.evaluate("TH.hide.length")==0, "预设「全部」没生效"
        # 手机尺寸:访问目标卡片附近,页面高度/滚动位置不应随实时刷新变化
        pg.set_viewport_size({"width":390,"height":800}); pg.evaluate("S.tab='overview';showTab();refresh()"); pg.wait_for_timeout(2500)
        pg.evaluate("document.querySelector('#rthostCard').scrollIntoView()"); pg.wait_for_timeout(500)
        y0=pg.evaluate("[scrollY,document.documentElement.scrollHeight]")
        for _ in range(8):
            pg.wait_for_timeout(1000); assert pg.evaluate("[scrollY,document.documentElement.scrollHeight]")==y0, "手机上页面在实时刷新时跳动"
        # 预设里的勾选要记在该预设里;三张卡片有行数设置
        pg.set_viewport_size({"width":1200,"height":1000}); pg.evaluate("openSettings('look')"); pg.wait_for_timeout(800)
        pg.locator('#lkView button').nth(2).click(); pg.wait_for_timeout(400)   # 排障
        pg.locator('#lkCards input[data-k=trend]').click(); pg.wait_for_timeout(300)
        pg.locator('#lkView button').nth(1).click(); pg.wait_for_timeout(300)   # 总览
        pg.locator('#lkView button').nth(2).click(); pg.wait_for_timeout(300)   # 回到排障
        assert pg.evaluate("TH.view")=="ts" and not pg.evaluate("TH.hide.includes('trend')"), "预设里的修改没有被记住"
        pg.locator('#lkView button').nth(0).click(); pg.wait_for_timeout(300)
        assert pg.evaluate("TH.hide.length")==0, "「全部」应显示所有卡片"
        for k in ("alertc","apps","qoe"):
            assert pg.locator(f'#lkCards select[data-k={k}][data-f=rows]').count()==1, "缺少行数设置:"+k
        pg.locator('#lkCards select[data-k=alertc][data-f=rows]').select_option("3"); pg.wait_for_timeout(300)
        assert pg.evaluate("TH.cards.alertc.rows")==3
        print("PASS 安全页各卡片都有内容,浏览器无报错")
finally:
    p.terminate()
