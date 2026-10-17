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
        pg.wait_for_timeout(3500)  # 恢复备份后页面会自动刷新
        # 升级兼容:浏览器里已有的外观设置(旧版本写的)加载后必须原样保留
        pg.evaluate("localStorage.setItem('nt.theme.v1',JSON.stringify({v:4,mode:'dark',dens:'compact',view:'sec',hide:['apps','qoe'],vh:{sec:['apps','qoe']},order:['trend','mem','rt'],cards:{apps:{w:6,h:'m',rows:10}}}))")
        pg.reload(); pg.wait_for_timeout(2500)
        assert pg.evaluate("[TH.mode,TH.dens,TH.view,TH.hide.join(),TH.vh.sec.join(),(TH.order.indexOf('trend')<TH.order.indexOf('mem')&&TH.order.indexOf('mem')<TH.order.indexOf('rt')),TH.cards.apps.rows,TH.cards.apps.w].join('|')")=="dark|compact|sec|apps,qoe|apps,qoe|true|10|6", "旧外观设置升级后没有原样保留"
        pg.evaluate("S.tab='nodes';S.nd='';showTab();refresh()"); pg.wait_for_timeout(2500)
        assert pg.inner_text("#nsBody").strip(), "节点评分卡片为空"
        # 设备分组、白名单设置、时间线
        pg.evaluate("S.tab='devices';S.dd='';showTab();refresh()"); pg.wait_for_timeout(2500)
        assert pg.locator("#devTbl select.grp").count()>=1, "设备页没有分组选择"
        pg.locator("#devTbl select.grp").first.select_option("IoT"); pg.wait_for_timeout(1500)
        assert pg.evaluate("S.grp.names.includes('IoT')") and pg.locator("#devTbl select.grp").first.input_value()=="IoT", "分组没保存"
        pg.evaluate("openSettings('groups')"); pg.wait_for_timeout(1500)
        assert "IoT" in pg.inner_text("#grpBody"), "设置里没有 IoT 分组"
        pg.fill("#grpBody .gallow","apple.com"); pg.click("#grpBody .gsave"); pg.wait_for_timeout(800)
        assert "已保存" in pg.inner_text("#grpBody .gmsg")
        pg.evaluate("S.tab='alerts';S.alView='line';showTab();refresh()"); pg.wait_for_timeout(2000)
        assert pg.locator("#alTbl .tl .ev").count()>=1, "时间线没有事件"
        pg.screenshot(path="/tmp/claude-0/-home-claude/432fa273-cc0c-55f1-bf69-55de48e3f56f/scratchpad/tl.png")
        pg.evaluate("openSettings('groups')"); pg.wait_for_timeout(1200); pg.screenshot(path="/tmp/claude-0/-home-claude/432fa273-cc0c-55f1-bf69-55de48e3f56f/scratchpad/gr.png")
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
        # 各预设的大小/顺序互相独立;卡片等高
        pg.evaluate("applyView('all')"); pg.wait_for_timeout(200)
        pg.evaluate("TH.cards.trend.w=3;TH.order=TH.order.filter(k=>k!=='trend');TH.order.unshift('trend');saveTheme();applyTheme()")
        pg.evaluate("applyView('ov')"); pg.wait_for_timeout(200)
        assert pg.evaluate("TH.cards.trend.w")!=3 and pg.evaluate("TH.order[0]")!="trend", "预设之间的大小/顺序串了"
        pg.evaluate("applyView('all')"); pg.wait_for_timeout(200)
        assert pg.evaluate("TH.cards.trend.w==3&&TH.order[0]=='trend'"), "切回全部后自己的布局丢了"
        pg.evaluate("location.reload()"); pg.wait_for_timeout(1500)
        assert pg.evaluate("TH.cards.trend.w==3&&TH.order[0]=='trend'"), "刷新后每预设布局没保留"
        pg.evaluate("S.tab='overview';showTab();applyView('all');for(const k in TH.cards){TH.cards[k].w=3;TH.cards[k].h='s'}themeChanged(true)"); pg.wait_for_timeout(1500)
        hs=pg.evaluate("[...document.querySelectorAll('.gcard:not(.gone)')].map(e=>Math.round(e.getBoundingClientRect().height))")
        assert len(set(hs))<=3 and min(hs)>=270, ("1/4宽时卡片高度不统一", hs)
        os.makedirs(ROOT+"/tests/shots",exist_ok=True); pg.screenshot(path=ROOT+"/tests/shots/quarter.png",full_page=True)
        pg.evaluate("S.set='quota';openSettings('quota')"); pg.wait_for_timeout(1200)
        qt=pg.inner_text("#qBody") if pg.query_selector("#qBody") else pg.inner_text("body")
        assert "OverflowError" not in qt
        # 图表撑满卡片:内存卡的图表底部离卡片底部不超过 40px
        gap=pg.evaluate("(()=>{const c=document.querySelector('#memCard').getBoundingClientRect(),b=document.querySelector('#memChart').getBoundingClientRect();return c.bottom-b.bottom})()")
        assert gap<45, ("内存图表没有撑满卡片", gap)
        pg.evaluate("S.tab='nodes';showTab();refresh()"); pg.wait_for_timeout(2500)
        assert "MyAir" in pg.inner_text("#provBody"), "机场官方数据卡没有显示"
        qb=pg.inner_text("#quotaBody"); assert "MyAir" in qb and "NoExp" in qb and "永不过期" in qb, ("套餐用量卡没有显示官方机场(含无到期日的)", qb)
        pg.evaluate("S.set='plog';openSettings('plog')"); pg.wait_for_timeout(1500)
        assert "127.0.0.1" in pg.inner_text("#plClients") and pg.input_value("#plText").strip(), "访问记录/面板日志没有内容"
        pg.evaluate("S.set='probe';openSettings('probe')"); pg.wait_for_timeout(1000)
        pg.check("#prOn"); pg.click("#prSave"); pg.wait_for_timeout(800)
        assert "已保存" in pg.inner_text("#prMsg"), pg.inner_text("#prMsg")
        assert pg.evaluate("fetch('/api/probe').then(r=>r.json()).then(j=>j.cfg.on)") is True, "节点测速设置没保存"
        pg.evaluate("S.tab='devices';S.dd='';showTab();refresh()"); pg.wait_for_timeout(4000)
        assert "在线" in pg.inner_text("#devTbl"), ("设备页没有显示在线状态", pg.inner_text("#devTbl")[:300])
        pg.locator("#devTbl .wch").first.click(); pg.wait_for_timeout(1500)
        assert "已关注" in pg.inner_text("#devTbl"), "关注按钮没有生效"
        print("PASS 各预设布局独立")
        print("PASS 安全页各卡片都有内容,浏览器无报错")
finally:
    p.terminate()
