"""浏览器冒烟测试(需要 playwright + chromium):打开「安全」页,各卡片都有内容、控制台没有报错。"""
import os, subprocess, sys, tempfile, time, shutil
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT+'/tests')
import mock_mihomo, mock_docker
mock_mihomo.start(19091, 18998); mock_mihomo.start_agh(19445); mock_docker.start(19332); mock_mihomo.STATE["leak"]=True
data=tempfile.mkdtemp(); neigh=data+"/n"
os.makedirs(data+"/geoip"); shutil.copy(ROOT+"/tests/data/country-test.mmdb",data+"/geoip/"); shutil.copy(ROOT+"/tests/data/asn-test.mmdb",data+"/geoip/")
open(neigh,"w").write("192.168.1.10 dev br lladdr aa:bb:cc:dd:ee:01 REACHABLE\n")
env=dict(os.environ,DATA_DIR=data,NIKKI_API="http://127.0.0.1:19091",NIKKI_SECRET="s3cret",INTERVAL_SEC="2",FLUSH_SEC="2",PROXY_SEC="2",LISTEN_HOST="127.0.0.1",LISTEN_PORT="18101",NEIGH_FILE=neigh,APP_VERSION="v0.11.5")
p=subprocess.Popen([sys.executable,"-m","app"],cwd=ROOT,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)

try:
    time.sleep(25)
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        br=pw.chromium.launch(**({"executable_path":os.environ.get("CHROMIUM_PATH","/opt/pw-browsers/chromium")} if os.path.exists(os.environ.get("CHROMIUM_PATH","/opt/pw-browsers/chromium")) else {}),args=["--no-sandbox"])
        pg=br.new_page(viewport={"width":1200,"height":1000}); msgs=[]
        pg.on("pageerror",lambda e: msgs.append("ERR "+str(e))); pg.on("console",lambda m: msgs.append(m.type+" "+m.text) if m.type in("warning","error") else None)
        pg.goto("http://127.0.0.1:18101/"); pg.wait_for_timeout(2000)
        import json
        pg.evaluate("fetch('/api/agh/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:'http://127.0.0.1:19445',user:'admin',pass:'pw123'})})"); pg.wait_for_timeout(500)
        pg.evaluate("S.tab='security';showTab();refresh()"); pg.wait_for_timeout(3000);         bad = [m for m in msgs if "favicon" not in m and "ERR_" not in m and "Failed to load resource" not in m]
        for tab, sels in (("ov", ("#secTiles", "#secFinds", "#qBody")), ("dns", ("#aghBody", "#lkBody")), ("rv", ("#geoBody", "#hmBody"))):
            pg.click(f'#secTabs button[data-k="{tab}"]'); pg.wait_for_timeout(500)
            assert pg.locator(f'.sectab[data-st="{tab}"]').is_visible() and pg.locator('.sectab:visible').count()==1, "安全页页签切换后可见区域不对:" + tab
            for sel in sels:
                assert pg.inner_text(sel).strip(), "安全页卡片内容为空:" + sel
        # 其它页面跳到卡片时要自动切到对应页签
        pg.evaluate("secGo('sec:agh')"); pg.wait_for_timeout(400); assert pg.evaluate("S.secTab")=="dns", "跳转没有切到对应页签"
        pg.click('#secTabs button[data-k="ov"]')
        assert not bad, bad
        pg.evaluate("S.tab='overview';showTab();refresh()"); pg.wait_for_timeout(3500)
        assert pg.inner_text("#sysTiles").strip(), "路由器状态卡片为空"
        assert "宽带" in pg.inner_text("#sysTiles"), "路由器状态卡片没有宽带质量"
        # 外观设置:刷新后要还在;浏览器清空后要从服务器取回
        pg.evaluate("applyView('all');TH.vh.all=['trend'];TH.hide=['trend'];themeChanged(true)"); pg.wait_for_timeout(2500)
        pg.reload(); pg.wait_for_timeout(2500)
        assert pg.evaluate("TH.view")=="all" and pg.evaluate("TH.vh.all&&TH.vh.all.includes('trend')"), "刷新后外观设置丢了"
        pg.evaluate("localStorage.removeItem('nt.theme.v1')"); pg.reload(); pg.wait_for_timeout(3500)
        assert pg.evaluate("TH.view")=="all" and pg.evaluate("TH.vh.all&&TH.vh.all.includes('trend')"), "浏览器清空后没有从服务器取回外观设置"
        pg.evaluate("S.set='backup';openSettings('backup')"); pg.wait_for_timeout(1200)
        with pg.expect_download() as dl: pg.click("#bkDl")
        import json as _j; bk=_j.load(open(dl.value.path())); assert bk["flux_backup"]==1 and bk["ui"]["view"]=="all", "备份下载内容不对"
        pg.once("dialog", lambda d: d.accept()); pg.set_input_files("#bkFile", dl.value.path()); pg.wait_for_timeout(1000)
        assert "已恢复" in pg.inner_text("#bkMsg"), pg.inner_text("#bkMsg")
        pg.wait_for_timeout(3500)  # 恢复备份后页面会自动刷新
        # 升级兼容:浏览器里已有的外观设置(旧版本写的)加载后必须原样保留
        pg.evaluate("localStorage.setItem('nt.theme.v1',JSON.stringify({v:4,mode:'dark',dens:'compact',view:'custom',hide:['apps','qoe'],order:['trend','mem','rt'],cards:{apps:{w:6,h:'m',rows:10}}}))")
        pg.reload(); pg.wait_for_timeout(2500)
        assert pg.evaluate("[TH.mode,TH.dens,TH.view,TH.hide.join(),(TH.order.indexOf('trend')<TH.order.indexOf('mem')&&TH.order.indexOf('mem')<TH.order.indexOf('rt')),TH.cards.apps.rows,TH.cards.apps.w].join('|')")=="dark|compact|custom|apps,qoe|true|10|6", "旧外观设置升级后没有原样保留"
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
        # 旧版本存过已删除的预设(总览 / 诊断 / 安全):升级后回到「状态」,并显示全部卡片
        pg.evaluate("localStorage.setItem('nt.theme.v1',JSON.stringify({v:4,view:'sec',hide:['apps','qoe']}))"); pg.reload(); pg.wait_for_timeout(2500)
        assert pg.evaluate("[TH.view,TH.hide.length].join()")=="all,0", "旧预设没有迁移到「状态」"
        # 「状态」开关:隐藏 / 显示路由器状、内存、实时速度这类全局卡片
        pg.evaluate("S.tab='overview';showTab()"); pg.wait_for_timeout(500)
        pg.click("#viewSeg button"); pg.wait_for_timeout(600)
        assert pg.evaluate("TH.gl")==False and pg.evaluate("getComputedStyle(document.querySelector('#memCard')||document.body).display")!=None
        assert pg.evaluate("['sys','mem','rt','rtdev','rtnode'].every(k=>document.querySelector(CARDS[k][0]).classList.contains('autohide'))"), "关掉「状态」后全局卡片没有隐藏"
        assert pg.evaluate("!document.querySelector(CARDS.trend[0]).classList.contains('autohide')"), "趋势卡片不应被「状态」隐藏"
        pg.click("#viewSeg button"); pg.wait_for_timeout(600)
        assert pg.evaluate("TH.gl")==True and pg.evaluate("!['sys','mem','rt','rtdev','rtnode'].some(k=>document.querySelector(CARDS[k][0]).classList.contains('autohide'))"), "再点一次没有恢复"
        pg.evaluate("openSettings('look')"); pg.wait_for_timeout(600)
        # 手机尺寸:访问目标卡片附近,页面高度/滚动位置不应随实时刷新变化
        pg.set_viewport_size({"width":390,"height":800}); pg.evaluate("S.tab='overview';showTab();refresh()"); pg.wait_for_timeout(2500)
        pg.evaluate("document.querySelector('#rthostCard').scrollIntoView()"); pg.wait_for_timeout(500)
        y0=pg.evaluate("[scrollY,document.documentElement.scrollHeight]")
        for _ in range(8):
            pg.wait_for_timeout(1000); assert pg.evaluate("[scrollY,document.documentElement.scrollHeight]")==y0, "手机上页面在实时刷新时跳动"
        # 预设里的勾选要记在该预设里;三张卡片有行数设置
        pg.set_viewport_size({"width":1200,"height":1000}); pg.evaluate("openSettings('look')"); pg.wait_for_timeout(800)
        assert pg.evaluate("TH.hide.length")==0, "「全部」应显示所有卡片"
        for k in ("alertc","apps","qoe"):
            assert pg.locator(f'#lkCards select[data-k={k}][data-f=rows]').count()==1, "缺少行数设置:"+k
        pg.locator('#lkCards select[data-k=alertc][data-f=rows]').select_option("3"); pg.wait_for_timeout(300)
        assert pg.evaluate("TH.cards.alertc.rows")==3
        # 各预设的大小/顺序互相独立;卡片等高
        pg.evaluate("applyView('all')"); pg.wait_for_timeout(200)
        pg.evaluate("TH.cards.trend.w=3;TH.order=TH.order.filter(k=>k!=='trend');TH.order.unshift('trend');saveTheme();applyTheme()")
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
        pg.wait_for_timeout(1500); assert pg.inner_text("#plFinds").strip() and "自检中" not in pg.inner_text("#plFinds"), "自检没有结果"
        with pg.expect_download() as dd: pg.click("#dgDl")
        import json as _j2; dj=_j2.load(open(dd.value.path())); assert dj["flux_diag"]==1 and dj["masked"], "诊断包下载内容不对"
        pg.evaluate("S.set='probe';openSettings('probe')"); pg.wait_for_timeout(1000)
        pg.check("#prOn"); pg.click("#prSave"); pg.wait_for_timeout(800)
        assert "已保存" in pg.inner_text("#prMsg"), pg.inner_text("#prMsg")
        assert pg.evaluate("fetch('/api/probe').then(r=>r.json()).then(j=>j.cfg.on)") is True, "节点测速设置没保存"
        pg.evaluate("S.set='syslog';openSettings('syslog')"); pg.wait_for_timeout(1200)
        assert "uci set system" in pg.inner_text("#slCmd") and "未开启" in pg.inner_text("#slInfo"), ("路由器日志设置页没有内容", pg.inner_text("#slInfo"))
        pg.check("#slOn"); pg.fill("#slPort","25514"); pg.click("#slSave"); pg.wait_for_timeout(1200)
        assert "已保存" in pg.inner_text("#slMsg"), pg.inner_text("#slMsg")
        assert pg.evaluate("fetch('/api/syslog').then(r=>r.json()).then(j=>j.cfg.on&&j.cfg.port===25514)") is True, "系统日志设置没保存"
        pg.evaluate("S.set='ext';openSettings('ext')"); pg.wait_for_timeout(1500)
        assert "挂载点" in pg.inner_text("#dkRows") and "还没有填名单" in pg.inner_text("#exRes") and "未开启" in pg.inner_text("#upInfo"), ("UPS/到期/磁盘页没有内容", pg.inner_text("#dkRows")[:200])
        pg.fill("#exCerts","127.0.0.1:1"); pg.click("#exSave"); pg.wait_for_timeout(1500)
        assert "已保存" in pg.inner_text("#exMsg") and "127.0.0.1:1" in pg.inner_text("#exRes"), (pg.inner_text("#exMsg"), pg.inner_text("#exRes"))
        pg.click("#upTest"); pg.wait_for_timeout(1500); assert "连不上" in pg.inner_text("#upMsg"), pg.inner_text("#upMsg")
        pg.evaluate("fetch('/api/expiry',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({certs:'',domains:''})})")
        pg.evaluate("S.set='docker';openSettings('docker')"); pg.wait_for_timeout(1200)
        assert "docker-socket-proxy" in pg.inner_text("#dkYml1") and "ALLOW_RESTARTS" in pg.inner_text("#dkYml2"), "容器设置页没有 compose 示例"
        pg.check("#dkOn"); pg.fill("#dkUrl","http://127.0.0.1:19332"); pg.click("#dkTest"); pg.wait_for_timeout(1500)
        assert "4 个容器" in pg.inner_text("#dkMsg"), pg.inner_text("#dkMsg")
        pg.click("#dkSave"); pg.wait_for_timeout(1500); assert "已保存" in pg.inner_text("#dkMsg"), pg.inner_text("#dkMsg")
        assert "容器" in pg.inner_text("#nav"), "开启后导航里没有「容器」"
        pg.evaluate("S.tab='docker';showTab();refresh()"); pg.wait_for_timeout(2500)
        tb=pg.inner_text("#dkBody"); assert "navidrome" in tb and "lrcapi" in tb and "40%" in tb and "已停止" in tb, tb
        assert pg.locator('#dkBody button[data-dk="stop"]').count()==0, "只读模式下不该有停止按钮"
        pg.locator('#dkBody button[data-dk="logs"]').nth(1).click(); pg.wait_for_timeout(1500)
        assert "hello /" in pg.input_value("#dkLog"), pg.input_value("#dkLog")
        pg.evaluate("fetch('/api/docker/cfg',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({on:false})}).then(()=>status())"); pg.wait_for_timeout(800)
        assert pg.evaluate("S.tab")=="overview" or "容器" not in pg.inner_text("#nav"), "关闭后导航里还有「容器」"
        pg.evaluate("S.tab='devices';S.dd='';showTab();refresh()"); pg.wait_for_timeout(4000)
        assert "在线" in pg.inner_text("#devTbl"), ("设备页没有显示在线状态", pg.inner_text("#devTbl")[:300])
        pg.locator("#devTbl .wch").first.click(); pg.wait_for_timeout(1500)
        assert "已关注" in pg.inner_text("#devTbl"), "关注按钮没有生效"
        pg.evaluate("S.dd='';loadDevicesTab()"); pg.wait_for_timeout(2500)
        assert pg.locator("#newDevCard").is_visible() and "新设备" in pg.inner_text("#newDevCard") and pg.locator("#ndDays button").count()==4, "设备页没有「新设备」卡片"
        assert pg.locator("#hideOff").count()==1, "设备页没有「隐藏离线」选项"
        pg.select_option("#hideOff","7"); pg.wait_for_timeout(800); assert pg.evaluate("S.hideOff")==7 and pg.locator("#devTbl").count()==1
        pg.select_option("#hideOff","0"); pg.wait_for_timeout(500)
        print("PASS 各预设布局独立")
        print("PASS 安全页各卡片都有内容,浏览器无报错")
finally:
    p.terminate()
