"""应用特征库:用「域名特征(SNI/Host)+ 目标端口 + 传输层」识别具体应用和类别。

说明:这不是包检测(DPI)。FLUX 通过 mihomo 的 API 读连接信息,看不到数据包,TLS 内容也是加密的;
所以这里只能按 mihomo 给出的域名 / 端口 / TCP-UDP 来认。能认出 YouTube、网盘、WireGuard 这类
有明显特征的东西,认不出的归为「未识别」。你可以在 设置 → 应用特征库 里加自己的规则。
"""
import re
import threading

# 类别 → [(应用名, [域名后缀 或 ~关键字, ...]), ...]
# 写法:"example.com" 表示 example.com 及其所有子域名;"~keyword" 表示域名里包含 keyword
SIG = {
    "流媒体": [
        ("YouTube", ["youtube.com", "googlevideo.com", "ytimg.com", "youtu.be", "youtube-nocookie.com"]),
        ("Netflix", ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net", "nflxext.com"]),
        ("Disney+", ["disneyplus.com", "disney-plus.net", "bamgrid.com", "dssott.com"]),
        ("HBO Max", ["hbomax.com", "max.com", "hbo.com"]),
        ("Prime Video", ["primevideo.com", "aiv-cdn.net", "pv-cdn.net"]),
        ("Twitch", ["twitch.tv", "ttvnw.net", "jtvnw.net"]),
        ("Spotify", ["spotify.com", "scdn.co", "spotifycdn.com"]),
        ("Apple Music / TV", ["music.apple.com", "tv.apple.com", "itunes.apple.com"]),
        ("TikTok", ["tiktok.com", "tiktokv.com", "tiktokcdn.com", "byteoversea.com", "musical.ly"]),
        ("哔哩哔哩", ["bilibili.com", "bilivideo.com", "hdslb.com", "biliapi.net", "b23.tv"]),
        ("抖音", ["douyin.com", "douyinvod.com", "douyinpic.com", "iesdouyin.com", "douyincdn.com", "amemv.com"]),
        ("快手", ["kuaishou.com", "kwai.com", "yximgs.com", "gifshow.com", "kwaicdn.com"]),
        ("爱奇艺", ["iqiyi.com", "iqiyipic.com", "qiyi.com", "71.am"]),
        ("腾讯视频", ["v.qq.com", "video.qq.com", "vv.video.qq.com", "qqlive.com", "ltsws.qq.com"]),
        ("优酷", ["youku.com", "ykimg.com", "youku.tv"]),
        ("芒果 TV", ["mgtv.com", "hitv.com"]),
        ("网易云音乐", ["music.163.com", "music.126.net", "163yun.com"]),
        ("QQ 音乐", ["y.qq.com", "qqmusic.qq.com", "stream.qqmusic.qq.com"]),
        ("Plex", ["plex.tv", "plex.direct"]),
    ],
    "社交 / 通讯": [
        ("Telegram", ["telegram.org", "t.me", "telegram.me", "tdesktop.com", "cdn-telegram.org", "telesco.pe"]),
        ("WhatsApp", ["whatsapp.com", "whatsapp.net", "wa.me"]),
        ("Discord", ["discord.com", "discordapp.com", "discord.gg", "discordapp.net", "discord.media"]),
        ("微信", ["weixin.qq.com", "wechat.com", "wx.qq.com", "wx2.qq.com", "weixin.com", "wxapp.tc.qq.com"]),
        ("微博", ["weibo.com", "weibo.cn", "sinaimg.cn", "sina.com.cn"]),
        ("X / Twitter", ["twitter.com", "x.com", "twimg.com", "t.co"]),
        ("Facebook", ["facebook.com", "fbcdn.net", "fb.com", "fbsbx.com", "facebook.net"]),
        ("Instagram", ["instagram.com", "cdninstagram.com"]),
        ("Reddit", ["reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"]),
        ("LINE", ["line.me", "line-apps.com", "line-scdn.net", "naver.jp"]),
        ("Signal", ["signal.org", "whispersystems.org"]),
        ("小红书", ["xiaohongshu.com", "xhscdn.com", "xhslink.com"]),
        ("知乎", ["zhihu.com", "zhimg.com"]),
        ("LinkedIn", ["linkedin.com", "licdn.com"]),
    ],
    "网盘 / 云存储": [
        ("百度网盘", ["pan.baidu.com", "baidupcs.com", "pcs.baidu.com", "yun.baidu.com"]),
        ("夸克网盘", ["quark.cn", "quark.com", "uc.cn"]),
        ("阿里云盘", ["aliyundrive.com", "alipan.com", "aliyundrive.net"]),
        ("天翼云盘", ["cloud.189.cn", "189.cn"]),
        ("115 网盘", ["115.com", "115cdn.com"]),
        ("OneDrive", ["onedrive.com", "1drv.com", "1drv.ms", "storage.live.com", "sharepoint.com"]),
        ("Google Drive", ["drive.google.com", "docs.google.com", "drive.usercontent.google.com", "googleusercontent.com"]),
        ("Dropbox", ["dropbox.com", "dropboxstatic.com", "dropboxusercontent.com", "dropbox-dns.com"]),
        ("iCloud", ["icloud.com", "icloud-content.com", "apple-cloudkit.com"]),
        ("MEGA", ["mega.nz", "mega.io", "mega.co.nz"]),
    ],
    "下载 / P2P": [
        ("迅雷", ["xunlei.com", "sandai.net", "xlmc.sandai.net"]),
        ("BT 种子站 / Tracker", ["~tracker", "~announce", "nyaa.si", "thepiratebay", "1337x", "rarbg", "dmhy.org", "mikanani.me"]),
        ("磁力 / 离线下载", ["~magnet", "aria2", "qbittorrent", "transmission"]),
    ],
    "游戏": [
        ("Steam", ["steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com", "steamserver.net", "valvesoftware.com", "steam-chat.com"]),
        ("Epic Games", ["epicgames.com", "epicgames.dev", "unrealengine.com", "epicgames.net"]),
        ("PlayStation", ["playstation.com", "playstation.net", "sonyentertainmentnetwork.com"]),
        ("Xbox", ["xboxlive.com", "xbox.com", "xboxservices.com"]),
        ("Nintendo", ["nintendo.com", "nintendo.net", "nintendoswitch.com"]),
        ("米哈游 / 原神", ["mihoyo.com", "hoyoverse.com", "yuanshen.com", "hoyolab.com"]),
        ("Riot / 英雄联盟", ["riotgames.com", "leagueoflegends.com", "riotcdn.net"]),
        ("暴雪战网", ["blizzard.com", "battle.net", "blzddist1-a.akamaihd.net"]),
        ("EA / Origin", ["ea.com", "origin.com", "easports.com"]),
    ],
    "AI 服务": [
        ("ChatGPT / OpenAI", ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"]),
        ("Claude / Anthropic", ["anthropic.com", "claude.ai", "claude.com"]),
        ("Gemini", ["gemini.google.com", "bard.google.com", "generativelanguage.googleapis.com", "aistudio.google.com"]),
        ("Perplexity", ["perplexity.ai"]),
        ("Hugging Face", ["huggingface.co", "hf.co"]),
        ("DeepSeek", ["deepseek.com"]),
        ("Midjourney", ["midjourney.com"]),
    ],
    "购物 / 电商": [
        ("淘宝 / 天猫", ["taobao.com", "tmall.com", "alicdn.com", "tbcdn.cn", "mmstat.com", "alibaba.com", "1688.com"]),
        ("京东", ["jd.com", "360buyimg.com", "jdcdn.com", "jd.hk"]),
        ("拼多多", ["pinduoduo.com", "pddpic.com", "yangkeduo.com"]),
        ("Amazon", ["amazon.com", "amazon.co.jp", "media-amazon.com", "ssl-images-amazon.com", "amazon.cn"]),
        ("eBay", ["ebay.com", "ebayimg.com"]),
    ],
    "搜索 / 资讯": [
        ("Google 搜索", ["google.com", "gstatic.com", "googleapis.com", "ggpht.com", "google.com.hk"]),
        ("百度", ["baidu.com", "bdstatic.com", "bdimg.com", "baidustatic.com"]),
        ("Bing / Microsoft", ["bing.com", "bing.net", "msn.com"]),
        ("Wikipedia", ["wikipedia.org", "wikimedia.org"]),
    ],
    "办公 / 开发": [
        ("GitHub", ["github.com", "githubusercontent.com", "githubassets.com", "ghcr.io", "github.io"]),
        ("GitLab", ["gitlab.com"]),
        ("Docker", ["docker.io", "docker.com", "gcr.io", "quay.io"]),
        ("npm / PyPI", ["npmjs.org", "npmjs.com", "pypi.org", "pythonhosted.org", "yarnpkg.com"]),
        ("Microsoft 365", ["office.com", "office365.com", "microsoftonline.com", "office.net", "live.com", "outlook.com"]),
        ("Zoom", ["zoom.us", "zoom.com", "zoomgov.com"]),
        ("钉钉 / 飞书", ["dingtalk.com", "feishu.cn", "larksuite.com", "feishucdn.com"]),
        ("Notion / Slack", ["notion.so", "notion.com", "slack.com", "slack-edge.com"]),
    ],
    "系统 / 更新": [
        ("Apple 服务", ["apple.com", "mzstatic.com", "cdn-apple.com", "aaplimg.com", "apple-dns.net", "icloud.com.cn"]),
        ("Windows 更新", ["windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com", "dl.delivery.mp.microsoft.com", "microsoft.com"]),
        ("Android / Google Play", ["play.googleapis.com", "android.com", "gvt1.com", "gvt2.com", "android.clients.google.com"]),
        ("小米 / 华为系统", ["xiaomi.com", "mi.com", "miui.com", "hicloud.com", "huawei.com", "dbankcdn.com", "hihonor.com"]),
        ("OpenWrt / 固件", ["openwrt.org", "immortalwrt.org", "downloads.openwrt.org"]),
        ("校时 NTP", ["ntp.org", "pool.ntp.org", "time.apple.com", "time.windows.com", "ntp.aliyun.com", "time.cloudflare.com"]),
    ],
    "广告 / 追踪": [
        ("广告 / 统计", ["doubleclick.net", "googlesyndication.com", "googleadservices.com", "adservice.google.com", "google-analytics.com",
                       "googletagmanager.com", "scorecardresearch.com", "umeng.com", "growingio.com", "appsflyer.com", "adjust.com",
                       "branch.io", "pangle.io", "adnxs.com", "criteo.com", "~adservice", "~analytics", "~telemetry", "~tracking", "~doubleclick"]),
    ],
    "代理 / VPN 隧道": [
        ("Tailscale", ["tailscale.com", "tailscale.io", "ts.net"]),
        ("Cloudflare WARP", ["cloudflareclient.com", "warp.plus"]),
        ("Tor", ["torproject.org"]),
        ("ZeroTier", ["zerotier.com"]),
        ("VPN 服务", ["~vpn"]),
    ],
}

# 这些端口特征很明确,优先于域名(目标是裸 IP 时尤其有用)。(端口, 传输层或空) → (应用, 类别)
PORT_FIRST = {
    (51820, "udp"): ("WireGuard", "代理 / VPN 隧道"),
    (1194, ""): ("OpenVPN", "代理 / VPN 隧道"),
    (500, "udp"): ("IPsec VPN", "代理 / VPN 隧道"),
    (4500, "udp"): ("IPsec VPN", "代理 / VPN 隧道"),
    (8388, ""): ("Shadowsocks(端口推测)", "代理 / VPN 隧道"),
    (8389, ""): ("Shadowsocks(端口推测)", "代理 / VPN 隧道"),
    (1080, "tcp"): ("SOCKS 代理(端口推测)", "代理 / VPN 隧道"),
    (9001, "tcp"): ("Tor(端口推测)", "代理 / VPN 隧道"),
    (9030, "tcp"): ("Tor(端口推测)", "代理 / VPN 隧道"),
    (9993, "udp"): ("ZeroTier", "代理 / VPN 隧道"),
    (41641, "udp"): ("Tailscale", "代理 / VPN 隧道"),
    (51413, ""): ("BitTorrent(端口推测)", "下载 / P2P"),
}
# 域名没认出来时,再按端口兜底
PORT_APP = {
    22: ("SSH", "办公 / 开发"), 25: ("邮件", "办公 / 开发"), 465: ("邮件", "办公 / 开发"), 587: ("邮件", "办公 / 开发"),
    110: ("邮件", "办公 / 开发"), 995: ("邮件", "办公 / 开发"), 143: ("邮件", "办公 / 开发"), 993: ("邮件", "办公 / 开发"),
    53: ("DNS 查询", "系统 / 更新"), 853: ("DNS 查询", "系统 / 更新"), 123: ("校时 NTP", "系统 / 更新"),
    3478: ("语音 / 视频通话(STUN)", "社交 / 通讯"), 3479: ("语音 / 视频通话(STUN)", "社交 / 通讯"),
    5060: ("SIP 电话", "社交 / 通讯"), 5061: ("SIP 电话", "社交 / 通讯"), 1935: ("RTMP 直播推流", "流媒体"), 554: ("RTSP 视频流", "流媒体"),
    3389: ("远程桌面 RDP", "办公 / 开发"), 5900: ("远程桌面 VNC", "办公 / 开发"), 445: ("SMB 文件共享", "局域网"), 139: ("SMB 文件共享", "局域网"),
    5353: ("mDNS 局域网发现", "局域网"), 1900: ("SSDP 局域网发现", "局域网"), 21: ("FTP", "下载 / P2P"),
}
UNKNOWN = ("未识别", "其他")

_lock = threading.Lock()
_suffix = {}
_keywords = []
_custom = []  # [(关键字, 应用, 类别)]
_text = ""


def _build():
    for cat, apps in SIG.items():
        for app, toks in apps:
            for t in toks:
                if t.startswith("~"):
                    _keywords.append((t[1:], app, cat))
                else:
                    _suffix.setdefault(t, (app, cat))


_build()
CATS = list(SIG) + ["局域网", "其他"]


def parse_rules(text):
    out = []
    lines = (text or "").splitlines()
    if len(lines) > 1000:
        raise ValueError("规则最多 1000 行")
    for i, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"第 {i} 行格式不对,要写成 域名关键字=应用名 或 域名关键字=应用名|类别")
        kw, rest = (x.strip() for x in line.split("=", 1))
        kw = re.sub(r"/.*$", "", re.sub(r"^https?://", "", re.sub(r"^\*\.", "", kw.lower())))   # 和导入时的规整一致:去掉 *. / http:// / 路径
        app, _, cat = rest.partition("|")
        app, cat = app.strip(), cat.strip() or "其他"
        if not kw or not app:
            raise ValueError(f"第 {i} 行的关键字和应用名都不能为空")
        if len(kw) > 80 or len(app) > 40 or len(cat) > 20:
            raise ValueError(f"第 {i} 行太长")
        out.append((kw.lower(), app, cat))
    return out


DEDUP = {"same": 0, "conflict": 0, "examples": []}


def dedupe(rules):
    """同一个关键字只留第一条(分类时也是靠前的先命中,所以不改变识别结果)。
    返回 (去重后的规则, 完全相同的条数, 同关键字但应用 / 类别不同的条数, 例子)。"""
    seen, out, same, conflict, ex = {}, [], 0, 0, []
    for kw, app, cat in rules:
        if kw in seen:
            if seen[kw] == (app, cat):
                same += 1
            else:
                conflict += 1
                if len(ex) < 5:
                    ex.append(f"{kw}:保留 {seen[kw][0]}|{seen[kw][1]},去掉 {app}|{cat}")
            continue
        seen[kw] = (app, cat)
        out.append((kw, app, cat))
    return out, same, conflict, ex


def set_rules(text):
    global _custom, _text
    rules, same, conflict, ex = dedupe(parse_rules(text))
    DEDUP.update(same=same, conflict=conflict, examples=ex)
    with _lock:
        _custom = rules
        _text = "\n".join(f"{k}={a}|{c}" for k, a, c in rules)
    _cache.clear()
    return len(rules)


def rules_text():
    with _lock:
        return _text


def load(con):
    try:
        r = con.execute("SELECT v FROM kv WHERE k='app_rules'").fetchone()
        if r:
            set_rules(r[0])
    except Exception:
        pass


def save(con, text):
    n = set_rules(text)
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES('app_rules',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (rules_text(),))
    return n


_cache = {}


def classify(host, port=0, net=""):
    """返回 (应用, 类别)。host 可能是域名、IP 或空。"""
    key = (host, port, net)
    hit = _cache.get(key)
    if hit:
        return hit
    r = _classify(host, port, net)
    if len(_cache) > 20000:
        _cache.clear()
    _cache[key] = r
    return r


def _classify(host, port, net):
    h = (host or "").lower().strip(".")
    with _lock:
        custom = list(_custom)
    for kw, app, cat in custom:
        if h == kw or h.endswith("." + kw) or ("." not in kw and kw in h):
            return app, cat
    pf = PORT_FIRST.get((port, net)) or PORT_FIRST.get((port, ""))
    if pf:
        return pf
    if 6881 <= port <= 6999:
        return "BitTorrent(端口推测)", "下载 / P2P"
    if h and not _is_ip(h):
        parts = h.split(".")
        for i in range(len(parts) - 1):
            r = _suffix.get(".".join(parts[i:]))
            if r:
                return r
        for kw, app, cat in _keywords:
            if kw in h:
                return app, cat
    if net == "udp" and port == 443 and not h:
        return "QUIC 未识别", "其他"
    return PORT_APP.get(port, UNKNOWN)


def _is_ip(h):
    return h.replace(".", "").isdigit() or ":" in h
