"""访问密码:可选。设置后,网页和接口都需要先登录(Cookie 会话)。
密码只存加盐哈希(pbkdf2),放在 data/auth.json;也可以用环境变量 PANEL_PASSWORD 指定(页面里就不能改)。"""
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import threading
import time

from . import config

COOKIE = "flux_sid"
TTL = 30 * 86400
_lock = threading.Lock()
_st = {"salt": "", "hash": "", "key": "", "env": False, "vsalt": "", "vhash": "", "venv": False}
_fails = {}  # ip -> [次数, 锁定到]
_sess = {}     # sid -> {role, ip, ua, created, last, exp}  已登录设备(单个踢下线用)
_revoked = {}  # sid -> 过期时间  被踢下线的会话(没过期前一直拒绝)
_sdirty = [0.0]
MAX_SESS = 200


def _path():
    return os.path.join(config.DATA_DIR, "auth.json")


def _hash(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 120000).hex()


def _save():
    os.makedirs(config.DATA_DIR, exist_ok=True)
    tmp = _path() + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        d = {"salt": _st["salt"], "hash": _st["hash"], "key": _st["key"]}
        if not _st["venv"]:
            d.update(vsalt=_st["vsalt"], vhash=_st["vhash"])
        json.dump(d, f)
    os.replace(tmp, _path())


def _spath():
    return os.path.join(config.DATA_DIR, "sessions.json")


def _sload():
    try:
        with open(_spath(), encoding="utf-8") as f:
            d = json.load(f)
        _sess.clear(); _sess.update({k: v for k, v in (d.get("sessions") or {}).items() if isinstance(v, dict)})
        _revoked.clear(); _revoked.update({k: int(v) for k, v in (d.get("revoked") or {}).items()})
    except (OSError, ValueError, AttributeError):
        _sess.clear(); _revoked.clear()


def _ssave():
    """调用方已持有 _lock。"""
    now = time.time()
    for k in [k for k, v in _sess.items() if v.get("exp", 0) < now]:
        del _sess[k]
    for k in [k for k, v in _revoked.items() if v < now]:
        del _revoked[k]
    try:
        os.makedirs(config.DATA_DIR, exist_ok=True)
        tmp = _spath() + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"sessions": _sess, "revoked": _revoked}, f)
        os.replace(tmp, _spath())
        _sdirty[0] = 0.0
    except OSError:
        pass


def load():
    _sload()
    with _lock:
        try:
            with open(_path(), encoding="utf-8") as f:
                d = json.load(f)
            _st.update(salt=d.get("salt", ""), hash=d.get("hash", ""), key=d.get("key", ""), env=False,
                       vsalt=d.get("vsalt", ""), vhash=d.get("vhash", ""), venv=False)
        except (OSError, ValueError):
            _st.update(salt="", hash="", key="", env=False, vsalt="", vhash="", venv=False)
        envpw = os.environ.get("PANEL_PASSWORD", "")
        if envpw:
            salt = secrets.token_hex(16)
            _st.update(salt=salt, hash=_hash(envpw, salt), key=_st["key"] or secrets.token_hex(32), env=True)
        venv = os.environ.get("PANEL_VIEWER_PASSWORD", "")
        if venv and _st["hash"]:
            salt = secrets.token_hex(16)
            _st.update(vsalt=salt, vhash=_hash(venv, salt), venv=True)


def enabled():
    return bool(_st["hash"])


def is_env():
    return _st["env"]


def has_viewer():
    return bool(_st["hash"] and _st["vhash"])


def viewer_is_env():
    return _st["venv"]


def check(pw):
    """只验管理员密码(改密码、设置只读密码前用)。"""
    with _lock:
        if not _st["hash"]:
            return True
        return hmac.compare_digest(_hash(pw or "", _st["salt"]), _st["hash"])


def check_role(pw):
    """登录:返回 'a'(管理员) / 'v'(只读) / None(密码不对)。没设密码 = 管理员。两个哈希都算一遍,耗时不泄露是哪种。"""
    with _lock:
        if not _st["hash"]:
            return "a"
        pw = pw or ""
        ra = hmac.compare_digest(_hash(pw, _st["salt"]), _st["hash"])
        rv = bool(_st["vhash"]) and hmac.compare_digest(_hash(pw, _st["vsalt"]), _st["vhash"])
        return "a" if ra else "v" if rv else None


def set_password(new):
    """new 为空 = 关闭密码(同时清掉只读密码)。换密码会让所有旧会话失效。"""
    if _st["env"]:
        raise ValueError("密码由环境变量 PANEL_PASSWORD 指定,要在 compose 里改")
    new = new or ""
    if new and len(new) < 6:
        raise ValueError("密码至少 6 位")
    if len(new) > 128:
        raise ValueError("密码太长")
    with _lock:
        if new and _st["vhash"] and hmac.compare_digest(_hash(new, _st["vsalt"]), _st["vhash"]):
            raise ValueError("管理员密码不能和只读密码相同")
        _st["key"] = secrets.token_hex(32)
        if new:
            _st["salt"] = secrets.token_hex(16)
            _st["hash"] = _hash(new, _st["salt"])
        else:
            _st["salt"] = _st["hash"] = _st["vsalt"] = _st["vhash"] = ""
        _save()
        _sess.clear(); _revoked.clear(); _ssave()


def set_viewer(new):
    """只读密码:必须先有管理员密码;留空 = 关闭只读登录。只读会话随之失效。"""
    if _st["venv"]:
        raise ValueError("只读密码由环境变量 PANEL_VIEWER_PASSWORD 指定,要在 compose 里改")
    if not _st["hash"]:
        raise ValueError("请先设置管理员访问密码")
    new = new or ""
    if new and len(new) < 6:
        raise ValueError("密码至少 6 位")
    if len(new) > 128:
        raise ValueError("密码太长")
    with _lock:
        if new and hmac.compare_digest(_hash(new, _st["salt"]), _st["hash"]):
            raise ValueError("只读密码不能和管理员密码相同")
        if new:
            _st["vsalt"] = secrets.token_hex(16)
            _st["vhash"] = _hash(new, _st["vsalt"])
        else:
            _st["vsalt"] = _st["vhash"] = ""
        _save()
        for k in [k for k, v in _sess.items() if v.get("role") == "v"]:
            del _sess[k]
        _ssave()


def revoke_all():
    """退出所有设备:换签名密钥,所有已发出的会话(含当前)立刻失效;调用方给当前浏览器重新发一个。"""
    if not _st["hash"]:
        raise ValueError("还没有设置访问密码")
    with _lock:
        _st["key"] = secrets.token_hex(32)
        _save()
        _sess.clear(); _revoked.clear(); _ssave()


def _sig(exp, role, sid=""):
    k = _st["key"] + (_st["vhash"] if role == "v" else "")
    return hmac.new(k.encode(), (f"{exp}.{role}.{sid}" if sid else f"{exp}.{role}").encode(), hashlib.sha256).hexdigest()


def make_cookie(role="a", ip="", ua=""):
    """新会话:Cookie = 过期时间.角色.会话号.签名;同时记下来源 IP / 浏览器,方便在「已登录设备」里看和踢下线。"""
    exp = int(time.time()) + TTL
    sid = secrets.token_hex(6)
    now = int(time.time())
    with _lock:
        _sess[sid] = {"role": role, "ip": ip, "ua": (ua or "")[:200], "created": now, "last": now, "exp": exp}
        if len(_sess) > MAX_SESS:
            for k in sorted(_sess, key=lambda k: _sess[k]["last"])[:len(_sess) - MAX_SESS]:
                del _sess[k]
        _ssave()
    return f"{exp}.{role}.{sid}.{_sig(str(exp), role, sid)}"


def _parse(val):
    """返回 (角色, 会话号, 是否有效)。支持三种格式:新(4 段)、v0.28.0 的(3 段,无会话号)、旧版(2 段,管理员)。"""
    parts = (val or "").split(".")
    if len(parts) == 2:
        exp, sig = parts
        good = hmac.new(_st["key"].encode(), exp.encode(), hashlib.sha256).hexdigest()
        return "a", "", int(exp) >= time.time() and hmac.compare_digest(sig, good)
    if len(parts) == 3:
        exp, role, sig = parts
        sid = ""
    else:
        exp, role, sid, sig = parts
    if role not in ("a", "v") or (role == "v" and not _st["vhash"]):
        return None, "", False
    return role, sid, int(exp) >= time.time() and hmac.compare_digest(sig, _sig(exp, role, sid))


def cookie_role(val):
    """Cookie 有效就返回角色 'a' / 'v',否则 None。没设密码 = 'a'。被踢下线的会话号一律无效。"""
    if not _st["hash"]:
        return "a"
    try:
        role, sid, good = _parse(val)
    except (ValueError, AttributeError):
        return None
    if not good or (sid and sid in _revoked):
        return None
    return role


def cookie_sid(val):
    try:
        return _parse(val)[1]
    except (ValueError, AttributeError):
        return ""


def touch(sid, ip="", ua=""):
    """记录这台设备最近一次访问(超过 60 秒才更新一次,最多每 60 秒写一次文件)。"""
    s_ = _sess.get(sid)
    if not s_:
        return
    now = int(time.time())
    if now - s_.get("last", 0) < 60 and s_.get("ip") == ip:
        return
    with _lock:
        s_["last"] = now
        if ip:
            s_["ip"] = ip
        if ua:
            s_["ua"] = ua[:200]
        if time.time() - _sdirty[0] > 60:
            _sdirty[0] = time.time()
            _ssave()


def list_sessions(current=""):
    now = time.time()
    with _lock:
        out = [dict(v, id=k, current=(k == current)) for k, v in _sess.items()
               if v.get("exp", 0) > now and k not in _revoked and not (v.get("role") == "v" and not _st["vhash"])]
    return sorted(out, key=lambda x: -x["last"])


def revoke_sid(sid):
    """把某一台设备踢下线(它的 Cookie 立刻失效)。"""
    with _lock:
        s_ = _sess.pop(sid, None)
        if not s_:
            raise ValueError("没有这个会话(可能已经过期或被踢下线)")
        _revoked[sid] = int(s_.get("exp", time.time() + TTL))
        _ssave()


def valid_cookie(val):
    return cookie_role(val) is not None


def cookie_header(val, clear=False, secure=False):
    age = 0 if clear else TTL
    return f"{COOKIE}={'' if clear else val}; Path=/; Max-Age={age}; HttpOnly; SameSite=Lax" + ("; Secure" if secure else "")


def locked(ip):
    f = _fails.get(ip)
    return bool(f and f[1] > time.time())


def fail(ip):
    f = _fails.setdefault(ip, [0, 0])
    f[0] += 1
    if f[0] >= 5:
        f[0], f[1] = 0, time.time() + 60
    if len(_fails) > 500:
        _fails.clear()


def ok(ip):
    _fails.pop(ip, None)


def _nets(env, default=""):
    out = []
    for x in (os.environ.get(env, default) or "").replace(";", ",").split(","):
        x = x.strip()
        if x:
            try:
                out.append(ipaddress.ip_network(x, strict=False))
            except ValueError:
                pass
    return out


def _in(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    a = a.ipv4_mapped if getattr(a, "ipv4_mapped", None) else a
    return any(a in n for n in nets if n.version == a.version)


def client_ip(peer, xff="", proto=""):
    """真实来源 IP:只有直连方是受信代理(默认只有本机,可用 TRUSTED_PROXIES 追加)时才采信 X-Forwarded-For,
    否则局域网里谁都能伪造这个头来躲开登录锁定。返回 (ip, 是否 https)。"""
    if _in(peer, _nets("TRUSTED_PROXIES", "127.0.0.1,::1")):
        hop = [h.strip() for h in (xff or "").split(",") if h.strip()]
        return (hop[0] if hop else peer), (proto or "").lower() == "https"
    return peer, False


def net_allowed(ip):
    """ALLOW_NETS(逗号分隔的网段,如 192.168.0.0/16)非空时,只允许这些网段访问面板。"""
    nets = _nets("ALLOW_NETS")
    return True if not nets else _in(ip, nets)


_LOGIN = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>FLUX 登录</title><link rel="icon" href="/favicon.png">
<style>:root{color-scheme:light dark;--bg:#f2f2ef;--s:rgba(255,255,255,.34);--ink:#1d1d1b;--mut:#3d3d3a;--line:rgba(20,20,20,.28);--brand:#0e0e0e;--brand2:#2c2c2e;--glow:#3b82f6;--glow2:#8b5cf6}
@media(prefers-color-scheme:dark){:root{--bg:#121211;--s:rgba(18,18,20,.38);--ink:#f4f4f1;--mut:#d0d0ca;--line:rgba(255,255,255,.34)}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}
body{background-image:radial-gradient(1100px 700px at 85% 15%,rgba(99,102,241,.28),transparent 60%),radial-gradient(900px 600px at 70% 95%,rgba(14,165,233,.22),transparent 60%)}
aside{position:fixed;left:5vw;top:0;bottom:0;width:min(420px,90vw);display:flex;flex-direction:column;padding:50px 52px 30px;background:var(--s);-webkit-backdrop-filter:blur(7px) saturate(1.25);backdrop-filter:blur(7px) saturate(1.25);box-shadow:0 0 60px rgba(0,0,0,.4),0 0 14px rgba(0,0,0,.22);border-left:1px solid rgba(255,255,255,.32);border-right:1px solid rgba(255,255,255,.18)}
.brand{display:flex;align-items:center;gap:16px}.brand img{width:52px;height:52px;border-radius:11px;display:block}
.brand b{font-size:24px;letter-spacing:.01em;font-weight:800}
form{margin-top:15vh}
h1{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
.fld{position:relative;border-bottom:1px solid var(--line);transition:border-color .2s}
.fld:focus-within{border-color:var(--ink)}
.fld svg{position:absolute;left:2px;top:50%;margin-top:-11px;width:22px;height:22px;fill:currentColor;opacity:.85}
input{width:100%;padding:14px 8px 12px 42px;border:0;background:transparent;color:inherit;font-size:17px;outline:0;letter-spacing:.04em}
input::placeholder{color:var(--mut);opacity:.75;letter-spacing:0;font-size:15px}
button{position:relative;margin-top:54px;width:100%;padding:13px;border:0;border-radius:4px;background:var(--brand);color:#fff;font-size:15px;font-weight:600;letter-spacing:.5em;text-indent:.5em;cursor:pointer;transition:background .2s,transform .08s,box-shadow .2s;box-shadow:0 3px 10px rgba(0,0,0,.22)}
button:hover{background:var(--brand2);box-shadow:0 5px 14px rgba(0,0,0,.3)}
button:active{transform:scale(.985);background:linear-gradient(110deg,var(--glow),var(--glow2))}
button.busy{background:linear-gradient(110deg,var(--glow),var(--glow2),var(--glow));background-size:220% 100%;animation:flow 1s linear infinite;pointer-events:none}
button.ok{background:#22a35a;animation:none}
button.bad{background:#c23a2e;animation:shake .35s}
@keyframes flow{to{background-position:-220% 0}}
@keyframes shake{20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}
#m{color:#d63a2c;font-size:13px;min-height:20px;margin-top:10px;font-weight:500}
footer{margin-top:auto;text-align:center;color:var(--mut);font-size:12px;line-height:2;text-shadow:0 0 6px rgba(255,255,255,.35)}
@media(prefers-color-scheme:dark){footer{text-shadow:none}}
@media(max-width:720px){aside{left:0;width:100%;padding:36px 30px 24px}form{margin-top:12vh}}</style><!--WP--></head><body>
<aside><div class="brand"><img src="/favicon.png" alt=""><b>FLUX</b></div>
<form id="f"><h1>请输入访问密码</h1><div class="fld"><svg viewBox="0 0 24 24"><path d="M12 1a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V11a2 2 0 0 0-2-2h-1V6a5 5 0 0 0-5-5zm0 2a3 3 0 0 1 3 3v3H9V6a3 3 0 0 1 3-3zm0 10a2 2 0 0 1 1 3.7V19h-2v-2.3A2 2 0 0 1 12 13z"/></svg><input id="p" type="password" placeholder="请输入访问密码" autocomplete="current-password" autofocus></div><div id="m"></div><button id="b">登录</button></form>
<footer>FLUX <!--VER--><br>nikki 流量面板</footer></aside>
<script>const B=document.getElementById("b");document.getElementById("f").onsubmit=async e=>{e.preventDefault();const m=document.getElementById("m");m.textContent="";
B.className="busy";B.textContent="登录中";
try{const r=await fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:document.getElementById("p").value})});
const j=await r.json();if(r.ok){B.className="ok";B.textContent="成功";location.reload()}else{B.className="bad";B.textContent="登录";m.textContent=j.error||"登录失败";setTimeout(()=>B.className="",900)}}catch(x){B.className="bad";B.textContent="登录";m.textContent="连接失败";setTimeout(()=>B.className="",900)}}</script></body></html>"""

_WP_CSS = """<style>body{background:#222 url(/wallpaper?v=%d) center/cover no-repeat fixed}
@media(max-width:720px){aside{background:linear-gradient(to bottom,rgba(0,0,0,.42),rgba(0,0,0,0) 34%%,rgba(0,0,0,0) 62%%,rgba(0,0,0,.5));-webkit-backdrop-filter:none;backdrop-filter:none;box-shadow:none;border:0;color:#fff;text-shadow:0 1px 6px rgba(0,0,0,.55)}
.fld{border-color:rgba(255,255,255,.75)}.fld:focus-within{border-color:#fff}input{color:#fff;text-shadow:none}input::placeholder{color:rgba(255,255,255,.85)}footer{color:rgba(255,255,255,.92)}#m{color:#ff8a80}}</style>"""


def login_html():
    """登录页;上传了壁纸就带上壁纸背景(毛玻璃卡片)。"""
    from . import wallpaper
    v = wallpaper.info()
    from . import config
    h = _LOGIN.replace("<!--VER-->", config.VERSION, 1)
    return h.replace("<!--WP-->", (_WP_CSS % v["v"]) if v["has"] else "", 1)

