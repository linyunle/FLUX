"""访问密码:可选。设置后,网页和接口都需要先登录(Cookie 会话)。
密码只存加盐哈希(pbkdf2),放在 data/auth.json;也可以用环境变量 PANEL_PASSWORD 指定(页面里就不能改)。"""
import hashlib
import hmac
import json
import os
import secrets
import threading
import time

from . import config

COOKIE = "flux_sid"
TTL = 30 * 86400
_lock = threading.Lock()
_st = {"salt": "", "hash": "", "key": "", "env": False}
_fails = {}  # ip -> [次数, 锁定到]


def _path():
    return os.path.join(config.DATA_DIR, "auth.json")


def _hash(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 120000).hex()


def _save():
    os.makedirs(config.DATA_DIR, exist_ok=True)
    tmp = _path() + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"salt": _st["salt"], "hash": _st["hash"], "key": _st["key"]}, f)
    os.replace(tmp, _path())


def load():
    with _lock:
        try:
            with open(_path(), encoding="utf-8") as f:
                d = json.load(f)
            _st.update(salt=d.get("salt", ""), hash=d.get("hash", ""), key=d.get("key", ""), env=False)
        except (OSError, ValueError):
            _st.update(salt="", hash="", key="", env=False)
        envpw = os.environ.get("PANEL_PASSWORD", "")
        if envpw:
            salt = secrets.token_hex(16)
            _st.update(salt=salt, hash=_hash(envpw, salt), key=_st["key"] or secrets.token_hex(32), env=True)


def enabled():
    return bool(_st["hash"])


def is_env():
    return _st["env"]


def check(pw):
    with _lock:
        if not _st["hash"]:
            return True
        return hmac.compare_digest(_hash(pw or "", _st["salt"]), _st["hash"])


def set_password(new):
    """new 为空 = 关闭密码。换密码会让所有旧会话失效。"""
    if _st["env"]:
        raise ValueError("密码由环境变量 PANEL_PASSWORD 指定,要在 compose 里改")
    new = new or ""
    if new and len(new) < 6:
        raise ValueError("密码至少 6 位")
    if len(new) > 128:
        raise ValueError("密码太长")
    with _lock:
        _st["key"] = secrets.token_hex(32)
        if new:
            _st["salt"] = secrets.token_hex(16)
            _st["hash"] = _hash(new, _st["salt"])
        else:
            _st["salt"] = _st["hash"] = ""
        _save()


def make_cookie():
    exp = str(int(time.time()) + TTL)
    sig = hmac.new(_st["key"].encode(), exp.encode(), hashlib.sha256).hexdigest()
    return f"{exp}.{sig}"


def valid_cookie(val):
    if not _st["hash"]:
        return True
    try:
        exp, sig = (val or "").split(".", 1)
        if int(exp) < time.time():
            return False
        good = hmac.new(_st["key"].encode(), exp.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, good)
    except (ValueError, AttributeError):
        return False


def cookie_header(val, clear=False):
    age = 0 if clear else TTL
    return f"{COOKIE}={'' if clear else val}; Path=/; Max-Age={age}; HttpOnly; SameSite=Lax"


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


_LOGIN = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>FLUX 登录</title><link rel="icon" href="/favicon.png">
<style>:root{color-scheme:light dark;--bg:#f2f2ef;--s:rgba(255,255,255,.34);--ink:#1d1d1b;--mut:#3d3d3a;--line:rgba(20,20,20,.28);--brand:#0e0e0e;--brand2:#2c2c2e;--glow:#3b82f6;--glow2:#8b5cf6}
@media(prefers-color-scheme:dark){:root{--bg:#121211;--s:rgba(18,18,20,.38);--ink:#f4f4f1;--mut:#d0d0ca;--line:rgba(255,255,255,.34)}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}
body{background-image:radial-gradient(1100px 700px at 85% 15%,rgba(99,102,241,.28),transparent 60%),radial-gradient(900px 600px at 70% 95%,rgba(14,165,233,.22),transparent 60%)}
aside{position:fixed;left:5vw;top:0;bottom:0;width:min(420px,90vw);display:flex;flex-direction:column;padding:50px 52px 30px;background:var(--s);-webkit-backdrop-filter:blur(7px) saturate(1.25);backdrop-filter:blur(7px) saturate(1.25)}
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

_WP_CSS = """<style>body{background:#222 url(/wallpaper?v=%d) center/cover no-repeat fixed}</style>"""


def login_html():
    """登录页;上传了壁纸就带上壁纸背景(毛玻璃卡片)。"""
    from . import wallpaper
    v = wallpaper.info()
    from . import config
    h = _LOGIN.replace("<!--VER-->", config.VERSION, 1)
    return h.replace("<!--WP-->", (_WP_CSS % v["v"]) if v["has"] else "", 1)

