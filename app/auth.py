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
<style>:root{color-scheme:light dark;--bg:#f2f2ef;--s:rgba(255,255,255,.66);--ink:#1d1d1b;--mut:#6f6f68;--line:rgba(0,0,0,.12);--fld:rgba(255,255,255,.72);--brand:#0e0e0e;--brand2:#2c2c2e;--glow:#3b82f6;--glow2:#8b5cf6}
@media(prefers-color-scheme:dark){:root{--bg:#121211;--s:rgba(24,24,26,.62);--ink:#f1f1ee;--mut:#9a9a93;--line:rgba(255,255,255,.14);--fld:rgba(0,0,0,.32);--brand:#0e0e0e;--brand2:#2c2c2e}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}
body{background-image:radial-gradient(1100px 700px at 85% 15%,rgba(99,102,241,.28),transparent 60%),radial-gradient(900px 600px at 70% 95%,rgba(14,165,233,.22),transparent 60%)}
aside{position:fixed;left:0;top:0;bottom:0;width:min(430px,100%);display:flex;flex-direction:column;padding:34px 40px 26px;background:var(--s);-webkit-backdrop-filter:blur(28px) saturate(1.6);backdrop-filter:blur(28px) saturate(1.6);border-right:1px solid var(--line);box-shadow:8px 0 40px rgba(0,0,0,.18)}
.brand{display:flex;align-items:center;gap:12px}.brand img{width:38px;height:38px;border-radius:9px;display:block;box-shadow:0 2px 8px rgba(0,0,0,.25)}
.brand b{font-size:21px;letter-spacing:.02em}
form{margin:auto 0;padding:0 0 8vh}
h1{font-size:26px;margin:0 0 6px;letter-spacing:-.01em}p{margin:0 0 22px;color:var(--mut);font-size:14px}
input{width:100%;padding:13px 14px;border:1px solid var(--line);border-radius:10px;background:var(--fld);color:inherit;font-size:16px;outline:0;transition:border-color .15s,box-shadow .15s}
input:focus{border-color:var(--brand2);box-shadow:0 0 0 3px rgba(120,120,128,.25)}
button{position:relative;overflow:hidden;margin-top:14px;width:100%;padding:13px;border:1px solid rgba(255,255,255,.1);border-radius:10px;background:var(--brand);color:#fff;font-size:16px;font-weight:600;letter-spacing:.06em;cursor:pointer;transition:background .2s,transform .08s,box-shadow .2s;box-shadow:0 4px 14px rgba(0,0,0,.28)}
button:hover{background:var(--brand2);box-shadow:0 6px 18px rgba(0,0,0,.34)}
button:active{transform:scale(.985);background:linear-gradient(110deg,var(--glow),var(--glow2))}
button.busy{background:linear-gradient(110deg,var(--glow),var(--glow2),var(--glow));background-size:220% 100%;animation:flow 1s linear infinite;pointer-events:none}
button.ok{background:#22a35a;animation:none}
button.bad{background:#c23a2e;animation:shake .35s}
@keyframes flow{to{background-position:-220% 0}}
@keyframes shake{20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}
#m{color:#e0483b;font-size:13px;min-height:20px;margin-top:10px}
footer{color:var(--mut);font-size:12px;display:flex;justify-content:space-between;gap:8px}
@media(max-width:720px){aside{padding:28px 26px 22px}}</style><!--WP--></head><body>
<aside><div class="brand"><img src="/favicon.png" alt=""><b>FLUX</b></div>
<form id="f"><h1>欢迎回来</h1><p>请输入访问密码</p><input id="p" type="password" autocomplete="current-password" autofocus><div id="m"></div><button id="b">登录</button></form>
<footer><span>FLUX <!--VER--></span><span>nikki 流量面板</span></footer></aside>
<script>const B=document.getElementById("b");document.getElementById("f").onsubmit=async e=>{e.preventDefault();const m=document.getElementById("m");m.textContent="";
B.className="busy";B.textContent="登录中…";
try{const r=await fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:document.getElementById("p").value})});
const j=await r.json();if(r.ok){B.className="ok";B.textContent="✓ 成功";location.reload()}else{B.className="bad";B.textContent="登录";m.textContent=j.error||"登录失败";setTimeout(()=>B.className="",900)}}catch(x){B.className="bad";B.textContent="登录";m.textContent="连接失败";setTimeout(()=>B.className="",900)}}</script></body></html>"""

_WP_CSS = """<style>body{background:#222 url(/wallpaper?v=%d) center/cover no-repeat fixed}</style>"""


def login_html():
    """登录页;上传了壁纸就带上壁纸背景(毛玻璃卡片)。"""
    from . import wallpaper
    v = wallpaper.info()
    from . import config
    h = _LOGIN.replace("<!--VER-->", config.VERSION, 1)
    return h.replace("<!--WP-->", (_WP_CSS % v["v"]) if v["has"] else "", 1)

