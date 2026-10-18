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
<title>FLUX 登录</title><!--WP--><link rel="icon" href="/favicon.png">
<style>:root{color-scheme:light dark;--bg:#f6f6f4;--s:#fcfcfb;--ink:#1d1d1b;--mut:#8a8a82;--line:#e3e3de;--acc:#2a6fdb}
@media(prefers-color-scheme:dark){:root{--bg:#121211;--s:#1a1a19;--ink:#ecece8;--mut:#85857e;--line:#2c2c2a;--acc:#6aa5f5}}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}
form{width:min(320px,88vw);background:var(--s);border:1px solid var(--line);border-radius:14px;padding:22px;box-shadow:0 4px 18px rgba(0,0,0,.08)}
h1{font-size:18px;margin:0 0 4px}p{margin:0 0 14px;color:var(--mut);font-size:13px}
input{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit;font-size:16px}
button{margin-top:12px;width:100%;padding:10px;border:0;border-radius:8px;background:var(--acc);color:#fff;font-size:15px;cursor:pointer}
#m{color:#c23a2e;font-size:13px;min-height:18px;margin-top:8px}</style></head><body>
<form id="f"><h1>FLUX</h1><p>请输入访问密码</p><input id="p" type="password" autocomplete="current-password" autofocus><div id="m"></div><button>登录</button></form>
<script>document.getElementById("f").onsubmit=async e=>{e.preventDefault();const m=document.getElementById("m");m.textContent="";
try{const r=await fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:document.getElementById("p").value})});
const j=await r.json();if(r.ok)location.reload();else m.textContent=j.error||"登录失败"}catch(x){m.textContent="连接失败"}}</script></body></html>"""

_WP_CSS = """<style>body{background:#222 url(/wallpaper?v=%d) center/cover no-repeat fixed}
form{background:rgba(255,255,255,.58);-webkit-backdrop-filter:blur(22px) saturate(1.7);backdrop-filter:blur(22px) saturate(1.7);border:1px solid rgba(255,255,255,.45);box-shadow:0 12px 40px rgba(0,0,0,.28)}
input{background:rgba(255,255,255,.55)}
@media(prefers-color-scheme:dark){form{background:rgba(28,28,30,.55);border-color:rgba(255,255,255,.12)}input{background:rgba(0,0,0,.25)}}</style>"""


def login_html():
    """登录页;上传了壁纸就带上壁纸背景(毛玻璃卡片)。"""
    from . import wallpaper
    v = wallpaper.info()
    return _LOGIN.replace("<!--WP-->", (_WP_CSS % v["v"]) if v["has"] else "", 1)

