"""证书与域名到期检查(可选:填了名单才会检查)。
- 证书:连一下 host:端口(默认 443),读 TLS 证书的到期时间,同时看一下证书是否被信任、域名是否匹配。
  只做一次 TLS 握手,不发任何数据;自签名证书(比如路由器、NAS 的管理页)也能读到期日。
- 域名:通过公共的 RDAP 服务(https://rdap.org)查注册到期日。不是所有后缀都支持,查不到会写明,不影响别的检查。
每 6 小时查一次(保存名单后也会立刻查一次),到期前 N 天提醒。"""
import json
import os
import re
import socket
import ssl
import tempfile
import threading
import time
import urllib.request
from datetime import datetime, timezone

from .util import log

DEFAULT = {"certs": [], "domains": []}
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}(:\d{1,5})?$")
DOM_RE = re.compile(r"^[a-z0-9\-]+(\.[a-z0-9\-]+)+$")
EVERY = 6 * 3600
STATE = {"at": 0, "running": False, "certs": {}, "domains": {}}
_lock = threading.Lock()


def load_cfg(con):
    try:
        r = con.execute("SELECT v FROM kv WHERE k='expiry'").fetchone()
        v = json.loads(r[0]) if r else {}
    except Exception:
        v = {}
    c = {"certs": [], "domains": []}
    if isinstance(v, dict):
        c["certs"] = [x for x in (v.get("certs") or []) if isinstance(x, str) and HOST_RE.match(x)][:20]
        c["domains"] = [x for x in (v.get("domains") or []) if isinstance(x, str) and DOM_RE.match(x)][:20]
    return c


def _lines(v):
    if isinstance(v, str):
        v = re.split(r"[\s,;]+", v)
    return [str(x).strip() for x in (v or []) if str(x).strip()]


def save_cfg(con, body):
    certs, doms = [], []
    for x in _lines(body.get("certs")):
        x = re.sub(r"^https?://", "", x).split("/")[0]
        if not HOST_RE.match(x):
            raise ValueError(f"证书地址「{x[:40]}」格式不对,写成 example.com 或 example.com:8443")
        if ":" in x and not 1 <= int(x.split(":")[1]) <= 65535:
            raise ValueError(f"「{x}」端口不对")
        if x not in certs:
            certs.append(x)
    for x in _lines(body.get("domains")):
        x = x.lower()
        if not DOM_RE.match(x):
            raise ValueError(f"域名「{x[:40]}」格式不对,写成 example.com")
        if x not in doms:
            doms.append(x)
    if len(certs) > 20 or len(doms) > 20:
        raise ValueError("每类最多 20 个")
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES('expiry',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                    (json.dumps({"certs": certs, "domains": doms}, ensure_ascii=False),))
    refresh_async(force=True)
    return load_cfg(con)


def _days(ts, now=None):
    return int((ts - (now or time.time())) // 86400)


def _decode_not_after(der):
    """不依赖第三方库:借 CPython 自带的证书解码读 notAfter(私有接口,不可用就返回 None)。"""
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(pem)
            p = f.name
        try:
            d = ssl._ssl._test_decode_cert(p)
        finally:
            os.unlink(p)
        return ssl.cert_time_to_seconds(d["notAfter"]), d
    except Exception:
        return None, None


def check_cert(target, timeout=6.0, now=None):
    host, _, port = target.partition(":")
    port = int(port or 443)
    r = {"target": target, "at": int(now or time.time()), "days": None, "not_after": 0, "trusted": None, "err": "", "issuer": ""}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                cert = t.getpeercert()
        r["trusted"] = True
        r["not_after"] = ssl.cert_time_to_seconds(cert["notAfter"])
        r["issuer"] = " ".join(v for rdn in cert.get("issuer", ()) for k, v in rdn if k == "organizationName")[:60]
    except ssl.SSLCertVerificationError as e:
        r["trusted"] = False
        r["err"] = (getattr(e, "verify_message", "") or str(e))[:120]
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as t:
                    na, d = _decode_not_after(t.getpeercert(True))
            if na:
                r["not_after"] = na
        except Exception:
            pass
    except Exception as e:
        r["err"] = (str(e) or e.__class__.__name__)[:120]
    if r["not_after"]:
        r["days"] = _days(r["not_after"], now)
    return r


def check_domain(domain, timeout=10.0, now=None):
    r = {"target": domain, "at": int(now or time.time()), "days": None, "not_after": 0, "err": "", "registrar": ""}
    try:
        req = urllib.request.Request("https://rdap.org/domain/" + domain, headers={"Accept": "application/rdap+json", "User-Agent": "flux-panel"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            j = json.loads(resp.read(300000).decode("utf-8", "replace"))
        exp = next((e.get("eventDate") for e in j.get("events", []) if e.get("eventAction") == "expiration"), None)
        if not exp:
            r["err"] = "这个后缀的 RDAP 没有给到期日"
        else:
            r["not_after"] = int(datetime.fromisoformat(exp.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp())
            r["days"] = _days(r["not_after"], now)
    except urllib.error.HTTPError as e:
        r["err"] = "查不到(这个后缀可能不支持 RDAP)" if e.code in (404, 400) else f"RDAP 服务返回 {e.code}"
    except Exception as e:
        r["err"] = ("查询失败:" + (str(e) or e.__class__.__name__))[:120]
    return r


def refresh(con=None, force=False):
    from . import db
    own = con is None
    con = con or db.open_db()
    try:
        cfg = load_cfg(con)
        now = time.time()
        certs = {t: check_cert(t, now=now) for t in cfg["certs"]}
        doms = {}
        for d in cfg["domains"]:
            doms[d] = check_domain(d, now=now)
        with _lock:
            STATE.update(at=int(now), certs=certs, domains=doms)
        try:
            with con:
                con.execute("INSERT INTO kv(k,v) VALUES('expiry_res',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                            (json.dumps({"at": int(now), "certs": certs, "domains": doms}, ensure_ascii=False),))
        except Exception:
            pass
    finally:
        STATE["running"] = False
        if own:
            con.close()


def refresh_async(force=False):
    with _lock:
        if STATE["running"]:
            return False
        STATE["running"] = True
    threading.Thread(target=lambda: _safe(), name="expiry", daemon=True).start()
    return True


def _safe():
    try:
        refresh()
    except Exception as e:
        log("到期检查出错", e)
        STATE["running"] = False


def _restore(con):
    if STATE["at"]:
        return
    try:
        r = con.execute("SELECT v FROM kv WHERE k='expiry_res'").fetchone()
        if r:
            j = json.loads(r[0])
            cfg = load_cfg(con)
            STATE.update(at=int(j.get("at") or 0), certs={k: v for k, v in (j.get("certs") or {}).items() if k in cfg["certs"]},
                         domains={k: v for k, v in (j.get("domains") or {}).items() if k in cfg["domains"]})
    except Exception:
        pass


def status(con):
    _restore(con)
    cfg = load_cfg(con)
    with _lock:
        return {"cfg": cfg, "at": STATE["at"], "running": STATE["running"], "certs": [STATE["certs"].get(t) or {"target": t, "pending": True} for t in cfg["certs"]],
                "domains": [STATE["domains"].get(d) or {"target": d, "pending": True} for d in cfg["domains"]]}


def check(con, cfg, now):
    from . import alerts
    _restore(con)
    uc = load_cfg(con)
    if not uc["certs"] and not uc["domains"]:
        return
    if now - STATE["at"] >= EVERY:
        refresh_async()
    for kind, rows, label in (("cert_expire", STATE["certs"], "证书"), ("domain_expire", STATE["domains"], "域名")):
        r = cfg["rules"][kind]
        for t, v in list(rows.items()):
            d = v.get("days")
            if d is None or d > r["days"]:
                continue
            if d < 0:
                title, lv = f"{label}已过期:{t}", "bad"
            else:
                title, lv = f"{label}还有 {d} 天到期:{t}", ("bad" if d <= 3 else "warn")
            when = time.strftime("%Y-%m-%d", time.localtime(v["not_after"]))
            detail = f"{t} 的{label}到期日是 {when}。" + ("证书过期后访问会提示不安全,用它的服务可能直接连不上;续期或重新签发即可。" if kind == "cert_expire" else "域名过期后会解析不了,记得到注册商那里续费(开了自动续费也确认一下付款方式)。")
            if r["on"] and alerts._allow(kind, t, r["cool_min"], now):
                alerts.fire(con, cfg, kind, lv, t, title, detail, now)
