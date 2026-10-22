"""Docker 容器页(可选,默认关闭)。

安全设计:面板**不挂载 docker.sock**(挂了就等于给了整台路由器的 root)。它只通过一个受限的 docker-socket-proxy 访问 Docker:
- 只读模式(默认):代理只放行 GET,面板只能看容器列表、资源占用、日志;
- 控制模式(单独的开关,默认关):代理多放行「启动 / 停止 / 重启」,并且面板侧还要求:已设置访问密码、不能操作 flux 自己和代理本身、
  每次操作都写进告警时间线(谁、从哪个 IP、对哪个容器)。
面板不会去读容器的环境变量(里面常有密码),也不会创建/删除容器、不会进入容器执行命令。"""
import concurrent.futures
import ipaddress
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import auth
from .util import log

DEFAULT = {"on": False, "url": "http://127.0.0.1:2375", "control": False}
STATE = {"ok": None, "err": "", "at": 0, "n": 0}
_cache = {"t": 0.0, "v": None, "busy": False}
_lock = threading.Lock()
_prev = {}          # 容器名 -> 上次轮询的状态(给「容器停了」告警用)
_expected = {}      # 容器名 -> 面板自己操作的时间(这段时间内的停止/重启不告警)
_last_act = [0.0]
_poll = {"t": 0.0, "bad": {}}
ID_RE = re.compile(r"^[0-9a-f]{12,64}$")
ACTIONS = {"start": "启动", "stop": "停止", "restart": "重启"}
PROTECT_IMG = ("linyunle/flux", "docker-socket-proxy", "wollomatic/socket-proxy")


def _url_ok(u):
    p = urllib.parse.urlparse(u)
    if p.scheme != "http" or not p.hostname or p.path not in ("", "/") or p.query or p.username:
        return False
    h = p.hostname
    try:
        a = ipaddress.ip_address(h)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return "." not in h and re.match(r"^[A-Za-z0-9\-_]{1,60}$", h) is not None     # 只允许 localhost / 单段主机名


def load_cfg(con):
    c = dict(DEFAULT)
    try:
        r = con.execute("SELECT v FROM kv WHERE k='docker'").fetchone()
        v = json.loads(r[0]) if r else {}
    except Exception:
        v = {}
    if isinstance(v, dict):
        c["on"] = bool(v.get("on"))
        c["control"] = bool(v.get("control"))
        u = str(v.get("url") or "").rstrip("/")
        if u and _url_ok(u):
            c["url"] = u
    return c


def control_ok():
    """能不能开控制:必须设置了访问密码。"""
    return auth.enabled()


def save_cfg(con, body):
    url = str(body.get("url") or DEFAULT["url"]).strip().rstrip("/")
    if url.startswith("unix:") or "docker.sock" in url:
        raise ValueError("不支持直接连 docker.sock。请用 docker-socket-proxy(设置页里有 compose 示例)")
    if not _url_ok(url):
        raise ValueError("地址要写成 http://127.0.0.1:2375 这样,只允许本机/内网地址")
    c = {"on": bool(body.get("on")), "url": url, "control": bool(body.get("control"))}
    if c["control"] and not control_ok():
        raise ValueError("要先在「设置 → 安全与访问」设置访问密码,才能开启容器的启动/停止功能")
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES('docker',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (json.dumps(c),))
    with _lock:
        _cache.update(t=0.0, v=None)
    STATE.update(ok=None, err="")
    return load_cfg(con)


def _req(cfg, path, method="GET", timeout=6.0, raw=False):
    req = urllib.request.Request(cfg["url"] + path, method=method, data=b"" if method == "POST" else None)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(2_000_000)
        code = r.status
    if raw:
        return code, data
    return code, (json.loads(data.decode("utf-8", "replace")) if data.strip() else None)


def _explain(e):
    if isinstance(e, urllib.error.HTTPError):
        if e.code == 403:
            return "代理拒绝了这个请求(403):docker-socket-proxy 没放行,检查它的环境变量(看容器要 CONTAINERS=1;启动/停止/重启要 ALLOW_START、ALLOW_STOP、ALLOW_RESTARTS 设为 1)"
        return f"Docker 返回 {e.code}"
    if isinstance(e, urllib.error.URLError):
        return f"连不上 {e.reason}。确认 docker-socket-proxy 在跑、地址和端口对"
    return (str(e) or e.__class__.__name__)[:150]


def protected(c):
    """返回不让操作的理由,可以操作返回空。"""
    img = (c.get("Image") or "").lower()
    names = [n.lstrip("/") for n in c.get("Names") or []]
    svc = (c.get("Labels") or {}).get("com.docker.compose.service", "")
    if "flux" in names or svc == "flux" or "linyunle/flux" in img:
        return "这是 FLUX 自己,停掉它面板就没了"
    if any(p in img for p in PROTECT_IMG[1:]) or any("socket-proxy" in n for n in names):
        return "这是面板用来连 Docker 的代理,停掉它面板就看不到容器了"
    return ""


def _cpu(st):
    cs, pcs = st.get("cpu_stats") or {}, st.get("precpu_stats") or {}
    dc = (cs.get("cpu_usage") or {}).get("total_usage", 0) - (pcs.get("cpu_usage") or {}).get("total_usage", 0)
    ds = (cs.get("system_cpu_usage") or 0) - (pcs.get("system_cpu_usage") or 0)
    n = cs.get("online_cpus") or len((cs.get("cpu_usage") or {}).get("percpu_usage") or []) or 1
    return round(dc / ds * n * 100, 1) if ds > 0 and dc >= 0 else None


def _mem(st):
    ms = st.get("memory_stats") or {}
    use = ms.get("usage")
    if use is None:
        return None, 0
    s = ms.get("stats") or {}
    use -= s.get("inactive_file", s.get("total_inactive_file", s.get("cache", 0))) or 0
    lim = ms.get("limit") or 0
    return max(0, use), (lim if 0 < lim < 1 << 50 else 0)


def _net(st):
    n = st.get("networks") or {}
    if not n:
        return None, None
    return sum(v.get("rx_bytes", 0) for v in n.values()), sum(v.get("tx_bytes", 0) for v in n.values())


def _ports(c):
    out = []
    for p in c.get("Ports") or []:
        s = (f"{p['PublicPort']}→" if p.get("PublicPort") else "") + f"{p.get('PrivatePort')}/{p.get('Type', 'tcp')}"
        if s not in out:
            out.append(s)
    return out[:6]


def _row(c):
    lb = c.get("Labels") or {}
    return {"id": (c.get("Id") or "")[:12], "name": (c.get("Names") or ["?"])[0].lstrip("/"), "image": c.get("Image") or "",
            "state": c.get("State") or "", "status": c.get("Status") or "", "created": c.get("Created") or 0,
            "ports": _ports(c), "net": (c.get("HostConfig") or {}).get("NetworkMode") or "", "project": lb.get("com.docker.compose.project", ""),
            "service": lb.get("com.docker.compose.service", ""), "cpu": None, "mem": None, "mem_limit": 0, "rx": None, "tx": None,
            "locked": protected(c)}


def _stats(cfg, cid):
    try:
        _, st = _req(cfg, f"/containers/{cid}/stats?stream=false&one-shot=false", timeout=8.0)
    except Exception:
        return cid, None
    return cid, st


def _build(cfg):
    _, lst = _req(cfg, "/containers/json?all=1&size=0")
    rows = [_row(c) for c in (lst or [])]
    run = [r for r in rows if r["state"] == "running"]
    if run:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            res = dict(ex.map(lambda r: _stats(cfg, r["id"]), run))
        for r in run:
            st = res.get(r["id"])
            if st:
                r["cpu"] = _cpu(st)
                r["mem"], r["mem_limit"] = _mem(st)
                r["rx"], r["tx"] = _net(st)
    rows.sort(key=lambda r: (r["state"] != "running", r["name"].lower()))
    return rows


def _refresh(cfg):
    try:
        rows = _build(cfg)
        with _lock:
            _cache.update(t=time.time(), v={"ok": True, "error": "", "rows": rows})
        STATE.update(ok=True, err="", at=int(time.time()), n=len(rows))
    except Exception as e:
        err = _explain(e)
        with _lock:
            _cache.update(t=time.time(), v={"ok": False, "error": err, "rows": []})
        STATE.update(ok=False, err=err, at=int(time.time()), n=0)
    finally:
        _cache["busy"] = False


def snapshot(con, force=False):
    cfg = load_cfg(con)
    out = {"cfg": cfg, "control": {"enabled": bool(cfg["control"] and control_ok()), "password": control_ok()}}
    if not cfg["on"]:
        return dict(out, ok=None, error="", rows=[], age=0)
    now = time.time()
    with _lock:
        v, age, busy = _cache["v"], now - _cache["t"], _cache["busy"]
        stale = v is None or age > 15 or force
        start = stale and not busy
        if start:
            _cache["busy"] = True
    if start:
        if v is None or force:
            _refresh(cfg)
        else:
            threading.Thread(target=_refresh, args=(cfg,), name="dockerpoll", daemon=True).start()
        with _lock:
            v, age = _cache["v"], now - _cache["t"]
    elif v is None:               # 别的线程正在首次拉取
        for _ in range(40):
            time.sleep(0.25)
            with _lock:
                if _cache["v"] is not None:
                    break
        with _lock:
            v = _cache["v"]
    v = v or {"ok": None, "error": "", "rows": []}
    return dict(out, ok=v["ok"], error=v["error"], rows=v["rows"], age=int(max(0, time.time() - _cache["t"])))


def test(body):
    url = str(body.get("url") or DEFAULT["url"]).strip().rstrip("/")
    if url.startswith("unix:") or "docker.sock" in url or not _url_ok(url):
        raise ValueError("地址要写成 http://127.0.0.1:2375 这样,只允许本机/内网地址;不支持直连 docker.sock")
    try:
        _, lst = _req({"url": url}, "/containers/json?all=1&size=0", timeout=5.0)
    except Exception as e:
        raise ValueError(_explain(e))
    try:
        _, v = _req({"url": url}, "/version", timeout=5.0)      # 代理可能没放行 /version,不影响使用
    except Exception:
        v = None
    return {"ok": True, "version": (v or {}).get("Version", ""), "containers": len(lst or [])}


def _find(cfg, cid):
    if not ID_RE.match(cid or ""):
        raise ValueError("容器 ID 不对")
    _, lst = _req(cfg, "/containers/json?all=1&size=0")
    for c in lst or []:
        if (c.get("Id") or "").startswith(cid):
            return c
    raise ValueError("找不到这个容器(可能已被删除),刷新一下页面")


def logs(con, cid, tail=200):
    cfg = load_cfg(con)
    if not cfg["on"]:
        raise ValueError("容器管理没有开启")
    c = _find(cfg, cid)
    tail = max(10, min(1000, int(tail)))
    try:
        _, data = _req(cfg, f"/containers/{c['Id']}/logs?stdout=1&stderr=1&timestamps=1&tail={tail}", timeout=8.0, raw=True)
    except Exception as e:
        raise ValueError(_explain(e))
    return {"name": (c.get("Names") or ["?"])[0].lstrip("/"), "text": _demux(data)[-200000:]}


def _demux(b):
    """docker 日志流:没有 TTY 时每帧前有 8 字节头(类型 + 长度),有 TTY 时就是纯文本。"""
    out, i, ok = [], 0, len(b) >= 8 and b[0] in (0, 1, 2) and b[1:4] == b"\0\0\0"
    if not ok:
        return b.decode("utf-8", "replace")
    while i + 8 <= len(b):
        n = int.from_bytes(b[i + 4:i + 8], "big")
        out.append(b[i + 8:i + 8 + n].decode("utf-8", "replace"))
        i += 8 + n
    return "".join(out)


def act(con, cid, action, ip=""):
    from . import alerts
    if action not in ACTIONS:
        raise ValueError("不支持的操作")
    cfg = load_cfg(con)
    if not cfg["on"] or not cfg["control"]:
        raise ValueError("没有开启容器的启动/停止功能(设置 → 容器管理)")
    if not control_ok():
        raise ValueError("没有设置访问密码,不能操作容器")
    now = time.time()
    if now - _last_act[0] < 1.5:
        raise ValueError("操作太快了,稍等一下")
    _last_act[0] = now
    c = _find(cfg, cid)
    name = (c.get("Names") or ["?"])[0].lstrip("/")
    why = protected(c)
    if why:
        raise ValueError(f"不能操作「{name}」:{why}")
    try:
        code, _ = _req(cfg, f"/containers/{c['Id']}/{action}" + ("?t=10" if action != "start" else ""), method="POST", timeout=30.0)
        res = "完成"
    except urllib.error.HTTPError as e:
        if e.code == 304:
            res = "没有变化(已经是这个状态)"
        else:
            alerts.note(con, "audit", "docker", f"容器操作失败:{ACTIONS[action]} {name}", f"来自 {ip or '?'};{_explain(e)}", level="warn")
            raise ValueError(_explain(e))
    except Exception as e:
        alerts.note(con, "audit", "docker", f"容器操作失败:{ACTIONS[action]} {name}", f"来自 {ip or '?'};{_explain(e)}", level="warn")
        raise ValueError(_explain(e))
    _expected[name] = now
    alerts.note(con, "audit", "docker", f"容器操作:{ACTIONS[action]} {name}", f"来自 {ip or '?'},结果:{res}")
    log("容器操作", ACTIONS[action], name, ip)
    with _lock:
        _cache["t"] = 0.0
    return {"ok": True, "result": res, "name": name}


def check(con, cfg, now):
    """给告警引擎用:每分钟看一眼,原本在跑的容器停了/一直在重启/不健康就告警。面板自己操作的不算。"""
    from . import alerts
    dc = load_cfg(con)
    if not dc["on"]:
        _prev.clear()
        return
    if now - _poll["t"] < 60:
        return
    _poll["t"] = now
    try:
        _, lst = _req(dc, "/containers/json?all=1&size=0", timeout=6.0)
    except Exception as e:
        STATE.update(ok=False, err=_explain(e), at=int(now))
        return
    STATE.update(ok=True, err="", at=int(now), n=len(lst or []))
    seen = {}
    for c in lst or []:
        name = (c.get("Names") or ["?"])[0].lstrip("/")
        st, status = c.get("State") or "", c.get("Status") or ""
        seen[name] = st
        was = _prev.get(name)
        exp = now - _expected.get(name, 0) < 300
        rd, ru = cfg["rules"]["docker_down"], cfg["rules"]["docker_unhealthy"]
        if was is not None and not exp:
            if was == "running" and st in ("exited", "dead", "restarting"):
                t, d = f"容器「{name}」停了", f"{name}({c.get('Image')})状态从运行中变成 {st}:{status}。看一下它的日志(面板「容器」页)。"
                (alerts.fire(con, cfg, "docker_down", "warn", name, t, d, now) if rd["on"] and alerts._allow("docker_down", name, rd["cool_min"], now)
                 else alerts.note(con, "docker_down", name, t, d, level="warn", now=now))
            elif st == "restarting" and was == "restarting" and alerts._allow("docker_down", name + "/loop", rd["cool_min"], now):
                t, d = f"容器「{name}」在反复重启", f"{name} 连续两次检查都在重启中:{status}。多半是它自己启动就崩溃了,看日志找原因。"
                alerts.fire(con, cfg, "docker_down", "bad", name + "/loop", t, d, now) if rd["on"] else alerts.note(con, "docker_down", name, t, d, level="bad", now=now)
        if "(unhealthy)" in status and not exp:
            t, d = f"容器「{name}」不健康", f"{name} 的健康检查没通过:{status}。"
            (alerts.fire(con, cfg, "docker_unhealthy", "warn", name, t, d, now) if ru["on"] and alerts._allow("docker_unhealthy", name, ru["cool_min"], now)
             else None)
    _prev.clear()
    _prev.update(seen)
