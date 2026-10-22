"""面板自己的监听地址 / 端口,可以在页面里改(端口被别的程序占用时用)。

怎么避免把自己锁在外面:
1. 修改时先在新地址上多开一个监听,旧的继续保留;
2. 必须用「新地址」打开面板并确认(页面会自动带你过去),确认后才永久生效、关掉旧的;
3. 120 秒内没有从新地址确认(比如新地址从你的设备访问不到),自动撤销,旧地址照常用;
4. 面板启动时如果配置的端口被别的程序占用,会自动顺延到下一个空闲端口(8099 被占 → 8100 …),并在日志和自检里提示,而不是起不来。
永久生效的设置存在 data/listen.json;万一要手动恢复,删掉这个文件再重启容器,就回到环境变量(LISTEN_HOST / LISTEN_PORT)的默认值。"""
import ipaddress
import json
import os
import threading
import time
from http.server import ThreadingHTTPServer

from . import config
from .util import log

CONFIRM_SEC = 120
_lock = threading.RLock()
_S = {"handler": None, "main": None, "pending": None, "fallback_from": 0, "last_msg": ""}


class _V6(ThreadingHTTPServer):
    import socket as _s
    address_family = _s.AF_INET6


def _path():
    return os.path.join(config.DATA_DIR, "listen.json")


def _load():
    try:
        with open(_path(), encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict) and d.get("port"):
            return {"host": valid_host(d.get("host") or "0.0.0.0"), "port": valid_port(d["port"])}
    except (OSError, ValueError, TypeError):
        pass
    return None


def _save(host, port):
    os.makedirs(config.DATA_DIR, exist_ok=True)
    tmp = _path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"host": host, "port": port}, f)
    os.replace(tmp, _path())


def _drop():
    try:
        os.remove(_path())
    except OSError:
        pass


def valid_host(h):
    h = str(h or "").strip()
    if h in ("0.0.0.0", "::"):
        return h
    try:
        ipaddress.ip_address(h)
    except ValueError:
        raise ValueError("监听地址要写 IP:0.0.0.0(所有网卡)、127.0.0.1(只有路由器本机能打开)或路由器的某个 IP")
    return h


def valid_port(p):
    try:
        p = int(p)
    except (TypeError, ValueError):
        raise ValueError("端口要填数字")
    if not 1 <= p <= 65535:
        raise ValueError("端口范围 1–65535")
    return p


def _open(host, port, name="http"):
    srv = (_V6 if ":" in host else ThreadingHTTPServer)((host, port), _S["handler"])
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, name=name, daemon=True).start()
    return srv


def _close(srv):
    try:
        srv.shutdown()
        srv.server_close()
    except Exception:
        pass


def boot(handler):
    """启动:页面里确认过的设置优先,其次环境变量;端口被占用就顺延。"""
    _S["handler"] = handler
    saved = _load()
    env = (config.LISTEN_HOST, config.LISTEN_PORT)
    host, port, src = (saved["host"], saved["port"], "file") if saved else (env[0], env[1], "env")
    last = None
    for p in [port] + list(range(port + 1, min(65535, port + 21))):
        try:
            srv = _open(host, p)
        except OSError as e:
            last = e
            if p == port:
                log(f"面板端口 {host}:{p} 绑定失败({e.strerror or e}),尝试下一个空闲端口 ...")
            continue
        if p != port:
            _S["fallback_from"] = port
            log(f"⚠ 端口 {port} 被占用,面板改用 :{p}。想固定端口:先在这个页面「设置 → 内核连接」里改一个没人用的端口")
        _S["main"] = {"host": host, "port": p, "srv": srv, "src": src if p == port else "fallback"}
        return srv
    if saved:                    # 页面里存的地址彻底绑不上:删掉它,回到环境变量
        log("页面里保存的监听地址绑定失败,已恢复为环境变量默认值")
        _drop()
        return boot(handler)
    raise last


def status():
    with _lock:
        m, p = _S["main"], _S["pending"]
        out = {"current": {"host": m["host"], "port": m["port"], "src": m["src"]} if m else None,
               "env": {"host": config.LISTEN_HOST, "port": config.LISTEN_PORT}, "fallback_from": _S["fallback_from"],
               "pending": None, "msg": _S["last_msg"]}
        if p:
            out["pending"] = {"host": p["host"], "port": p["port"], "left": max(0, int(p["deadline"] - time.time()))}
        return out


def change(host, port, reset=False):
    """在新地址多开一个监听,等从新地址确认。reset=True 表示恢复为环境变量默认。"""
    with _lock:
        if reset:
            host, port = config.LISTEN_HOST, config.LISTEN_PORT
        host, port = valid_host(host), valid_port(port)
        if _S["pending"]:
            raise ValueError("上一次修改还在等待确认,先确认或等它自动撤销")
        m = _S["main"]
        if (host, port) == (m["host"], m["port"]):
            raise ValueError("和现在的监听地址一样")
        try:
            srv = _open(host, port, name=f"http-new:{port}")
        except OSError as e:
            raise ValueError(f"绑定 {host}:{port} 失败:{e.strerror or e}。端口可能被别的程序占用了,或者这个 IP 不是路由器的地址")
        dl = time.time() + CONFIRM_SEC
        _S["pending"] = {"host": host, "port": port, "srv": srv, "deadline": dl}
        _S["last_msg"] = ""
        threading.Timer(CONFIRM_SEC + 1, _expire, args=(srv,)).start()
        log(f"面板监听地址修改中:新地址 {host}:{port},{CONFIRM_SEC} 秒内要从新地址确认,否则撤销")
        return {"ok": True, "host": host, "port": port, "seconds": CONFIRM_SEC}


def _expire(srv):
    with _lock:
        p = _S["pending"]
        if not p or p["srv"] is not srv:
            return
        _S["pending"] = None
        _S["last_msg"] = f"上次把监听改成 {p['host']}:{p['port']},但 {CONFIRM_SEC} 秒内没有从新地址确认,已撤销,仍在用原来的地址"
    _close(srv)
    log("面板监听地址修改未确认,已撤销")


def cancel():
    with _lock:
        p = _S["pending"]
        if not p:
            raise ValueError("没有等待确认的修改")
        _S["pending"] = None
    _close(p["srv"])
    return {"ok": True}


def confirm(via):
    """必须是从新地址的监听进来的请求(证明新地址你确实访问得到)才算数。"""
    with _lock:
        p = _S["pending"]
        if not p:
            raise ValueError("没有等待确认的修改(可能已经确认过,或已超时撤销)")
        if via is not p["srv"]:
            raise ValueError("要用新地址打开面板来确认,当前这个页面还是旧地址")
        old = _S["main"]
        _S["pending"] = None
        env = (config.LISTEN_HOST, config.LISTEN_PORT)
        if (p["host"], p["port"]) == env:
            _drop()
        else:
            _save(p["host"], p["port"])
        _S["main"] = {"host": p["host"], "port": p["port"], "srv": p["srv"], "src": "env" if (p["host"], p["port"]) == env else "file"}
        _S["fallback_from"] = 0
        _S["last_msg"] = ""
    threading.Thread(target=_close, args=(old["srv"],), daemon=True).start()     # 不在请求线程里关旧监听
    log(f"面板监听地址已改为 {p['host']}:{p['port']}")
    return {"ok": True, "host": p["host"], "port": p["port"]}
