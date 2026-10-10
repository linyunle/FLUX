"""出口详情:让每个节点各走一遍「查 IP」接口,拿到真实出口 IP / 位置 / 运营商。

原理:nikki 里放一个 select 组 egress-probe 和一个只监听本机的 http 入口(指向该组),
      逐个把组切到节点 → 通过入口访问回显接口 → 记录结果。需要 nikki 配置里加一段(见 SNIPPET)。
      不装这段也能用:页面只显示延迟和节点服务器地址,不做出口探测。
"""
import socket
import threading
import time
import urllib.error
import urllib.request

from . import config, db
from .util import api_call, http_json, log, q, stop

SNIPPET = f"""# 追加到 /etc/nikki/mixin.yaml(先备份:cp /etc/nikki/mixin.yaml /etc/nikki/mixin.yaml.bak)
listeners:
  - name: {config.PROBE_LISTENER}
    type: http
    listen: 127.0.0.1
    port: {config.PROBE_PORT}
    proxy: {config.PROBE_GROUP}
nikki-proxy-groups:
  - name: {config.PROBE_GROUP}
    type: select
    include-all: true
"""

_lock = threading.Lock()
PROGRESS = {"running": False, "done": 0, "total": 0, "current": "", "started": 0, "finished": 0}


def _norm(d):
    """把 ip.sb / ipwho.is 两种返回统一成 {ip,country,region,city,org,asn}。"""
    if not isinstance(d, dict) or d.get("success") is False:
        raise ValueError("回显接口返回异常")
    conn = d.get("connection") if isinstance(d.get("connection"), dict) else {}
    ip = d.get("ip") or ""
    if not ip:
        raise ValueError("回显里没有 IP")
    return {
        "ip": str(ip),
        "country": str(d.get("country") or ""),
        "region": str(d.get("region") or ""),
        "city": str(d.get("city") or ""),
        "org": str(d.get("organization") or d.get("isp") or conn.get("org") or conn.get("isp") or ""),
        "asn": str(d.get("asn") or conn.get("asn") or ""),
    }


def ready():
    """探测前提:select 组存在 + 本地入口端口在监听。"""
    res = {"group": False, "listener": False, "group_ok_type": False}
    try:
        g = api_call("/proxies/" + q(config.PROBE_GROUP), timeout=4)
        res["group"] = isinstance(g, dict) and isinstance(g.get("all"), list)
        res["group_ok_type"] = res["group"] and str(g.get("type", "")).lower() == "selector"
    except Exception:
        pass
    try:
        s = socket.create_connection(("127.0.0.1", config.PROBE_PORT), timeout=2)
        s.close()
        res["listener"] = True
    except OSError:
        pass
    res["ok"] = res["group_ok_type"] and res["listener"]
    return res


def probe_one(node):
    api_call("/proxies/" + q(config.PROBE_GROUP), method="PUT", body={"name": node}, timeout=6)
    purl = f"http://127.0.0.1:{config.PROBE_PORT}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": purl, "https": purl}))
    err = "无可用回显接口"
    for url in config.ECHO_URLS:
        try:
            return _norm(http_json(url.strip(), timeout=10, opener=opener)), None
        except Exception as e:
            err = f"{type(e).__name__}: {e}"[:200]
    return None, err


def _save(node, info, err):
    con = db.open_db()
    try:
        with con:
            if info:
                con.execute(
                    "INSERT INTO egress(node,ip,country,region,city,org,asn,probed_at,error) VALUES(?,?,?,?,?,?,?,?,NULL) "
                    "ON CONFLICT(node) DO UPDATE SET ip=excluded.ip,country=excluded.country,region=excluded.region,"
                    "city=excluded.city,org=excluded.org,asn=excluded.asn,probed_at=excluded.probed_at,error=NULL",
                    (node, info["ip"], info["country"], info["region"], info["city"], info["org"], info["asn"], int(time.time())))
            else:  # 失败保留上次成功的结果,只更新时间和错误
                con.execute(
                    "INSERT INTO egress(node,probed_at,error) VALUES(?,?,?) "
                    "ON CONFLICT(node) DO UPDATE SET probed_at=excluded.probed_at,error=excluded.error",
                    (node, int(time.time()), err))
    finally:
        con.close()


def run_probe(nodes):
    """逐个探测。同一时间只跑一轮。返回 (started, message)。"""
    if not _lock.acquire(blocking=False):
        return False, "上一轮还没跑完"
    r = ready()
    if not r["ok"]:
        _lock.release()
        why = []
        if not r["group_ok_type"]:
            why.append(f"nikki 里没有名为 {config.PROBE_GROUP} 的 select 组")
        if not r["listener"]:
            why.append(f"127.0.0.1:{config.PROBE_PORT} 没有在监听")
        return False, ";".join(why)

    def work():
        try:
            PROGRESS.update(running=True, done=0, total=len(nodes), current="", started=int(time.time()))
            # 记下原来选中的节点,探测完还原
            try:
                g = api_call("/proxies/" + q(config.PROBE_GROUP), timeout=4)
                orig = g.get("now") or ""
            except Exception:
                orig = ""
            for n in nodes:
                if stop.is_set():
                    break
                PROGRESS["current"] = n
                try:
                    info, err = probe_one(n)
                except Exception as e:
                    info, err = None, f"{type(e).__name__}: {e}"[:200]
                try:
                    _save(n, info, err)
                except Exception as e:
                    log("保存出口结果失败:", e)
                PROGRESS["done"] += 1
            if orig:
                try:
                    api_call("/proxies/" + q(config.PROBE_GROUP), method="PUT", body={"name": orig}, timeout=4)
                except Exception:
                    pass
        finally:
            PROGRESS.update(running=False, current="", finished=int(time.time()))
            _lock.release()

    threading.Thread(target=work, name="egress-probe", daemon=True).start()
    return True, f"开始探测 {len(nodes)} 个节点"


def current_nodes():
    from . import collector
    c = collector.COLLECTOR
    return sorted(c.nodes) if c else []


def auto_worker():
    """按间隔自动刷新(EGRESS_INTERVAL_H=0 则只手动)。"""
    if config.EGRESS_INTERVAL_H <= 0:
        return
    stop.wait(60)
    while not stop.is_set():
        try:
            if ready()["ok"] and not PROGRESS["running"]:
                con = db.open_db(readonly=True)
                try:
                    cut = int(time.time() - config.EGRESS_INTERVAL_H * 3600)
                    done = {r[0] for r in con.execute("SELECT node FROM egress WHERE probed_at >= ?", (cut,))}
                finally:
                    con.close()
                todo = [n for n in current_nodes() if n not in done]
                if todo:
                    run_probe(todo)
        except Exception as e:
            log("自动探测异常:", e)
        stop.wait(600)
