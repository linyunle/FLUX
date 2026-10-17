"""节点测速(可选):nikki 只给策略组里的节点做延迟测试,其它节点没有测速数据,节点评分就看不到。
开启后,面板每隔一段时间让 nikki 给「最近 24 小时真正用过的节点」测一次延迟(GET /proxies/节点/delay,
不改任何配置),结果会进 nikki 的测速记录,再被面板读回去算评分。只测在用的节点,请求量很小。"""
import json
import threading
import urllib.error
import time
import urllib.parse

from .util import api_call, log

DEFAULT = {"on": False, "minutes": 30, "top": 12, "url": "https://www.gstatic.com/generate_204"}
_state = {"last": 0, "running": False, "result": None}


def _kv_get(con, k, d):
    try:
        r = con.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
        return json.loads(r[0]) if r else d
    except Exception:
        return d


def load_cfg(con):
    c = dict(DEFAULT)
    v = _kv_get(con, "probe", {}) or {}
    if isinstance(v, dict):
        c["on"] = bool(v.get("on"))
        c["minutes"] = max(10, min(1440, int(v.get("minutes") or c["minutes"])))
        c["top"] = max(1, min(40, int(v.get("top") or c["top"])))
        u = str(v.get("url") or "")
        if u.startswith(("http://", "https://")) and len(u) <= 200:
            c["url"] = u
    return c


def save_cfg(con, body):
    try:
        c = {"on": bool(body.get("on")), "minutes": int(body.get("minutes") or 30), "top": int(body.get("top") or 12),
             "url": str(body.get("url") or DEFAULT["url"]).strip()}
    except (TypeError, ValueError):
        raise ValueError("间隔和数量要填数字")
    if not c["url"].startswith(("http://", "https://")) or len(c["url"]) > 200:
        raise ValueError("测速地址要以 http:// 或 https:// 开头")
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES('probe',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (json.dumps(c, ensure_ascii=False),))
    return load_cfg(con)


def candidates(con, top, now=None):
    since = time.strftime("%Y-%m-%d %H", time.localtime((now or time.time()) - 24 * 3600))
    rows = con.execute("SELECT node, SUM(up+down) s FROM hourly WHERE hour>=? GROUP BY node ORDER BY s DESC LIMIT ?", (since, top * 3)).fetchall()
    from . import airports
    out = []
    for n, _ in rows:
        if n and n not in airports.SPECIAL and n not in ("DIRECT", "REJECT", "UNKNOWN", "直连", "拒绝", "未知"):
            out.append(n)
    return out[:top]


def _test_one(n, url, prov):
    """让 nikki 测一个节点。订阅(provider)里的节点要走 /providers/proxies/<订阅>/<节点>/healthcheck,
    本地配置的节点走 /proxies/<节点>/delay。返回 (是否有响应, 错误说明)。"""
    q = f"url={urllib.parse.quote(url, safe='')}&timeout=5000"
    paths = ([f"/providers/proxies/{urllib.parse.quote(prov, safe='')}/{urllib.parse.quote(n, safe='')}/healthcheck?{q}"] if prov else []) \
        + [f"/proxies/{urllib.parse.quote(n, safe='')}/delay?{q}"]
    err = ""
    for path in paths:
        try:
            api_call(path, timeout=8)
            return True, ""
        except urllib.error.HTTPError as e:
            err = f"HTTP {e.code}"
            if e.code in (404, 400) and path is not paths[-1]:
                continue   # 这个接口不认,换下一个
            return False, err   # 504 之类 = 节点测速超时,是正常的失败
        except Exception as e:
            return False, type(e).__name__
    return False, err


def _run(nodes, url):
    from . import airports
    ok = bad = 0
    errs = {}
    for n in nodes:
        with airports._lock:
            prov = airports._prov.get(n, "")
        good, err = _test_one(n, url, prov)
        if good:
            ok += 1
        else:
            bad += 1   # 超时也会被 nikki 记成一次失败的测速,这正是评分要的数据
            errs[err] = errs.get(err, 0) + 1
    _state.update(running=False, result={"at": int(time.time()), "ok": ok, "fail": bad, "n": len(nodes), "errs": errs})
    log(f"节点测速完成:{len(nodes)} 个节点,{ok} 个有响应,{bad} 个超时/失败" + (f"({'、'.join(f'{k}×{v}' for k, v in errs.items())})" if errs else ""))


def check(con, cfg, now):
    c = load_cfg(con)
    if not c["on"] or _state["running"] or now - _state["last"] < c["minutes"] * 60:
        return
    _state["last"] = now
    nodes = candidates(con, c["top"], now)
    if not nodes:
        return
    _state["running"] = True
    threading.Thread(target=_run, args=(nodes, c["url"]), daemon=True).start()


def status(con):
    c = load_cfg(con)
    return {"cfg": c, "last": _state["result"], "running": _state["running"], "nodes": candidates(con, c["top"])}
