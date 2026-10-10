"""网页和 JSON 接口。"""
import ipaddress
import json
import mimetypes
import os
import re
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import collector, config, db, devices, realtime, update
from .util import api_call, is_mac, log, stop

STATIC = os.path.join(os.path.dirname(__file__), "static")
DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
RAW_COL = {"node": "node", "group": "grp", "rule": "rule", "host": "host"}
MODES = ("direct", "reject", "proxy")
_kind_cache = {"at": 0.0, "d": ["DIRECT"], "r": []}


def kind_names():
    """按节点「类型」判断直连/拒绝,而不是按名字(你的直连出口可能叫「直连」而不是 DIRECT)。"""
    if time.time() - _kind_cache["at"] < 20:
        return _kind_cache["d"], _kind_cache["r"]
    d, r = {"DIRECT"}, set()
    c = collector.COLLECTOR
    pt = dict(c.ptype) if c else {}
    try:
        con = ro()
        try:
            for n, typ in con.execute("SELECT node, type FROM nodeinfo"):
                pt.setdefault(n, typ or "")
        finally:
            con.close()
    except Exception:
        pass
    for n, typ in pt.items():
        tl = (typ or "").lower()
        if tl == "direct":
            d.add(n)
        elif tl in ("reject", "rejectdrop"):
            r.add(n)
    _kind_cache.update(at=time.time(), d=sorted(d), r=sorted(r))
    return _kind_cache["d"], _kind_cache["r"]


def _in(names):
    return "(" + ",".join("?" * len(names)) + ")"


def mode_clause(mode):
    """返回 (sql, args)。"""
    d, r = kind_names()
    rej = f"(node IN {_in(r)} OR node LIKE 'REJECT%')" if r else "node LIKE 'REJECT%'"
    if mode == "direct":
        return f"node IN {_in(d)}", list(d)
    if mode == "reject":
        return rej, list(r)
    return f"(node NOT IN {_in(d)} AND NOT {rej})", list(d) + list(r)
DEVX = "COALESCE((SELECT mac FROM ipmap WHERE ip = client), client)"  # 旧数据里的 IP 也并到设备上


def one(p, k, d=""):
    return p.get(k, [d])[0]


def csv(p, k):
    return [x for x in one(p, k).split(",") if x]


def day_range(p):
    today = time.strftime("%Y-%m-%d")
    d1, d2 = one(p, "from", today), one(p, "to", "")
    d2 = d2 or d1
    if not (DAY_RE.match(d1) and DAY_RE.match(d2)):
        d1 = d2 = today
    if d1 > d2:
        d1, d2 = d2, d1
    return d1, d2


def filters(p, cols, skip_mode=False):
    """cols: 该表有哪些可筛选维度。返回 (where 列表, 参数)。"""
    where, args = [], []
    devs = [d.lower() for d in csv(p, "dev")]
    if devs and "dev" in cols:
        where.append(f"{DEVX} IN ({','.join('?' * len(devs))})")
        args += devs
    for f, col in RAW_COL.items():
        v = one(p, f)
        if v and f in cols:
            where.append(f"{col} = ?")
            args.append(v)
    kw = one(p, "q").strip()
    if kw and "host" in cols:
        where.append("host LIKE ? ESCAPE '\\'")
        args.append("%" + kw.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    mode = one(p, "mode")
    if mode in MODES and not skip_mode:
        sql, a = mode_clause(mode)
        where.append(sql)
        args += a
    return where, args


T_COLS = {"dev", "node", "group", "rule", "host"}
H_COLS = {"dev", "node"}


def ro():
    return db.open_db(readonly=True)


def live():
    c = collector.COLLECTOR
    return c.live if c else {"at": 0, "nodes": {}, "clients": {}}


# ---------------------------------------------------------------- 查询
def q_summary(p):
    by = one(p, "by", "client")
    if by not in ("client", "node", "group", "rule", "host"):
        return 400, {"error": "by 不对"}
    expr = DEVX if by == "client" else RAW_COL[by]
    d1, d2 = day_range(p)
    try:
        limit = max(1, min(500, int(one(p, "limit", "50"))))
    except ValueError:
        limit = 50
    fw, fa = filters(p, T_COLS)
    where = " AND ".join(["day >= ?", "day <= ?"] + fw)
    args = [d1, d2] + fa
    con = ro()
    try:
        rows = con.execute(f"SELECT {expr} k, SUM(up), SUM(down) FROM traffic WHERE {where} GROUP BY k "
                           f"ORDER BY SUM(up)+SUM(down) DESC LIMIT ?", (*args, limit)).fetchall()
        tot = con.execute(f"SELECT COALESCE(SUM(up),0), COALESCE(SUM(down),0) FROM traffic WHERE {where}", args).fetchone()
        n_all = con.execute(f"SELECT COUNT(DISTINCT {expr}) FROM traffic WHERE {where}", args).fetchone()[0]
        macips = devices.ips_by_dev(con) if by == "client" else {}
        stored = devices.stored_names(con) if by == "client" else {}
        nodes_by = {}
        if by in ("group", "rule") and rows:  # 每个策略组/规则最终走了哪些节点
            keys = [r[0] for r in rows]
            for k, n, b in con.execute(
                    f"SELECT {expr}, node, SUM(up)+SUM(down) FROM traffic WHERE {where} AND {expr} IN {_in(keys)} "
                    f"GROUP BY {expr}, node", args + keys):
                nodes_by.setdefault(k, []).append((n, b))
    finally:
        con.close()
    lv = live()
    out = []
    for key, up, down in rows:
        r = {"key": key, "up": up, "down": down}
        if by == "client":
            ips = macips.get(key, [] if is_mac(key) else [key])
            r.update(name=devices.NAMES.label(key, ips, stored), ips=ips[:8], is_mac=is_mac(key),
                     live=lv["clients"].get(key))
        elif by == "node":
            r["live"] = lv["nodes"].get(key)
        elif by in ("group", "rule"):
            r["nodes"] = [{"node": n, "bytes": b} for n, b in sorted(nodes_by.get(key, []), key=lambda x: -x[1])[:3]]
        out.append(r)
    return 200, {"from": d1, "to": d2, "by": by, "total": {"up": tot[0], "down": tot[1]}, "count": n_all, "rows": out}


def q_modes(p):
    d1, d2 = day_range(p)
    fw, fa = filters(p, T_COLS, skip_mode=True)
    where = " AND ".join(["day >= ?", "day <= ?"] + fw)
    con = ro()
    try:
        d, r = kind_names()
        case = (f"CASE WHEN node IN {_in(d)} THEN 'direct' "
                f"WHEN {('node IN ' + _in(r) + ' OR ') if r else ''}node LIKE 'REJECT%' THEN 'reject' ELSE 'proxy' END")
        rows = con.execute(f"SELECT {case}, SUM(up), SUM(down) FROM traffic WHERE {where} GROUP BY 1",
                           list(d) + list(r) + [d1, d2] + fa).fetchall()
        wan = con.execute("SELECT COALESCE(SUM(up),0), COALESCE(SUM(down),0), COUNT(*) FROM wan WHERE day >= ? AND day <= ?",
                          (d1, d2)).fetchone()
    finally:
        con.close()
    m = {k: {"up": 0, "down": 0} for k in ("proxy", "direct", "reject")}
    for k, u, d in rows:
        m[k] = {"up": u, "down": d}
    return 200, {"from": d1, "to": d2, "modes": m, "wan": {"up": wan[0], "down": wan[1]} if wan[2] else None}


def q_days(p):
    d1, d2 = day_range(p)
    if one(p, "days"):
        try:
            n = max(1, min(180, int(one(p, "days"))))
        except ValueError:
            n = 14
        d2 = time.strftime("%Y-%m-%d")
        d1 = time.strftime("%Y-%m-%d", time.localtime(time.time() - (n - 1) * 86400))
    fw, fa = filters(p, T_COLS)
    where = " AND ".join(["day >= ?", "day <= ?"] + fw)
    con = ro()
    try:
        rows = {d: (u, w) for d, u, w in con.execute(
            f"SELECT day, SUM(up), SUM(down) FROM traffic WHERE {where} GROUP BY day", [d1, d2] + fa)}
    finally:
        con.close()
    out, t = [], time.mktime(time.strptime(d1, "%Y-%m-%d"))
    end = time.mktime(time.strptime(d2, "%Y-%m-%d"))
    while t <= end + 1:
        d = time.strftime("%Y-%m-%d", time.localtime(t))
        u, w = rows.get(d, (0, 0))
        out.append({"day": d, "up": u, "down": w})
        t += 86400
        t = time.mktime(time.strptime(time.strftime("%Y-%m-%d", time.localtime(t + 3600)), "%Y-%m-%d"))
    return 200, {"from": d1, "to": d2, "days": out}


CC_SLD = {"com", "net", "org", "gov", "edu", "ac", "co"}


def reg_domain(h):
    """a.b.example.com -> example.com;com.cn / co.uk 这类按三段算。IP 和单段名不动。"""
    h = (h or "").strip().lower().rstrip(".")
    if not h or "." not in h:
        return h
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass
    parts = h.split(".")
    if len(parts) <= 2:
        return h
    n = 3 if len(parts[-1]) == 2 and parts[-2] in CC_SLD else 2
    return ".".join(parts[-n:])


def q_domains(p):
    """每个域名:总量、去向(直连/代理)、哪些设备访问、最近哪天。可合并子域名。"""
    d1, d2 = day_range(p)
    try:
        limit = max(1, min(2000, int(one(p, "limit", "300"))))
    except ValueError:
        limit = 300
    merge = one(p, "merge", "1") != "0"
    fw, fa = filters(p, T_COLS)
    where = " AND ".join(["day >= ?", "day <= ?"] + fw)
    d, _r = kind_names()
    con = ro()
    try:
        rows = con.execute(
            f"SELECT host, {DEVX} k, SUM(up), SUM(down), COUNT(DISTINCT day), MAX(day), "
            f"SUM(CASE WHEN node IN {_in(d)} THEN up+down ELSE 0 END) "
            f"FROM traffic WHERE {where} GROUP BY host, k LIMIT 200000", list(d) + [d1, d2] + fa).fetchall()
        macips = devices.ips_by_dev(con)
        stored = devices.stored_names(con)
    finally:
        con.close()
    label_cache = {}

    def label(k):
        if k not in label_cache:
            ips = macips.get(k, [] if is_mac(k) else [k])
            label_cache[k] = devices.NAMES.label(k, ips, stored) or next((i for i in ips if ":" not in i), "") or k
        return label_cache[k]

    agg = {}
    for host, k, up, down, days, last, direct in rows:
        key = reg_domain(host) if merge else host
        a = agg.setdefault(key, {"key": key, "up": 0, "down": 0, "direct": 0, "days": 0, "last": "", "devs": {}, "subs": set()})
        a["up"] += up
        a["down"] += down
        a["direct"] += direct
        a["days"] = max(a["days"], days)
        a["last"] = max(a["last"], last or "")
        a["devs"][k] = a["devs"].get(k, 0) + up + down
        if merge and host != key:
            a["subs"].add(host)
    out = []
    for a in sorted(agg.values(), key=lambda a: -(a["up"] + a["down"]))[:limit]:
        top = sorted(a["devs"].items(), key=lambda kv: -kv[1])
        out.append({"key": a["key"], "up": a["up"], "down": a["down"], "direct": a["direct"], "days": a["days"],
                    "last": a["last"], "ndev": len(top), "subs": len(a["subs"]),
                    "devs": [{"key": k, "name": label(k), "bytes": b} for k, b in top[:3]]})
    return 200, {"from": d1, "to": d2, "merge": merge, "count": len(agg), "rows": out}


def q_realtime(p):
    try:
        secs = max(10, min(600, int(one(p, "seconds", "120"))))
    except ValueError:
        secs = 120
    now = time.time()
    samples = [[round(ts, 1), u, d] for ts, u, d in list(realtime.SAMPLES) if ts >= now - secs]
    lv = live()
    con = ro()
    try:
        stored = devices.stored_names(con)
        macips = devices.ips_by_dev(con)
    finally:
        con.close()

    def rate(v):
        return v["up_rate"] + v["down_rate"]
    devs = []
    for k, v in sorted(lv["clients"].items(), key=lambda kv: -rate(kv[1])):
        if rate(v) <= 0 or len(devs) >= 6:
            continue
        ips = macips.get(k, [] if is_mac(k) else [k])
        name = devices.NAMES.label(k, ips, stored) or next((i for i in ips if ":" not in i), "") or k
        devs.append({"key": k, "name": name, **v})
    nodes = [{"node": k, **v} for k, v in sorted(lv["nodes"].items(), key=lambda kv: -rate(kv[1])) if rate(v) > 0][:6]
    last = samples[-1] if samples else None
    return 200, {"ok": realtime.STATE["ok"], "error": realtime.STATE["error"], "samples": samples,
                 "now": {"up": last[1], "down": last[2]} if last else {"up": 0, "down": 0},
                 "devices": devs, "nodes": nodes, "at": lv["at"]}


def q_hours(p):
    try:
        n = max(1, min(14 * 24, int(one(p, "hours", "24"))))
    except ValueError:
        n = 24
    now = time.time()
    labels = [time.strftime("%Y-%m-%d %H", time.localtime(now - i * 3600)) for i in range(n - 1, -1, -1)]
    fw, fa = filters(p, H_COLS)
    where = " AND ".join(["hour >= ?", "hour <= ?"] + fw)
    con = ro()
    try:
        rows = {h: (u, d) for h, u, d in con.execute(
            f"SELECT hour, SUM(up), SUM(down) FROM hourly WHERE {where} GROUP BY hour", [labels[0], labels[-1]] + fa)}
    finally:
        con.close()
    return 200, {"hours": [{"hour": h, "up": rows.get(h, (0, 0))[0], "down": rows.get(h, (0, 0))[1]} for h in labels]}


def q_devices(p):
    """筛选用的设备清单:近 KEEP_DAYS 天内有流量的设备,按流量降序。"""
    d2 = time.strftime("%Y-%m-%d")
    d1 = time.strftime("%Y-%m-%d", time.localtime(time.time() - 30 * 86400))
    con = ro()
    try:
        rows = con.execute(f"SELECT {DEVX} k, SUM(up)+SUM(down) FROM traffic WHERE day >= ? AND day <= ? AND client != '' "
                           "GROUP BY k ORDER BY 2 DESC LIMIT 200", (d1, d2)).fetchall()
        macips = devices.ips_by_dev(con)
        stored = devices.stored_names(con)
    finally:
        con.close()
    out = []
    for k, total in rows:
        ips = macips.get(k, [] if is_mac(k) else [k])
        out.append({"key": k, "name": devices.NAMES.label(k, ips, stored), "ips": ips[:8]})
    return 200, {"devices": out}


def q_status(p):
    c = collector.COLLECTOR
    cf = config.get()
    return 200, {
        "version": config.VERSION, "update": update.check(),
        "conn": dict(c.status) if c else {"ok": False, "error": "采集器未启动"},
        "config": {"api": cf["api"], "has_secret": bool(cf["secret"]), "source": cf["source"]},
        "interval": config.INTERVAL, "keep_days": config.KEEP_DAYS, "hour_keep_days": config.HOUR_KEEP_DAYS,
        "now": int(time.time()), "live_at": live()["at"],
        "wan": bool(collector.WAN_IFACES),
    }


def q_live(p):
    return 200, live()


GET_ROUTES = {"/api/status": q_status, "/api/summary": q_summary, "/api/modes": q_modes, "/api/days": q_days,
              "/api/hours": q_hours, "/api/domains": q_domains, "/api/realtime": q_realtime, "/api/devices": q_devices, "/api/live": q_live}


# ---------------------------------------------------------------- POST
def p_config(body):
    import urllib.error
    api = config.normalize_api(str(body.get("api") or ""))
    if not api:
        raise ValueError("地址不能为空")
    secret = body.get("secret")
    secret = None if secret is None else str(secret)
    test = {"api": api, "secret": config.get()["secret"] if secret is None else secret}
    try:
        v = api_call("/version", timeout=5, conf=test)
    except urllib.error.HTTPError as e:
        raise ValueError("密码不对(401)" if e.code == 401 else f"接口返回 {e.code}")
    except Exception as e:
        raise ValueError(f"连不上 {api}:{e}")
    st = config.save(api, secret)
    log(f"连接设置已更新:{st['api']}")
    return {"ok": True, "version": (v or {}).get("version", "")}


def p_device(body):
    con = db.open_db()
    try:
        devices.rename(con, body.get("dev"), body.get("name"))
    finally:
        con.close()
    return {"ok": True}


def p_import(body):
    con = db.open_db()
    try:
        r = devices.import_uci(con, str(body.get("text") or ""))
    finally:
        con.close()
    if not r["hosts"]:
        raise ValueError("没找到 host 段。请粘贴 `uci show dhcp` 的输出或 /etc/config/dhcp 的内容")
    return dict(r, ok=True)


def p_update(body):
    return update.check(force=True)


POST_ROUTES = {"/api/config": p_config, "/api/device": p_device,
               "/api/devices/import": p_import, "/api/update/check": p_update}


# ---------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "nikki-traffic"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _authed(self, params):
        tok = config.PAGE_TOKEN
        if not tok:
            return True
        return one(params, "t") == tok or self.headers.get("X-Token", "") == tok

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(u.query)
        if u.path == "/health":
            return self._send(200, b"ok", "text/plain")
        if u.path == "/favicon.ico":
            return self._send(204, b"", "image/x-icon")
        if not self._authed(params):
            return self._send(401, {"error": "需要 ?t=<token>"})
        if u.path in ("/", "/index.html"):
            with open(os.path.join(STATIC, "index.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        fn = GET_ROUTES.get(u.path)
        if not fn:
            return self._send(404, {"error": "not found"})
        try:
            code, data = fn(params)
        except Exception as e:
            log("接口出错", u.path, e)
            return self._send(500, {"error": f"{type(e).__name__}: {e}"})
        self._send(code, data)

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(u.query)
        if not self._authed(params):
            return self._send(401, {"error": "需要 ?t=<token>"})
        origin = self.headers.get("Origin")
        if origin and urllib.parse.urlparse(origin).netloc != self.headers.get("Host", ""):
            return self._send(403, {"error": "跨站请求被拒绝"})
        fn = POST_ROUTES.get(u.path)
        if not fn:
            return self._send(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 256 * 1024:
                return self._send(413, {"error": "内容太大"})
            body = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
            if not isinstance(body, dict):
                raise ValueError("需要 JSON 对象")
            data = fn(body)
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        except Exception as e:
            log("接口出错", u.path, e)
            return self._send(500, {"error": f"{type(e).__name__}: {e}"})
        self._send(200, data)


def serve():
    srv = ThreadingHTTPServer((config.LISTEN_HOST, config.LISTEN_PORT), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, name="http", daemon=True).start()
    return srv
