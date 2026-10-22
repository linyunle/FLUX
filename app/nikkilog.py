"""nikki 日志:内核(mihomo)日志 + 插件(luci-app-nikki)日志,存进面板自己的数据库,方便查看、复制、导出,并并入诊断包。

两种来源,哪种能用就用哪种:
- 日志文件(推荐,内容最全):在 compose 里只读挂载路由器的 /var/log/nikki 目录到 /host/var/log/nikki,面板读
  core.log(内核)和 app.log(插件)。读的是新增的行,文件被轮转 / 清空会自动重新开始。
- 接口(没挂目录时,只有内核日志):面板连 nikki 的 external-controller 的 /logs 接口,实时接收内核日志;
  这个接口只给「连上之后」的日志,没有历史,而且只按所选级别推送。
级别默认只收「警告及以上」:info 级别每条连接一行,量非常大,诊断问题一般用不上;要看就在设置里改成 info。
只读:面板不会改 nikki 的任何设置;按保留天数 / 最大条数自动清理,每秒最多入库 200 条。"""
import json
import os
import re
import threading
import time
import urllib.request

from . import config, db
from .util import log, stop

DEFAULT = {"on": True, "level": "warning", "days": 3, "max_rows": 20000, "dir": "", "ignore": []}
LEVELS = {"error": 3, "warning": 4, "info": 6, "debug": 7}
LV_NAME = {0: "紧急", 1: "警报", 2: "严重", 3: "错误", 4: "警告", 5: "注意", 6: "信息", 7: "调试"}
SRC_NAME = {"core": "内核", "app": "插件"}
FILES = (("core.log", "core"), ("app.log", "app"))
RATE = 200
_state = {"mode": {"core": "", "app": ""}, "err": {"core": "", "app": ""}, "rx": 0, "drop": 0, "last_rx": 0, "ignored": 0, "last_prune": 0}
_lock = threading.Lock()
_pending = []
CORE_RE = re.compile(r'^time="([^"]*)"\s+level=(\w+)\s+msg="(.*)"\s*$')
APP_TS = re.compile(r"^\[?(\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d)\]?[ :-]*(.*)$")
ERR_WORDS = re.compile(r"error|fail|fatal|panic|denied|refused|cannot|can't|无法|失败|错误|出错", re.I)
WARN_WORDS = re.compile(r"warn|timeout|timed out|retry|警告|超时|重试", re.I)


def default_dir():
    return os.environ.get("NIKKI_LOG_DIR", "/host/var/log/nikki")


def load_cfg(con):
    c = dict(DEFAULT)
    try:
        r = con.execute("SELECT v FROM kv WHERE k='nklog_cfg'").fetchone()
        v = json.loads(r[0]) if r else {}
    except Exception:
        v = {}
    if isinstance(v, dict):
        c["on"] = bool(v.get("on", True))
        if v.get("level") in LEVELS:
            c["level"] = v["level"]
        for k, lo, hi in (("days", 1, 30), ("max_rows", 1000, 200000)):
            try:
                c[k] = max(lo, min(hi, int(v.get(k, c[k]))))
            except (TypeError, ValueError):
                pass
        c["dir"] = str(v.get("dir") or "")[:200]
        c["ignore"] = _kw(v.get("ignore"))
    c["dir_eff"] = c["dir"] or default_dir()
    return c


def _kw(v):
    if isinstance(v, str):
        v = v.splitlines()
    out = []
    for x in v or []:
        x = str(x).strip()[:80]
        if x and x.lower() not in [o.lower() for o in out]:
            out.append(x)
    return out[:30]


def save_cfg(con, body):
    cur = load_cfg(con)
    c = {"on": bool(body.get("on", cur["on"])), "level": body.get("level") or cur["level"], "ignore": _kw(body.get("ignore", cur["ignore"]))}
    if c["level"] not in LEVELS:
        raise ValueError("级别只能是 error / warning / info / debug")
    try:
        c["days"] = int(body.get("days") or cur["days"])
        c["max_rows"] = int(body.get("max_rows") or cur["max_rows"])
    except (TypeError, ValueError):
        raise ValueError("天数、条数要填数字")
    if not 1 <= c["days"] <= 30:
        raise ValueError("保留天数范围 1–30")
    if not 1000 <= c["max_rows"] <= 200000:
        raise ValueError("最大条数范围 1000–200000")
    d = str(body.get("dir") if body.get("dir") is not None else cur["dir"]).strip()
    if d and (not d.startswith("/") or ".." in d or len(d) > 200):
        raise ValueError("日志目录要填容器里的绝对路径,例如 /host/var/log/nikki")
    c["dir"] = d
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES('nklog_cfg',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (json.dumps(c, ensure_ascii=False),))
    return load_cfg(con)


def _ignored(cfg, msg):
    t = msg.lower()
    return any(k.lower() in t for k in cfg.get("ignore") or [])


def _guess(msg):
    return 3 if ERR_WORDS.search(msg) else 4 if WARN_WORDS.search(msg) else 6


def _ts(s):
    for f in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return int(time.mktime(time.strptime(s[:19], f)))
        except ValueError:
            pass
    return int(time.time())


def parse_core(line):
    """mihomo 日志文件的一行 → (ts, 级别数字, 内容)。认不出格式就整行当内容。"""
    m = CORE_RE.match(line)
    if m:
        lv = LEVELS.get({"warn": "warning", "err": "error"}.get(m.group(2).lower(), m.group(2).lower()), 6)
        return _ts(m.group(1)), lv, m.group(3).replace('\\"', '"')[:1000]
    return int(time.time()), _guess(line), line[:1000]


def parse_app(line):
    m = APP_TS.match(line)
    if m:
        return _ts(m.group(1)), _guess(m.group(2)), m.group(2)[:1000]
    return int(time.time()), _guess(line), line[:1000]


def _push(cfg, src, ts, lv, msg):
    """入队(带限速和级别 / 忽略过滤);由 run() 统一写库。"""
    msg = msg.strip()
    if not msg:
        return
    if src == "core" and lv > LEVELS[cfg["level"]]:
        return
    if _ignored(cfg, msg):
        _state["ignored"] += 1
        return
    with _lock:
        sec = int(time.time())
        if _state.get("_sec") != sec:
            _state["_sec"], _state["_cnt"] = sec, 0
        _state["_cnt"] += 1
        if _state["_cnt"] > RATE:
            _state["drop"] += 1
            return
        _pending.append((ts, src, lv, msg))
        _state["rx"] += 1
        _state["last_rx"] = sec


def _flush(con):
    with _lock:
        rows = _pending[:]
        del _pending[:]
    if rows:
        with con:
            con.executemany("INSERT INTO nklog(ts,src,lvl,msg) VALUES(?,?,?,?)", rows)


# ---------- 文件 ----------
_pos = {}


def tail_file(cfg, path, src, first_lines=200):
    """读文件新增的行。第一次只取最后 first_lines 行(避免把几 MB 的老日志全灌进来)。返回读到的行数,文件读不了返回 -1。"""
    try:
        st = os.stat(path)
    except OSError as e:
        _state["err"][src] = f"读不了 {path}:{e.strerror or e}"
        return -1
    key = path
    p = _pos.get(key)
    if p is None or p[0] != st.st_ino or st.st_size < p[1]:
        start = max(0, st.st_size - 64 * 1024) if p is None else 0
        first = p is None
    else:
        start, first = p[1], False
    try:
        with open(path, "rb") as f:
            f.seek(start)
            data = f.read(1024 * 1024)
    except OSError as e:
        _state["err"][src] = f"读不了 {path}:{e.strerror or e}"
        return -1
    if first and start > 0:
        data = data.split(b"\n", 1)[-1]        # 从中间读起,丢掉第一行半截话
    end = data.rfind(b"\n")
    if end < 0:
        _pos[key] = (st.st_ino, start)          # 没有完整的一行,下次再读
        _state["err"][src] = ""
        return 0
    chunk = data[:end + 1]
    _pos[key] = (st.st_ino, start + len(chunk))
    lines = [x for x in chunk.decode("utf-8", "replace").splitlines() if x.strip()]
    if first:
        lines = lines[-first_lines:]
    parse = parse_core if src == "core" else parse_app
    for ln in lines:
        _push(cfg, src, *(lambda r: (r[0], r[1], r[2]))(parse(ln)))
    _state["err"][src] = ""
    return len(lines)


# ---------- 接口 ----------
_stream = {"th": None, "level": ""}


def _stream_loop():
    while not stop.is_set() and not _stream.get("stop"):
        c = config.get()
        lvl = _stream["level"] or "warning"
        url = f"{c['api']}/logs?level={lvl}"
        req = urllib.request.Request(url, headers={"Authorization": "Bearer " + c["secret"]} if c["secret"] else {})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                _state["err"]["core"] = ""
                while not stop.is_set():
                    if _stream["level"] != lvl or _stream.get("stop"):
                        break
                    try:
                        raw = r.readline()
                    except OSError:                  # 读超时:这段时间没有日志,继续等
                        continue
                    if not raw:
                        break
                    try:
                        j = json.loads(raw.decode("utf-8", "replace"))
                    except ValueError:
                        continue
                    t = {"warn": "warning", "err": "error"}.get(str(j.get("type", "")).lower(), str(j.get("type", "")).lower())
                    _push(_cur_cfg, "core", int(time.time()), LEVELS.get(t, 6), str(j.get("payload", "")))
        except Exception as e:
            _state["err"]["core"] = f"接口 /logs 连不上:{type(e).__name__}"
        stop.wait(5)


_cur_cfg = dict(DEFAULT)


def run():
    global _cur_cfg
    con = db.open_db()
    last_cfg = 0.0
    cfg = dict(DEFAULT, dir_eff=default_dir())
    while not stop.is_set():
        now = time.time()
        if now - last_cfg > 5:
            last_cfg = now
            try:
                cfg = _cur_cfg = load_cfg(con)
            except Exception:
                pass
        if not cfg["on"]:
            _state["mode"] = {"core": "", "app": ""}
            _stream["stop"] = True
            stop.wait(2)
            continue
        d = cfg["dir_eff"]
        have = {}
        for name, src in FILES:
            n = tail_file(cfg, os.path.join(d, name), src)
            have[src] = n >= 0
            _state["mode"][src] = "file" if have[src] else ""
        if not have["core"]:
            _state["mode"]["core"] = "api"
            _stream["stop"] = False
            _stream["level"] = cfg["level"]
            if not (_stream["th"] and _stream["th"].is_alive()):
                _stream["th"] = threading.Thread(target=_stream_loop, name="nklog-api", daemon=True)
                _stream["th"].start()
        else:
            _stream["stop"] = True
            _state["err"]["core"] = ""
        try:
            _flush(con)
            if now - _state["last_prune"] > 3600:
                prune(con, cfg, now)
        except Exception as e:
            log("nikki 日志写库出错", e)
            _state["last_prune"] = int(now)
        stop.wait(2)


def prune(con, cfg, now=None):
    now = now or time.time()
    with con:
        n = con.execute("DELETE FROM nklog WHERE ts<?", (int(now - cfg["days"] * 86400),)).rowcount
        r = con.execute("SELECT MAX(id) FROM nklog").fetchone()[0]
        if r:
            n += con.execute("DELETE FROM nklog WHERE id<=?", (r - cfg["max_rows"],)).rowcount
    _state["last_prune"] = int(now)
    return n


# ---------- 查询 ----------
def query(con, src="", level=7, q="", n=200, before=0):
    n = max(1, min(5000, int(n)))
    sql, args = "SELECT id,ts,src,lvl,msg FROM nklog WHERE lvl<=?", [max(0, min(7, int(level)))]
    if src in SRC_NAME:
        sql += " AND src=?"
        args.append(src)
    if before:
        sql += " AND id<?"
        args.append(int(before))
    q = (q or "").strip()[:60]
    if q:
        sql += " AND msg LIKE ? ESCAPE '\\'"
        args.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(n)
    return [{"id": r[0], "ts": r[1], "src": r[2], "src_name": SRC_NAME[r[2]], "lvl": r[3], "lv": LV_NAME[r[3]], "msg": r[4]} for r in con.execute(sql, args)]


def status(con):
    cfg = load_cfg(con)
    n, lo, hi = con.execute("SELECT COUNT(*),MIN(ts),MAX(ts) FROM nklog").fetchone()
    by = {f"{r[0]}:{LV_NAME[r[1]]}": r[2] for r in con.execute("SELECT src,lvl,COUNT(*) FROM nklog WHERE ts>=? GROUP BY src,lvl", (int(time.time()) - 86400,))}
    return {"cfg": cfg, "mode": dict(_state["mode"]), "err": dict(_state["err"]), "rx": _state["rx"], "drop": _state["drop"], "ignored": _state["ignored"],
            "last_rx": _state["last_rx"], "rows": n or 0, "oldest": lo or 0, "newest": hi or 0, "by_24h": by}


def clear(con):
    with con:
        n = con.execute("DELETE FROM nklog").rowcount
    return {"ok": True, "deleted": n}


NORM = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b|\b[0-9a-f]{8,}\b|\d+")


def top_messages(con, since, n=10):
    """近 24 小时 警告及以上 的日志按「去掉数字 / IP」后的样子合并,看哪类问题最多。"""
    cnt, sample = {}, {}
    for src, lvl, msg in con.execute("SELECT src,lvl,msg FROM nklog WHERE ts>=? AND lvl<=4", (since,)):
        k = (src, NORM.sub("#", msg)[:160])
        cnt[k] = cnt.get(k, 0) + 1
        sample.setdefault(k, (lvl, msg))
    top = sorted(cnt.items(), key=lambda x: -x[1])[:n]
    return [{"src": k[0], "n": c, "lv": LV_NAME[sample[k][0]], "example": sample[k][1][:200]} for k, c in top]


def provider_errors(con, name="", n=5, days=7):
    """nikki 日志里和订阅(provider)更新有关的警告 / 错误,最新的在前;name 非空时只要提到这个订阅的。"""
    since = int(time.time()) - days * 86400
    sql, args = "SELECT ts,msg FROM nklog WHERE ts>=? AND lvl<=4 AND (msg LIKE '%rovider%' OR msg LIKE '%ubscri%' OR msg LIKE '%订阅%')", [since]
    if name:
        sql += " AND msg LIKE ? ESCAPE '\\'"
        args.append("%" + name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(max(1, min(50, n)))
    return [(r[0], r[1]) for r in con.execute(sql, args)]
