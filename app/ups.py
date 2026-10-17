"""UPS 状态(NUT)。只读:连上路由器上的 upsd(默认 127.0.0.1:3493),发一条 `LIST VAR 名称`,
读电量、负载、预计续航、市电状态。不需要 NUT 的用户名密码,不发任何控制命令,不碰你已有的关机脚本。
断电 / 恢复 / 电量低 / 读不到 UPS 会进告警时间线并推送。默认关闭。"""
import collections
import json
import re
import socket
import time

from .util import log

DEFAULT = {"on": False, "host": "127.0.0.1", "port": 3493, "name": "CyberPower"}
STATE = {"at": 0, "ok": None, "err": "", "vars": {}, "fail_since": 0, "onbatt_since": 0, "info": None}
SERIES = collections.deque(maxlen=360)   # (ts, 电量%, 负载%, 续航秒, 输入电压),约 3 小时
TOKENS = {"OL": "市电正常", "OB": "电池供电(市电断了)", "LB": "电量低", "HB": "电量高", "RB": "电池需要更换", "CHRG": "充电中",
          "DISCHRG": "放电中", "BYPASS": "旁路", "CAL": "校准中", "OFF": "已关闭", "OVER": "过载", "TRIM": "降压", "BOOST": "升压", "FSD": "正在关机"}
NAME_RE = re.compile(r"^[\w.\-]{1,40}$")
HOST_RE = re.compile(r"^[\w.\-:]{1,100}$")
VAR_RE = re.compile(r'^VAR\s+\S+\s+(\S+)\s+"(.*)"\s*$')


def load_cfg(con):
    c = dict(DEFAULT)
    try:
        r = con.execute("SELECT v FROM kv WHERE k='ups'").fetchone()
        v = json.loads(r[0]) if r else {}
    except Exception:
        v = {}
    if isinstance(v, dict):
        c["on"] = bool(v.get("on"))
        if HOST_RE.match(str(v.get("host") or "")):
            c["host"] = str(v["host"])
        if NAME_RE.match(str(v.get("name") or "")):
            c["name"] = str(v["name"])
        try:
            c["port"] = max(1, min(65535, int(v.get("port") or c["port"])))
        except (TypeError, ValueError):
            pass
    return c


def save_cfg(con, body):
    host, name = str(body.get("host") or "127.0.0.1").strip(), str(body.get("name") or "").strip()
    if not HOST_RE.match(host):
        raise ValueError("地址格式不对")
    if not NAME_RE.match(name):
        raise ValueError("UPS 名称只能含字母数字和 . _ -(就是 NUT 里 ups.conf 方括号里的名字)")
    try:
        port = int(body["port"]) if body.get("port") not in (None, "") else 3493
    except (TypeError, ValueError):
        raise ValueError("端口要填数字")
    if not 1 <= port <= 65535:
        raise ValueError("端口范围 1–65535")
    c = {"on": bool(body.get("on")), "host": host, "port": port, "name": name}
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES('ups',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (json.dumps(c),))
    STATE.update(at=0, ok=None, err="", fail_since=0)
    return load_cfg(con)


def read(host, port, name, timeout=3.0):
    """连 upsd 读全部变量,返回 dict。出错抛异常(含 upsd 返回的 ERR 信息)。"""
    out, buf = {}, b""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(f"LIST VAR {name}\n".encode())
        while b"END LIST VAR" not in buf and not buf.startswith(b"ERR"):
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 200000:
                break
        try:
            s.sendall(b"LOGOUT\n")
        except OSError:
            pass
    text = buf.decode("utf-8", "replace")
    if text.startswith("ERR"):
        e = text.split("\n", 1)[0].strip()
        raise RuntimeError({"ERR UNKNOWN-UPS": "upsd 里没有这个名字的 UPS", "ERR DATA-STALE": "UPS 驱动没有数据(掉线了?)"}.get(e, e))
    for ln in text.splitlines():
        m = VAR_RE.match(ln.strip())
        if m:
            out[m.group(1)] = m.group(2)
    if not out:
        raise RuntimeError("upsd 没有返回数据")
    return out


def _f(v, k):
    try:
        return float(v.get(k))
    except (TypeError, ValueError):
        return None


def summarize(v):
    toks = (v.get("ups.status") or "").split()
    ch, ld, rt, iv = _f(v, "battery.charge"), _f(v, "ups.load"), _f(v, "battery.runtime"), _f(v, "input.voltage")
    return {"status": toks, "status_text": "、".join(TOKENS.get(t, t) for t in toks) or "未知", "charge": ch, "load": ld, "runtime": rt,
            "input_v": iv, "model": (v.get("ups.model") or v.get("device.model") or "").strip(), "mfr": (v.get("ups.mfr") or v.get("device.mfr") or "").strip(),
            "watts": (ld / 100 * _f(v, "ups.realpower.nominal")) if ld is not None and _f(v, "ups.realpower.nominal") else None,
            "battery_v": _f(v, "battery.voltage")}


def snapshot():
    s = dict(STATE)
    s["vars"] = {}
    return s


def check(con, cfg, now):
    from . import alerts
    uc = load_cfg(con)
    if not uc["on"]:
        STATE.update(ok=None, info=None, err="", fail_since=0)
        return
    try:
        v = read(uc["host"], uc["port"], uc["name"])
    except Exception as e:
        if not STATE["fail_since"]:
            STATE["fail_since"] = now
        STATE.update(at=int(now), ok=False, err=str(e) or e.__class__.__name__)
        r = cfg["rules"]["ups_lost"]
        mins = int((now - STATE["fail_since"]) // 60)
        if mins >= r["after_min"] and alerts._allow("ups_lost", "ups", r["cool_min"], now):
            detail = f"面板已有 {mins} 分钟读不到 UPS({uc['host']}:{uc['port']} / {uc['name']}):{STATE['err']}。检查 NUT 服务(nut-server)是否在跑、UPS 的 USB 线、名称是否写对。"
            if r["on"]:
                alerts.fire(con, cfg, "ups_lost", "warn", "ups", "读不到 UPS", detail, now)
            else:
                alerts.note(con, "ups_lost", "ups", "读不到 UPS", detail, level="warn", now=now)
        return
    STATE["fail_since"] = 0
    s = summarize(v)
    STATE.update(at=int(now), ok=True, err="", info=s)
    SERIES.append((now, s["charge"], s["load"], s["runtime"], s["input_v"]))
    toks = s["status"]
    ob = "OB" in toks
    was = STATE["onbatt_since"]
    r = cfg["rules"]["ups_onbatt"]
    chtxt = f"电量 {s['charge']:g}%" if s["charge"] is not None else "电量未知"
    rttxt = f",预计还能撑 {int(s['runtime'] // 60)} 分钟" if s["runtime"] else ""
    if ob and not was:
        STATE["onbatt_since"] = now
        detail = f"市电断了,UPS 正在用电池供电:{chtxt}{rttxt}。路由器和所有设备靠电池撑着,你自己设的关机逻辑会按时间/电量处理。"
        if r["on"] and alerts._allow("ups_onbatt", "ups", r["cool_min"], now):
            alerts.fire(con, cfg, "ups_onbatt", "bad", "ups", "市电断了,UPS 在用电池", detail, now)
        else:
            alerts.note(con, "ups_onbatt", "ups", "市电断了,UPS 在用电池", detail, level="bad", now=now)
    elif was and not ob:
        STATE["onbatt_since"] = 0
        mins = max(1, int((now - was) // 60))
        detail = f"市电恢复了,这次用了 {mins} 分钟电池,现在{chtxt}。"
        if r["on"]:
            alerts.fire(con, cfg, "ups_onbatt", "ok", "ups-back", "市电恢复", detail, now)
        else:
            alerts.note(con, "ups_onbatt", "ups-back", "市电恢复", detail, level="ok", now=now)
    lr = cfg["rules"]["ups_low"]
    low = "LB" in toks or (ob and s["charge"] is not None and s["charge"] <= lr["pct"])
    if low and alerts._allow("ups_low", "low", lr["cool_min"], now):
        detail = f"UPS {'报告电量低' if 'LB' in toks else '电量降到阈值以下'}:{chtxt}{rttxt}。马上就要断电关机了。"
        if lr["on"]:
            alerts.fire(con, cfg, "ups_low", "bad", "low", "UPS 电量低", detail, now)
        else:
            alerts.note(con, "ups_low", "low", "UPS 电量低", detail, level="bad", now=now)
    if "RB" in toks and alerts._allow("ups_low", "rb", 10080 * 1, now):
        detail = "UPS 自检认为电池老化,需要更换。电池坏了的话断电时撑不了多久。"
        if lr["on"]:
            alerts.fire(con, cfg, "ups_low", "warn", "rb", "UPS 电池需要更换", detail, now)
        else:
            alerts.note(con, "ups_low", "rb", "UPS 电池需要更换", detail, level="warn", now=now)


def status(con):
    cfg = load_cfg(con)
    now = time.time()
    s = dict(STATE)
    s["onbatt_for"] = int(now - s["onbatt_since"]) if s["onbatt_since"] else 0
    return {"cfg": cfg, "state": s, "series": [[round(r[0], 1)] + list(r[1:]) for r in SERIES]}


def test(con, body):
    """用页面上填的(还没保存的)参数连一次,返回读到的概要,方便确认名称对不对。"""
    host, name = str(body.get("host") or "127.0.0.1").strip(), str(body.get("name") or "").strip()
    if not HOST_RE.match(host) or not NAME_RE.match(name):
        raise ValueError("地址或名称格式不对")
    try:
        port = int(body.get("port") or 3493)
    except (TypeError, ValueError):
        raise ValueError("端口要填数字")
    try:
        return {"ok": True, "info": summarize(read(host, port, name))}
    except (OSError, RuntimeError) as e:
        raise ValueError(f"连不上:{e}")
