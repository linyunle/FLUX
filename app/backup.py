"""设置的备份与恢复。
- 外观(卡片显示/顺序/主题)原本只存在浏览器里,现在也会同步一份到服务器(kv: ui_theme),换浏览器/清缓存不会丢。
- 备份文件是一个 JSON:外观、告警规则与渠道、AdGuard、套餐、周报、机场归类规则、应用识别规则、设备名。
  默认不含任何密钥(推送地址/Token、AdGuard 密码);勾选「包含密钥」才写进去,文件要自己保管好。
- 恢复只覆盖文件里有的部分;缺密钥的推送渠道/AdGuard 密码会沿用已保存的,没有就跳过并提示。"""
import json
import time

from . import agh, airports, alerts, appsig, config, devices, insight

MAX_THEME = 64 * 1024


def _kv(con, k):
    r = con.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
    return r[0] if r else None


def _kv_put(con, k, v):
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))


def get_ui(con):
    raw = _kv(con, "ui_theme")
    at = _kv(con, "ui_theme_at")
    try:
        return {"theme": json.loads(raw) if raw else None, "at": int(float(at)) if at else 0}
    except Exception:
        return {"theme": None, "at": 0}


def set_ui(con, theme):
    if not isinstance(theme, dict):
        raise ValueError("外观设置格式不对")
    raw = json.dumps(theme, ensure_ascii=False, separators=(",", ":"))
    if len(raw) > MAX_THEME:
        raise ValueError("外观设置太大")
    _kv_put(con, "ui_theme", raw)
    _kv_put(con, "ui_theme_at", str(time.time()))
    return {"ok": True}


def export(con, secrets=False):
    out = {"flux_backup": 1, "version": config.VERSION, "created": int(time.time()), "secrets": bool(secrets)}
    ui = get_ui(con)["theme"]
    if ui:
        out["ui"] = ui
    ac = alerts.load_cfg(con)
    chans = []
    for c in ac["channels"]:
        c = dict(c)
        if not secrets:
            for k in ("url", "token", "chat"):
                c.pop(k, None)
        chans.append(c)
    out["alerts"] = {"rules": ac["rules"], "quiet": ac["quiet"], "channels": chans}
    a = agh.load_cfg(con)
    out["agh"] = {"url": a["url"], "user": a["user"], "on": a["on"], **({"pass": a["pass"]} if secrets else {})}
    out["quota"] = insight.quota_cfg(con)
    out["report"] = insight.report_cfg(con)
    out["airport_rules"] = airports.rules_text()
    out["app_rules"] = appsig.rules_text()
    out["devices"] = devices.stored_names(con)
    return out


def restore(con, d):
    if not isinstance(d, dict) or d.get("flux_backup") != 1:
        raise ValueError("这不是 FLUX 的备份文件")
    done, skipped = [], []

    def step(name, fn):
        try:
            fn()
            done.append(name)
        except Exception as e:
            skipped.append(f"{name}:{e}")

    if isinstance(d.get("ui"), dict):
        step("外观", lambda: set_ui(con, d["ui"]))
    if isinstance(d.get("alerts"), dict):
        def f():
            cur = {c["id"] for c in alerts.load_cfg(con)["channels"]}
            body = dict(d["alerts"])
            keep = []
            for c in body.get("channels") or []:
                if not isinstance(c, dict):
                    continue
                has = c.get("token") or c.get("url") or c.get("chat")
                if has or str(c.get("id")) in cur:
                    keep.append(c)
                else:
                    skipped.append(f"推送渠道「{c.get('name') or c.get('type')}」:备份里没有密钥,请手动重新添加")
            body["channels"] = keep
            alerts.save_cfg(con, body)
        step("告警规则与渠道", f)
    if isinstance(d.get("agh"), dict):
        step("AdGuard", lambda: agh.save_cfg(con, d["agh"]))
    if isinstance(d.get("quota"), dict):
        step("机场套餐", lambda: insight.save_quota(con, {"quota": d["quota"]}))
    if isinstance(d.get("report"), dict):
        step("周报", lambda: insight.save_report_cfg(con, d["report"]))
    if isinstance(d.get("airport_rules"), str):
        step("机场归类规则", lambda: airports.save(con, d["airport_rules"]))
    if isinstance(d.get("app_rules"), str):
        step("应用识别规则", lambda: appsig.save(con, d["app_rules"]))
    if isinstance(d.get("devices"), dict):
        def g():
            for k, v in list(d["devices"].items())[:2000]:
                devices.rename(con, str(k), str(v))
        step("设备名", g)
    return {"ok": True, "done": done, "skipped": skipped}
