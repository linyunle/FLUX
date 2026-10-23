"""设置的备份恢复。
- 外观(卡片显示/顺序/主题)原本只存在浏览器里,现在也会同步一份到服务器(kv: ui_theme),换浏览器/清缓存不会丢。
- 备份文件是一个 JSON:外观、告警规则与渠道、AdGuard、套餐、周报、订阅归类规则、应用特征库规则、设备别名。
  默认不含任何密钥(推送地址/Token、AdGuard 密码);勾选「包含密钥」才写进去,文件要自己保管好。
- 恢复只覆盖文件里有的部分;缺密钥的推送渠道/AdGuard 密码会沿用已保存的,没有就跳过并提示。"""
import json
import re
import time

from . import agh, dnsx, nikkilog, airports, alerts, appsig, config, devices, groups, insight, presence, probe, syslog, ups, expiry, dockerapi

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


_HOSTRE = re.compile(r"^[A-Za-z0-9._\-]{1,100}$|^\[[0-9a-fA-F:]{2,60}\]$")


def nikki_ui(con):
    """「在 nikki 里更新订阅」链接用的主机名 / 端口 / 路径;留空 = 自动(当前访问面板的主机名 + nikki 控制端口 + /ui/)。"""
    try:
        d = json.loads(_kv(con, "nikki_ui") or "{}")
    except ValueError:
        d = {}
    return {"host": str(d.get("host") or ""), "port": str(d.get("port") or ""), "path": str(d.get("path") or "")}


def set_nikki_ui(con, body):
    host, port, path = (str((body or {}).get(k) or "").strip() for k in ("host", "port", "path"))
    if host and not _HOSTRE.match(host):
        raise ValueError("主机名只能是域名 / IP(不要带 http:// 和端口)")
    if port and not (port.isdigit() and 1 <= int(port) <= 65535):
        raise ValueError("端口要是 1-65535 的数字")
    if path and (not path.startswith("/") or len(path) > 200 or re.search(r"[\s<>\"']", path)):
        raise ValueError("路径要以 / 开头,例如 /ui/")
    _kv_put(con, "nikki_ui", json.dumps({"host": host, "port": port, "path": path}, ensure_ascii=False))
    return nikki_ui(con)


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
    out["alerts"] = {"rules": ac["rules"], "quiet": ac["quiet"], "channels": chans, "disks": ac.get("disks", {})}
    a = agh.load_cfg(con)
    out["agh"] = {"url": a["url"], "user": a["user"], "on": a["on"], **({"pass": a["pass"]} if secrets else {})}
    out["dns"] = dnsx.load_cfg(con)
    out["quota"] = insight.quota_cfg(con)
    out["report"] = insight.report_cfg(con)
    out["airport_rules"] = airports.rules_text()
    out["app_rules"] = appsig.rules_text()
    out["devices"] = devices.stored_names(con)
    out["dev_groups"] = groups.dev_groups(con)
    out["group_policy"] = groups.policy(con)
    out["probe"] = probe.load_cfg(con)
    out["dev_watch"] = presence.watch_list(con)
    out["syslog"] = syslog.load_cfg(con)
    out["ups"] = ups.load_cfg(con)
    out["expiry"] = expiry.load_cfg(con)
    out["docker"] = dockerapi.load_cfg(con)
    out["nklog"] = nikkilog.load_cfg(con)
    out["nikki_ui"] = nikki_ui(con)
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
    if isinstance(d.get("dns"), dict):
        step("DNS 服务器", lambda: dnsx.save_cfg(con, d["dns"]))
    if isinstance(d.get("quota"), dict):
        step("订阅额度", lambda: insight.save_quota(con, {"quota": d["quota"]}))
    if isinstance(d.get("report"), dict):
        step("周报", lambda: insight.save_report_cfg(con, d["report"]))
    if isinstance(d.get("airport_rules"), str):
        step("订阅归类规则", lambda: airports.save(con, d["airport_rules"]))
    if isinstance(d.get("app_rules"), str):
        step("应用特征库规则", lambda: appsig.save(con, d["app_rules"]))
    if isinstance(d.get("devices"), dict):
        def g():
            for k, v in list(d["devices"].items())[:2000]:
                devices.rename(con, str(k), str(v))
        step("设备别名", g)
    if isinstance(d.get("dev_groups"), dict):
        def h():
            for k, v in list(d["dev_groups"].items())[:2000]:
                groups.set_group(con, str(k), str(v))
        step("设备分组", h)
    if isinstance(d.get("group_policy"), dict):
        def i():
            for g, v in list(d["group_policy"].items())[:50]:
                if isinstance(v, dict):
                    groups.save_policy(con, g, v.get("on"), v.get("allow"))
        step("分组白名单", i)
    if isinstance(d.get("probe"), dict):
        step("节点探测", lambda: probe.save_cfg(con, d["probe"]))
    if isinstance(d.get("dev_watch"), list):
        def w():
            for k in d["dev_watch"][:500]:
                presence.set_watch(con, k, True)
        step("关注的设备", w)
    if isinstance(d.get("syslog"), dict):
        step("系统日志设置", lambda: syslog.save_cfg(con, d["syslog"]))
    if isinstance(d.get("ups"), dict):
        step("UPS 设置", lambda: ups.save_cfg(con, d["ups"]))
    if isinstance(d.get("expiry"), dict):
        step("到期检查名单", lambda: expiry.save_cfg(con, d["expiry"]))
    if isinstance(d.get("docker"), dict):
        step("容器管理设置", lambda: dockerapi.save_cfg(con, d["docker"]))
    if isinstance(d.get("nikki_ui"), dict):
        step("nikki 面板地址", lambda: set_nikki_ui(con, d["nikki_ui"]))
    if isinstance(d.get("nklog"), dict):
        step("nikki 日志设置", lambda: nikkilog.save_cfg(con, d["nklog"]))
    return {"ok": True, "done": done, "skipped": skipped}
