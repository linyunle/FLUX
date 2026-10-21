"""健康检查、数据占用与清理、升级前自动备份。只读检查为主;清理只作用于面板自己的数据库。"""
import json
import os
import re
import shutil
import sqlite3
import threading
import time

from . import auth, backup, collector, config, nikkilog

START = time.time()
THREADS = ["realtime", "alerts", "wanq", "syslog", "nklog", "dnsprobe", "wallpaper"]
BK_DIR = "backups"
KEEP_BK = 3
NAME_RE = re.compile(r"^auto-[A-Za-z0-9._-]{1,60}\.json$")
TRIM = {"nklog": "ts", "syslog": "ts", "alerts": "ts"}      # 允许按天数清理的表(都有时间列)


def _mb(n):
    return f"{n / 1048576:.0f} MB" if n >= 1048576 else f"{n / 1024:.0f} KB"


def _ago(s):
    s = int(s)
    return f"{s}秒" if s < 90 else f"{s // 60}分钟" if s < 5400 else f"{s // 3600}小时" if s < 172800 else f"{s // 86400}天"


def _item(name, level, detail, hint=""):
    return {"name": name, "level": level, "detail": detail, "hint": hint}


def _dbsize():
    sz = 0
    for suf in ("", "-wal"):
        try:
            sz += os.path.getsize(config.DB_PATH + suf)
        except OSError:
            pass
    return sz


def checks(con):
    out = []
    now = time.time()
    out.append(_item("面板", "ok", f"{config.VERSION},已运行 {_ago(now - START)}"))
    c = collector.COLLECTOR
    st = dict(c.status) if c else {"ok": False, "error": "采集器未启动", "last_ok": 0}
    if st.get("ok"):
        out.append(_item("nikki 接口", "ok", f"连接正常,最近一次成功 {_ago(now - st.get('last_ok', now))}前"))
    else:
        out.append(_item("nikki 接口", "bad", st.get("error") or "连不上", "到「设置 → 连接」检查 API 地址和密钥"))
    try:
        du = shutil.disk_usage(config.DATA_DIR)
        lv = "bad" if du.free < 100 << 20 else "warn" if du.free < 500 << 20 else "ok"
        out.append(_item("数据目录磁盘", lv, f"剩余 {_mb(du.free)} / 共 {_mb(du.total)}", "空间不足时先到「数据占用」清理日志" if lv != "ok" else ""))
    except OSError as e:
        out.append(_item("数据目录磁盘", "warn", f"读不到磁盘信息:{e}"))
    try:
        t = os.path.join(config.DATA_DIR, ".wtest")
        with open(t, "w") as f:
            f.write("1")
        os.remove(t)
        out.append(_item("数据目录可写", "ok", config.DATA_DIR))
    except OSError as e:
        out.append(_item("数据目录可写", "bad", f"写不进 {config.DATA_DIR}:{e}", "检查 compose 里 ./data:/data 挂载和目录权限"))
    db = _dbsize()
    out.append(_item("数据库大小", "warn" if db > 2 << 30 else "ok", _mb(db), "超过 2GB 建议缩短保留天数或清理" if db > 2 << 30 else ""))
    alive = {t.name for t in threading.enumerate()}
    miss = [n for n in THREADS if n not in alive]
    out.append(_item("后台任务", "bad" if miss else "ok", ("已停止:" + "、".join(miss)) if miss else f"{len(THREADS)} 个后台任务都在运行", "重启容器;反复出现请把诊断包发给我" if miss else ""))
    nk = nikkilog.status(con)
    d = nikkilog.default_dir()
    d = nk["cfg"].get("dir") or d
    try:
        fs = [f for f in os.listdir(d) if os.access(os.path.join(d, f), os.R_OK)]
        out.append(_item("nikki 日志目录", "ok", f"{d} 可读({len(fs)} 个文件)"))
    except OSError:
        out.append(_item("nikki 日志目录", "warn", f"{d} 不存在或读不了,只能通过 nikki 接口收内核日志",
                         "compose 里加只读挂载 /var/log/nikki:/host/var/log/nikki(设置 → nikki 日志里有写法)"))
    lease = "/host/tmp/dhcp.leases"
    out.append(_item("DHCP 租约文件", "ok" if os.access(lease, os.R_OK) else "info",
                     "可读" if os.access(lease, os.R_OK) else "没挂载:动态地址的设备只能显示 IP,看不到主机名"))
    if not auth.enabled():
        out.append(_item("访问密码", "warn", "没有设置:同一局域网的任何人都能打开并修改面板", "设置 → 安全与隐私 里设置访问密码"))
    else:
        out.append(_item("访问密码", "ok", "已设置" + ("(含只读账号)" if auth.has_viewer() else "")))
    if os.environ.get("ALLOW_NETS"):
        out.append(_item("访问网段限制", "ok", os.environ["ALLOW_NETS"]))
    if time.gmtime(now).tm_year < 2024:
        out.append(_item("系统时间", "warn", "时间明显不对,流量按天统计和证书检查都会错", "检查路由器 NTP"))
    return out


# ---------------------------------------------------------------- 占用与清理
def storage(con):
    tables, sizes = [], {}
    try:
        for n, b in con.execute("SELECT name, SUM(pgsize) FROM dbstat GROUP BY name"):
            sizes[n] = b
    except sqlite3.Error:
        pass        # 没编译 dbstat 就只显示行数
    for (n,) in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall():
        b = sizes.get(n)
        rows = None
        if b is None or b < 256 << 20:
            try:
                rows = con.execute(f'SELECT COUNT(*) FROM "{n}"').fetchone()[0]
            except sqlite3.Error:
                pass
        tables.append({"name": n, "rows": rows, "bytes": b, "trim": n in TRIM})
    tables.sort(key=lambda t: -(t["bytes"] or 0))
    try:
        du = shutil.disk_usage(config.DATA_DIR)
        disk = {"free": du.free, "total": du.total}
    except OSError:
        disk = {}
    return {"db": _dbsize(), "tables": tables, "disk": disk, "keep_days": config.KEEP_DAYS, "hour_keep_days": config.HOUR_KEEP_DAYS}


def clean(body):
    """action: vacuum(压缩数据库) / trim(table + days:删掉 N 天前的日志类数据)。"""
    act = str(body.get("action") or "")
    if act == "trim":
        t = str(body.get("table") or "")
        if t not in TRIM:
            raise ValueError("这张表不允许手动清理")
        days = int(body.get("days") or 0)
        if not 0 <= days <= 3650:
            raise ValueError("天数不对")
        from . import db
        con = db.open_db()
        try:
            with con:
                n = con.execute(f"DELETE FROM {t} WHERE {TRIM[t]}<?", (int(time.time()) - days * 86400,)).rowcount
        finally:
            con.close()
        return {"ok": True, "deleted": n}
    if act == "vacuum":
        before = _dbsize()
        try:
            free = shutil.disk_usage(config.DATA_DIR).free
        except OSError:
            free = 0
        if free < before * 1.2 + (50 << 20):
            raise ValueError(f"磁盘剩余 {_mb(free)},压缩需要大约 {_mb(int(before * 1.2))},先腾出空间")
        con = sqlite3.connect(config.DB_PATH, timeout=120, isolation_level=None)
        try:
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            con.execute("VACUUM")
        finally:
            con.close()
        return {"ok": True, "before": before, "after": _dbsize()}
    raise ValueError("不支持的操作")


# ---------------------------------------------------------------- 升级前自动备份
def _bdir():
    return os.path.join(config.DATA_DIR, BK_DIR)


def _vfile():
    return os.path.join(config.DATA_DIR, ".last_version")


def auto_backup(con):
    """版本号和上次启动不同(= 升级了)就把配置(含密钥,权限 600)存一份到 data/backups/,只留最近 3 份。返回文件名或 None。"""
    ver = config.VERSION
    if ver == "dev":
        return None
    try:
        with open(_vfile(), encoding="utf-8") as f:
            old = f.read().strip()
    except OSError:
        old = ""
    if old == ver:
        return None
    name = None
    try:
        has = con.execute("SELECT COUNT(*) FROM kv").fetchone()[0] > 0
        if has:
            os.makedirs(_bdir(), exist_ok=True)
            name = f"auto-{re.sub(r'[^A-Za-z0-9._-]', '', old or 'old')}-to-{re.sub(r'[^A-Za-z0-9._-]', '', ver)}-{time.strftime('%Y%m%d-%H%M%S')}.json"
            path = os.path.join(_bdir(), name)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(backup.export(con, True), f, ensure_ascii=False)
            for old_f in sorted(listing(), key=lambda x: -x["at"])[KEEP_BK:]:
                try:
                    os.remove(os.path.join(_bdir(), old_f["name"]))
                except OSError:
                    pass
    finally:
        try:
            with open(_vfile(), "w", encoding="utf-8") as f:
                f.write(ver)
        except OSError:
            pass
    return name


def listing():
    out = []
    try:
        for n in os.listdir(_bdir()):
            if NAME_RE.match(n):
                st = os.stat(os.path.join(_bdir(), n))
                out.append({"name": n, "size": st.st_size, "at": int(st.st_mtime)})
    except OSError:
        pass
    return sorted(out, key=lambda x: -x["at"])


def read_backup(name):
    if not NAME_RE.match(name or ""):
        raise ValueError("文件名不对")
    with open(os.path.join(_bdir(), name), "rb") as f:
        return f.read()
