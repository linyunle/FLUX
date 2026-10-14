"""SQLite:表结构与升级。v1(day/client/node/host)和早期 v2 都能原地升上来。"""
import os
import sqlite3

from . import config
from .util import log

SCHEMA = """
CREATE TABLE IF NOT EXISTS traffic(
  day TEXT NOT NULL, client TEXT NOT NULL, node TEXT NOT NULL, grp TEXT NOT NULL,
  rule TEXT NOT NULL, host TEXT NOT NULL,
  up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(day, client, node, grp, rule, host)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS hourly(
  hour TEXT NOT NULL, client TEXT NOT NULL, node TEXT NOT NULL,
  up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(hour, client, node)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS wan(
  day TEXT PRIMARY KEY, up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS wan_hourly(
  hour TEXT PRIMARY KEY, up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS ipmap(
  ip TEXT PRIMARY KEY, mac TEXT NOT NULL, seen INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS nodeinfo(
  node TEXT PRIMARY KEY, type TEXT, remote TEXT, geo TEXT, geo_at INTEGER, seen INTEGER
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS devices(
  dev TEXT PRIMARY KEY, name TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS proto(
  day TEXT NOT NULL, client TEXT NOT NULL, node TEXT NOT NULL, proto TEXT NOT NULL,
  up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(day, client, node, proto)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS app(
  day TEXT NOT NULL, client TEXT NOT NULL, node TEXT NOT NULL, app TEXT NOT NULL, cat TEXT NOT NULL,
  up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(day, client, node, app, cat)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS app_hourly(
  hour TEXT NOT NULL, client TEXT NOT NULL, app TEXT NOT NULL, cat TEXT NOT NULL,
  up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(hour, client, app, cat)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS proto_hourly(
  hour TEXT NOT NULL, client TEXT NOT NULL, proto TEXT NOT NULL,
  up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(hour, client, proto)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS qoe(
  hour TEXT NOT NULL, node TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0, sum_d REAL NOT NULL DEFAULT 0,
  sum_sq REAL NOT NULL DEFAULT 0, fails INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(hour, node)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS tcp(
  hour TEXT PRIMARY KEY, out INTEGER NOT NULL DEFAULT 0, retrans INTEGER NOT NULL DEFAULT 0, resets INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS dns(
  host TEXT NOT NULL, ip TEXT NOT NULL, mode TEXT NOT NULL, last INTEGER NOT NULL,
  PRIMARY KEY(host, ip)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, kind TEXT NOT NULL, level TEXT NOT NULL,
  key TEXT NOT NULL DEFAULT '', title TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', sent TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts(ts);
CREATE TABLE IF NOT EXISTS known_dev(
  client TEXT PRIMARY KEY, first INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS kv(
  k TEXT PRIMARY KEY, v TEXT NOT NULL
) WITHOUT ROWID;
"""
SCHEMA_VERSION = 3


def open_db(readonly=False):
    if readonly:
        con = sqlite3.connect(f"file:{config.DB_PATH}?mode=ro", uri=True, timeout=10)
    else:
        con = sqlite3.connect(config.DB_PATH, timeout=30)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
    return con


def migrate(con):
    ver = con.execute("PRAGMA user_version").fetchone()[0]
    if ver >= SCHEMA_VERSION:
        con.executescript(SCHEMA)
        return
    if ver < 2:
        has_v1 = con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='traffic'").fetchone()
        if has_v1:
            log("检测到旧版数据库,迁移中 ...")
            con.executescript(
                "DROP INDEX IF EXISTS traffic_node; DROP INDEX IF EXISTS traffic_client;"
                "ALTER TABLE traffic RENAME TO traffic_v1; ALTER TABLE hourly RENAME TO hourly_v1;")
        con.executescript(SCHEMA)
        if has_v1:
            with con:
                con.execute("INSERT INTO traffic(day,client,node,grp,rule,host,up,down) "
                            "SELECT day,client,node,'','',host,up,down FROM traffic_v1")
                con.execute("INSERT INTO hourly(hour,client,node,up,down) SELECT hour,'','',up,down FROM hourly_v1")
                con.execute("DROP TABLE traffic_v1")
                con.execute("DROP TABLE hourly_v1")
            log("迁移完成,旧数据已保留(规则/策略组列为空)")
    else:
        con.executescript(SCHEMA)
    con.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    con.commit()


def init_db():
    os.makedirs(os.path.dirname(config.DB_PATH) or ".", exist_ok=True)
    con = open_db()
    migrate(con)
    return con
