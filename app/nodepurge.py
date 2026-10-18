"""清理已经不存在的节点(比如在 nikki 里删掉了某个订阅):
- 「已不存在」= 面板的测速评分 / 节点信息里有记录,但 nikki 现在的节点列表里没有。
- 默认只清评分和测速数据(qoe、节点信息),这些不会影响流量统计;
- 可选同时删这些节点的历史流量统计(会让历史总量变小,所以单独勾选)。
nikki 连不上、或现在一个节点都读不到时拒绝执行,避免把全部节点误判成「已不存在」。"""
from . import airports

TRAFFIC_TABLES = ("traffic", "hourly", "proto", "app")


def _live():
    from . import collector
    c = collector.COLLECTOR
    if not c or not c.status.get("ok") or not c.nodes:
        raise ValueError("现在连不上 nikki,或读不到任何节点,为了避免误删先不执行。连上后再试。")
    return set(c.nodes)


def _known(con):
    out = {}
    for n, seen in con.execute("SELECT node, seen FROM nodeinfo"):
        out[n] = {"seen": seen or 0, "qoe": 0}
    for n, c in con.execute("SELECT node, COUNT(*) FROM qoe GROUP BY node"):
        out.setdefault(n, {"seen": 0, "qoe": 0})["qoe"] = c
    return out


def stale(con, airport_of=None):
    live = _live()
    skip = set(airports.SPECIAL) | {"DIRECT", "REJECT", ""}
    rows = []
    for n, v in _known(con).items():
        if n in live or n in skip:
            continue
        b = con.execute("SELECT COALESCE(SUM(up+down),0) FROM hourly WHERE node=?", (n,)).fetchone()[0]
        rows.append({"node": n, "airport": airport_of(n) if airport_of else "", "seen": v["seen"], "qoe_rows": v["qoe"], "bytes": int(b)})
    rows.sort(key=lambda r: (r["airport"], r["node"]))
    return {"rows": rows, "live": len(live)}


def purge(con, nodes=None, history=False, airport_of=None):
    st = stale(con, airport_of)
    names = {r["node"] for r in st["rows"]}
    if nodes is not None:
        names &= set(map(str, nodes))
    if not names:
        return {"ok": True, "nodes": 0, "qoe": 0, "traffic": 0}
    q = tr = 0
    with con:
        for n in names:
            q += con.execute("DELETE FROM qoe WHERE node=?", (n,)).rowcount
            con.execute("DELETE FROM nodeinfo WHERE node=?", (n,))
            if history:
                for t in TRAFFIC_TABLES:
                    tr += con.execute(f"DELETE FROM {t} WHERE node=?", (n,)).rowcount
    return {"ok": True, "nodes": len(names), "qoe": q, "traffic": tr}
