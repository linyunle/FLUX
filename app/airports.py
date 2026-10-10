"""机场归类:节点属于哪个机场。

nikki 的配置里通常没有「机场」这个概念(订阅合并后只剩一堆节点),所以按节点名判断:
  1. 先看你在页面里写的规则(每行「关键字=机场名」,节点名里包含关键字就算)
  2. 没命中就取节点名里竖线(| ｜ │)前面的部分,比如「CF | 香港 01」→ CF
  3. 都没有 → 未分类
直连 / 拒绝 / 未知 不属于任何机场,另外标出来。
"""
import re
import threading

SEP = re.compile(r"\s*[|｜│¦]\s*")
NONE, DIRECT, REJECT, UNKNOWN = "未分类", "直连", "拒绝", "未知"
SPECIAL = {DIRECT, REJECT, UNKNOWN}
_lock = threading.Lock()
_rules = []  # [(关键字, 机场名)]
_text = ""


def parse_rules(text):
    out = []
    lines = (text or "").splitlines()
    if len(lines) > 200:
        raise ValueError("规则最多 200 行")
    for i, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"第 {i} 行格式不对,要写成 关键字=机场名")
        kw, name = (x.strip() for x in line.split("=", 1))
        if not kw or not name:
            raise ValueError(f"第 {i} 行的关键字和机场名都不能为空")
        if len(kw) > 60 or len(name) > 40:
            raise ValueError(f"第 {i} 行太长")
        out.append((kw, name))
    return out


def set_rules(text):
    global _rules, _text
    rules = parse_rules(text)
    with _lock:
        _rules, _text = rules, "\n".join(f"{k}={n}" for k, n in rules)
    return len(rules)


def rules_text():
    with _lock:
        return _text


def load(con):
    try:
        r = con.execute("SELECT v FROM kv WHERE k='airport_rules'").fetchone()
        if r:
            set_rules(r[0])
    except Exception:
        pass


def save(con, text):
    n = set_rules(text)
    with con:
        con.execute("INSERT INTO kv(k,v) VALUES('airport_rules',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (rules_text(),))
    return n


def of(node, kind="proxy"):
    """kind: proxy / direct / reject(按节点类型,由调用方判断)。"""
    if kind == "direct":
        return DIRECT
    if kind == "reject":
        return REJECT
    if not node or node == "UNKNOWN":
        return UNKNOWN
    with _lock:
        rules = list(_rules)
    for kw, name in rules:
        if kw in node:
            return name
    m = SEP.search(node)
    if m and m.start() > 0:
        return re.sub(r"\s+", " ", node[:m.start()]).strip() or NONE
    return NONE
