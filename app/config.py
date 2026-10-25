"""配置:环境变量给默认值,页面里保存的连接设置(data/config.json)优先。"""
import json
import os
import threading
import urllib.parse

VERSION = os.environ.get("APP_VERSION", "dev")
GITHUB_REPO = os.environ.get("GITHUB_REPO", "")  # 形如 owner/FLUX,构建镜像时写入

DATA_DIR = os.environ.get("DATA_DIR", "/data")
DB_PATH = os.environ.get("DB_PATH", os.path.join(DATA_DIR, "traffic.db"))
CONF_PATH = os.path.join(DATA_DIR, "config.json")

INTERVAL = max(2.0, float(os.environ.get("INTERVAL_SEC", "10")))
FLUSH = max(INTERVAL, float(os.environ.get("FLUSH_SEC", "60")))
ALERT_EVAL = max(2.0, float(os.environ.get("ALERT_EVAL_SEC", "30")))
ALERT_LEARN = max(0.0, float(os.environ.get("ALERT_LEARN_SEC", "900")))  # 首次启动后这段时间内见到的设备都算已知,不报新设备
PROXY_EVERY = max(2.0, float(os.environ.get("PROXY_SEC", "60")))
KEEP_DAYS = max(1, int(os.environ.get("KEEP_DAYS", "90")))
HOUR_KEEP_DAYS = max(2, int(os.environ.get("HOUR_KEEP_DAYS", "14")))

RET_PATH = os.path.join(DATA_DIR, "retention.json")
HOUR_KEEP_MAX, KEEP_MAX = 90, 365


def load_retention():
    """页面里改过的保留天数(data/retention.json)优先于环境变量。启动时和保存时调用。"""
    global KEEP_DAYS, HOUR_KEEP_DAYS
    try:
        with open(os.path.join(DATA_DIR, "retention.json"), encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict):
            if isinstance(d.get("hour_days"), int):
                HOUR_KEEP_DAYS = max(2, min(HOUR_KEEP_MAX, d["hour_days"]))
            if isinstance(d.get("days"), int):
                KEEP_DAYS = max(7, min(KEEP_MAX, d["days"]))
    except (OSError, ValueError):
        pass


def set_retention(hour_days, days):
    hour_days, days = int(hour_days), int(days)
    if not 2 <= hour_days <= HOUR_KEEP_MAX:
        raise ValueError(f"小时数据保留天数要在 2 到 {HOUR_KEEP_MAX} 之间")
    if not 7 <= days <= KEEP_MAX:
        raise ValueError(f"按天明细保留天数要在 7 到 {KEEP_MAX} 之间")
    if hour_days > days:
        raise ValueError("小时数据保留的天数不能比按天明细还长")
    global KEEP_DAYS, HOUR_KEEP_DAYS
    os.makedirs(DATA_DIR, exist_ok=True)
    path = os.path.join(DATA_DIR, "retention.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"hour_days": hour_days, "days": days}, f)
    os.replace(tmp, path)
    HOUR_KEEP_DAYS, KEEP_DAYS = hour_days, days
    return {"hour_days": hour_days, "days": days}


LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8099"))
METRICS_TOKEN = os.environ.get("METRICS_TOKEN", "")  # 非空:/metrics 可用 Bearer / ?t= 这个口令抓取(给 Prometheus)
PAGE_TOKEN = os.environ.get("PAGE_TOKEN", "")  # 非空则网页和接口都要带 ?t=<token>

_lock = threading.Lock()
_state = {"api": "", "secret": "", "rev": 0, "source": "env"}


def normalize_api(api):
    api = (api or "").strip().rstrip("/")
    if not api:
        return ""
    if "://" not in api:
        api = "http://" + api
    p = urllib.parse.urlparse(api)
    if p.scheme not in ("http", "https") or not p.netloc:
        raise ValueError("地址格式不对,例如 http://127.0.0.1:9090")
    return api


def load():
    """启动时调用:config.json 优先,没有就用环境变量。"""
    load_retention()
    api, secret, source = os.environ.get("NIKKI_API", "http://127.0.0.1:9090"), os.environ.get("NIKKI_SECRET", ""), "env"
    try:
        with open(CONF_PATH, encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict) and d.get("api"):
            api, secret, source = d["api"], str(d.get("secret", "")), "file"
    except (OSError, ValueError):
        pass
    with _lock:
        _state.update(api=normalize_api(api), secret=secret, source=source)


def get():
    with _lock:
        return dict(_state)


def save(api, secret=None):
    """页面里保存连接设置。secret 为 None 表示沿用原来的。返回新状态。"""
    api = normalize_api(api)
    if not api:
        raise ValueError("地址不能为空")
    with _lock:
        if secret is None:
            secret = _state["secret"]
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = CONF_PATH + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"api": api, "secret": secret}, f)
        os.replace(tmp, CONF_PATH)
        _state.update(api=api, secret=secret, rev=_state["rev"] + 1, source="file")
        return dict(_state)
