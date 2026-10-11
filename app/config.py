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
KEEP_DAYS = max(1, int(os.environ.get("KEEP_DAYS", "90")))
HOUR_KEEP_DAYS = max(2, int(os.environ.get("HOUR_KEEP_DAYS", "14")))

LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8099"))
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
