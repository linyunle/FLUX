"""小工具:日志、nikki API 调用、地址处理。"""
import ipaddress
import json
import re
import threading
import time
import urllib.parse
import urllib.request

from . import config

stop = threading.Event()

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def log(*a):
    line = time.strftime("%F %T") + " " + " ".join(str(x) for x in a)
    print(line, flush=True)
    try:
        from . import panellog
        panellog.add_line(line)
    except Exception:
        pass


def is_mac(s):
    return bool(MAC_RE.match(s or ""))


def api_call(path, method="GET", body=None, timeout=8, conf=None):
    """调 nikki(mihomo)的 external-controller。返回解析后的 JSON(204 返回 None)。"""
    c = conf or config.get()
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if c["secret"]:
        headers["Authorization"] = "Bearer " + c["secret"]
    req = urllib.request.Request(c["api"] + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
    if not raw:
        return None
    return json.loads(raw.decode("utf-8", "replace"))


def q(name):
    return urllib.parse.quote(name, safe="")


def host_of(remote):
    """'1.2.3.4:443' / '[2001:db8::1]:443' -> 去掉端口。"""
    r = (remote or "").strip()
    if not r:
        return ""
    if r.startswith("["):
        return r[1:].split("]")[0]
    if r.count(":") == 1:
        return r.split(":")[0]
    return r


def is_public_ip(s):
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)


def is_local_ip(s):
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return ip.is_loopback


def http_json(url, timeout=8, opener=None):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 FLUX"})
    op = opener.open if opener else urllib.request.urlopen
    with op(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))
