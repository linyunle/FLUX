"""模拟 mihomo 的 external-controller 和出口探测用的 http 入口。"""
import json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

SECRET = "s3cret"
STATE = {"tick": 0, "probe_sel": "HK-01", "puts": [], "jp_down": False, "hk_down": False, "extra_dev": False, "pt": 0, "hist": {}, "leak": False}
GEO = {"HK-01": {"ip": "203.0.113.5", "country": "Hong Kong", "city": "Central", "organization": "HKT", "asn": 4760},
       "JP-01": {"ip": "198.51.100.7", "success": True, "country": "Japan", "region": "Tokyo", "city": "Tokyo",
                 "connection": {"org": "IIJ", "asn": 2497}}}


def conns():
    t = STATE["tick"]
    def c(i, src, chains, rule, host, k, inbound="mixed-in"):
        return {"id": i, "upload": 1000 * k * t, "download": 5000 * k * t, "chains": chains, "rule": rule, "rulePayload": "",
                "metadata": {"sourceIP": src, "host": host, "destinationIP": "1.1.1.1" if not host.startswith("netflix") else "", "dnsMode": "normal" if not host.startswith("netflix") else "fake-ip", "remoteDestination": "203.0.113.5:443",
                            "inboundName": inbound, "network": "udp" if host.startswith("r1.") else "tcp", "destinationPort": "80" if host.startswith("dl.") else "443", "inboundPort": "7890"}}
    extra = [c("x", "192.168.1.99", ["HK-01", "Proxy"], "RuleSet", "example.org", 1)] if STATE["extra_dev"] else []
    if STATE["leak"]:
        l2 = c("l2", "192.168.1.20", ["直连", "国内"], "Match", "www.google.com", 1)
        l2["metadata"]["destinationIP"] = "89.160.20.112"
        l3 = c("l3", "192.168.1.10", ["HK-01", "Proxy"], "RuleSet", "api.example.org", 1)
        l3["metadata"]["destinationIP"] = "216.160.83.56"
        extra += [c("l1", "192.168.1.10", ["HK-01", "Proxy"], "RuleSet", "www.bilibili.com", 2), l2, l3]
    extra += [c(pc["id"], "127.0.0.1", ["直连", "国内"], "RuleSet", pc["host"], 1) | {"rulePayload": "mockset"} for pc in STATE.get("probe_conns", [])]
    return extra + [
        c("a", "192.168.1.10", ["HK-01", "Proxy"], "RuleSet", "youtube.com", 1),
        c("b", "fd00::10", ["HK-01", "Proxy"], "RuleSet", "netflix.com", 2),     # 同一台设备的 IPv6
        c("c", "192.168.1.20", ["直连", "国内"], "GeoIP", "baidu.com", 1),   # 直连出口不叫 DIRECT
        c("e", "192.168.1.10", ["HK-01", "Proxy"], "RuleSet", "r1.googlevideo.com", 1),
        c("f", "192.168.1.10", ["HK-01", "Proxy"], "RuleSet", "r2.googlevideo.com", 1),
        c("g", "192.168.1.20", ["直连", "国内"], "GeoIP", "dl.drive.quark.cn", 2),
    ]


class API(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _j(self, code, obj):
        b = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(code); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def _auth(self):
        if self.headers.get("Authorization") != "Bearer " + SECRET:
            self._j(401, {"message": "Unauthorized"}); return False
        return True

    def do_GET(self):
        if not self._auth(): return
        p = unquote(self.path)
        if p == "/version": return self._j(200, {"version": "v1.19.0-mock"})
        if p == "/configs": return self._j(200, {"mixed-port": STATE.get("mixed", 0), "mode": "rule"})
        if p.startswith("/logs"):   # 流式日志:第一次连上发 3 行,之后的连接只挂着 2 秒就断开
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            import time as _t
            try:
                if not STATE.get("logs_sent"):
                    STATE["logs_sent"] = True
                    for typ, msg in (("warning", "mock-warn-line dial tcp 10.1.2.3:443 timeout"), ("info", "mock-info-line"), ("error", "mock-error-line")):
                        self.wfile.write((json.dumps({"type": typ, "payload": msg}) + "\n").encode()); self.wfile.flush()
                _t.sleep(2)
            except OSError:
                pass
            return
        if p == "/traffic":   # 流式:每 0.3 秒一行,发几行就断开(读取方应自动重连)
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            import time as _t
            try:
                for i in range(6):
                    self.wfile.write((json.dumps({"up": 1000 + i, "down": 5000 + i}) + "\n").encode()); self.wfile.flush(); _t.sleep(0.3)
            except OSError:
                pass
            return
        if p == "/connections":
            STATE["tick"] += 1
            return self._j(200, {"connections": conns(), "memory": 88000000})
        if p == "/proxies":
            STATE["pt"] += 1
            n = STATE["pt"]
            def hist(node, d):
                h = STATE["hist"].setdefault(node, [])
                h.append({"time": "2026-10-13T10:%02d:%02d+08:00" % (n // 60 % 60, n % 60), "delay": d})
                del h[:-10]
                return list(h)
            return self._j(200, {"proxies": {
                "DIRECT": {"type": "Direct"},
                "直连": {"type": "Direct"},
                "HK-01": {"type": "Vless", "history": hist("HK-01", 0 if STATE["hk_down"] else 88 + n % 7 * 5)},
                "JP-01": {"type": "Trojan", "history": hist("JP-01", 0 if STATE["jp_down"] else 120)},
                "Proxy": {"type": "Selector", "now": "HK-01", "all": ["HK-01", "JP-01"]},
                "egress-probe": {"type": "Selector", "now": STATE["probe_sel"], "all": ["HK-01", "JP-01"]}}})
        if p.split("?")[0].startswith("/providers/proxies/") and p.split("?")[0].endswith("/healthcheck") and p.count("/") >= 5:
            STATE.setdefault("hc", []).append(unquote(p.split("?")[0]))
            return self._j(200, {"delay": 77})
        if p.split("?")[0].startswith("/proxies/") and p.split("?")[0].endswith("/delay"):
            STATE.setdefault("delays", []).append(p.split("?")[0].split("/")[2])
            return self._j(200, {"delay": 99})
        if p == "/providers/proxies":
            return self._j(200, {"providers": {
                "default": {"type": "Proxy", "vehicleType": "Compatible", "proxies": []},
                "MyAir": {"type": "Proxy", "vehicleType": "HTTP", "updatedAt": "2026-10-16T08:00:00+08:00",
                          "subscriptionInfo": {"Upload": 1 << 30, "Download": 5 << 30, "Total": 100 << 30, "Expire": 1893456000},
                          "proxies": [{"name": "XX-01", "type": "Vless", "history": [{"time": "2026-10-16T08:00:00+08:00", "delay": 88}]}, {"name": "XX-02", "type": "Trojan", "history": []}]},
                "NoExp": {"type": "Proxy", "vehicleType": "HTTP", "updatedAt": "2026-10-16T06:16:00.123456789+08:00",
                          "subscriptionInfo": {"Upload": 0, "Download": 7 << 40, "Total": 24 << 40, "Expire": 4102444800},
                          "proxies": [{"name": "YY-01"}]}}})
        if p == "/rules":
            ex = lambda n: {"disabled": False, "hitCount": n, "hitAt": "2026-10-13T10:00:00+08:00", "missCount": 3}
            return self._j(200, {"rules": [
                {"index": 0, "type": "DomainSuffix", "payload": "youtube.com", "proxy": "Proxy", "size": -1, "extra": ex(5)},
                {"index": 1, "type": "DomainSuffix", "payload": "unused.example", "proxy": "Proxy", "size": -1, "extra": ex(0)},
                {"index": 2, "type": "GeoIP", "payload": "CN", "proxy": "直连", "size": -1, "extra": ex(9)},
                {"index": 3, "type": "Match", "payload": "", "proxy": "Proxy", "size": -1, "extra": ex(2)}]})
        if p == "/proxies/egress-probe":
            return self._j(200, {"type": "Selector", "now": STATE["probe_sel"], "all": ["HK-01", "JP-01"]})
        self._j(404, {})

    def do_PUT(self):
        if not self._auth(): return
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        if unquote(self.path) == "/proxies/egress-probe":
            STATE["probe_sel"] = body["name"]; STATE["puts"].append(body["name"])
            return self._j(204, None)
        self._j(404, {})


class Probe(BaseHTTPRequestHandler):
    """http 代理入口:GET 绝对地址 → 按当前选中的节点返回回显 JSON。"""
    def log_message(self, *a): pass

    def do_GET(self):
        b = json.dumps(GEO[STATE["probe_sel"]]).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)


class ConnectProxy(BaseHTTPRequestHandler):
    """只认 CONNECT:登记一条来自 127.0.0.1 的连接,回 200"""
    def log_message(self, *a): pass
    def do_CONNECT(self):
        host = self.path.rsplit(":", 1)[0]
        STATE.setdefault("probe_conns", []).append({"id": "pc%d" % len(STATE.get("probe_conns", [])), "host": host})
        self.send_response(200, "Connection established"); self.end_headers()


def start(api_port, probe_port):
    STATE["mixed"] = api_port + 1
    cp = ThreadingHTTPServer(("127.0.0.1", api_port + 1), ConnectProxy); cp.daemon_threads = True
    threading.Thread(target=cp.serve_forever, daemon=True).start()
    for port, h in ((api_port, API), (probe_port, Probe)):
        s = ThreadingHTTPServer(("127.0.0.1", port), h); s.daemon_threads = True
        threading.Thread(target=s.serve_forever, daemon=True).start()


AGH_STATE = {"hits": 0}


class AGH(BaseHTTPRequestHandler):
    """模拟 AdGuard Home:Basic 认证 admin / pw123。"""
    def log_message(self, *a): pass

    def _j(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        import base64
        AGH_STATE["hits"] += 1
        if self.headers.get("Authorization") != "Basic " + base64.b64encode(b"admin:pw123").decode():
            return self._j(401, {"message": "Unauthorized"})
        p = self.path
        if p.startswith("/control/status"): return self._j(200, {"version": "v0.107.50", "running": True})
        if p.startswith("/control/stats"):
            return self._j(200, {"time_units": "hours", "num_dns_queries": 2000, "num_blocked_filtering": 300, "num_replaced_safebrowsing": 2,
                                 "num_replaced_parental": 0, "avg_processing_time": 0.012,
                                 "top_queried_domains": [{"example.com": 100}], "top_blocked_domains": [{"ads.tracker.net": 120}, {"telemetry.example": 60}],
                                 "top_clients": [{"192.168.1.10": 900}, {"192.168.1.77": 50}],
                                 "dns_queries": [10, 20, 30], "blocked_filtering": [1, 2, 3]})
        if p.startswith("/control/querylog"):
            return self._j(200, {"data": [{"time": "2026-10-14T09:00:00.1+08:00", "client": "192.168.1.10", "question": {"name": "ads.tracker.net", "type": "A"},
                                           "reason": "FilteredBlackList", "rule": "||tracker.net^"}], "oldest": ""})
        self._j(404, {})


def start_agh(port):
    s = ThreadingHTTPServer(("127.0.0.1", port), AGH); s.daemon_threads = True
    threading.Thread(target=s.serve_forever, daemon=True).start()
