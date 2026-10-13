"""模拟 mihomo 的 external-controller 和出口探测用的 http 入口。"""
import json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

SECRET = "s3cret"
STATE = {"tick": 0, "probe_sel": "HK-01", "puts": []}
GEO = {"HK-01": {"ip": "203.0.113.5", "country": "Hong Kong", "city": "Central", "organization": "HKT", "asn": 4760},
       "JP-01": {"ip": "198.51.100.7", "success": True, "country": "Japan", "region": "Tokyo", "city": "Tokyo",
                 "connection": {"org": "IIJ", "asn": 2497}}}


def conns():
    t = STATE["tick"]
    def c(i, src, chains, rule, host, k, inbound="mixed-in"):
        return {"id": i, "upload": 1000 * k * t, "download": 5000 * k * t, "chains": chains, "rule": rule, "rulePayload": "",
                "metadata": {"sourceIP": src, "host": host, "destinationIP": "1.1.1.1" if not host.startswith("netflix") else "", "dnsMode": "normal" if not host.startswith("netflix") else "fake-ip", "remoteDestination": "203.0.113.5:443",
                            "inboundName": inbound, "network": "udp" if host.startswith("r1.") else "tcp", "destinationPort": "80" if host.startswith("dl.") else "443", "inboundPort": "7890"}}
    return [
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
            def hist(d):
                n = STATE["tick"]
                return [{"time": "2026-10-13T10:%02d:%02d+08:00" % (n // 60 % 60, n % 60), "delay": (d + n % 7 * 5) if d else (0 if n % 2 else 120)}]
            return self._j(200, {"proxies": {
                "DIRECT": {"type": "Direct"},
                "直连": {"type": "Direct"},
                "HK-01": {"type": "Vless", "history": hist(88)},
                "JP-01": {"type": "Trojan", "history": hist(0)},
                "Proxy": {"type": "Selector", "now": "HK-01", "all": ["HK-01", "JP-01"]},
                "egress-probe": {"type": "Selector", "now": STATE["probe_sel"], "all": ["HK-01", "JP-01"]}}})
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


def start(api_port, probe_port):
    for port, h in ((api_port, API), (probe_port, Probe)):
        s = ThreadingHTTPServer(("127.0.0.1", port), h); s.daemon_threads = True
        threading.Thread(target=s.serve_forever, daemon=True).start()
