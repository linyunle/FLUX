"""模拟 docker-socket-proxy 后面的 Docker API(只实现面板用到的几个接口)。ALLOW 控制哪些操作放行。"""
import json, struct, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {"allow_post": True, "posts": []}
C = [
    {"Id": "a" * 64, "Names": ["/flux"], "Image": "ghcr.io/linyunle/flux:latest", "State": "running", "Status": "Up 2 hours", "Created": 1792000000,
     "Ports": [], "HostConfig": {"NetworkMode": "host"}, "Labels": {"com.docker.compose.project": "flux", "com.docker.compose.service": "flux"}},
    {"Id": "b" * 64, "Names": ["/navidrome"], "Image": "deluan/navidrome:latest", "State": "running", "Status": "Up 3 days", "Created": 1791000000,
     "Ports": [{"IP": "0.0.0.0", "PrivatePort": 4533, "PublicPort": 4533, "Type": "tcp"}, {"IP": "::", "PrivatePort": 4533, "PublicPort": 4533, "Type": "tcp"}],
     "HostConfig": {"NetworkMode": "bridge"}, "Labels": {}},
    {"Id": "c" * 64, "Names": ["/lrcapi"], "Image": "hisatri/lrcapi:latest", "State": "exited", "Status": "Exited (0) 5 hours ago", "Created": 1790000000,
     "Ports": [], "HostConfig": {"NetworkMode": "host"}, "Labels": {}},
    {"Id": "d" * 64, "Names": ["/docker-socket-proxy"], "Image": "tecnativa/docker-socket-proxy:latest", "State": "running", "Status": "Up 1 hour", "Created": 1792000100,
     "Ports": [], "HostConfig": {"NetworkMode": "bridge"}, "Labels": {}},
]


def stats(c):
    return {"cpu_stats": {"cpu_usage": {"total_usage": 2_000_000}, "system_cpu_usage": 100_000_000, "online_cpus": 4},
            "precpu_stats": {"cpu_usage": {"total_usage": 1_000_000}, "system_cpu_usage": 90_000_000},
            "memory_stats": {"usage": 300_000_000, "limit": 8_000_000_000, "stats": {"inactive_file": 100_000_000}},
            "networks": {"eth0": {"rx_bytes": 1000, "tx_bytes": 500}} if c["HostConfig"]["NetworkMode"] != "host" else {}}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _j(self, code, obj=None, raw=None):
        b = raw if raw is not None else (json.dumps(obj).encode() if obj is not None else b"")
        self.send_response(code); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/version": return self._j(200, {"Version": "27.0.1"})
        if p == "/containers/json": return self._j(200, C)
        parts = p.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "containers":
            c = next((x for x in C if x["Id"].startswith(parts[1])), None)
            if not c: return self._j(404, {"message": "no such container"})
            if parts[2] == "stats": return self._j(200, stats(c))
            if parts[2] == "logs":
                out = b""
                for i, ln in enumerate([f"2026-10-18T00:00:0{i}Z hello {c['Names'][0]} line {i}\n" for i in range(3)]):
                    d = ln.encode(); out += struct.pack(">BxxxI", 1 if i % 2 == 0 else 2, len(d)) + d
                return self._j(200, raw=out)
        self._j(404, {"message": "nf"})

    def do_POST(self):
        parts = self.path.split("?")[0].strip("/").split("/")
        if not STATE["allow_post"]: return self._j(403, {"message": "forbidden"})
        c = next((x for x in C if len(parts) == 3 and x["Id"].startswith(parts[1])), None)
        if not c: return self._j(404, {"message": "no such container"})
        STATE["posts"].append((c["Names"][0], parts[2]))
        if parts[2] == "stop":
            if c["State"] != "running": return self._j(304)
            c["State"], c["Status"] = "exited", "Exited (0) just now"
        elif parts[2] == "start":
            if c["State"] == "running": return self._j(304)
            c["State"], c["Status"] = "running", "Up 1 second"
        elif parts[2] == "restart":
            c["State"], c["Status"] = "running", "Up 1 second"
        self._j(204)


def start(port):
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
