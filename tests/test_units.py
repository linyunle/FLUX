import socket, struct, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import devices


def nl_neigh(family, ip, mac, state=0x02):
    dst = socket.inet_pton(family, ip)
    attrs = struct.pack("=HH", 4 + len(dst), 1) + dst
    attrs += b"\0" * (-len(dst) % 4)
    attrs += struct.pack("=HH", 4 + 6, 2) + bytes.fromhex(mac.replace(":", "")) + b"\0\0"
    body = struct.pack("=BBHiHBB", family, 0, 0, 2, state, 0, 0) + attrs
    return struct.pack("=IHHII", 16 + len(body), 28, 2, 1, 0) + body


def test_netlink():
    buf = (nl_neigh(socket.AF_INET, "192.168.1.10", "aa:bb:cc:dd:ee:01")
           + nl_neigh(socket.AF_INET6, "fd00::10", "aa:bb:cc:dd:ee:01")
           + nl_neigh(socket.AF_INET, "192.168.1.99", "aa:bb:cc:dd:ee:09", state=0x20)  # FAILED 要忽略
           + struct.pack("=IHHII", 16, 3, 2, 1, 0))
    r = devices.parse_neigh_dump(buf)
    assert r == {"192.168.1.10": "aa:bb:cc:dd:ee:01", "fd00::10": "aa:bb:cc:dd:ee:01"}, r


def test_uci():
    show = """dhcp.@host[0]=host
dhcp.@host[0].name='iphone'
dhcp.@host[0].mac='AA:BB:CC:DD:EE:01'
dhcp.@host[0].ip='192.168.1.10'
dhcp.@host[1]=host
dhcp.@host[1].name='tv'
dhcp.@host[1].ip='192.168.1.30'
dhcp.lan=dhcp
dhcp.lan.start='100'
"""
    h = devices.parse_uci_text(show)
    assert h == [{"name": "iphone", "mac": ["aa:bb:cc:dd:ee:01"], "ip": ["192.168.1.10"]},
                 {"name": "tv", "mac": [], "ip": ["192.168.1.30"]}], h
    conf = "config dnsmasq\n\toption x '1'\nconfig host\n\toption name 'nas'\n\toption mac 'aa:bb:cc:dd:ee:02'\n\toption ip '192.168.1.5'\n"
    assert devices.parse_uci_text(conf)[0]["name"] == "nas"


def test_ip_neigh_text():
    t = "192.168.1.10 dev br-lan lladdr aa:bb:cc:dd:ee:01 REACHABLE\nfe80::1 dev br-lan lladdr aa:bb:cc:dd:ee:02 STALE\n192.168.1.7 dev br-lan  FAILED\n"
    assert devices.parse_ip_neigh(t) == {"192.168.1.10": "aa:bb:cc:dd:ee:01", "fe80::1": "aa:bb:cc:dd:ee:02"}


def test_airports():
    from app import airports as a
    a.set_rules("")
    assert a.of("CF | 香港 01") == "CF" and a.of("SSRDOG ｜ 日本 02") == "SSRDOG" and a.of("牛逼 ｜ 新加坡 01") == "牛逼"
    assert a.of("备用节点") == "未分类" and a.of("UNKNOWN") == "未知"
    assert a.of("直连", "direct") == "直连" and a.of("REJECT", "reject") == "拒绝"
    a.set_rules("备用=自建机场\n# 注释\n香港 01=不该命中")
    assert a.of("备用节点") == "自建机场" and a.of("CF | 香港 01") == "不该命中"  # 规则优先于竖线前缀
    for bad in ("没有等号", "=x", "x="):
        try:
            a.parse_rules(bad); assert False, bad
        except ValueError:
            pass
    a.set_rules("")


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f(); print("ok", n)
