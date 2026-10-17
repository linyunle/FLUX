import signal
import threading

from . import airports, alerts, appsig, auth, collector, config, db, geo, realtime, syslog, wan, web
from .util import log, stop


def main():
    config.load()
    auth.load()
    con = db.init_db()
    airports.load(con)
    appsig.load(con)
    geo.load()
    c = collector.Collector(con)
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    web.serve()
    threading.Thread(target=realtime.run, name="realtime", daemon=True).start()
    threading.Thread(target=alerts.run, name="alerts", daemon=True).start()
    threading.Thread(target=wan.run, name="wanq", daemon=True).start()
    threading.Thread(target=syslog.run, name="syslog", daemon=True).start()
    cf = config.get()
    log(f"采集开始 {config.VERSION}  API={cf['api']}({cf['source']})  页面 :{config.LISTEN_PORT}"
        f"{'  (需要 ?t=token)' if config.PAGE_TOKEN else ''}")
    c.run()
    log("已停止")


main()
