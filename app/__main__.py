import signal
import threading

from . import airports, appsig, collector, config, db, realtime, web
from .util import log, stop


def main():
    config.load()
    con = db.init_db()
    airports.load(con)
    appsig.load(con)
    c = collector.Collector(con)
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    web.serve()
    threading.Thread(target=realtime.run, name="realtime", daemon=True).start()
    cf = config.get()
    log(f"采集开始 {config.VERSION}  API={cf['api']}({cf['source']})  页面 :{config.LISTEN_PORT}"
        f"{'  (需要 ?t=token)' if config.PAGE_TOKEN else ''}")
    c.run()
    log("已停止")


main()
