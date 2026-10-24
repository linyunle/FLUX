import signal
import threading

from . import agh, airports, alerts, appsig, auth, collector, config, db, geo, health, dnsx, nikkilog, realtime, syslog, wallpaper, wan, web
from .util import log, stop


def main():
    config.load()
    auth.load()
    con = db.init_db()
    try:
        bk = health.auto_backup(con)
        if bk:
            log(f"升级前已自动备份配置:data/backups/{bk}")
    except Exception as e:
        log("升级前自动备份失败(不影响运行)", e)
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
    threading.Thread(target=agh.run, name="aghsample", daemon=True).start()
    threading.Thread(target=syslog.run, name="syslog", daemon=True).start()
    threading.Thread(target=nikkilog.run, name="nklog", daemon=True).start()
    threading.Thread(target=dnsx.run, name="dnsprobe", daemon=True).start()
    threading.Thread(target=wallpaper.run, name="wallpaper", daemon=True).start()
    cf = config.get()
    log(f"采集开始 {config.VERSION}  API={cf['api']}({cf['source']})  页面 :{config.LISTEN_PORT}"
        f"{'  (需要 ?t=token)' if config.PAGE_TOKEN else ''}")
    c.run()
    log("已停止")


main()
