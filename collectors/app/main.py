import time
import logging
import schedule
from configparser import ConfigParser

from vxug import Vxug
from bazaar import Bazaar
from urlhaus import Urlhaus
from malshare import Malshare
from virusshare import Virusshare
from hybridanalysis import HybridAnalysis


logging.getLogger('schedule').propagate = False
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(threadName)s: %(message)s")

logging.info("Reading configuration files ...")
cfg = ConfigParser()
cfg.read(['secrets.ini', '../secrets.ini', '../../secrets.ini'])

virusshare_token: str = cfg.get("virusshare", "token")


def run_threaded():
    for source in [Vxug(), Bazaar(), Urlhaus(), Malshare(), Virusshare(virusshare_token), HybridAnalysis()]:
        source.start()


# create schedule for jobs
schedule.every(5).minutes.do(run_threaded)

while True:
    schedule.run_pending()
    time.sleep(1)
