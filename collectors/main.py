import time
import yaml
import logging
import schedule

from vxug import Vxug
from bazaar import Bazaar
from urlhaus import Urlhaus
from malshare import Malshare
from threatfox import Threatfox
from virusshare import Virusshare
from hybridanalysis import HybridAnalysis


def run_threaded():
    """
    Runs each collector in a dedicated thread.
    """
    for source in [Vxug(redis_url), Bazaar(redis_url), Urlhaus(redis_url), Malshare(redis_url), Threatfox(redis_url),
                   Virusshare(redis_url, virusshare_feed), HybridAnalysis(redis_url)]:
        source.start()


if __name__ == '__main__':

    # read configuration yaml file
    with open("configs.yml", "r") as file:
        config: dict = yaml.safe_load(file)
        logging_level: str = config["logging"]["level"]
        logging_format: str = config["logging"]["format"]
        collectors_interval: int = config["collectors"]["interval"]

    # read secrets yaml file
    with open(config["secrets"], "r") as file:
        secrets: dict = yaml.safe_load(file)
        redis_url: str = secrets["redis"]["url"]
        virusshare_feed: str = secrets["virusshare"]["feed"]

    # configure logger
    logging.getLogger("schedule").propagate = False
    logging.basicConfig(format=logging_format, level=logging_level)

    # create scheduled runs each x minutes
    schedule.every(collectors_interval).minutes.do(run_threaded)

    while True:
        schedule.run_pending()
        time.sleep(1)
