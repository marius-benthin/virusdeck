import re
import json
import logging
from typing import List

from virusdeck.collectors.collector import Collector


class HybridAnalysis(Collector):

    def __init__(self, redis_url: str):
        Collector.__init__(self, redis_url=redis_url, offset=5)

    @staticmethod
    def parse_feed(feed: str, pattern: re.Pattern = None) -> List:
        """
        Extracts file hashes from Hybrid Analysis feed.
        :param feed: fetched feed
        :param pattern: None, not used
        :return: list of file hashes
        """
        file_hashes: List = []
        try:
            json_feed: json = json.loads(feed)
            for sample in json_feed["data"]:
                if "isurlanalysis" in sample and not sample["isurlanalysis"]:
                    if "threatlevel" in sample and sample["threatlevel"] >= 2:
                        if "sha256" in sample:
                            file_hashes.append(sample["sha256"])
                        if "md5" in sample:
                            file_hashes.append(sample["md5"])
        except ValueError as w:
            logging.warning(w)
        return file_hashes

    def get_file_hashes(self) -> List:
        """
        Hybrid Analysis generates file hashes approximately every five minutes.
        :return: list of file hashes
        """
        feed: str = self.fetch_feed("https://www.hybrid-analysis.com/feed?json",
                                    headers={'User-Agent': 'Falcon Sandbox'})
        return self.parse_feed(feed=feed)
