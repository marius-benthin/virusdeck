import re
import json
import logging
from typing import List
from datetime import datetime

from virusdeck.collectors.collector import Collector


class Malshare(Collector):

    def __init__(self, redis_url: str, malshare_api_key: str):
        Collector.__init__(self, redis_url=redis_url, offset=4)
        self.malshare_api_key = malshare_api_key

    @staticmethod
    def parse_feed(feed: str, pattern: re.Pattern = None) -> List:
        """
        Extracts file hashes from Malshare feed.
        :param feed: fetched feed
        :param pattern: None, not used
        :return: list of file hashes
        """
        file_hashes: List = []
        try:
            json_feed: json = json.loads(feed)
            for sample in json_feed:
                if "sha256" in sample:
                    file_hashes.append(sample["sha256"])
                if "md5" in sample:
                    file_hashes.append(sample["md5"])
        except ValueError as w:
            logging.warning(w)
        return file_hashes

    def get_file_hashes(self) -> List:
        """
        Malshare generates file hashes approximately every five minutes.
        :return: list of file hashes
        """
        feed: str = self.fetch_feed(f"https://malshare.com/api.php?api_key={self.malshare_api_key}&action=getlist")
        return self.parse_feed(feed=feed)
