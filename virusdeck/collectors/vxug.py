import re
import json
import logging
from typing import List

from virusdeck.collectors.collector import Collector


class Vxug(Collector):

    def __init__(self, redis_url: str, mwdb_token: str):
        Collector.__init__(self, redis_url=redis_url, offset=3)
        self.mwdb_token = mwdb_token

    @staticmethod
    def parse_feed(feed: str, pattern: re.Pattern = None) -> List:
        """
        Extracts file hashes from vx-underground feed.
        :param feed: fetched feed
        :param pattern: None, not used
        :return: list of file hashes
        """
        file_hashes: List = []
        try:
            json_feed: json = json.loads(feed)
            for sample in json_feed["files"]:
                if "sha256" in sample:
                    file_hashes.append(sample["sha256"])
                if "md5" in sample:
                    file_hashes.append(sample["md5"])
        except ValueError as w:
            logging.warning(w)
        return file_hashes

    def get_file_hashes(self) -> List:
        """
        Vx-underground generates file hashes randomly.
        :return: list of file hashes
        """
        feed: str = self.fetch_feed("https://virus.exchange/api/file",
                                    headers={"Authorization": f"Bearer {self.mwdb_token}"})
        return self.parse_feed(feed=feed)
