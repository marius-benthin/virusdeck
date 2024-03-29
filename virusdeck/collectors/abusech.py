import re
import json
import logging
from typing import List

from virusdeck.collectors.collector import Collector


class AbuseCh(Collector):

    def __init__(self, redis_url: str, offset: int):
        Collector.__init__(self, redis_url=redis_url, offset=offset)

    @staticmethod
    def parse_feed(feed: str, pattern: re.Pattern = None) -> List:
        """
        Extracts file hashes from Abuse.ch feeds.
        :param feed: fetched feed
        :param pattern: None, not used
        :return: list of file hashes
        """
        file_hashes: List = []
        try:
            json_feed: json = json.loads(feed)
            feed_key: str or None = None
            if "payloads" in json_feed:
                feed_key = "payloads"
            elif "data" in json_feed:
                feed_key = "data"
            if feed_key is not None:
                for sample in json_feed[feed_key]:
                    if "sha256_hash" in sample:
                        file_hashes.append(sample["sha256_hash"])
                    if "md5_hash" in sample:
                        file_hashes.append(sample["md5_hash"])
                    if "ioc_type" in sample:
                        if sample["ioc_type"] in ["md5_hash", "sha256_hash"]:
                            file_hashes.append(sample["ioc"])
        except ValueError as w:
            logging.warning(w)
        return file_hashes

    def get_file_hashes(self) -> List:
        """
        To be implemented by child classes.
        :return: list of file hashes
        """
        return []
