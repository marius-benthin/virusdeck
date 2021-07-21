import re
import redis
import logging
import requests
from typing import List, Dict
from threading import Thread


class Collector(Thread):

    def __init__(self, redis_url: str, offset: int):
        Thread.__init__(self)
        # position of source in bitmap
        self.offset: int = offset
        # name of source
        self.name: str = self.__class__.__name__
        # in-memory database
        self.redis: redis.Redis = redis.from_url(redis_url)
        # regex for supported file hash types
        self.pattern_md5: re.Pattern = re.compile("[a-f0-9]{32}", re.IGNORECASE)
        self.pattern_sha256: re.Pattern = re.compile("[a-f0-9]{64}", re.IGNORECASE)

    def store_hash(self, file_hash: str) -> int:
        """
        Sets bit of source for the given file hash to 1.
        :param file_hash: MD5 or SHA-256
        :return: 0 if bit is already 1, else 1
        """
        return self.redis.setbit(name=file_hash.lower(), offset=self.offset, value=1)

    @staticmethod
    def fetch_feed(url: str, headers: Dict = None, post_data: Dict = None, post_json: Dict = None) -> str:
        """
        Fetches file hash feed from source.
        :return: feed as string
        """
        feed: str = ''
        try:
            if post_data is None and post_json is None:
                r = requests.get(url=url, headers=headers)
            elif post_json is not None:
                r = requests.post(url=url, headers=headers, json=post_json)
            else:
                r = requests.post(url=url, headers=headers, data=post_data)
            if r.status_code == requests.codes.ok:
                feed = r.text
            elif r.status_code == 404:
                logging.info("Hash list not released yet: %s" % url)
            else:
                logging.warning("Request failed with %s" % r.status_code)
        except requests.exceptions.RequestException as w:
            logging.warning(w)
        return feed

    @staticmethod
    def parse_feed(feed: str, pattern: re.Pattern) -> List:
        """
        Extracts file hashes from feed.
        :param feed: fetched feed
        :param pattern: MD5 or SHA256
        :return: list of file hashes
        """
        return re.findall(pattern=pattern, string=feed)

    def get_file_hashes(self) -> List:
        """
        To be implemented by child classes.
        :return: list of file hashes
        """
        return []

    def run(self):
        """
        Imports latest file hashes from source.
        """
        new_file_hashes: int = 0
        file_hashes: List = self.get_file_hashes()
        for file_hash in file_hashes:
            new_file_hashes += (self.store_hash(file_hash) + 1) % 2
        logging.info("Found %s new file hash(es)" % new_file_hashes)
