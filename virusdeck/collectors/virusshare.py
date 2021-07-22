from typing import List
from datetime import date, datetime, timedelta

from virusdeck.collectors.collector import Collector


class Virusshare(Collector):

    def __init__(self, redis_url: str, virusshare_feed: str):
        Collector.__init__(self, redis_url=redis_url, offset=2)
        self.virusshare_feed = virusshare_feed

    def get_md5s(self) -> List:
        """
        Collects latest block of MD5s from Virusshare.
        :return: list of MD5s
        """
        block: int = 0
        if self.redis.exists(self.name):
            block: int = int(self.redis.get(self.name))
        feed: str = self.fetch_feed("https://virusshare.com/hashfiles/VirusShare_%s.md5" % str(block).zfill(5))
        md5s: List = self.parse_feed(feed=feed, pattern=self.pattern_md5)
        if len(md5s) > 0:
            self.redis.incr(self.name, 1)
        return md5s

    def get_sha256s(self) -> List:
        """
        Collects SHA256s of last day from Virusshare.
        :return: list of SHA256s
        """
        yesterday: date = date.today() - timedelta(days=1)
        feed: str = self.fetch_feed(
            "https://virusshare.com/hashlist/%s/%s.txt" % (self.virusshare_feed, yesterday))
        return self.parse_feed(feed=feed, pattern=self.pattern_sha256)

    def get_file_hashes(self) -> List:
        """
        Virusshare generates file hashes daily at midnight.
        Try to import SHA-256 hashes between 01:00 - 01:10 UTC only.
        Check once per hour for MD5 hashes.
        :return: list of file hashes
        """
        utc_time: datetime = datetime.utcnow()
        file_hashes: List = []
        if utc_time.hour == 1 and utc_time.minute <= 10:
            file_hashes += self.get_sha256s()
        if utc_time.minute < 5:
            file_hashes += self.get_md5s()
        return file_hashes
