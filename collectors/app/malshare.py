from typing import List
from datetime import datetime

from collector import Collector


class Malshare(Collector):

    def __init__(self):
        Collector.__init__(self, offset=4)

    def get_md5s(self) -> List:
        """
        Collects recent MD5s from Malshare.
        :return: list of MD5s
        """
        feed: str = self.fetch_feed("https://www.malshare.com/daily/malshare.current.txt")
        return self.parse_feed(feed=feed, pattern=self.pattern_md5)

    def get_sha256s(self) -> List:
        """
        Collects recent SHA256s from Malshare.
        :return: list of SHA256s
        """
        feed: str = self.fetch_feed("https://www.malshare.com/daily/malshare.current.sha256.txt")
        return self.parse_feed(feed=feed, pattern=self.pattern_sha256)

    def get_file_hashes(self) -> List:
        """
        Malshare generates file hashes daily at 00:00 UTC.
        Try to import hashes between 00:00 - 00:10 UTC only.
        :return: list of file hashes
        """
        utc_time: datetime = datetime.utcnow()
        if utc_time.hour == 0 and utc_time.minute <= 10:
            return self.get_sha256s() + self.get_md5s()
        else:
            return []
