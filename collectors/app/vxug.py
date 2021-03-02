from typing import List
from datetime import datetime

from collector import Collector


class Vxug(Collector):

    def __init__(self):
        Collector.__init__(self, offset=3)

    def get_md5s(self) -> List:
        """
        Collects latest block of MD5s from vx-underground.
        :return: list of MD5s
        """
        block: int = 0
        if self.redis.exists(self.name):
            block: int = int(self.redis.get(self.name))
        feed: str = self.fetch_feed("https://vx-underground.org/samples/Block.%s.txt" % str(block).zfill(4))
        md5s: List = self.parse_feed(feed=feed, pattern=self.pattern_md5)
        if len(md5s) > 0:
            self.redis.incr(self.name, 1)
        return md5s

    def get_file_hashes(self) -> List:
        """
        Vx-underground generates file hashes randomly.
        Check once per hour for MD5 hashes.
        :return: list of file hashes
        """
        utc_time: datetime = datetime.utcnow()
        if utc_time.minute < 5:
            return self.get_md5s()
        else:
            return []
