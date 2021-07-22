from typing import List

from virusdeck.collectors.abusech import AbuseCh


class Urlhaus(AbuseCh):

    def __init__(self, redis_url: str):
        AbuseCh.__init__(self, redis_url=redis_url, offset=1)

    def get_file_hashes(self) -> List:
        """
        Urlhaus generates file hashes every five minutes.
        :return: list of file hashes
        """
        feed: str = self.fetch_feed("https://urlhaus-api.abuse.ch/v1/payloads/recent/")
        return self.parse_feed(feed=feed)
