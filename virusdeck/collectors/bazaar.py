from typing import List

from virusdeck.collectors.abusech import AbuseCh


class Bazaar(AbuseCh):

    def __init__(self, redis_url: str):
        AbuseCh.__init__(self, redis_url=redis_url, offset=0)

    def get_file_hashes(self) -> List:
        """
        Malware Bazaar generates file hashes every five minutes.
        :return: list of file hashes
        """
        post_data = {"query": "get_recent", "selector": "time"}
        feed: str = self.fetch_feed("https://mb-api.abuse.ch/api/v1", post_data=post_data)
        return self.parse_feed(feed=feed)
