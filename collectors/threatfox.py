from typing import List

from abusech import AbuseCh


class Threatfox(AbuseCh):

    def __init__(self, redis_url: str):
        AbuseCh.__init__(self, redis_url=redis_url, offset=6)

    def get_file_hashes(self) -> List:
        """
        Threatfox generates file hashes every five minutes.
        :return: list of file hashes
        """
        post_json = {"query": "get_iocs", "days": 1}
        feed: str = self.fetch_feed("https://threatfox-api.abuse.ch/api/v1/", post_json=post_json)
        return self.parse_feed(feed=feed)
