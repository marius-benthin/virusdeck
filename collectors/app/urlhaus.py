from typing import List

from abusech import AbuseCh


class Urlhaus(AbuseCh):

    def __init__(self):
        AbuseCh.__init__(self, offset=1)

    def get_file_hashes(self) -> List:
        """
        Urlhaus generates file hashes every five minutes.
        :return: list of file hashes
        """
        feed: str = self.fetch_feed("https://urlhaus-api.abuse.ch/v1/payloads/recent/")
        return self.parse_feed(feed=feed)
