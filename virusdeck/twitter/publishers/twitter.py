import logging
import redis
from threading import Thread
from tweepy import OAuthHandler, Status, Stream, StreamListener

from virusdeck.twitter.publishers.publisher import Publisher


class TwitterListener(Thread):
    """
    Twitter thread to start stream listening to users or keywords.
    """

    def __init__(self, name: str, twitter_oauth: OAuthHandler, redis_url: str, rabbitmq_url: str, rabbitmq_queue: str):
        """
        Initializes stream listener to Twitter API.
        :param name: Thread name
        :param twitter_oauth: Twitter API credentials
        :param redis_url: Redis URL
        :param rabbitmq_url: RabbitMQ URL
        :param rabbitmq_queue: RabbitMQ queue name
        """
        Thread.__init__(self, name=name)
        self.name = name
        self.oauth = twitter_oauth
        self.filters = [f.decode() for f in redis.from_url(redis_url).smembers(self.name)]
        self.listener = TwitterStreamListener(name, rabbitmq_url, rabbitmq_queue)

    def run(self):
        """
        Starts the Twitter stream listener and filters either users or keywords.
        """
        if len(self.filters) > 0:
            restart = True
            while restart:
                try:
                    stream = Stream(self.oauth, self.listener)
                    restart = False
                    if self.filters[0].isnumeric():
                        stream.filter(follow=self.filters, is_async=True, stall_warnings=True)
                    else:
                        stream.filter(track=self.filters, is_async=True, stall_warnings=True)
                except Exception as e:
                    logging.warning("Stream error -> %s" % e)
                    restart = True
                    pass
        else:
            logging.warning("No filter values have been found")


class TwitterStreamListener(StreamListener, Publisher):
    """
    Twitter stream listener that publishes incoming Tweets to AMQP messaging server.
    """

    def __init__(self, name: str, connection: str, queue_name: str):
        """
        Initializes StreamListener and AMQP Producer.
        :param connection: AMQP connection
        """
        Publisher.__init__(self, connection, queue_name)
        StreamListener.__init__(self)
        self.name = name

    def on_status(self, status: Status):
        """
        Publishes new Tweet to message queue.
        :param status: Tweet status object
        """
        self.publish(status._json)

    def on_exception(self, exception):
        logging.warning("Tweepy Exception -> %s" % exception)

    def on_error(self, error_code: int):
        """
        Logs tweepy error codes.
        https://developer.twitter.com/en/support/twitter-api/error-troubleshooting#error-codes
        :param error_code: tweepy error code
        """
        logging.error("Tweepy Code -> %s" % error_code)
