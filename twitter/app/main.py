import os
import time
import logging
import redis
from redis import ConnectionError as RedisConnectionError
from kombu import Connection as Kombu
from kombu.exceptions import ConnectionError as KombuConnectionError
import sqlalchemy as db
from tweepy import OAuthHandler
from configparser import ConfigParser

from consumers.twitter import TwitterAnalyzer
from publishers.twitter import TwitterListener


def test_redis_on_startup(retry: int = 10, wait: float = 10):
    """
    Tests connection to Redis on application start up.
    :param retry: amount of connection retries
    :param wait: seconds to wait until connection retry
    """
    logging.info("Trying to connect to Redis ...")
    redis_connection = redis.from_url(redis_url)
    for i in range(0, retry):
        try:
            redis_connection.ping()
            logging.info("Successfully connected to Redis!")
            redis_connection.close()
            return True
        except RedisConnectionError:
            logging.warning("Redis is not yet ready!")
            time.sleep(wait)
    raise Exception("Cannot connect to Redis!")


def test_mysql_on_startup(retry: int = 10, wait: float = 10):
    """
    Tests connection to MySQL server on application start up.
    :param retry: amount of connection retries
    :param wait: seconds to wait until connection retry
    """
    logging.info("Trying to connect to MySQL server ...")
    engine = db.create_engine(mysql_url)
    for i in range(0, retry):
        try:
            mysql_connection = engine.connect()
            logging.info("Successfully connected to MySQL server!")
            mysql_connection.close()
            return True
        except RedisConnectionError:
            logging.warning("MySQL server is not yet ready!")
            time.sleep(wait)
        finally:
            engine.dispose()
    raise Exception("Cannot connect to MySQL server!")


def test_rabbitmq_on_startup(retry: int = 3, wait: float = 10):
    """
    Tests connection to RabbitMQ on application start up.
    :param retry: amount of connection retries
    :param wait: seconds to wait until connection retry
    """
    logging.info("Trying to connect to RabbitMQ ...")
    rabbitmq_connection = Kombu(rabbitmq_url)
    for i in range(0, retry):
        try:
            rabbitmq_connection.connect()
            logging.info("Successfully connected to RabbitMQ!")
            rabbitmq_connection.release()
            return True
        except KombuConnectionError or ConnectionRefusedError:
            logging.warning("RabbitMQ is not yet ready!")
            time.sleep(wait)
    raise Exception("Cannot connect to RabbitMQ!")


if __name__ == '__main__':

    logging.basicConfig(format="%(asctime)s [%(levelname)s] %(threadName)s: %(message)s", level=logging.INFO)

    script: str = os.getenv("script")

    logging.info("Reading configuration files ...")
    cfg = ConfigParser()
    cfg.read(['secrets.ini', '../secrets.ini', '../../secrets.ini'])

    redis_url: str = cfg.get("redis", "url")

    mysql_url: str = cfg.get("mysql", "url")

    rabbitmq_url: str = cfg.get("rabbitmq", "url")
    rabbitmq_queue: str = cfg.get("rabbitmq", "queue")

    telegram_url: str = cfg.get("telegram", "url")
    telegram_channel: str = cfg.get("telegram", "channel")

    threatfox_url: str = cfg.get("threatfox", "url")
    threatfox_token: str = cfg.get("threatfox", "token")

    logging.info("Waiting few seconds before testing connections ...")
    time.sleep(60)
    test_redis_on_startup()
    test_mysql_on_startup()
    test_rabbitmq_on_startup()

    if script is None:
        logging.warning("Environment variable 'script' is undefined!")
    elif script == "twitter_analyzer":
        logging.info("Initializing tweet analyzers ...")
        name = "twitter_analyzer"
        ta = TwitterAnalyzer(script, redis_url, mysql_url, rabbitmq_url, rabbitmq_queue, telegram_url, telegram_channel,
                             threatfox_url, threatfox_token)
        ta.start()
    else:
        twitter_oauth = OAuthHandler(cfg.get("twitter", "consumer_key"), cfg.get("twitter", "consumer_secret"))
        twitter_oauth.set_access_token(cfg.get("twitter", "access_token"), cfg.get("twitter", "access_token_secret"))
        if script == "twitter_users":
            logging.info("Initializing user stream listener ...")
            tu = TwitterListener(script, twitter_oauth, redis_url, rabbitmq_url, rabbitmq_queue)
            tu.start()
        elif script == "twitter_keywords":
            logging.info("Initializing keyword stream listener ...")
            tk = TwitterListener(script, twitter_oauth, redis_url, rabbitmq_url, rabbitmq_queue)
            tk.start()
