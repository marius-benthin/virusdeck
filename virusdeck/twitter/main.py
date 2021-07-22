import os
import time
import yaml
import logging
import redis
from redis import ConnectionError as RedisConnectionError
from kombu import Connection as Kombu
from kombu.exceptions import ConnectionError as KombuConnectionError
import sqlalchemy as db
from tweepy import OAuthHandler

from virusdeck.twitter.consumers.twitter import TwitterAnalyzer
from virusdeck.twitter.publishers.twitter import TwitterListener


def test_redis_on_startup(retries: int = 10, wait: int = 10):
    """
    Tests connection to Redis on application start up.
    :param retries: amount of connection retries
    :param wait: seconds to wait until connection retry
    """
    logging.info("Trying to connect to Redis ...")
    redis_connection = redis.from_url(redis_url)
    for i in range(0, retries):
        try:
            redis_connection.ping()
            logging.info("Successfully connected to Redis!")
            redis_connection.close()
            return True
        except RedisConnectionError:
            logging.warning("Redis is not yet ready!")
            time.sleep(wait)
    raise Exception("Cannot connect to Redis!")


def test_mysql_on_startup(retries: int = 10, wait: int = 10):
    """
    Tests connection to MySQL server on application start up.
    :param retries: amount of connection retries
    :param wait: seconds to wait until connection retry
    """
    logging.info("Trying to connect to MySQL server ...")
    engine = db.create_engine(mysql_url)
    for i in range(0, retries):
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


def test_rabbitmq_on_startup(retries: int = 3, wait: int = 10):
    """
    Tests connection to RabbitMQ on application start up.
    :param retries: amount of connection retries
    :param wait: seconds to wait until connection retry
    """
    logging.info("Trying to connect to RabbitMQ ...")
    rabbitmq_connection = Kombu(rabbitmq_url)
    for i in range(0, retries):
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

    # get target script to run from environment variable (users/keywords/analyzers)
    script: str = os.getenv("script")

    # read configuration yaml file
    with open("configs.yml", "r") as file:
        config: dict = yaml.safe_load(file)
        logging_level: str = config["logging"]["level"]
        logging_format: str = config["logging"]["format"]
        startup_retries: int = config["startup"]["retries"]
        startup_wait_init: int = config["startup"]["wait"]["init"]
        startup_wait_retry: int = config["startup"]["wait"]["retry"]

    # read secrets yaml file
    with open(config["secrets"], "r") as file:
        secrets: dict = yaml.safe_load(file)
        redis_url: str = secrets["redis"]["url"]
        mysql_url: str = secrets["mysql"]["url"]
        rabbitmq_url: str = secrets["rabbitmq"]["url"]
        rabbitmq_queue: str = secrets["rabbitmq"]["queue"]
        telegram_url: str = secrets["telegram"]["url"]
        telegram_channel: str = secrets["telegram"]["channel"]
        threatfox_url: str = secrets["threatfox"]["url"]
        threatfox_token: str = secrets["threatfox"]["token"]
        twitter_consumer_key: str = secrets["twitter"]["consumer"]["key"]
        twitter_consumer_secret: str = secrets["twitter"]["consumer"]["secret"]
        twitter_access_token: str = secrets["twitter"]["access"]["token"]
        twitter_access_token_secret: str = secrets["twitter"]["access"]["secret"]

    # configure logger
    logging.basicConfig(format=logging_format, level=logging_level)

    logging.info(f"Waiting {startup_wait_init} seconds before testing connections ...")
    time.sleep(startup_wait_init)
    test_redis_on_startup(retries=startup_retries, wait=startup_wait_retry)
    test_mysql_on_startup(retries=startup_retries, wait=startup_wait_retry)
    test_rabbitmq_on_startup(retries=startup_retries, wait=startup_wait_retry)

    if script is None:
        logging.warning("Environment variable 'script' is undefined!")
    elif script == "twitter_analyzer":
        logging.info("Initializing tweet analyzers ...")
        name = "twitter_analyzer"
        ta = TwitterAnalyzer(script, redis_url, mysql_url, rabbitmq_url, rabbitmq_queue, telegram_url, telegram_channel,
                             threatfox_url, threatfox_token)
        ta.start()
    else:
        twitter_oauth = OAuthHandler(twitter_consumer_key, twitter_consumer_secret)
        twitter_oauth.set_access_token(twitter_access_token, twitter_access_token_secret)
        if script == "twitter_users":
            logging.info("Initializing user stream listener ...")
            tu = TwitterListener(script, twitter_oauth, redis_url, rabbitmq_url, rabbitmq_queue)
            tu.start()
        elif script == "twitter_keywords":
            logging.info("Initializing keyword stream listener ...")
            tk = TwitterListener(script, twitter_oauth, redis_url, rabbitmq_url, rabbitmq_queue)
            tk.start()
