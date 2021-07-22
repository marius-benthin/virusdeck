import re
import logging
import pydantic
import pymysql
import requests
from abc import ABC
import redis
from threading import Thread
from typing import List, Dict
from kombu import Message
import sqlalchemy as db
from sqlalchemy import exc
from sqlalchemy.dialects.mysql import insert

from .subscriber import Subscriber
from ...models.twitter_tweet import Tweet
from ...models.twitter_tables import Base, TableTweet, TableUser


class TwitterAnalyzer(Thread, Subscriber, ABC):
    """
    Twitter thread to start stream listening to users or keywords.
    """

    def __init__(self, name: str, redis_url: str, mysql_url: str, rabbitmq_url: str, rabbitmq_queue: str,
                 telegram_url: str, telegram_channel: str, threatfox_url: str, threatfox_token: str):
        """
        Initializes stream listener to Twitter API.
        :param name: Thread name
        :param rabbitmq_url: RabbitMQ URL
        :param rabbitmq_queue: RabbitMQ queue name
        :param telegram_url: Telegram API URL
        :param telegram_channel: Telegram channel ID
        """
        Thread.__init__(self, name=name)
        Subscriber.__init__(self, rabbitmq_url, rabbitmq_queue)

        self.redis = redis.from_url(redis_url)

        self.engine = db.create_engine(mysql_url, pool_pre_ping=True, pool_recycle=True)
        Base.metadata.create_all(self.engine)

        self.telegram_url = telegram_url
        self.telegram_channel = telegram_channel

        self.threatfox_url = threatfox_url
        self.threatfox_token = threatfox_token

        self.malpedia_families = self.get_malpedia_families()

        self.md5 = re.compile('[a-f0-9]{32}', re.I)
        self.sha1 = re.compile('[a-f0-9]{40}', re.I)
        self.sha256 = re.compile('[a-f0-9]{64}', re.I)

    def run(self):
        """
        Starts to consume messages from RabbitMQ server.
        """
        try:
            Subscriber.run(self)
        except Exception as e:
            logging.warning("Analyzer error -> %s" % e)
            if self.connection.connected:
                self.connection.close()
            logging.info("Reconnecting to RabbitMQ ...")
            self.connection.connect()
            pass

    def send_telegram(self, message: str):
        """
        Send message to Telegram channel.
        :param message: message to be sent
        """
        headers = {"Content-Type": "application/json"}
        params = {"chat_id": self.telegram_channel, "text": message}
        try:
            requests.get(self.telegram_url + "/sendMessage", headers=headers, params=params)
        except requests.exceptions.RequestException as e:
            logging.warning("Failed to send Telegram -> %s" % e)

    def send_dashboard(self, message: dict):
        """
        Send message to Virusdeck dashboard1.
        :param message: message to be sent
        """
        self.dashboard.send(message, json=True)

    def send_threatfox(self, reference: str, sha256s: List[str], md5s: List[str], malware_family: str):
        """
        Submit IOCs to ThreatFox.
        :param malware_family: Malware Family
        :param reference: Tweet URL
        :param sha256s: SHA-256 file hashes
        :param md5s: MD5 file hashes
        """
        for ioc_type, iocs in {'sha256_hash': sha256s, 'md5_hash': md5s}.items():
            if len(iocs) > 0:
                data = {'query': 'submit_ioc', 'threat_type': 'payload', 'ioc_type': ioc_type,
                        'malware': malware_family, 'reference': reference, 'iocs': iocs, 'confidence_level': '50',
                        'anonymous': 0}
                try:
                    logging.info("Submitting to Threatfox -> %s" % data)
                    r = requests.post(self.threatfox_url, headers={"API-KEY": self.threatfox_token}, json=data)
                    logging.info(r.json())
                except requests.exceptions.RequestException as e:
                    logging.warning("Failed to submit to ThreatFox -> %s" % e)

    def get_malpedia_families(self):
        """
        Get malware families from Malpedia.
        :return: malware families as dict
        """
        families = {}
        try:
            r = requests.post(self.threatfox_url, json={"query": "malware_list"})
            response = r.json()
            for name, malware in response['data'].items():
                families[name] = [name.split('.')[1]]
                if malware['malware_alias'] is not None:
                    families[name] += malware['malware_alias'].lower().replace(' ', '_').split(',')
        except ValueError as e:
            logging.error("Failed to decode ThreatFox response -> %s" % e)
            raise e
        except requests.exceptions.RequestException as e:
            logging.warning("Failed to query ThreatFox -> %s" % e)
            raise e
        return families

    def extract_hashes(self, text: str):
        """
        Extracts hashes from given text.
        :param text: haystack
        :return: distinct file hashes
        """
        sha256s = list(re.findall(self.sha256, text))
        text = re.sub(self.sha256, '', text)
        md5s = list(re.findall(self.md5, text))
        return sha256s, md5s

    def analyze(self, body: Dict, message: Message):
        """
        Analyze incoming Tweet and extract indicators of compromise.
        :param body: Json message
        :param message: AMPQ message object
        """

        try:
            tweet: Tweet = Tweet.parse_obj(body)
            if tweet.retweeted_status is not None:
                tweet: Tweet = Tweet.parse_obj(tweet.retweeted_status)
            elif tweet.quoted_status is not None:
                tweet: Tweet = Tweet.parse_obj(tweet.quoted_status)

            if hasattr(tweet.extended_tweet, 'full_text'):
                text = tweet.extended_tweet.full_text
                entities = tweet.extended_entities
            else:
                text = tweet.text
                entities = tweet.entities

            if entities is not None:
                for url in entities.urls:
                    text = text.replace(url.url, url.expanded_url)

            sha256s, md5s = self.extract_hashes(text)

            malware: bool = False
            for h in set(sha256s + md5s):
                h = h.lower()
                for i in range(0, 6):
                    if self.redis.getbit(h, i):
                        malware = True
                        break
                if malware:
                    break

            if malware:
                if not self.redis.getbit(tweet.id_str, 0):
                    tweet_url: str = "https://twitter.com/" + tweet.user.screen_name + "/status/" + tweet.id_str

                    logging.info(tweet_url)

                    self.redis.setbit(tweet.id_str, 0, 1)
                    self.redis.expire(tweet.id_str, 172800)  # 48 hours

                    self.send_dashboard({
                        "created_at": tweet.created_at,
                        "id": tweet.id_str,
                        "text": tweet.text,
                        "lang": tweet.lang,
                        "name": tweet.user.name,
                        "screen_name": tweet.user.screen_name,
                        "profile_image_url_https": tweet.user.profile_image_url_https
                    })

                    malware_family: str = ""
                    for hashtag in [hashtag.text.lower() for hashtag in tweet.entities.hashtags]:
                        for name, keywords in self.malpedia_families.items():
                            if hashtag in keywords:
                                malware_family = name
                                break

                    if malware_family != "":
                        self.send_telegram("#" + malware_family.replace('.', '_') + " " + tweet_url)
                        self.send_threatfox(tweet_url, sha256s, md5s, malware_family)
                    else:
                        logging.info("Could not find any malware family in Tweet -> %s" % tweet_url)
                        self.send_telegram(tweet_url)

                    mysql = self.engine.connect()

                    mysql.execute(insert(TableUser).values(
                        id=tweet.user.id,
                        name=tweet.user.name,
                        screen_name=tweet.user.screen_name,
                        protected=tweet.user.protected,
                        verified=tweet.user.verified,
                        created_at=tweet.user.created_at,
                        profile_image_url_https=tweet.user.profile_image_url_https
                    ).on_duplicate_key_update(
                        name=tweet.user.name,
                        screen_name=tweet.user.screen_name,
                        protected=tweet.user.protected,
                        verified=tweet.user.verified,
                        profile_image_url_https=tweet.user.profile_image_url_https))

                    mysql.execute(insert(TableTweet).values(
                        id=tweet.id,
                        user_id=tweet.user.id,
                        created_at=tweet.created_at,
                        text=text,
                        source=tweet.source,
                        truncated=tweet.truncated,
                        in_reply_to_user_id=tweet.in_reply_to_user_id,
                        in_reply_to_status_id=tweet.in_reply_to_status_id,
                        in_reply_to_screen_name=tweet.in_reply_to_screen_name,
                        possibly_sensitive=tweet.possibly_sensitive,
                        lang=tweet.lang
                    ).on_duplicate_key_update(id=tweet.id))

                    mysql.close()

        except pydantic.ValidationError as e:
            logging.warning("Failed to decode Tweet ->\n%s" % e)

        except pymysql.err.IntegrityError as e:
            logging.warning("Tweet already in table ->\n%s" % e)

        except exc.SQLAlchemyError as e:
            logging.warning("Failed to insert Tweet into database ->\n%s" % e)

        finally:
            message.ack()
