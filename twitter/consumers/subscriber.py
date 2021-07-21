from typing import Dict
from abc import abstractmethod
from flask_socketio import SocketIO
from kombu import Connection, Message, Queue
from kombu.mixins import ConsumerProducerMixin


class Subscriber(ConsumerProducerMixin):
    """
    Consumes messages from messaging server.
    """

    def __init__(self, rabbitmq_url: str, rabbitmq_queue: str):
        """
        Initializes connection to messaging server.
        :param rabbitmq_url: RabbitMQ URL
        :param rabbitmq_queue: RabbitMQ queue name
        """
        self.connection = Connection(rabbitmq_url, connect_timeout=10)
        self.queue = Queue(name=rabbitmq_queue, routing_key=rabbitmq_queue)
        self.consumer = self.connection.Consumer(queues=self.queue)
        self.dashboard = SocketIO(message_queue=rabbitmq_url)

    def get_consumers(self, consumer, channel):
        """
        Accepts incoming messages from RabbitMQ server.
        """
        return [consumer(self.queue, callbacks=[self.analyze])]

    @abstractmethod
    def analyze(self, body: Dict, message: Message):
        """
        Analyzes a message. To be implemented by consumer.
        """
        pass
