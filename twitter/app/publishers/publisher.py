import logging
from kombu import Connection, Queue


class Publisher:
    """
    Publishes messages to AMQP messaging server.
    """

    def __init__(self, rabbitmq_url: str, queue_name: str):
        """
        Initializes connection to messaging server.
        :param rabbitmq_url: RabbitMQ URL
        :param queue_name: queue on messaging server
        """
        self.connection = Connection(rabbitmq_url, connect_timeout=10)
        self.queue = Queue(name=queue_name, exchange='', routing_key=queue_name)
        self.producer = self.connection.Producer()

    def publish(self, message: dict):
        """
        Publishes a new message to RabbitMQ server.
        :param message: message as json dict
        """
        logging.debug("Publishing new message ...")
        try:
            self.producer.publish(
                body=message,
                routing_key=self.queue.name,
                exchange=self.queue.exchange,
                declare=[self.queue],
                expiration=60)
        except Exception as e:
            logging.warning("Publishing failed -> %s" % e)
            if self.connection.connected:
                self.connection.close()
            logging.info("Reconnecting to RabbitMQ ...")
            self.connection.connect()
            pass
