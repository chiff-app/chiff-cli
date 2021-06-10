from chiff import api, crypto
import logging


class QueueHandler:
    """A QueueHandler for polling a SQS queue."""

    def __init__(self, keypair, env, endpoint):
        self.keypair = keypair
        self.url = "{host}/{env}/sessions/{pub_key}/{endpoint}".format(
            host=api.API_URL,
            env=api.get_endpoint(env),
            pub_key=crypto.to_base64(keypair.verify_key.__bytes__()),
            endpoint=endpoint,
        )

    def start(self, slow_polling, timeout):
        """Start checking messages on this queue."""
        logging.info(f"Polling queue, {timeout} attempts left.")
        result = api.get_from_sqs(self.keypair, self.url, 20 if slow_polling else 0)
        messages = result["messages"]
        if result and len(messages) > 0:
            return messages
        elif timeout > 0:
            return self.start(slow_polling, timeout - 1)
        elif timeout < 0:
            # negative means indefinite
            return self.start(slow_polling, timeout)
        else:
            return []
