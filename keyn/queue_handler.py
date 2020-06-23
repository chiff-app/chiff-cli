from keyn import api


class QueueHandler:

    def __init__(self, keypair, endpoint):
        self.keypair = keypair
        self.endpoint = endpoint

    def start(self, indefinite):
        result = api.get_from_sqs(self.keypair, self.endpoint, 20 if indefinite else 0)
        messages = result["messages"]
        if result and len(messages) > 0:
            return messages
        elif indefinite:
            return self.start(indefinite)
        else:
            return []

