from keyn import api, crypto


class QueueHandler:

    def __init__(self, keypair, endpoint):
        self.keypair = keypair
        self.url = '%s/%s/%s/%s/%s' % (api.API_URL, api.ENV, 'sessions',
                                            crypto.to_base64(keypair.verify_key.__bytes__()), endpoint)

    def start(self, indefinite):
        result = api.get_from_sqs(self.keypair, self.url, 20 if indefinite else 0)
        messages = result["messages"]
        if result and len(messages) > 0:
            return messages
        elif indefinite:
            return self.start(indefinite)
        else:
            return []

