from keyn import api, crypto
from os import path
import os
import qrcode
import pickle
import click
import json
import time
from keyn.queue_handler import QueueHandler

APP_NAME = "Chiff"


class Session:

    def __init__(self, key, session_id, user_id, version, os, app_version, env, arn):
        self.key = key
        self.id = session_id
        self.user_id = user_id
        self.version = version
        self.os = os
        self.app_version = app_version
        self.env = env
        self.arn = arn
        signing_keypair = crypto.create_signing_keypair(key)
        self.signing_keypair = signing_keypair
        self.volatile_queue_handler = QueueHandler(signing_keypair, 'volatile')
        self.persistent_queue_handler = QueueHandler(signing_keypair, 'app-to-browser')



    @staticmethod
    def get():
        session_path = "%s/session" % click.get_app_dir(APP_NAME)
        if path.exists(session_path):
            with open(session_path, 'rb') as f:
                session = pickle.load(f)
                f.close()
                return session


    @staticmethod
    def pair():
        pairing_path = "%s/pairing" % click.get_app_dir(APP_NAME)
        if path.exists(pairing_path):
            with open(pairing_path, 'rb') as f:
                pairing = pickle.load(f)
                seed = pairing["seed"]
                priv_key = pairing["priv_key"]
                pub_key = pairing["pub_key"]
                f.close()
            pairing_keypair = crypto.create_signing_keypair(seed)
        else:
            seed = crypto.generate_seed(32)
            priv_key, pub_key = crypto.generate_keypair()
            pairing_keypair = crypto.create_signing_keypair(seed)
            api.create_pairing_queue(pairing_keypair)
            with open(pairing_path, 'wb') as f:
                pickle.dump({"seed": seed, "priv_key": priv_key, "pub_key": pub_key}, f)
                f.close()

        queue_handler = QueueHandler(pairing_keypair, 'pairing')
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=8,
            border=2,
        )
        qr.add_data('https://keyn.app/pair?p=%s&q=%s&b=cli&o=%s&v=1' % (pub_key, crypto.to_base64(seed), 'Mac%20OS'))
        qr.make(fit=True)
        qr.print_ascii()
        message = queue_handler.start(True)[0]["body"]
        message = crypto.verify(message, pairing_keypair.verify_key)
        message = crypto.decryptAnonymous(message, priv_key)
        message = json.loads(message)
        if message["type"] != 0 or pub_key != message["browserPubKey"]:
            raise Exception("Pairing error")
        shared_key = crypto.generate_shared_key(message["pubKey"], priv_key)
        session = Session(shared_key, message["sessionID"], message["userID"], message["version"], message["os"],
                          message["appVersion"], message["environment"], message["arn"])
        # TODO: Save accounts
        with open("%s/session" % click.get_app_dir(APP_NAME), 'wb') as f:
            pickle.dump(session, f)
            f.close()
        api.delete_pairing_queue(pairing_keypair)
        os.remove(pairing_path)
        return session, message["accounts"]
