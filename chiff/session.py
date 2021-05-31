from chiff import api, crypto
from os import path
from random import randint
import os
import qrcode
import pickle
import click
import json
from chiff.queue_handler import QueueHandler
from chiff.constants import APP_NAME, MessageType
import itertools
import threading
import time
import sys
import platform
from urllib.parse import urlencode


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
        self.volatile_queue_handler = QueueHandler(signing_keypair, env, "volatile")
        self.persistent_queue_handler = QueueHandler(
            signing_keypair, env, "app-to-browser"
        )

    def get_accounts(self):
        result = api.get_session_data(self.signing_keypair, self.env)
        data = json.loads(crypto.decrypt(result["data"], self.key))
        if data["appVersion"] != self.app_version:
            self.app_version = data["appVersion"]
            with open("%s/session" % click.get_app_dir(APP_NAME), "wb") as f:
                pickle.dump(self, f)
                f.close()
        accounts = result["accounts"]
        for id, ciphertext in accounts.items():
            account = json.loads(crypto.decrypt(ciphertext, self.key))
            if "id" not in account:
                account["id"] = id
            accounts[id] = account
        return accounts

    def send_push_message(self, message, category, body, **kwargs):
        apns_payload = {
            "aps": {
                "category": category,
                "mutable-content": 1,
                "launch-image": "logo",
                "alert": {"body": body},
                "sound": "chime.aiff",
            },
            "sessionID": self.id,
            "data": message,
        }
        gcm_payload = {"data": {"sessionID": self.id, "message": message}}
        title = kwargs.get("title", None)
        if title:
            apns_payload["aps"]["alert"]["title"] = title
        data = json.dumps(
            {
                "APNS_SANDBOX"
                if self.env == "dev"
                else "APNS": json.dumps(apns_payload),
                "GCM": json.dumps(gcm_payload),
            }
        )
        api.send_to_sns(self.signing_keypair, data, self.arn, self.env)

    def send_request(self, request):
        request_id = randint(0, 1e9)
        request["b"] = request_id
        request["z"] = int(time.time() * 1000)
        request = crypto.encrypt(json.dumps(request).encode("utf-8"), self.key)
        self.send_push_message(
            request, "PASSWORD_REQUEST", "Open to authorize", title="Login request"
        )
        return self.poll_queue(request_id)

    def poll_queue(self, request_id):
        messages = self.volatile_queue_handler.start(True)
        for response in messages:
            message = json.loads(crypto.decrypt(response["body"], self.key))
            api.delete_from_volatile_queue(
                self.signing_keypair, response["receiptHandle"], self.env
            )
            if message["b"] == request_id:
                return message
            else:
                return self.poll_queue(request_id)

    def pairing_status(self):
        messages = self.persistent_queue_handler.start(False)
        for message in messages:
            decrypted_message = json.loads(crypto.decrypt(message["body"], self.key))
            if decrypted_message["t"] == MessageType.END.value:
                self.end(True)
                return False
        return True

    def send_bulk_accounts(self, accounts):
        persistent_message = {"t": MessageType.ADD_BULK.value, "b": accounts}
        api.send_bulk_accounts(
            crypto.encrypt(json.dumps(persistent_message).encode("utf-8"), self.key),
            self.signing_keypair,
            self.env,
        )
        request = {"r": MessageType.ADD_BULK.value, "x": len(accounts)}
        return self.send_request(request)

    def end(self, including_queues=False):
        if including_queues:
            api.delete_queues(self.signing_keypair, self.env)
        else:
            request = {"r": 7, "z": int(time.time() * 1000)}
            request = crypto.encrypt(json.dumps(request).encode("utf-8"), self.key)
            self.send_push_message(request, "END_SESSION", "Session ended by CLI")
        os.remove("%s/session" % click.get_app_dir(APP_NAME))

    @staticmethod
    def get():
        session_path = "%s/session" % click.get_app_dir(APP_NAME)
        if path.exists(session_path):
            with open(session_path, "rb") as f:
                session = pickle.load(f)
                f.close()
                if session.pairing_status():
                    return session
                else:
                    return None

    @staticmethod
    def pair():
        pairing_path = "%s/pairing" % click.get_app_dir(APP_NAME)
        if path.exists(pairing_path):
            with open(pairing_path, "rb") as f:
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
            with open(pairing_path, "wb") as f:
                pickle.dump({"seed": seed, "priv_key": priv_key, "pub_key": pub_key}, f)
                f.close()

        queue_handler = QueueHandler(pairing_keypair, "dev", "pairing")
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=4,
            border=2,
        )
        qr.add_data(
            "https://chiff.app/pair?%s"
            % urlencode(
                {
                    "p": pub_key,
                    "q": crypto.to_base64(seed),
                    "b": "cli",
                    "o": platform.node(),
                    "v": 1,
                }
            )
        )
        qr.make()
        qr.print_ascii(tty=True)
        done = False

        def animate():
            for c in itertools.cycle(["|", "/", "-", "\\"]):
                if done:
                    break
                sys.stdout.write("\rWaiting for pairing " + c)
                sys.stdout.flush()
                time.sleep(0.1)

        t = threading.Thread(target=animate)
        t.daemon = True
        t.start()

        message = queue_handler.start(True)[0]["body"]
        done = True
        message = crypto.verify(message, pairing_keypair.verify_key)
        message = crypto.decrypt_anonymous(message, priv_key)
        message = json.loads(message)
        if message["type"] != 0 or pub_key != message["browserPubKey"]:
            raise Exception("Pairing error")
        shared_key = crypto.generate_shared_key(message["pubKey"], priv_key)
        version = 1
        if "version" in message:
            version = message["version"]
        session = Session(
            shared_key,
            message["sessionID"],
            message["userID"],
            version,
            message["os"],
            message["appVersion"],
            message["environment"],
            message["arn"],
        )
        with open("%s/session" % click.get_app_dir(APP_NAME), "wb") as f:
            pickle.dump(session, f)
            f.close()
        api.delete_pairing_queue(pairing_keypair)
        os.remove(pairing_path)
        return session, message["accounts"]
