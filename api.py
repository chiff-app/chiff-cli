import requests, json
import time
import crypto

API_URL = "https://api.keyn.app/dev/backup"


def get_backup_data(keypair):
    url, params, headers = sign_request({"httpMethod": "GET"}, keypair)
    return requests.get(url, params=params, headers=headers).json()


def sign_request(message, keypair):
    message["timestamp"] = int(time.time() * 1000)
    signed_message, pub_key = crypto.sign(json.dumps(message), keypair)
    headers = {'Content-Type': 'application/json'}
    params = {
        'm': signed_message.message.decode().rstrip("="),
        's': signed_message.signature.decode().rstrip("=")
    }
    url = '%s/%s' % (API_URL, pub_key.decode().rstrip("="))
    return url, params, headers
