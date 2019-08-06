import requests, json
import time
import crypto

API_URL = "https://api.keyn.app/dev/backup"
PPD_URL = "https://api.keyn.app/dev/ppd"


def get_backup_data(keypair):
    url, params, headers = sign_request({"httpMethod": "GET"}, keypair)
    return requests.get(url, params=params, headers=headers).json()


def create_backup_data(keypair):
    url, params, headers = sign_request({"httpMethod": "PUT"}, keypair)
    return requests.put(url, params=params, headers=headers).json()


def set_backup_data(id, data, keypair):
    url, params, headers = sign_request({
        "httpMethod": "POST",
        "id": id,
        "data": data
    }, keypair)
    return requests.post(url, params=params, headers=headers).json()


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


def delete_account(id, keypair):
    url, params, headers = sign_request({
        "httpMethod": "DELETE",
        "id": id
    }, keypair)
    return requests.delete(url, params=params, headers=headers).json()


def delete_seed(keypair):
    url, params, headers = sign_request({
        "httpMethod": "DELETE"
    }, keypair)
    return requests.delete("%s/all" % url, params=params, headers=headers).json()


def get_ppd(id):
    headers = {'Content-Type': 'application/json',
               'Accept': 'application/json'}
    params = {'v': '1'}
    url = '%s/%s' % (PPD_URL, id)
    result = requests.get(url, params=params, headers=headers)
    if result.status_code == 200:
        return result.json()
    elif result.status_code != 404:
        raise Exception("A network error occurred: %d" % result.status_code)
