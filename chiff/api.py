import time

import json
import requests

from chiff import crypto

API_URL = "https://api.chiff.dev"
ENV = "v1"


def create_pairing_queue(keypair):
    pub_key, params, headers = sign_request({"httpMethod": "POST"}, keypair)
    url = "%s/%s/%s/%s/%s" % (API_URL, ENV, "sessions", pub_key, "pairing")
    response = requests.post(url, params=params, headers=headers)
    if response:
        return response.json()
    else:
        raise Exception("Error %d: %s" % (response.status_code, response.text))


def delete_pairing_queue(keypair):
    pub_key, params, headers = sign_request({"httpMethod": "DELETE"}, keypair)
    url = "%s/%s/%s/%s/%s" % (API_URL, ENV, "sessions", pub_key, "pairing")
    response = requests.delete(url, params=params, headers=headers)
    if response:
        return response.json()
    else:
        raise Exception("Error %d: %s" % (response.status_code, response.text))


def delete_queues(keypair, env):
    pub_key, params, headers = sign_request({"httpMethod": "DELETE"}, keypair)
    url = "%s/%s/%s/%s" % (API_URL, get_endpoint(env), "sessions", pub_key)
    response = requests.delete(url, params=params, headers=headers)
    if response:
        return response.json()
    else:
        raise Exception("Error %d: %s" % (response.status_code, response.text))


def get_session_data(keypair, env):
    pub_key, params, headers = sign_request({"httpMethod": "GET"}, keypair)
    url = "%s/%s/%s/%s" % (API_URL, get_endpoint(env), "sessions", pub_key)
    response = requests.get(url, params=params, headers=headers)
    if response:
        return response.json()
    else:
        raise Exception("Error %d: %s" % (response.status_code, response.text))


def get_from_sqs(keypair, url, wait_time):
    pub_key, params, headers = sign_request(
        {"httpMethod": "GET", "waitTime": wait_time}, keypair
    )
    response = requests.get(url, params=params, headers=headers)
    if response:
        return response.json()
    else:
        raise Exception("Error %d: %s" % (response.status_code, response.text))


def send_to_sns(keypair, message, arn, env):
    pub_key, params, headers = sign_request(
        {"httpMethod": "PUT", "data": message, "arn": arn}, keypair
    )
    url = "%s/%s/%s/%s/%s" % (API_URL, get_endpoint(env), "sessions", pub_key, "push")
    response = requests.put(url, params=params, headers=headers)
    if response:
        return response.json()
    else:
        raise Exception("Error %d: %s" % (response.status_code, response.text))


def delete_from_volatile_queue(keypair, receipt_handle, env):
    pub_key, params, headers = sign_request(
        {"httpMethod": "DELETE", "receiptHandle": receipt_handle}, keypair
    )
    url = "%s/%s/%s/%s/%s" % (
        API_URL,
        get_endpoint(env),
        "sessions",
        pub_key,
        "volatile",
    )
    response = requests.delete(url, params=params, headers=headers)
    if response:
        return response.json()
    else:
        raise Exception("Error %d: %s" % (response.status_code, response.text))


def get_backup_data(keypair):
    pub_key, params, headers = sign_request({"httpMethod": "GET"}, keypair)
    url = "%s/%s/%s/%s/%s" % (API_URL, ENV, "users", pub_key, "accounts")
    response = requests.get(url, params=params, headers=headers)
    if response:
        return response.json()
    else:
        raise Exception("Error %d: %s" % (response.status_code, response.text))


def create_backup_data(keypair):
    pub_key, params, headers = sign_request(
        {"httpMethod": "POST", "userId": crypto.user_id(keypair), "os": "cli"}, keypair
    )
    url = "%s/%s/%s/%s" % (API_URL, ENV, "users", pub_key)
    response = requests.post(url, params=params, headers=headers)
    if response:
        return response.json()
    else:
        raise Exception("Error %d: %s" % (response.status_code, response.text))


def set_backup_data(id, data, keypair):
    pub_key, params, headers = sign_request(
        {"httpMethod": "PUT", "id": id, "data": data}, keypair
    )
    url = "%s/%s/%s/%s/%s/%s" % (API_URL, ENV, "users", pub_key, "accounts", id)
    response = requests.put(url, params=params, headers=headers)
    if response:
        return response.json()
    else:
        raise Exception("Error %d: %s" % (response.status_code, response.text))


def delete_account(id, keypair):
    pub_key, params, headers = sign_request({"httpMethod": "DELETE", "id": id}, keypair)
    url = "%s/%s/%s/%s/%s/%s" % (API_URL, ENV, "users", pub_key, "accounts", id)
    response = requests.delete(url, params=params, headers=headers)
    if response:
        return response.json()
    else:
        raise Exception("Error %d: %s" % (response.status_code, response.text))


def delete_seed(keypair):
    pub_key, params, headers = sign_request({"httpMethod": "DELETE"}, keypair)
    url = "%s/%s/%s/%s" % (API_URL, ENV, "users", pub_key)
    response = requests.delete("%s/all" % url, params=params, headers=headers)
    if response:
        return response.json()
    else:
        raise Exception("Error %d: %s" % (response.status_code, response.text))


def get_ppd(id):
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    params = {"v": "1"}
    url = "%s/%s/%s/%s" % (API_URL, ENV, "ppd", id)
    response = requests.get(url, params=params, headers=headers)
    if response.status_code == 200:
        return response.json()
    elif response.status_code != 404:
        raise Exception("A network error occurred: %d" % response.status_code)


def sign_request(message, keypair):
    message["timestamp"] = int(time.time() * 1000)
    signed_message, pub_key = crypto.sign(json.dumps(message), keypair)
    headers = {
        "Content-Type": "application/json",
        "keyn-signature": signed_message.signature.decode().rstrip("="),
    }
    params = {"m": signed_message.message.decode().rstrip("=")}
    return pub_key.decode().rstrip("="), params, headers


def get_endpoint(env):
    if env == "prod":
        return "v1"
    else:
        return env
