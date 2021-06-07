import time

import json
import requests

from chiff import crypto

API_URL = "https://api.chiff.dev"
ENV = "v1"


def create_pairing_queue(keypair):
    pub_key, headers, params = sign_request({"httpMethod": "POST"}, keypair)
    url = "{host}/{env}/sessions/{pub_key}/pairing".format(
        host=API_URL, env=ENV, pub_key=pub_key
    )
    response = requests.post(url, params=params, headers=headers)
    if response:
        return response.json()
    else:
        raise Exception(
            "Error {status}: {response}".format(
                status=response.status_code, response=response.text
            )
        )


def delete_pairing_queue(keypair):
    pub_key, headers, params = sign_request({"httpMethod": "DELETE"}, keypair)
    url = "{host}/{env}/sessions/{pub_key}/pairing".format(
        host=API_URL, env=ENV, pub_key=pub_key
    )
    response = requests.delete(url, params=params, headers=headers)
    if response:
        return response.json()
    else:
        raise Exception(
            "Error {status}: {response}".format(
                status=response.status_code, response=response.text
            )
        )


def delete_queues(keypair, env):
    pub_key, headers, params = sign_request({"httpMethod": "DELETE"}, keypair)
    url = "{host}/{env}/sessions/{pub_key}".format(
        host=API_URL, env=get_endpoint(env), pub_key=pub_key
    )
    response = requests.delete(url, params=params, headers=headers)
    if response:
        return response.json()
    else:
        raise Exception(
            "Error {status}: {response}".format(
                status=response.status_code, response=response.text
            )
        )


def get_session_data(keypair, env):
    pub_key, headers, params = sign_request({"httpMethod": "GET"}, keypair)
    url = "{host}/{env}/sessions/{pub_key}".format(
        host=API_URL, env=get_endpoint(env), pub_key=pub_key
    )
    response = requests.get(url, params=params, headers=headers)
    if response:
        return response.json()
    else:
        raise Exception(
            "Error {status}: {response}".format(
                status=response.status_code, response=response.text
            )
        )


def get_from_sqs(keypair, url, wait_time):
    pub_key, headers, params = sign_request(
        {"httpMethod": "GET", "waitTime": wait_time}, keypair
    )
    response = requests.get(url, params=params, headers=headers)
    if response:
        return response.json()
    else:
        raise Exception(
            "Error {status}: {response}".format(
                status=response.status_code, response=response.text
            )
        )


def send_to_sns(keypair, message, arn, env):
    pub_key, headers, params = sign_request(
        {"httpMethod": "PUT", "data": message, "arn": arn}, keypair
    )
    url = "{host}/{env}/sessions/{pub_key}/push".format(
        host=API_URL, env=get_endpoint(env), pub_key=pub_key
    )
    response = requests.put(url, params=params, headers=headers)
    if response:
        return response.json()
    else:
        raise Exception(
            "Error {status}: {response}".format(
                status=response.status_code, response=response.text
            )
        )


def delete_from_volatile_queue(keypair, receipt_handle, env):
    pub_key, headers, params = sign_request(
        {"httpMethod": "DELETE", "receiptHandle": receipt_handle}, keypair
    )
    url = "{host}/{env}/sessions/{pub_key}/volatile".format(
        host=API_URL, env=get_endpoint(env), pub_key=pub_key
    )
    response = requests.delete(url, params=params, headers=headers)
    if response:
        return response.json()
    else:
        raise Exception(
            "Error {status}: {response}".format(
                status=response.status_code, response=response.text
            )
        )


def send_bulk_accounts(data, keypair, env):
    message = {"timestamp": int(time.time() * 1000), "httpMethod": "PUT", "data": data}
    signed_message, pub_key = crypto.sign(json.dumps(message), keypair)
    headers = {
        "Content-Type": "application/json",
        "keyn-signature": signed_message.signature.decode().rstrip("="),
    }
    url = "{host}/{env}/sessions/{pub_key}/accounts/import".format(
        host=API_URL, env=get_endpoint(env), pub_key=pub_key.decode().rstrip("=")
    )
    response = requests.put(url, json=message, headers=headers)
    if response:
        return response.json()
    else:
        raise Exception(
            "Error {status}: {response}".format(
                status=response.status_code, response=response.text
            )
        )


def sign_request(message, keypair):
    message["timestamp"] = int(time.time() * 1000)
    signed_message, pub_key = crypto.sign(json.dumps(message), keypair)
    headers = {
        "Content-Type": "application/json",
        "keyn-signature": signed_message.signature.decode().rstrip("="),
    }
    params = {"m": signed_message.message.decode().rstrip("=")}
    return pub_key.decode().rstrip("="), headers, params


def get_endpoint(env):
    if env == "prod":
        return "v1"
    else:
        return env
