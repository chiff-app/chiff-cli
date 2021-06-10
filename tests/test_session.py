from tests.test_helper import (
    ECDSA_PUB_KEY,
    PAIRING_SEED,
    PAIR_CLI_PRIV_KEY,
    PAIR_CLI_PUB_KEY_B64,
    SHARED_KEY,
    get_sqs_message,
)
from chiff.constants import MessageType

from chiff.ssh_key import KeyType
from nacl import public

import json

from chiff import crypto
from chiff.session import Session


def test_get_session(session):
    assert Session.get().id == session.id


def test_pair(mocker, get_pairing_from_sqs, get_empty_tmp_path):
    mocker.patch(
        "chiff.crypto.generate_keypair",
        lambda: (public.PrivateKey(PAIR_CLI_PRIV_KEY), PAIR_CLI_PUB_KEY_B64),
    )
    mocker.patch("chiff.crypto.generate_seed", lambda n: PAIRING_SEED)
    mocker.patch("click.get_app_dir", get_empty_tmp_path)
    mocker.patch("chiff.api.get_from_sqs", get_pairing_from_sqs)
    session, accounts = Session.pair()
    assert session.id == "test-session-id"
    assert accounts["account_id"]["id"] == "account_id"


def test_end_session(mocker, session):
    session.end()


def test_get_accounts(mocker, session, get_session_data):
    mocker.patch("chiff.api.get_session_data", get_session_data)
    accounts = session.get_accounts()
    assert len(accounts) == 1
    assert accounts["account_id"]["username"] == "test-username"


def test_ssh_identities(mocker, session, get_session_data):
    mocker.patch("chiff.api.get_session_data", get_session_data)
    identities = session.get_ssh_identities()
    assert len(identities) == 1
    assert identities[0].id == "identity_id"


def test_get_ssh_identity(mocker, session, get_session_data):
    mocker.patch("chiff.api.get_session_data", get_session_data)
    identity = session.get_ssh_identity(ECDSA_PUB_KEY, KeyType.ECDSA256)
    assert identity.id == "identity_id"


def test_session_pairing_status(session):
    assert session.pairing_status()


def test_send_request(mocker, session):
    response = {"b": 42, "p": "p@ssword"}
    mocker.patch(
        "chiff.api.get_from_sqs",
        get_sqs_message(
            crypto.encrypt(json.dumps(response).encode("utf-8"), SHARED_KEY)
        ),
    )
    request = {"a": "account_id", "r": MessageType.GET_DETAILS.value, "n": "Unknown"}
    message = session.send_request(request)
    assert message["p"] == "p@ssword"


def test_send_bulk_accounts(mocker, session):
    response = {"b": 42, "r": MessageType.ADD_BULK.value}
    mocker.patch(
        "chiff.api.get_from_sqs",
        get_sqs_message(
            crypto.encrypt(json.dumps(response).encode("utf-8"), SHARED_KEY)
        ),
    )
    message = session.send_bulk_accounts(
        [
            {
                "u": "username",
                "p": "password",
                "n": "site_name",
                "s": "site_id",
                "l": "url",
                "y": "notes",
            }
        ]
    )
    assert message["r"] == MessageType.ADD_BULK.value


def test_session_pairing_status_ended(mocker, session, get_end_session_from_sqs):
    mocker.patch("chiff.api.get_from_sqs", get_end_session_from_sqs)
    assert not session.pairing_status()
