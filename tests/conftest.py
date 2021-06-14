import json
import pickle
import pytest

from os import path
from requests_mock import ANY
from nacl import public, encoding

from chiff.session import Session
from chiff import crypto
from tests.test_helper import (
    ECDSA_PUB_KEY,
    PAIRING_SEED,
    PAIR_APP_PUB_KEY_B64,
    PAIR_CLI_PUB_KEY_B64,
    SHARED_KEY,
    TEST_ACCOUNT,
    api_call,
    get_sqs_message,
)


@pytest.fixture
def session():
    return Session(
        SHARED_KEY,
        "test-session-id",
        "test-user_id",
        1,
        "ios",
        "3.9.0",
        "dev",
        "test-arn",
    )


@pytest.fixture
def get_test_resource(pytestconfig, request):
    return pytestconfig.rootpath / "tests" / "resources" / request.param


@pytest.fixture(autouse=True)
def set_temp_path(mocker, tmp_path, session, requests_mock):
    """Automatically sets the home dir to temporary path with the session."""

    def print_ascii(out=None, tty=False, invert=False):
        return

    def get_tmp_path(app_name):
        d = tmp_path / app_name
        if not path.exists(d):
            d.mkdir()
        p = d / "session"
        with open(p, "wb") as f:
            pickle.dump(session, f)
        return d

    mocker.patch("click.get_app_dir", get_tmp_path)
    mocker.patch("chiff.session.randint", lambda x, y: 42)
    mocker.patch("chiff.session.QRCode.print_ascii", print_ascii)
    mocker.patch("chiff.api.get_from_sqs", api_call({"messages": []}))
    requests_mock.post(ANY, json={})
    requests_mock.delete(ANY, json={})
    requests_mock.put(ANY, json={})
    requests_mock.get(ANY, json={})


@pytest.fixture
def get_parameterized_tmp_path(request, session, tmp_path):
    def _get_path(app_name):
        d = tmp_path / app_name
        if not path.exists(d):
            d.mkdir()
        if request.param:
            p = d / "session"
            with open(p, "wb") as f:
                pickle.dump(session, f)
        return d

    return _get_path


@pytest.fixture
def get_empty_tmp_path(tmp_path):
    def _get_empty_tmp_path(app_name):
        d = tmp_path / app_name
        if not path.exists(d):
            d.mkdir()
        return d

    return _get_empty_tmp_path


@pytest.fixture
def get_pairing_from_sqs():
    pairing_keypair = crypto.create_signing_keypair(PAIRING_SEED)
    box = public.SealedBox(public.PublicKey(crypto.from_base64(PAIR_CLI_PUB_KEY_B64)))
    message = {
        "sessionID": "test-session-id",
        "version": 1,
        "pubKey": PAIR_APP_PUB_KEY_B64,
        "browserPubKey": PAIR_CLI_PUB_KEY_B64,
        "type": 0,
        "arn": "test-arn",
        "environment": "dev",
        "appVersion": "3.9.0",
        "os": "ios",
        "userID": "test-user_id",
        "accounts": {"account_id": TEST_ACCOUNT},
    }
    return get_sqs_message(
        pairing_keypair.sign(
            box.encrypt(json.dumps(message).encode("utf-8")),
            encoder=encoding.URLSafeBase64Encoder,
        )
        .decode("utf-8")
        .rstrip("=")
    )


@pytest.fixture
def get_end_session_from_sqs():
    return get_sqs_message(
        "9YJyQzUqSkvHgNPj2iY-0V9gmbPPjj-"
        "d2SbV0-ODhuwJE-tyYeGCIf-OZVUrX3tlz7KRXN"
        "5Kqaz_RYDZqeH0bDSZc24gHgPmxk3vrLfNsVGV7xw"
        "S7Rj1LZXbPN1a_hfBXZmczk5tFs2Qdplyv0VXgD0Y"
        "a4GMw9UiXdLXMYR67USxy5UMYLgFS5ks87CVBfuU7"
        "awsfK9en2C0L2bv3s1Rf521ERCNldQDrlO8uU0Oyw"
        "SgB_V1Zwfq090OYFLEPMCjpF-nR49h8AxwpuwwqBu"
        "Y6anHNC43jXwIwUT_dZiLmuA50LJoh3oLRCCXK7Ao"
        "M4XN"
    )


@pytest.fixture(params=["3.9.0", "3.9.1"])
def get_session_data(request):
    response = {
        "data": crypto.encrypt(
            json.dumps({"appVersion": request.param}).encode("utf-8"), SHARED_KEY
        ),
        "accounts": {
            "account_id": crypto.encrypt(
                json.dumps(TEST_ACCOUNT).encode("utf-8"),
                SHARED_KEY,
            ),
            "identity_id": crypto.encrypt(
                json.dumps(
                    {
                        "id": "identity_id",
                        "pubKey": crypto.to_base64(ECDSA_PUB_KEY),
                        "name": "test-identity",
                        "algorithm": "ecdsa-sha2-nistp256",
                        "type": "ssh",
                    }
                ).encode("utf-8"),
                SHARED_KEY,
            ),
        },
    }
    return api_call(response)
