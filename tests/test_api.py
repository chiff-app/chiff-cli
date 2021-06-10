import pytest
from chiff import api
from chiff.api import (
    create_pairing_queue,
    delete_from_volatile_queue,
    delete_queues,
    delete_pairing_queue,
    get_from_sqs,
    get_session_data,
    send_bulk_accounts,
    send_to_sns,
)
from contextlib import ExitStack as does_not_raise
from tests.test_helper import (
    PAIRING_SEED,
    SEED,
)
from chiff import crypto
from requests_mock import ANY


@pytest.mark.parametrize(
    "status_code, expected",
    [
        (200, does_not_raise()),
        (200, does_not_raise()),
        (500, pytest.raises(Exception)),
    ],
)
def test_create_pairing_queue(requests_mock, status_code, expected):
    requests_mock.post(ANY, json={}, status_code=status_code)
    keypair = crypto.create_signing_keypair(PAIRING_SEED)
    with expected:
        assert create_pairing_queue(keypair) == {}


@pytest.mark.parametrize(
    "status_code, expected",
    [
        (200, does_not_raise()),
        (200, does_not_raise()),
        (500, pytest.raises(Exception)),
    ],
)
def test_delete_pairing_queue(requests_mock, status_code, expected):
    requests_mock.delete(ANY, json={}, status_code=status_code)
    keypair = crypto.create_signing_keypair(PAIRING_SEED)
    with expected:
        assert delete_pairing_queue(keypair) == {}


@pytest.mark.parametrize(
    "status_code, expected, env",
    [
        (200, does_not_raise(), "dev"),
        (200, does_not_raise(), "prod"),
        (500, pytest.raises(Exception), "dev"),
    ],
)
def test_delete_queues(requests_mock, status_code, expected, env):
    requests_mock.delete(ANY, json={}, status_code=status_code)
    keypair = crypto.create_signing_keypair(SEED + SEED)
    with expected:
        assert delete_queues(keypair, env) == {}


@pytest.mark.parametrize(
    "status_code, expected, env",
    [
        (200, does_not_raise(), "dev"),
        (200, does_not_raise(), "prod"),
        (500, pytest.raises(Exception), "dev"),
    ],
)
def test_get_session_data(requests_mock, status_code, expected, env):
    requests_mock.get(ANY, json={}, status_code=status_code)
    keypair = crypto.create_signing_keypair(SEED + SEED)
    with expected:
        assert get_session_data(keypair, env) == {}


@pytest.mark.parametrize(
    "status_code, expected, env",
    [
        (200, does_not_raise(), "dev"),
        (200, does_not_raise(), "prod"),
        (500, pytest.raises(Exception), "dev"),
    ],
)
def test_get_from_sqs(requests_mock, status_code, expected, env):
    requests_mock.get(ANY, json={}, status_code=status_code)
    keypair = crypto.create_signing_keypair(SEED + SEED)
    url = "{host}/{env}/sessions/{pub_key}/{endpoint}".format(
        host="https://api.chiff.dev",
        env=api.get_endpoint(env),
        pub_key=crypto.to_base64(keypair.verify_key.__bytes__()),
        endpoint="volatile",
    )
    with expected:
        assert get_from_sqs(keypair, url, 0) == {}


@pytest.mark.parametrize(
    "status_code, expected, env",
    [
        (200, does_not_raise(), "dev"),
        (200, does_not_raise(), "prod"),
        (500, pytest.raises(Exception), "dev"),
    ],
)
def test_send_to_sns(requests_mock, status_code, expected, env):
    requests_mock.put(ANY, json={}, status_code=status_code)
    keypair = crypto.create_signing_keypair(SEED + SEED)
    with expected:
        assert send_to_sns(keypair, "todo", "arn", env) == {}


@pytest.mark.parametrize(
    "status_code, expected, env",
    [
        (200, does_not_raise(), "dev"),
        (200, does_not_raise(), "prod"),
        (500, pytest.raises(Exception), "dev"),
    ],
)
def test_delete_from_volatile_queue(requests_mock, status_code, expected, env):
    requests_mock.delete(ANY, json={}, status_code=status_code)
    keypair = crypto.create_signing_keypair(SEED + SEED)
    with expected:
        assert delete_from_volatile_queue(keypair, "bonnie", env) == {}


@pytest.mark.parametrize(
    "status_code, expected, env",
    [
        (200, does_not_raise(), "dev"),
        (200, does_not_raise(), "prod"),
        (500, pytest.raises(Exception), "dev"),
    ],
)
def test_send_bulk_accounts(requests_mock, status_code, expected, env):
    requests_mock.put(ANY, json={}, status_code=status_code)
    keypair = crypto.create_signing_keypair(SEED + SEED)
    with expected:
        assert send_bulk_accounts("data", keypair, env) == {}
