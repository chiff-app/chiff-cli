from chiff.constants import MessageType
from contextlib import ExitStack as does_not_raise
import json
from chiff import crypto
from click.testing import CliRunner
from chiff.main import main
from nacl import public
from tests.test_helper import (
    BASE64_ECDSA_PUB_KEY,
    BASE64_PUB_KEY,
    PAIRING_SEED,
    PAIR_CLI_PRIV_KEY,
    PAIR_CLI_PUB_KEY_B64,
    SHARED_KEY,
    get_sqs_message,
)
import pytest
from pytest_mock import MockerFixture


def test_main():
    runner = CliRunner()
    result = runner.invoke(main)
    assert result.exit_code == 0


@pytest.mark.parametrize(
    "get_parameterized_tmp_path, expected",
    [
        (True, "There is an active session with id test-session-id."),
        (False, "There is no active session."),
    ],
    indirect=["get_parameterized_tmp_path"],
)
def test_status(
    mocker: MockerFixture,
    get_parameterized_tmp_path,
    get_session_data,
    expected,
):
    mocker.patch("chiff.session.Session.pairing_status", lambda x: True)
    mocker.patch("click.get_app_dir", get_parameterized_tmp_path)
    mocker.patch("chiff.api.get_session_data", get_session_data)
    runner = CliRunner()
    result = runner.invoke(main, ["status"])
    assert not result.exception
    assert expected in result.output


@pytest.mark.parametrize(
    "get_parameterized_tmp_path, test_input, expected",
    [
        (True, "y\n", "New session successfully created!"),
        (True, "n\n", "Exiting..."),
        (False, None, "Session successfully created!"),
    ],
    indirect=["get_parameterized_tmp_path"],
)
def test_pair_session(
    mocker,
    get_parameterized_tmp_path,
    get_pairing_from_sqs,
    test_input,
    expected,
):
    mocker.patch(
        "chiff.crypto.generate_keypair",
        lambda: (public.PrivateKey(PAIR_CLI_PRIV_KEY), PAIR_CLI_PUB_KEY_B64),
    )
    mocker.patch("click.get_app_dir", get_parameterized_tmp_path)
    mocker.patch("chiff.crypto.generate_seed", lambda n: PAIRING_SEED)
    mocker.patch("chiff.api.get_from_sqs", get_pairing_from_sqs)
    mocker.patch("chiff.session.Session.pairing_status", lambda x: True)
    runner = CliRunner()
    result = runner.invoke(main, ["pair"], input=test_input)
    assert not result.exception
    assert expected in result.output


@pytest.mark.parametrize(
    "get_parameterized_tmp_path, test_input, expected",
    [
        (True, "y\n", "Are you sure you want to end the current session?"),
        (True, "n\n", "Exiting..."),
        (False, None, "There currently does not seem to be an active session."),
    ],
    indirect=["get_parameterized_tmp_path"],
)
def test_unpair_session(
    mocker,
    get_parameterized_tmp_path,
    test_input,
    expected,
):
    mocker.patch("click.get_app_dir", get_parameterized_tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["unpair"], input=test_input)
    assert not result.exception
    assert expected in result.output


@pytest.mark.parametrize(
    "test_input, response, expected, raises",
    [
        (
            ["get", "-i", "account_id"],
            {"p": "p@ssword", "b": 42, "t": MessageType.GET_DETAILS.value},
            "p@ssword",
            does_not_raise(),
        ),
        (
            ["get", "-i", "account_id", "-s"],
            {"p": "p@ssword", "b": 42, "t": MessageType.GET_DETAILS.value},
            "p@ssword",
            does_not_raise(),
        ),
        (
            ["get", "-i", "account_id", "-n"],
            {"y": "important note", "b": 42, "t": MessageType.GET_DETAILS.value},
            "important note",
            does_not_raise(),
        ),
        (
            ["get", "-i", "account_id", "-j"],
            {
                "p": "p@ssword",
                "y": "important note",
                "b": 42,
                "t": MessageType.GET_DETAILS.value,
            },
            '{"username": "test-username", "password": '
            + '"p@ssword", "notes": "important note"}',
            does_not_raise(),
        ),
        (
            ["get", "-i", "account_id"],
            {"b": 42, "t": MessageType.GET_DETAILS.value},
            "p@ssword",
            pytest.raises(Exception),
        ),
        (
            ["get", "-i", "account_id", "-n"],
            {"b": 42, "t": MessageType.GET_DETAILS.value},
            "important note",
            pytest.raises(Exception),
        ),
        (
            ["get", "-i", "account_id"],
            {"b": 42, "t": MessageType.REJECT.value},
            "",
            does_not_raise(),
        ),
    ],
)
def test_get_account(
    mocker,
    test_input,
    expected,
    get_session_data,
    response,
    raises,
):
    mocker.patch("chiff.session.Session.pairing_status", lambda x: True)
    mocker.patch("chiff.api.get_session_data", get_session_data)
    mocker.patch(
        "chiff.api.get_from_sqs",
        get_sqs_message(
            crypto.encrypt(json.dumps(response).encode("utf-8"), SHARED_KEY)
        ),
    )
    runner = CliRunner()
    with raises:
        result = runner.invoke(main, test_input)
        assert expected in result.output


@pytest.mark.parametrize(
    "test_input, prompted_input, expected",
    [
        (
            ["https://example.com", "-p", "p@ssword"],
            None,
            "Account created with id "
            + "77f5e71a91c7633f405ff1c69a9c4df452d5b75d75d410dc8b9faeba64a0a24e",
        ),
        (
            ["https://anotherexample.com", "-p", "p@ssword"],
            None,
            "Account created with id "
            + "ced42804f6a8021b8aa4c137c03ea91ad894424a86f65263b10ca04581575e8e",
        ),
        (
            ["https://example.com"],
            "p@ssword\np@ssword\n",
            "Account created with id "
            + "77f5e71a91c7633f405ff1c69a9c4df452d5b75d75d410dc8b9faeba64a0a24e",
        ),
        (
            ["https://example.com", "-n", "important note"],
            "p@ssword\np@ssword\n",
            "Account created with id "
            + "77f5e71a91c7633f405ff1c69a9c4df452d5b75d75d410dc8b9faeba64a0a24e",
        ),
    ],
)
def test_add_account(
    mocker,
    test_input,
    prompted_input,
    expected,
    get_session_data,
):
    mocker.patch("chiff.session.Session.pairing_status", lambda x: True)
    mocker.patch("chiff.api.get_session_data", get_session_data)
    mocker.patch(
        "chiff.api.get_from_sqs",
        get_sqs_message(
            crypto.encrypt(
                json.dumps({"b": 42, "t": MessageType.ADD.value}).encode("utf-8"),
                SHARED_KEY,
            )
        ),
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "add",
            "-u",
            "username",
            "-s",
            "example-site",
            "-l",
        ]
        + test_input,
        input=prompted_input,
    )
    assert expected in result.output


@pytest.mark.parametrize(
    "test_input, prompted_input, expected",
    [
        (["-i", "account_id", "-u", "new_username"], None, does_not_raise()),
        (["-i", "account_id", "-n", '"important note"'], None, does_not_raise()),
        (["-i", "account_id", "-l", "https://newurl.com"], None, does_not_raise()),
        (["-i", "account_id", "-s", "new name"], None, does_not_raise()),
        (["-i", "account_id", "-p", "newp@ssword"], None, does_not_raise()),
        (["-i", "account_id", "-p"], "newp@ssword\nnewp@ssword\n", does_not_raise()),
        (
            ["-i", "unknown_account_id", "-u", "new_username"],
            None,
            pytest.raises(Exception),
        ),
    ],
)
def test_update_account(
    mocker,
    test_input,
    prompted_input,
    expected,
    get_session_data,
):
    mocker.patch("chiff.session.Session.pairing_status", lambda x: True)
    mocker.patch("chiff.api.get_session_data", get_session_data)
    mocker.patch(
        "chiff.api.get_from_sqs",
        get_sqs_message(
            crypto.encrypt(
                json.dumps({"b": 42, "t": MessageType.UPDATE_ACCOUNT.value}).encode(
                    "utf-8"
                ),
                SHARED_KEY,
            )
        ),
    )
    runner = CliRunner()
    with expected:
        result = runner.invoke(
            main,
            [
                "update",
            ]
            + test_input,
            input=prompted_input,
        )
        assert "Account successfully updated." in result.output


@pytest.mark.parametrize(
    "test_input, get_test_resource, prompted_input, expected",
    [
        (
            ["csv"],
            "test.csv",
            None,
            "Sending 3 accounts to phone...",
        ),
        (
            ["csv", "-s"],
            "test.csv",
            None,
            "Sending 2 accounts to phone...",
        ),
        (
            ["json"],
            "test.json",
            None,
            "Sending 2 accounts to phone...",
        ),
        (
            ["kdbx"],
            "test.kdbx",
            "p@ssword\n",
            "Sending 2 accounts to phone...",
        ),
        (
            ["kdbx"],
            "test.kdbx",
            "wrongp@ssword\n",
            "The keepass password appears to be incorrect. Exiting",
        ),
    ],
    indirect=["get_test_resource"],
)
def test_imports_accounts(
    mocker,
    test_input,
    get_test_resource,
    prompted_input,
    expected,
    get_session_data,
):
    mocker.patch("chiff.session.Session.pairing_status", lambda x: True)
    mocker.patch("chiff.api.get_session_data", get_session_data)
    mocker.patch(
        "chiff.api.get_from_sqs",
        get_sqs_message(
            crypto.encrypt(
                json.dumps({"b": 42, "t": MessageType.ADD_BULK.value}).encode("utf-8"),
                SHARED_KEY,
            )
        ),
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["import", "-f", *test_input, "-p", get_test_resource],
        input=prompted_input,
    )
    if "incorrect" not in expected:
        assert not result.exception
    assert expected in result.output


@pytest.mark.parametrize(
    "test_input, expected, pub_key",
    [
        (
            ["Test"],
            "SSH key created:\nssh-ed25519 "
            + "AAAAC3NzaC1lZDI1NTE5AAAAIMEfg"
            + "/7OUIYGjc+6MPwVLULcg/NEwHILL"
            + "gAc+B5+bAaS Test",
            BASE64_PUB_KEY,
        ),
        (
            ["Test", "-e"],
            "SSH key created:\necdsa-sha2-nistp256 "
            + "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIb"
            + "mlzdHAyNTYAAABBBAGSrbCjhhqFGuMoFCo6x"
            + "owzcFL4k2spMELv05tn9mJTfExx6e4VRGGyZ"
            + "kCX6qn1vDfOXZ+bR4e+DSbxZTT2xqg= Test",
            BASE64_ECDSA_PUB_KEY,
        ),
    ],
)
def test_ssh_keygen(
    mocker,
    test_input,
    expected,
    pub_key,
    get_session_data,
):
    mocker.patch("chiff.session.Session.pairing_status", lambda x: True)
    mocker.patch("chiff.api.get_session_data", get_session_data)
    mocker.patch(
        "chiff.api.get_from_sqs",
        get_sqs_message(
            crypto.encrypt(
                json.dumps(
                    {
                        "a": "identity_id",
                        "b": 42,
                        "t": MessageType.SSH_CREATE.value,
                        "pk": pub_key,
                    }
                ).encode("utf-8"),
                SHARED_KEY,
            )
        ),
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["ssh-keygen", "-n"] + test_input,
    )
    assert not result.exception
    assert expected in result.output
