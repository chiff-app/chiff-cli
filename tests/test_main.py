from click.testing import CliRunner
from chiff.main import main
from nacl import public
from tests.test_helper import (
    PAIRING_SEED,
    PAIR_CLI_PRIV_KEY,
    PAIR_CLI_PUB_KEY_B64,
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
    get_nothing_from_sqs,
    get_session_data,
    expected,
):
    mocker.patch("chiff.api.get_from_sqs", get_nothing_from_sqs)
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
    empty_api_call,
    test_input,
    expected,
):
    def print_ascii(out=None, tty=False, invert=False):
        return

    mocker.patch(
        "chiff.crypto.generate_keypair",
        lambda: (public.PrivateKey(PAIR_CLI_PRIV_KEY), PAIR_CLI_PUB_KEY_B64),
    )
    mocker.patch("click.get_app_dir", get_parameterized_tmp_path)
    mocker.patch("chiff.crypto.generate_seed", lambda n: PAIRING_SEED)
    mocker.patch("chiff.session.QRCode.print_ascii", print_ascii)
    mocker.patch("chiff.api.get_from_sqs", get_pairing_from_sqs)
    mocker.patch("chiff.session.Session.pairing_status", lambda x: True)
    mocker.patch("chiff.api.send_to_sns", empty_api_call)  # For ending the session
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
    get_nothing_from_sqs,
    empty_api_call,
    test_input,
    expected,
):
    mocker.patch("click.get_app_dir", get_parameterized_tmp_path)
    mocker.patch("chiff.api.get_from_sqs", get_nothing_from_sqs)
    mocker.patch("chiff.api.send_to_sns", empty_api_call)  # For ending the session
    runner = CliRunner()
    result = runner.invoke(main, ["unpair"], input=test_input)
    assert not result.exception
    assert expected in result.output
