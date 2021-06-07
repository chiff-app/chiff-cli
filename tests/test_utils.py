from chiff.utils import check_response, length_and_data
from chiff.constants import MessageType


def test_check_response_reject_false():
    response = {"t": MessageType.REJECT.value}
    assert not check_response(response)


def test_check_response_error_false():
    response = {"t": MessageType.ERROR.value}
    assert not check_response(response)


def test_check_response_error_false_with_error():
    response = {"t": MessageType.ERROR.value, "e": "Something bad.."}
    assert not check_response(response)


def test_check_response_true():
    response = {"t": MessageType.LOGIN.value}
    assert check_response(response)


def test_length_and_data():
    data = b"\xde\xad\xbe\xef"
    result = length_and_data(data)
    assert result == b"\x00\x00\x00\x04\xde\xad\xbe\xef"
