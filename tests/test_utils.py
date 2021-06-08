from tests.test_helper import SSH_SIGNING_REQUEST
from chiff.utils import check_response, length_and_data, ssh_reader
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


def test_ssh_reader():
    hash_data, challenge, flags = ssh_reader(SSH_SIGNING_REQUEST)
    hash_reader = ssh_reader(hash_data)
    assert next(hash_reader) == b"ecdsa-sha2-nistp256"
    assert next(hash_reader) == b"nistp256"
    assert next(hash_reader) == (
        b"\x04(\xb7\x9fI\xee\x81~\x83\xe5g\xd0"
        b"\xff\n\xe0\xcf&w\xd6\xc7\x17 \xf9\x98\xad.>/S"
        b"\x15\xdb\x8d;\x18\n\x85k\x19\xa6gE\x98^b*Y\x9ch#"
        b"\xaddO`\x9d>\x02\x02\xd0\xa4\x8b\x87\x95\x12{\xed"
    )
