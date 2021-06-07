from chiff.queue_handler import QueueHandler
from tests.test_helper import (
    SEED,
)
from chiff import crypto


def test_queue_handler_start_empty(mocker):
    def mock_get_from_sqs(keypair, url, wait_time):
        return {"messages": []}

    mocker.patch("chiff.api.get_from_sqs", mock_get_from_sqs)
    # mocker.return_value = {"messages": ["1", "2"]}
    signing_keypair = crypto.create_signing_keypair(SEED + SEED)
    handler = QueueHandler(signing_keypair, "dev", "volatile")
    messages = handler.start(False)
    assert len(messages) == 0


def test_queue_handler_start_return(mocker):
    def mock_get_from_sqs(keypair, url, wait_time):
        return {"messages": ["dummy-message"]}

    mocker.patch("chiff.api.get_from_sqs", mock_get_from_sqs)
    # mocker.return_value = {"messages": ["1", "2"]}
    signing_keypair = crypto.create_signing_keypair(SEED + SEED)
    handler = QueueHandler(signing_keypair, "dev", "volatile")
    messages = handler.start(True)
    assert len(messages) == 1


def test_queue_handler_start_return_second_time(mocker):
    second = False

    def mock_get_from_sqs(keypair, url, wait_time):
        nonlocal second
        if second:
            return {"messages": ["dummy-message"]}
        else:
            second = True
            return {"messages": []}

    mocker.patch("chiff.api.get_from_sqs", mock_get_from_sqs)
    # mocker.return_value = {"messages": ["1", "2"]}
    signing_keypair = crypto.create_signing_keypair(SEED + SEED)
    handler = QueueHandler(signing_keypair, "dev", "volatile")
    messages = handler.start(True)
    assert len(messages) == 1
