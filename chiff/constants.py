from enum import Enum

APP_NAME = "Chiff"


class MessageType(Enum):
    PAIR = 0
    LOGIN = 1
    REGISTER = 2
    CHANGE = 3
    ADD = 4
    ADD_BULK = 5
    ADD_AND_LOGIN = 6
    END = 7
    ACKNOWLEDGE = 8
    FILL = 9
    REJECT = 10
    ERROR = 11
    PREFERENCES = 12
    ADD_TO_EXISTING = 13
    DISABLED = 14
    ADMIN_LOGIN = 15
    WEBAUTHN_CREATE = 16
    WEBAUTHN_LOGIN = 17
    BULK_LOGIN = 18
    GET_DETAILS = 19
    UPDATE_ACCOUNT = 20
