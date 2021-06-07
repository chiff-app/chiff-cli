from chiff.ssh_key import Key, KeyType
from tests.test_helper import (
    ECDSA_PUB_KEY,
    PUB_KEY,
)


def test_ssh_key_identity_ed25519():
    key = Key("someid", PUB_KEY, KeyType.ED25519, "test")
    assert (
        key.ssh_identity()
        == b"\x00\x00\x003\x00\x00\x00\x0bssh-ed25519"
        + b"\x00\x00\x00 \xc1\x1f\x83\xfe\xceP\x86\x06"
        + b"\x8d\xcf\xba0\xfc\x15-B\xdc\x83\xf3D\xc0r\x0b."
        + b"\x00\x1c\xf8\x1e~l\x06\x92\x00\x00\x00\x04test"
    )


def test_ssh_key_fingerprint_ed25519():
    key = Key("someid", PUB_KEY, KeyType.ED25519, "test")
    assert key.fingerprint() == "SHA256:eTaY3BtCm51ckdLnyL9UP5uuATbD+m1qyiPjo7cNPks"


def test_ssh_key_string_ed25519():
    key = Key("someid", PUB_KEY, KeyType.ED25519, "test")
    assert (
        str(key)
        == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMEfg/7OUIYGjc+"
        + "6MPwVLULcg/NEwHILLgAc+B5+bAaS test"
    )


def test_ssh_key_identity_ecdsa():
    key = Key("someid", ECDSA_PUB_KEY, KeyType.ECDSA256, "test")
    print(key.ssh_identity())
    assert (
        key.ssh_identity()
        == b"\x00\x00\x00h\x00\x00\x00\x13ecdsa-sha2-nistp256"
        + b"\x00\x00\x00\x08nistp256\x00\x00\x00A\x04\x01\x92"
        + b"\xad\xb0\xa3\x86\x1a\x85\x1a\xe3(\x14*:\xc6\x8c3pR"
        + b"\xf8\x93k)0B\xef\xd3\x9bg\xf6bS|Lq\xe9\xee\x15Da"
        + b"\xb2f@\x97\xea\xa9\xf5\xbc7\xce]\x9f\x9bG\x87\xbe"
        + b"\r&\xf1e4\xf6\xc6\xa8\x00\x00\x00\x04test"
    )


def test_ssh_key_fingerprint_ecdsa():
    key = Key("someid", ECDSA_PUB_KEY, KeyType.ECDSA256, "test")
    assert key.fingerprint() == "SHA256:aYJv4kHn+6JhK6xk7ahSoVCn33JLgq1sEcwvG2aTpwE"


def test_ssh_key_string_ecdsa():
    key = Key("someid", ECDSA_PUB_KEY, KeyType.ECDSA256, "test")
    assert (
        str(key)
        == "ecdsa-sha2-nistp256 "
        + "AAAAE2VjZHNhLXNoYTItb"
        + "mlzdHAyNTYAAAAIbmlzdH"
        + "AyNTYAAABBBAGSrbCjhhq"
        + "FGuMoFCo6xowzcFL4k2sp"
        + "MELv05tn9mJTfExx6e4VR"
        + "GGyZkCX6qn1vDfOXZ+bR4"
        + "e+DSbxZTT2xqg= test"
    )
