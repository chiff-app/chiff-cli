from chiff.ssh_key import Key, KeyType
from tests.test_helper import (
    ECDSA_PUB_KEY,
    ECDSA_SIGNATURE,
    ECDSA_SIGNATURE_NEG,
    ED25519_SIGNATURE,
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


def test_encode_ed25519_signature():
    key = Key("someid", PUB_KEY, KeyType.ED25519, "test")
    print(key.encode_signature(ED25519_SIGNATURE))
    assert (
        key.encode_signature(ED25519_SIGNATURE)
        == b"\x00\x00\x00S\x00\x00\x00\x0bssh-ed25519"
        + b"\x00\x00\x00@\xec\x10@)\xe5\xc4\xb9[\xacts\x1f"
        + b"\xc2\x9b9\xd1\x8eA ,W\xbf\x13\xc9\x14\xa2\x9c"
        + b"\xdb}e'\x0e\x8c\xcfr\xa2\x9d}\x12\xa3\r\xd3\xf6"
        + b"Hl$\x7f@\xf2\x12\xe8O\x89\xe4F9\x93\xdfw+btM\x06"
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


def test_encode_ecdsa_signature():
    key = Key("someid", ECDSA_PUB_KEY, KeyType.ECDSA256, "test")
    assert (
        key.encode_signature(ECDSA_SIGNATURE)
        == b"\x00\x00\x00e\x00\x00\x00\x13ecdsa-sha2-nistp256\x00"
        + b"\x00\x00J\x00\x00\x00!\x00\xe1\x1f\x08\x90\xda\xca\xb7"
        + b"\x9a\xe2\xee\xaaa<\x91c)\xa8K\x0e&m\xcc\xdd\x137\x80q"
        + b"\xa7P\xd7\xd8\xd0\x00\x00\x00!\x00\xc2\x9a\xbfSN\x99F'"
        + b"\xe4\xe7\xb0Y\x07x\xe5z\xfa\xf3>\xcf\x1e\xcbr\xf2\xac"
        + b"\x85\xed\xec0\x9c\xaf\xfe"
    )


def test_encode_ecdsa_signature_negative():
    key = Key("someid", ECDSA_PUB_KEY, KeyType.ECDSA256, "test")
    assert (
        key.encode_signature(ECDSA_SIGNATURE_NEG)
        == b"\x00\x00\x00c\x00\x00\x00\x13ecdsa-sha2-nistp256\x00"
        + b"\x00\x00H\x00\x00\x00 &t+>\xb6\xc6\xe6\xf2\x1b\x04s9."
        + b"\x08\xb5t\x92\xe4\xa8$\xb7Ry\\3O;zaB\xfd)\x00\x00\x00"
        + b" m\xda\xf5\xb9\x1f\x90\xb6\x1bTE\x99%&\x1fw\xe3\xc2,-4"
        + b"\xdb\x87\xa1\x98\xbd\xb8S\xa3\xd5\x12Ek"
    )
