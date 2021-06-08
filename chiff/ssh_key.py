from chiff.crypto import sha256_data, to_default_base64
from chiff.utils import length_and_data
from enum import Enum, unique


@unique
class KeyType(Enum):
    """A SSH key type."""

    ECDSA256 = "ecdsa-sha2-nistp256"
    ED25519 = "ssh-ed25519"

    @property
    def raw(self):
        return bytes(self.value, "utf-8")

    @property
    def curve(self):
        if self == KeyType.ECDSA256:
            return b"nistp256"


class Key(object):
    """A SSH key."""

    def __init__(self, id, pubkey, key_type, name):
        self.id = id
        self.pubkey = pubkey
        self.key_type = key_type
        self.name = name

    def ssh_identity(self):
        return length_and_data(self.__key_blob()) + length_and_data(
            bytes(self.name, "utf-8")
        )

    def encode_signature(self, signature):
        signature_data = length_and_data(self.key_type.raw)
        if self.key_type is KeyType.ECDSA256:
            r = signature[: len(signature) // 2]
            if r[0] > 127:
                # Prepend with zero if first bit is positive.
                r = length_and_data(b"\x00" + r)
            else:
                r = length_and_data(r)
            s = signature[len(signature) // 2 :]
            if s[0] > 127:
                # Prepend with zero if first bit is positive.
                s = length_and_data(b"\x00" + s)
            else:
                s = length_and_data(s)
            signature_data += length_and_data(r + s)
        else:
            signature_data += length_and_data(signature)
        return length_and_data(signature_data)

    def fingerprint(self):
        return "SHA256:{hash}".format(
            hash=to_default_base64(sha256_data(self.__key_blob())).rstrip("=")
        )

    def __key_blob(self):
        if self.key_type is KeyType.ECDSA256:
            return (
                length_and_data(KeyType.ECDSA256.raw)
                + length_and_data(KeyType.ECDSA256.curve)
                + length_and_data(self.pubkey)
            )
        elif self.key_type is KeyType.ED25519:
            return length_and_data(KeyType.ED25519.raw) + length_and_data(self.pubkey)

    def __str__(self):
        return "{type} {key} {name}".format(
            type=self.key_type.value,
            key=to_default_base64(self.__key_blob()),
            name=self.name,
        )
