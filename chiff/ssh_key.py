from chiff.crypto import to_default_base64
from chiff.utils import length_and_data
from enum import Enum, unique


@unique
class KeyType(Enum):
    ECDSA256 = "ecdsa-sha2-nistp256"
    ED25519 = "ssh-ed25519"

    @property
    def raw(self):
        return bytes(self.value, "utf-8")

    @property
    def curve(self):
        if self == KeyType.ECDSA256:
            return b"nistp256"
        else:
            return None


class Key(object):
    def __init__(self, id, pubkey, key_type, name):
        self.id = id
        self.pubkey = pubkey
        self.key_type = key_type
        self.name = name

    def ssh_identity(self):
        return length_and_data(self.key_blob()) + length_and_data(
            bytes(self.name, "utf-8")
        )

    def encode_signature(self, signature):
        signature_data = length_and_data(self.key_type.raw)
        if self.key_type is KeyType.ECDSA256:
            r = length_and_data(signature[: len(signature) // 2])
            s = length_and_data(signature[len(signature) // 2 :])
            signature_data += length_and_data(r + s)
        else:
            signature_data += length_and_data(signature)
        return length_and_data(signature_data)

    def key_blob(self):
        if self.key_type is KeyType.ECDSA256:
            return (
                length_and_data(KeyType.ECDSA256.raw)
                + length_and_data(KeyType.ECDSA256.curve)
                + length_and_data(self.pubkey)
            )
        elif self.key_type is KeyType.ED25519:
            return length_and_data(KeyType.ED25519.raw) + length_and_data(self.pubkey)

    def __str__(self):
        return "%s %s %s" % (
            self.key_type.value,
            to_default_base64(self.key_blob()),
            self.name,
        )
