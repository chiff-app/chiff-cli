from math import ceil

import nacl.encoding
import nacl.secret
import nacl.signing
import nacl.utils
from nacl.hash import sha256 as nacl_sha256, blake2b
import nacl.public

SEED_SIZE = 16
PADDING_BLOCK_SIZE = 200


def generate_seed(size=SEED_SIZE):
    return nacl.utils.random(size)


def sign(message, signing_key: nacl.signing.SigningKey):
    return (
        signing_key.sign(
            message.encode("utf-8"), encoder=nacl.encoding.URLSafeBase64Encoder
        ),
        signing_key.verify_key.encode(nacl.encoding.URLSafeBase64Encoder),
    )


def verify(message64, pub_key: nacl.signing.VerifyKey):
    return pub_key.verify(
        add_padding(message64), encoder=nacl.encoding.URLSafeBase64Encoder
    )


def encrypt(message, key):
    box = nacl.secret.SecretBox(key)
    return (
        box.encrypt(pad(message), encoder=nacl.encoding.URLSafeBase64Encoder)
        .decode("utf-8")
        .rstrip("=")
    )


def decrypt(message, key):
    return unpad(
        nacl.secret.SecretBox(key).decrypt(
            add_padding(message), encoder=nacl.encoding.URLSafeBase64Encoder
        )
    )


def decrypt_anonymous(message, key: nacl.public.PrivateKey):
    box = nacl.public.SealedBox(key)
    return box.decrypt(message)


def create_signing_keypair(seed):
    return nacl.signing.SigningKey(seed)


def generate_shared_key(pub_key_64, priv_key):
    pub_key = nacl.public.PublicKey(
        nacl.encoding.URLSafeBase64Encoder.decode(add_padding(pub_key_64))
    )
    return nacl.public.Box(priv_key, pub_key).shared_key()


def generate_keypair():
    priv_key = nacl.public.PrivateKey.generate()
    return (
        priv_key,
        priv_key.public_key.encode(nacl.encoding.URLSafeBase64Encoder)
        .decode("utf-8")
        .rstrip("="),
    )


def sha256(data):
    return nacl_sha256(data, encoder=nacl.encoding.HexEncoder).decode("utf-8")


def sha256_data(data):
    return nacl_sha256(data, encoder=nacl.encoding.RawEncoder)


def generic_hash_string(string):
    return blake2b(string.encode("utf-8"), encoder=nacl.encoding.HexEncoder).decode(
        "utf-8"
    )


def add_padding(string):
    padding = 4 - (len(string) % 4)
    return string + ("=" * padding)


def to_base64(data):
    return nacl.encoding.URLSafeBase64Encoder.encode(data).decode("utf-8").rstrip("=")


def to_default_base64(data):
    return nacl.encoding.Base64Encoder.encode(data).decode("utf-8")


def from_base64(str):
    return nacl.encoding.URLSafeBase64Encoder.decode(add_padding(str))


def pad(src):
    src_len = len(src)
    block_number = ceil((src_len + 1) / PADDING_BLOCK_SIZE)
    pad_size = block_number * PADDING_BLOCK_SIZE - src_len
    return src + b"\x80" + bytes([0] * (pad_size - 1))


def unpad(encoded_bytes):
    for idx, byte in enumerate(reversed(encoded_bytes)):
        pad_size = 0
        if bytes([byte]) == b"\x80":
            pad_size = idx + 1
            break
    return encoded_bytes[:-pad_size]
