from tests.test_helper import (
    BASE64_PUB_KEY,
    DEFAULT_BASE64_PUB_KEY,
    PUB_KEY,
    SEED,
    SHARED_KEY,
)
from chiff import crypto
from nacl import signing, encoding, public


def test_test_generate_seed():
    seed = crypto.generate_seed()
    assert len(seed) == 16


def test_test_generate_seed_custom_size():
    size = 32
    seed = crypto.generate_seed(size)
    assert len(seed) == size


def test_sign():
    signing_key = signing.SigningKey(SEED + SEED)
    message = "Hello!"
    signed_message, pub_key = crypto.sign(message, signing_key)
    assert pub_key == signing_key.verify_key.encode(
        encoder=encoding.URLSafeBase64Encoder
    )
    assert signing_key.verify_key.verify(
        signed_message, encoder=encoding.URLSafeBase64Encoder
    )


def test_verify():
    signing_key = signing.SigningKey(SEED + SEED)
    message = "Hello!"
    signed_message = (
        (
            signing_key.sign(
                message.encode("utf-8"), encoder=encoding.URLSafeBase64Encoder
            )
        )
        .decode("utf-8")
        .rstrip("=")
    )
    assert (
        crypto.verify(signed_message, signing_key.verify_key).decode("utf-8") == message
    )


def test_encrypt_and_decrypt():
    message = b"Hello!"
    key = SEED + SEED
    encrypted = crypto.encrypt(message, key)
    assert crypto.decrypt(encrypted, key) == message


def test_decrypt_anonymous():
    message = b"Hello!Hello!Hello!Hello!Hello!Hello!Helloasoudhasoudhaoishdaosidhj"
    key = public.PrivateKey(SEED + SEED)
    box = public.SealedBox(key.public_key)
    ciphertext = box.encrypt(message)
    return crypto.decrypt_anonymous(ciphertext, key) == message


def test_create_signing_keypair():
    key_pair = crypto.create_signing_keypair(SEED + SEED)
    assert key_pair.verify_key.encode() == PUB_KEY


def test_generate_shared_key():
    priv_key = public.PrivateKey(SEED + SEED)
    shared_key = crypto.generate_shared_key(BASE64_PUB_KEY, priv_key)
    assert shared_key == SHARED_KEY


def test_generate_keypair():
    priv_key, pub_key = crypto.generate_keypair()
    assert pub_key == priv_key.public_key.encode(
        encoder=encoding.URLSafeBase64Encoder
    ).decode("utf-8").rstrip("=")


def test_sha256():
    assert (
        crypto.sha256(b"Hello!")
        == "334d016f755cd6dc58c53a86e183882f8ec14f52fb05345887c8a5edd42c87b7"
    )


def test_sha256_data():
    assert (
        crypto.sha256_data(b"Hello!")
        == b"3M\x01ou\\\xd6\xdcX\xc5:\x86\xe1\x83\x88/\x8e\xc1OR\xfb"
        + b"\x054X\x87\xc8\xa5\xed\xd4,\x87\xb7"
    )


def test_generic_hash_string():
    assert (
        crypto.generic_hash_string("Hello!")
        == "8c722f76c12a9585d1bd96b4919d376d9c02a22488590b8ecca68426bac82c4b"
    )


def test_to_base64():
    assert crypto.to_base64(PUB_KEY) == BASE64_PUB_KEY


def test_to_default_base64():
    assert crypto.to_default_base64(PUB_KEY) == DEFAULT_BASE64_PUB_KEY


def test_from_base64():
    assert crypto.from_base64(BASE64_PUB_KEY) == PUB_KEY
