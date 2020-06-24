import secrets
from functools import reduce
from urllib.parse import urlparse
from math import ceil

import nacl.encoding
import nacl.secret
import nacl.signing
import nacl.utils
import tldextract
from nacl.hash import sha256, blake2b
import nacl.public

try:
    import importlib.resources as pkg_resources
except ImportError:
    import importlib_resources as pkg_resources
    # Try backported to PY<37 `importlib_resources`.


SEED_SIZE = 16
PADDING_BLOCK_SIZE = 200
SEED_CONTEXT = "keynseed"
BACKUP_CONTEXT = "keynback"
PASSWORD_CONTEXT = "keynpass"
TEAM_CONTEXT = "teamseed"
PASSWORD_KEY_INDEX = 0
BACKUP_KEY_INDEX = 1
WORD_LIST = pkg_resources.read_text('keyn', "wordlist.txt")


def random_example_seed():
    words = WORD_LIST.splitlines()
    return tuple(map(
        lambda i: words[i], [secrets.randbelow(2048) for _ in range(1, 13)]))


def generate_seed(size=SEED_SIZE):
    return nacl.utils.random(size)


def mnemonic(seed):
    hash = sha256(seed, encoder=nacl.encoding.RawEncoder)
    bitstring = reduce((lambda x, y: x + y), map(
        lambda x: bin(x)[2:].zfill(8), seed))
    bitstring += bin(hash[0])[2:].zfill(8)[:4]
    indices = map(
        lambda x: int(x, 2),
        [bitstring[start:start+11] for start in range(0, len(bitstring), 11)])
    words = WORD_LIST.splitlines()
    return map(
        lambda i: words[i], indices)


def recover(mnemonic):
    words = WORD_LIST.splitlines()
    bitstring = reduce(
        (lambda x, y: x + y),
        map(lambda x: bin(words.index(x.strip()))[2:].zfill(11), mnemonic))
    checksum = bitstring[-4:]
    bitstring = bitstring[:-4]
    seed = bytes(map(
        lambda x: int(x, 2),
        [bitstring[start:start + 8] for start in range(0, len(bitstring), 8)]))
    hash = bin(sha256(seed,
                      encoder=nacl.encoding.RawEncoder)[0])[2:].zfill(8)[:4]
    if hash == checksum:
        return seed
    else:
        raise Exception("Invalid mnemonic")


def derive_keys_from_seed(seed):
    seed_hash = generic_hash(seed)
    password_key = kdf_derive_from_key(seed,
                                       PASSWORD_KEY_INDEX,
                                       SEED_CONTEXT)
    backup_key = kdf_derive_from_key(seed_hash,
                                     BACKUP_KEY_INDEX,
                                     SEED_CONTEXT)
    return password_key,\
        nacl.signing.SigningKey(backup_key), \
        nacl.secret.SecretBox(kdf_derive_from_key(backup_key,
                                                  0,
                                                  BACKUP_CONTEXT))


def derive_keys_from_team_seed(seed):
    password_key = kdf_derive_from_key(seed,
                                       PASSWORD_KEY_INDEX,
                                       TEAM_CONTEXT)
    backup_key = kdf_derive_from_key(seed,
                                     BACKUP_KEY_INDEX,
                                     TEAM_CONTEXT)

    return password_key,\
        nacl.signing.SigningKey(backup_key), \
        nacl.secret.SecretBox(kdf_derive_from_key(backup_key,
                                                  0,
                                                  TEAM_CONTEXT))


def sign(message, signing_key: nacl.signing.SigningKey):
    return signing_key.sign(message.encode("utf-8"),
                            encoder=nacl.encoding.URLSafeBase64Encoder), \
           signing_key.verify_key.encode(nacl.encoding.URLSafeBase64Encoder)


def verify(message64, pub_key: nacl.signing.VerifyKey):
    return pub_key.verify(add_padding(message64), encoder=nacl.encoding.URLSafeBase64Encoder)


def encrypt_symmetric(message, key: nacl.secret.SecretBox):
    return key.encrypt(message,
                       encoder=nacl.encoding.URLSafeBase64Encoder).decode("utf-8").rstrip("=")


def decrypt_symmetric(message, key: nacl.secret.SecretBox):
    return key.decrypt(add_padding(message),
                       encoder=nacl.encoding.URLSafeBase64Encoder)


def encrypt(message, key):
    box = nacl.secret.SecretBox(key)
    return box.encrypt(pad(message), encoder=nacl.encoding.URLSafeBase64Encoder).decode("utf-8").rstrip("=")


def decrypt(message, key):
    return unpad(nacl.secret.SecretBox(key).decrypt(add_padding(message), encoder=nacl.encoding.URLSafeBase64Encoder))


def decrypt_anonymous(message, key: nacl.public.PrivateKey):
    box = nacl.public.SealedBox(key)
    return box.decrypt(message)


def create_signing_keypair(seed):
    return nacl.signing.SigningKey(seed)


def generate_shared_key(pub_key_64, priv_key):
    pub_key = nacl.public.PublicKey(nacl.encoding.URLSafeBase64Encoder.decode(add_padding(pub_key_64)))
    return nacl.public.Box(priv_key, pub_key).shared_key()


def generate_keypair():
    priv_key = nacl.public.PrivateKey.generate()
    return priv_key, \
        priv_key.public_key.encode(nacl.encoding.URLSafeBase64Encoder).decode("utf-8").rstrip("=")


def generic_hash(data):
    return blake2b(data, encoder=nacl.encoding.RawEncoder)


def generic_hash_string(string):
    return blake2b(string.encode("utf-8"),
                   encoder=nacl.encoding.HexEncoder).decode("utf-8")


def kdf_derive_from_key(data, index, context):
    return blake2b(b'', key=data, salt=index.to_bytes(16, byteorder='little'),
                   person=context.encode("utf-8"),
                   encoder=nacl.encoding.RawEncoder)


def password_key(seed, site_id, index, username, version):
    site_hash = sha256(site_id.encode("utf-8"),
                       encoder=nacl.encoding.HexEncoder if version == 0 else nacl.encoding.RawEncoder)[:8]
    username_hash = sha256(username.encode("utf-8"),
                           encoder=nacl.encoding.HexEncoder if version == 0 else nacl.encoding.URLSafeBase64Encoder)[:8]
    site_key = blake2b(b'', key=seed, salt=site_hash,
                       person=PASSWORD_CONTEXT.encode("utf-8"),
                       encoder=nacl.encoding.RawEncoder)
    return blake2b(b'', key=site_key,
                   salt=index.to_bytes(16, byteorder='little'),
                   person=username_hash,
                   encoder=nacl.encoding.RawEncoder)


def deterministic_random_bytes(seed, size):
    return nacl.utils.randombytes_deterministic(size, seed)


def add_padding(string):
    padding = 4 - (len(string) % 4)
    return string + ("=" * padding)


def user_id(key):
    pubkey = key.verify_key.encode(encoder=nacl.encoding.URLSafeBase64Encoder).decode("utf-8").rstrip("=")
    return sha256(pubkey.encode("utf-8"), encoder=nacl.encoding.HexEncoder).decode("utf-8")


def to_base64(data):
    return nacl.encoding.URLSafeBase64Encoder.encode(data).decode("utf-8").rstrip("=")


def from_base64(str):
    return nacl.encoding.URLSafeBase64Encoder.decode(add_padding(str))


def pad(src):
    src_len = len(src)
    block_number = ceil((src_len+1)/PADDING_BLOCK_SIZE)
    pad_size = block_number * PADDING_BLOCK_SIZE - src_len
    return src + b'\x80' + bytes([0] * (pad_size-1))


def unpad(encoded_bytes):
    for idx, byte in enumerate(reversed(encoded_bytes)):
        pad_size = 0
        if bytes([byte]) == b'\x80':
            pad_size = idx+1
            break
    return encoded_bytes[:-pad_size]


def get_site_ids(url):
    parsed_domain = urlparse(url)  # contains the protocol
    extracted_domain = tldextract.extract(url)
    top_domain = ""

    if parsed_domain is None and url is None:
        raise ValueError("Invalid / empty URL")

    if extracted_domain.subdomain == "":
        full_domain = sha256((parsed_domain.scheme + "://" +
                              extracted_domain.domain + "." +
                              extracted_domain.suffix).encode("utf-8"),
                             encoder=nacl.encoding.HexEncoder)
    else:
        full_domain = sha256((parsed_domain.scheme + "://" +
                              extracted_domain.subdomain + "." +
                              extracted_domain.domain + "." +
                              extracted_domain.suffix).encode("utf-8"),
                             encoder=nacl.encoding.HexEncoder)
        top_domain = sha256((parsed_domain.scheme + "://" +
                             extracted_domain.domain + "." +
                             extracted_domain.suffix).encode("utf-8"),
                            encoder=nacl.encoding.HexEncoder)

    return full_domain, top_domain
