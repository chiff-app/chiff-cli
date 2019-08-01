import nacl.utils, nacl.encoding
from nacl.hash import sha256, blake2b
import nacl.signing
import nacl.secret
import nacl.utils
import tldextract
from urllib.parse import urlparse
from functools import reduce


SEED_SIZE = 16
SEED_CONTEXT = "keynseed"
BACKUP_CONTEXT = "keynback"
PASSWORD_CONTEXT = "keynpass"
PASSWORD_KEY_INDEX = 0
BACKUP_KEY_INDEX = 1


def generate_seed():
    return nacl.utils.random(SEED_SIZE)


def mnemonic(seed):
    hash = sha256(seed, encoder=nacl.encoding.RawEncoder)
    bitstring = reduce((lambda x, y: x + y), map(lambda x: bin(x)[2:].zfill(8), seed))
    bitstring += bin(hash[0])[2:].zfill(8)[:4]
    indices = map(lambda x: int(x, 2), [bitstring[start:start+11] for start in range(0, len(bitstring), 11)])
    with open('wordlist.txt') as wordfile:
        words = wordfile.read().splitlines()
        return map(lambda i: words[i], indices)


def recover(mnemonic):
    with open('wordlist.txt') as wordfile:
        words = wordfile.read().splitlines()
        bitstring = reduce((lambda x, y: x + y), map(lambda x: bin(words.index(x))[2:].zfill(11), mnemonic))
        checksum = bitstring[-4:]
        bitstring = bitstring[:-4]
        seed = bytes(map(lambda x: int(x, 2), [bitstring[start:start + 8] for start in range(0, len(bitstring), 8)]))
        hash = bin(sha256(seed, encoder=nacl.encoding.RawEncoder)[0])[2:].zfill(8)[:4]
        if hash == checksum:
            return seed
        else:
            raise Exception("Invalid mnemonic")


def derive_keys_from_seed(seed):
    seed_hash = generic_hash(seed)
    password_key = kdf_derive_from_key(seed_hash, PASSWORD_KEY_INDEX, SEED_CONTEXT)
    backup_key = kdf_derive_from_key(seed_hash, BACKUP_KEY_INDEX, SEED_CONTEXT)
    return password_key, nacl.signing.SigningKey(backup_key), nacl.secret.SecretBox(kdf_derive_from_key(backup_key, 0, BACKUP_CONTEXT))


def sign(message, signing_key: nacl.signing.SigningKey):
    return signing_key.sign(message.encode("utf-8"), encoder=nacl.encoding.URLSafeBase64Encoder), \
           signing_key.verify_key.encode(nacl.encoding.URLSafeBase64Encoder)


def decrypt(message, key: nacl.secret.SecretBox):
    return key.decrypt(addUnneccesaryPadding(message), encoder=nacl.encoding.URLSafeBase64Encoder)


def create_signing_keypair(seed):
    return nacl.signing.SigningKey(seed)


def generic_hash(data):
    return blake2b(data, encoder=nacl.encoding.RawEncoder)


def kdf_derive_from_key(data, index, context):
    return blake2b(b'', key=data, salt=index.to_bytes(16, byteorder='little'), person=context.encode("utf-8"),
                   encoder=nacl.encoding.RawEncoder)


def password_key(seed, site_id, index, username):
    site_hash = sha256(site_id.encode("utf-8"), encoder=nacl.encoding.HexEncoder)[:8]
    username_hash = sha256(username.encode("utf-8"), encoder=nacl.encoding.HexEncoder)[:8]
    site_key = blake2b(b'', key=seed, salt=site_hash,
                       person=PASSWORD_CONTEXT.encode("utf-8"), encoder=nacl.encoding.RawEncoder)
    return blake2b(b'', key=site_key, salt=index.to_bytes(16, byteorder='little'), person=username_hash,
                   encoder=nacl.encoding.RawEncoder)


def deterministic_random_bytes(seed, size):
    return nacl.utils.randombytes_deterministic(size, seed)


def addUnneccesaryPadding(string):
    padding = 4 - (len(string) % 4)
    return string + ("=" * padding)

def get_site_ids(url):
    parsed_domain = urlparse(url)  # contains the protocol
    extracted_domain = tldextract.extract(url)
    top_domain = ""

    if parsed_domain is None and url is None:
        raise ValueError("Invalid / empty URL")

    if extracted_domain.subdomain == "":
        full_domain = sha256((parsed_domain.scheme + "://" + extracted_domain.domain + "." + extracted_domain.suffix).encode("utf-8"),
        encoder=nacl.encoding.HexEncoder)
    else:
        full_domain = sha256((parsed_domain.scheme + "://" + extracted_domain.subdomain + "." + extracted_domain.domain
        + "." + extracted_domain.suffix).encode("utf-8"), encoder=nacl.encoding.HexEncoder)
        top_domain = sha256((parsed_domain.scheme + "://" + extracted_domain.domain + "." + extracted_domain.suffix).encode("utf-8"),
        encoder=nacl.encoding.HexEncoder)

    return full_domain, top_domain