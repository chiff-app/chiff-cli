import nacl.utils, nacl.encoding
from nacl.hash import sha256
from functools import reduce

SEED_SIZE = 16


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
