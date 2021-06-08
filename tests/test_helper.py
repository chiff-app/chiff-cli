import time

SEED = b"\xfe<u\xe8\xee\x8bV\x91\x12\xb0\xe0A\xad\x1d\x9b\xb6"
PUB_KEY = b"\xc1\x1f\x83\xfe\xceP\x86\x06\x8d\xcf\xba0\xfc\x15-B\xdc\x83\xf3D\xc0r\x0b.\x00\x1c\xf8\x1e~l\x06\x92"
BASE64_PUB_KEY = "wR-D_s5QhgaNz7ow_BUtQtyD80TAcgsuABz4Hn5sBpI"
DEFAULT_BASE64_PUB_KEY = "wR+D/s5QhgaNz7ow/BUtQtyD80TAcgsuABz4Hn5sBpI="
SHARED_KEY = b"\xc2\xee\x153\xf7\xf6\xfd\xe4=/&\xbf\xe8\x08\xe7\xc0\xb0\xcf}\x9e\x0f5\x94\xbc;\x89\xf7\xd6\xe1\xf7^\xc8"
ECDSA_PUB_KEY = b"\x04\x01\x92\xad\xb0\xa3\x86\x1a\x85\x1a\xe3(\x14*:\xc6\x8c3pR\xf8\x93k)0B\xef\xd3\x9bg\xf6bS|Lq\xe9\xee\x15Da\xb2f@\x97\xea\xa9\xf5\xbc7\xce]\x9f\x9bG\x87\xbe\r&\xf1e4\xf6\xc6\xa8"
ECDSA_PRIV_KEY = b"\x04\x01\x92\xad\xb0\xa3\x86\x1a\x85\x1a\xe3(\x14*:\xc6\x8c3pR\xf8\x93k)0B\xef\xd3\x9bg\xf6bS|Lq\xe9\xee\x15Da\xb2f@\x97\xea\xa9\xf5\xbc7\xce]\x9f\x9bG\x87\xbe\r&\xf1e4\xf6\xc6\xa8w\xf4\xaa\x97\xd3b\x818\x15\x08\xef\x11\xb9\xe8\x9f\x8b\xb3%\x04\xe2\xb53\xe0c30\x89\x8e\x16\xf9\xbd0"
SSH_CHALLENGE = b"\x00\x00\x00 \n\xd9\x8dp\xe3c\xf0\x1b\xf4\xce\x0f\xf5\x94L2\xe9\xd4\xd1\x18\xf7Lf\xfe\xb3d\xa5\x80Wlk\x06\xdd2\x00\x00\x00\x04rhtb\x00\x00\x00\x0essh-connection\x00\x00\x00\tpublickey\x01\x00\x00\x00\x0bssh-ed25519\x00\x00\x003\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 \x19\x92\xb9\x10>9a[[\x8e5IOR\xffA\xf13\xdb\xf5h\xc9]\x80\x12~\xa5:[N]\xba"
ED25519_SIGNATURE = b"\xec\x10@)\xe5\xc4\xb9[\xacts\x1f\xc2\x9b9\xd1\x8eA ,W\xbf\x13\xc9\x14\xa2\x9c\xdb}e'\x0e\x8c\xcfr\xa2\x9d}\x12\xa3\r\xd3\xf6Hl$\x7f@\xf2\x12\xe8O\x89\xe4F9\x93\xdfw+btM\x06"
ECDSA_SIGNATURE = b"\xec\x10@)\xe5\xc4\xb9[\xacts\x1f\xc2\x9b9\xd1\x8eA ,W\xbf\x13\xc9\x14\xa2\x9c\xdb}e'\x0e\x8c\xcfr\xa2\x9d}\x12\xa3\r\xd3\xf6Hl$\x7f@\xf2\x12\xe8O\x89\xe4F9\x93\xdfw+btM\x06"


def sample_ppd(
    min_length,
    max_length,
    max_consecutive=None,
    character_set_settings=None,
    position_restrictions=None,
    requirement_groups=None,
):
    character_sets = [
        {"characters": "abcdefghijklmnopqrstuvwxyz", "name": "LowerLetters"},
        {"characters": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "name": "UpperLetters"},
        {"characters": "0123456789", "name": "Numbers"},
        {"characters": ")(*&^%$#@!{}[]:;\"'?/,.<>`~|", "name": "Specials"},
    ]
    ppd_character_settings = None
    if (
        character_set_settings is not None
        or position_restrictions is not None
        or requirement_groups is not None
    ):
        ppd_character_settings = {
            "characterSetSettings": character_set_settings,
            "requirementGroups": requirement_groups,
            "positionRestrictions": position_restrictions,
        }

    properties = {
        "characterSettings": ppd_character_settings,
        "maxConsecutive": max_consecutive,
        "minLength": min_length,
        "maxLength": max_length,
    }

    ppd = {
        "characterSets": character_sets,
        "properties": properties,
        "service": None,
        "version": "1.0",
        "timestamp": time.time(),
        "url": "https://example.com",
        "redirect": None,
        "name": "Example",
    }

    return ppd
