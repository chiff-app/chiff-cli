import time
import nacl.encoding
from keyn import crypto
from nacl.hash import sha256


mnemonic = "blind pony swarm upper stomach amount fresh screen purse unhappy garbage ride"
base64seed = "_jx16O6LVpESsOBBrR2btg"
linked_in_ppd_handle = "c53526a0b5fc33cb7d089d53a45a76044ed5f4aea170956d5799d01b2478cdfa"


def sample_site():
    test_ppd = sample_ppd(8, 32)
    b = "example.com".encode("utf-8")
    site = {
        "name": "Example",
        "id": sha256(b, encoder=nacl.encoding.HexEncoder).decode("utf-8"),
        "url": "example.com",
        "ppd": test_ppd
    }
    return site


def sample_ppd(min_length, max_length, max_consecutive=None, character_set_settings=None,
               position_restrictions=None, requirement_groups=None):
    character_sets = [
        {"characters": "abcdefghijklmnopqrstuvwxyz", "name": "LowerLetters"},
        {"characters": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "name": "UpperLetters"},
        {"characters": "0123456789", "name": "Numbers"},
        {"characters": ")(*&^%$#@!{}[]:;\"'?/,.<>`~|", "name": "Specials"}
    ]
    ppd_character_settings = None
    if character_set_settings is not None or position_restrictions is not None or requirement_groups is not None:
        ppd_character_settings = {
            "characterSetSettings": character_set_settings,
            "requirementGroups": requirement_groups,
            "positionRestrictions": position_restrictions
        }

    properties = {
        "characterSettings": ppd_character_settings,
        "maxConsecutive": max_consecutive,
        "minLength": min_length,
        "maxLength": max_length
    }

    ppd = {
        "characterSets": character_sets, "properties": properties, "service": None, "version": "1.0",
        "timestamp":  time.time(), "url": "https://example.com", "redirect": None, "name": "Example"
    }

    return ppd


def create_seed():
    seed = crypto.recover(mnemonic.split(" "))
    return seed
