import time
import nacl.encoding
from keyn import crypto
from nacl.hash import sha256


class TestHelper:

    mnemonic = "blind pony swarm upper stomach amount fresh screen purse unhappy garbage ride"
    base64seed = "_jx16O6LVpESsOBBrR2btg"
    linked_in_ppd_handle = "c53526a0b5fc33cb7d089d53a45a76044ed5f4aea170956d5799d01b2478cdfa"

    def sample_site(self):
        test_ppd = self.sample_ppd(8, 32)
        site = {
            "name": "Example",
            "id": sha256("example.com", encoder=nacl.encoding.RawEncoder),
            "url": "example.com",
            "ppd": test_ppd
        }
        return site

    def sample_ppd(self, min_length, max_length, max_consecutive=None, character_set_settings=None,
                   position_restrictions=None, requirement_groups=None):
        character_sets = {}
        character_sets.update({"characters": "abcdefghijklmnopqrstuvwxyz", "name": "LowerLetters"})
        character_sets.update({"characters": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "name": "UpperLetters"})
        character_sets.update({"characters": "0123456789", "name": "Numbers"})
        character_sets.update({"characters": ")(*&^%$#@!{}[]:;\"'?/,.<>`~|", "name": "Specials"})

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

    def create_seed(self):
        seed = crypto.recover(self.mnemonic)
        return seed