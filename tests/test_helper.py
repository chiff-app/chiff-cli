import time


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
