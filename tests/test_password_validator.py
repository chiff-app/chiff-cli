from tests import test_helper
from chiff import password_validator


def test_validate_returns_false_when_max_length_exceeded():
    ppd = test_helper.sample_ppd(8, 32)
    validator = password_validator.PasswordValidator(ppd)
    password = "Ver8aspdisd8nad8*(&sa8d97mjaVer8a"  # 33 characters

    assert not validator.validate(password)


def test_validate_returns_false_when_min_length_underceeded():
    ppd = test_helper.sample_ppd(8, 32)
    validator = password_validator.PasswordValidator(ppd)
    password = "sh0rt*r"  # 7 characters

    assert not validator.validate(password)


def test_validate_returns_false_when_max_length_exceeded_using_fallback():
    ppd = test_helper.sample_ppd(8, None)
    validator = password_validator.PasswordValidator(ppd)
    password = ("a" * (password_validator.MAX_PASSWORD_LENGTH_BOUND + 1))

    assert not validator.validate(password)


def test_validate_returns_false_when_min_length_underceeded_using_fallback():
    ppd = test_helper.sample_ppd(None, 32)
    validator = password_validator.PasswordValidator(ppd)
    password = ("a" * (password_validator.MIN_PASSWORD_LENGTH_BOUND - 1))

    assert not validator.validate(password)


def test_validate_returns_false_for_unallowed_characters():
    ppd = test_helper.sample_ppd(8, 32)
    validator = password_validator.PasswordValidator(ppd)

    assert not validator.validate("Ver8aspdi€sd8na")


def test_validate_returns_false_for_too_many_consecutive_characters():
    ppd = test_helper.sample_ppd(8, 32, 3)
    validator = password_validator.PasswordValidator(ppd)
    password = "sod8na9p8d7snaaaa"

    assert not validator.validate(password)


def test_validate_returns_true_for_not_too_many_consecutive_characters():
    ppd = test_helper.sample_ppd(8, 32, 4)
    validator = password_validator.PasswordValidator(ppd)
    password = "sod8na9p8d7snaaaa"

    assert validator.validate(password)


def test_validate_returns_false_for_too_many_ordered_consecutive_characters():
    ppd = test_helper.sample_ppd(8, 32, 3)
    validator = password_validator.PasswordValidator(ppd)
    password = "sod8na9p8d7snabcd"

    assert not validator.validate(password)


def test_validate_returns_true_for_not_too_many_ordered_consecutive_characters():
    ppd = test_helper.sample_ppd(8, 32, 4)
    validator = password_validator.PasswordValidator(ppd)
    password = "sod8na9p8d7snabcd"

    assert validator.validate(password)


# For readability the character sets are defined in Testhelper.examplePPPD().
def test_validate_returns_false_when_character_set_min_occurs_not_met():
    character_set_settings = [{"minOccurs": 1, "maxOccurs": None, "name": "UpperLetters"}]
    ppd = test_helper.sample_ppd(8, 32, 0, character_set_settings)
    validator = password_validator.PasswordValidator(ppd)

    assert not validator.validate("onlylowerletters")


def test_validate_returns_false_when_character_set_max_occurs_exceeded():
    character_set_settings = [{"minOccurs": None, "maxOccurs": 4, "name": "UpperLetters"}]
    ppd = test_helper.sample_ppd(8, 32, 0, character_set_settings)
    validator = password_validator.PasswordValidator(ppd)

    assert not validator.validate("toomanyUPPER")


def test_validate_returns_false_if_position_restriction_not_met():
    position_restriction = [{"positions": "0", "minOccurs": 1, "maxoccurs": None, "characterSet": "UpperLetters"}]
    # password should start with a capital
    ppd = test_helper.sample_ppd(8, 32, None, None, position_restriction)
    validator = password_validator.PasswordValidator(ppd)

    assert not validator.validate("asdpuhfjkad45")


def test_validate_returns_false_if_multiple_position_restriction_not_met():
    position_restriction = [{"positions": "0,1,2", "minOccurs": 0, "maxOccurs": 2, "characterSet": "Specials"}]
    # There should be no more than 2 specials combined on positions 1, 2, 3
    ppd = test_helper.sample_ppd(8, 32, None, None, position_restriction)
    validator = password_validator.PasswordValidator(ppd)

    assert validator.validate("**d**********")
    assert not validator.validate("***puhfjkad45")


def test_validate_should_return_false_if_requirement_group_is_not_met():
    requirement_groups = []
    rule1 = {"positions": "0", "minOccurs": 1, "maxOccurs": None, "characterSet": "UpperLetters"}
    rule2 = {"positions": "-1,-2", "minOccurs": 2, "maxOccurs": 2, "characterSet": "Numbers"}
    requirement_groups.append({"minRules": 2, "requirementRules": [rule1, rule2]})

    ppd = test_helper.sample_ppd(8, 32, None, None, None, requirement_groups)
    validator = password_validator.PasswordValidator(ppd)

    assert validator.validate("Password123")  # follows both
    assert not validator.validate("Password")  # follows rule1 not rule2
    assert not validator.validate("password123")  # follows rule2 not rule1
