import re

FALLBACK_PASSWORD_LENGTH = 22
MIN_PASSWORD_LENGTH_BOUND = 8
MAX_PASSWORD_LENGTH_BOUND = 50
OPTIMAL_CHARACTER_SET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0987654321"
MAXIMAL_CHARACTER_SET = (
    " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_"
    "`abcdefghijklmnopqrstuvwxyz{|}~"
)


class PasswordValidator:
    def __init__(self, ppd):
        self.ppd = ppd
        self.character_set_dictionary = {}
        self.characters = ""
        if self.ppd is not None and "characterSets" in self.ppd:
            for character_set in self.ppd["characterSets"]:
                if character_set.get("characters") is not None:
                    self.characters += character_set["characters"]
                self.character_set_dictionary[character_set["name"]] = character_set[
                    "characters"
                ]
        else:
            self.characters = OPTIMAL_CHARACTER_SET

    def validate(self, password):
        # Checks if password is less than or equal to maximum length.
        # Relevant for custom passwords.
        if not self.validate_max_length(password):
            return False

        # Checks is password is less than or equal to minimum length.
        # Relevant for custom passwords.
        if not self.validate_min_length(password):
            return False

        # Checks if password doesn't contain unallowed characters
        if not self.validate_characters(password):
            return False

        # Max consecutive characters. This tests if n characteres are the same
        if not self.validate_consecutive_characters(password):
            return False

        # Max consecutive characters.
        # This tests if n characters are an ordered sequence.
        if not self.validate_consecutive_ordered_characters(password):
            return False

        # Characterset restrictions
        if not self.validate_character_set(password):
            return False

        # Position restrictions
        if not self.validate_position_restrictions(password):
            return False

        # Requirement groups
        if not self.validate_requirement_groups(password):
            return False

        return True

    def validate_max_length(self, password):
        if (
            self.ppd is not None
            and self.ppd.get("properties") is not None
            and self.ppd.get("properties").get("maxLength") is not None
        ):
            max_length = self.ppd.get("properties").get("maxLength")
        else:
            max_length = MAX_PASSWORD_LENGTH_BOUND

        return len(password) <= max_length

    def validate_min_length(self, password):
        if (
            self.ppd is not None
            and self.ppd.get("properties") is not None
            and self.ppd.get("properties").get("minLength") is not None
        ):
            min_length = self.ppd.get("properties").get("minLength")
        else:
            min_length = MIN_PASSWORD_LENGTH_BOUND

        return len(password) >= min_length

    def validate_characters(self, password):
        for char in password:
            if char not in self.characters:
                return False

        return True

    def validate_consecutive_characters(self, password):
        if (
            self.ppd is not None
            and self.ppd.get("properties") is not None
            and self.ppd.get("properties").get("maxConsecutive") is not None
        ):
            if self.ppd.get("properties").get("maxConsecutive") > 0:
                return self.check_consecutive_characters(
                    password,
                    self.characters,
                    self.ppd.get("properties").get("maxConsecutive"),
                )
            else:
                return True
        else:
            return True

    def validate_consecutive_ordered_characters(self, password):
        if (
            self.ppd is not None
            and self.ppd.get("properties") is not None
            and self.ppd.get("properties").get("maxConsecutive") is not None
        ):
            if self.ppd.get("properties").get("maxConsecutive") > 0:
                return self.check_consecutive_characters_order(
                    password, self.ppd.get("properties").get("maxConsecutive")
                )
            else:
                return True
        else:
            return True

    def validate_character_set(self, password):
        if (
            self.ppd is not None
            and self.ppd.get("properties") is not None
            and self.ppd.get("properties").get("characterSettings") is not None
            and self.ppd.get("properties")
            .get("characterSettings")
            .get("characterSetSettings")
            is not None
        ):
            return self.check_character_set_settings(
                password,
                self.ppd.get("properties")
                .get("characterSettings")
                .get("characterSetSettings"),
            )
        else:
            return True

    def validate_position_restrictions(self, password):
        if (
            self.ppd is not None
            and self.ppd.get("properties") is not None
            and self.ppd.get("properties").get("characterSettings") is not None
            and self.ppd.get("properties")
            .get("characterSettings")
            .get("positionRestrictions")
            is not None
        ):
            return self.check_position_restrictions(
                password,
                self.ppd.get("properties")
                .get("characterSettings")
                .get("positionRestrictions"),
            )
        else:
            return True

    def validate_requirement_groups(self, password):
        if (
            self.ppd is not None
            and self.ppd.get("properties") is not None
            and self.ppd.get("properties").get("characterSettings")
            and self.ppd.get("properties")
            .get("characterSettings")
            .get("requirementGroups")
        ):
            return self.check_requirement_groups(
                password,
                self.ppd.get("properties")
                .get("characterSettings")
                .get("requirementGroups"),
            )
        else:
            return True

    def check_character_set_settings(self, password, character_set_settings):
        for character_set_setting in character_set_settings:
            if (
                self.character_set_dictionary.get(character_set_setting["name"])
                is not None
            ):
                character_set = self.character_set_dictionary[
                    character_set_setting["name"]
                ]
                occurrences = self.count_character_occurrences(password, character_set)
                if (
                    character_set_setting.get("minOccurs") is not None
                    and occurrences < character_set_setting["minOccurs"]
                ):
                    return False
                if (
                    character_set_setting.get("maxOccurs") is not None
                    and occurrences > character_set_setting["maxOccurs"]
                ):
                    return False
        return True

    def check_position_restrictions(self, password, position_restrictions):
        for position_restriction in position_restrictions:
            if (
                self.character_set_dictionary.get(
                    position_restriction.get("characterSet")
                )
                is not None
            ):
                character_set = self.character_set_dictionary.get(
                    position_restriction.get("characterSet")
                )
                occurrences = self.check_positions(
                    password, position_restriction.get("positions"), character_set
                )
                if (
                    occurrences is not None
                    and occurrences < position_restriction["minOccurs"]
                ):
                    return False
                if (
                    occurrences is not None
                    and occurrences > position_restriction["maxOccurs"]
                ):
                    return False

        return True

    def check_requirement_groups(self, password, requirement_groups):
        for requirement_group in requirement_groups:
            valid_rules = 0
            for requirement_rule in requirement_group.get("requirementRules"):
                occurrences = 0
                if (
                    self.character_set_dictionary.get(
                        requirement_rule.get("characterSet")
                    )
                    is not None
                ):
                    if requirement_rule.get("positions") is not None:
                        occurrences += self.check_positions(
                            password,
                            requirement_rule.get("positions"),
                            self.character_set_dictionary.get(
                                requirement_rule.get("characterSet")
                            ),
                        )
                    else:
                        occurrences += self.count_character_occurrences(
                            password,
                            self.character_set_dictionary.get(
                                requirement_rule.get("characterSet")
                            ),
                        )
                if requirement_rule.get("maxOccurs") is not None:
                    if (
                        requirement_rule.get("minOccurs")
                        <= occurrences
                        <= requirement_rule.get("maxOccurs")
                    ):
                        valid_rules += 1
                else:
                    if occurrences >= requirement_rule.get("minOccurs"):
                        valid_rules += 1
            if valid_rules < requirement_group.get("minRules"):
                return False
        return True

    @staticmethod
    def check_consecutive_characters(password, characters, max_consecutive):
        escaped_chars = re.escape(characters)
        return (
            re.search(r"([%s])\1{%d,}" % (escaped_chars, max_consecutive), password)
            is None
        )

    @staticmethod
    def check_consecutive_characters_order(password, max_consecutive):
        last_value = 255
        longest_sequence = 0
        counter = 1
        character_bytes = list(
            map(
                lambda x: ord(x),
                list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0987654321"),
            )
        )
        for letter in password:
            value = ord(letter)
            if value == last_value + 1 and value in character_bytes:
                counter += 1
            else:
                counter = 1
            last_value = value
            if counter > longest_sequence:
                longest_sequence = counter

        return longest_sequence <= max_consecutive

    @staticmethod
    def check_positions(password, positions, character_set):
        occurrences = 0
        for position in positions.split(","):
            if password[int(position)] in character_set:
                occurrences += 1

        return occurrences

    @staticmethod
    def count_character_occurrences(password, character_set):
        result = 0
        for char in password:
            if char in character_set:
                result += 1

        return result
