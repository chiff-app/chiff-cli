import math
from chiff import password_validator, crypto


class PasswordGenerator:

    def __init__(self, username, site_id, seed, ppd, version=1):
        self.username = username
        self.site_id = site_id
        self.seed = seed
        self.ppd = ppd
        self.characters = ""
        self.version = version
        if ppd is not None and self.ppd.get("characterSets") is not None:
            for character_set in self.ppd.get("characterSets"):
                self.characters += ''.join(sorted(character_set["characters"]))
        else:
            self.characters = password_validator.OPTIMAL_CHARACTER_SET

    def generate(self, password_index, offset):
        length = self.length(offset is not None)
        if length < password_validator.MIN_PASSWORD_LENGTH_BOUND:
            raise ValueError("Password too short")

        index = password_index
        password = self.generate_password_candidate(index, length, offset)

        if offset is None:
            validator = password_validator.PasswordValidator(self.ppd)

            while not validator.validate(password):
                index += 1
                password = self.generate_password_candidate(index, length, offset)

        return password, index

    def calculate_offset(self, index, password):
        chars = password_validator.MAXIMAL_CHARACTER_SET
        length = self.length(True)
        validator = password_validator.PasswordValidator(self.ppd)

        if not validator.validate_max_length(password):
            raise ValueError("The password is too long.")

        key = crypto.password_key(self.seed, self.site_id, index, self.username, self.version)
        bit_length = length * math.ceil(math.log2(len(chars))) + (128 + length - (128 % length))
        byte_length = int(self.round_up(n=bit_length, m=(length * 8)) / 8)
        bytes_per_char = int(byte_length / length)
        key_data = crypto.deterministic_random_bytes(key, byte_length)
        characters = list(password)
        modulus = len(chars) + 1
        offset = []

        for i in range(0, length):
            char_index = chars.index(characters[i]) if i < len(characters) else len(chars)
            index = int.from_bytes(key_data[i: i + bytes_per_char], byteorder="big")
            offset.append((char_index - index) % modulus)

        return offset

    def length(self, is_custom_password):
        length = password_validator.MAX_PASSWORD_LENGTH_BOUND if is_custom_password else password_validator.FALLBACK_PASSWORD_LENGTH
        chars = password_validator.MAXIMAL_CHARACTER_SET if is_custom_password else password_validator.OPTIMAL_CHARACTER_SET
        if self.ppd is not None and "properties" in self.ppd and "maxLength" in self.ppd["properties"] and \
                self.ppd["properties"]["maxLength"] is not None:
            max_length = self.ppd["properties"]["maxLength"]
            if max_length < password_validator.MAX_PASSWORD_LENGTH_BOUND:
                length = min(max_length, password_validator.MAX_PASSWORD_LENGTH_BOUND)
            else:
                length = math.ceil(128 / math.log2(len(chars)))
        return length

    def generate_password_candidate(self, index, length, offset):
        chars = password_validator.MAXIMAL_CHARACTER_SET if offset is not None else self.characters
        key = crypto.password_key(self.seed, self.site_id, index, self.username, self.version)
        bit_length = length * math.ceil(math.log2(len(chars))) + (128 + length - (128 % length))  # number of bits in the pw
        byte_length = int(self.round_up(n=bit_length, m=(length*8)) / 8)
        key_data = crypto.deterministic_random_bytes(key, byte_length)
        modulus = len(chars) + 1 if offset is not None else len(chars)
        offset = offset if offset is not None else [0] * length
        bytes_per_char = int(byte_length / length)
        password = ""

        for i in range(0, length):
            index = (int.from_bytes(key_data[i:i + bytes_per_char], byteorder="big") + offset[i]) % modulus
            if index < len(chars):
                password += chars[index]

        return password

    @staticmethod
    def round_up(n, m):
        if n >= 0:
            return (int((n + m - 1) / m)) * m
        else:
            return int(n / m) * m
