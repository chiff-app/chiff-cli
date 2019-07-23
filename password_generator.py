import crypto
import math
import password_validator


class PasswordGenerator:

    def __init__(self, username, site_id, seed, ppd):
        self.username = username
        self.site_id = site_id
        self.seed = seed
        self.ppd = ppd

    def generate(self, password_index, offset):
        length = self.length(offset is not None)
        if length < password_validator.MIN_PASSWORD_LENGTH_BOUND:
            raise ValueError("Password too short")

        index = password_index
        password = self.generate_password_candidate(index, length, offset)

        #if offset is None add ppd later

        return password, index

    def calculate_offset(self):
        return "todo"

    def length(self, is_custom_password):
        length = password_validator.MAX_PASSWORD_LENGTH_BOUND if is_custom_password else password_validator.FALLBACK_PASSWORD_LENGTH
        chars = password_validator.MAXIMAL_CHARACTER_SET if is_custom_password else password_validator.OPTIMAL_CHARACTER_SET
        #todo ppd

        return length

    def generate_password_candidate(self, index, length, offset):
        chars = password_validator.MAXIMAL_CHARACTER_SET if offset is not None else self.characters()
        key = crypto.password_key(self.seed, self.site_id, index, self.username)
        bit_length = length * math.ceil(math.log2(len(chars))) + (128 + length - (128 % length))  # number of bits in the pw
        byte_length = int(self.round_up(n=bit_length, m=(length*8)) / 8)
        key_data = crypto.deterministic_random_bytes(key, byte_length)
        modulus = len(chars) + 1 if offset is not None else len(chars)
        offset = offset if offset is not None else []
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

    @staticmethod
    def characters():
        return "blablalasdlksajdlasjdenhierkomtnogmeerbij"
