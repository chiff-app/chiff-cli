import crypto

FALLBACK_PASSWORD_LENGTH = 22
MIN_PASSWORD_LENGTH_BOUND = 8
MAX_PASSWORD_LENGTH_BOUND = 50
OPTIMAL_CHARACTER_SET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0987654321"
MAXIMAL_CHARACTER_SET = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_" \
                        "`abcdefghijklmnopqrstuvwxyz{|}~"

class PasswordValidator:
    def __init__(self, ppd):
        self.ppd = ppd

    def validate_characters(self, password, characters):
        return True  # change later

    def validate_max_length(self, password):
        return True  # change later
