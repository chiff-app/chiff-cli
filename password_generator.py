import crypto
import math
from password_validator import MAXIMAL_CHARACTER_SET

class PasswordGenerator:

    def __init__(self, username, site_id, seed, ppd):
        self.username = username
        self.site_id = site_id
        self.seed = seed
        self.ppd = ppd

    def generate(self):
        return "todo"

    def calculate_offset(self):
        return "todo"

    def length(self):
        return 22

    def generate_password_candidate(self, index, length, offset):
        chars = MAXIMAL_CHARACTER_SET if offset is not None else self.characters()
        key = self.generate_key(index)
        bit_length = length * math.ceil(math.log2(chars.count())) + (128 + length - (128 % length))
        byte_length = self.round_up(bit_length, base=length*8) / 8



    # private func generatePasswordCandidate(index passwordIndex: Int, length: Int, offset: [Int]?) throws -> String {
    #     let chars = offset != nil ? PasswordValidator.MAXIMAL_CHARACTER_SET.sorted() : characters
    #     let key = try generateKey(index: passwordIndex)
    #     let bitLength = length * Int(ceil(log2(Double(chars.count)))) + (128 + length - (128 % length))
    #     let byteLength = roundUp(n: bitLength, m: (length * 8)) / 8 // Round to nearest multiple of L * 8, so we can use whole bytes
    #     let keyData = try Crypto.shared.deterministicRandomBytes(seed: key, length: byteLength)
    #     let modulus = offset == nil ? chars.count : chars.count + 1
    #     let offset = offset ?? Array<Int>(repeatElement(0, count: length))
    #
    #     return (0..<length).reduce("") { (pw, index) -> String in
    #         let charIndex = (keyData[index..<index + (byteLength / length)].reduce(0) { ($0 << 8 + Int($1)).mod(modulus) } + offset[index]).mod(modulus)
    #         return charIndex == chars.count ? pw : pw + String(chars[charIndex])
    #     }
    # }

    def round_up(self, x, base):
        return base * round(x / base)

    @staticmethod
    def characters():
        return "blablalasdlksajdlasjd"

    def generate_key(self, index):
        return crypto.password_key(self.seed, self.site_id, index, self.username)
