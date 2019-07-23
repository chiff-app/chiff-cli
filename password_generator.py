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
        chars = password_validator.MAXIMAL_CHARACTER_SET if offset is not None else self.characters() #self.characters is chosen
        key = self.generate_key(index) #selects what pw to generate to from thelist (if there is any)
        #print(base64.b64encode(key))
        #print(len(chars)) #length of the usable charsarray
        #print(length) #length of the pw
        bit_length = length * math.ceil(math.log2(len(chars))) + (128 + length - (128 % length)) #ammount of bits in the pw
        byte_length = int(self.round_up(bit_length, base=length*8) / 8) #ammount of bytes in a pw
        key_data = crypto.deterministic_random_bytes(key, byte_length)
        #print(key_data)
        #print(base64.b64encode(key_data))
        modulus = len(chars) if offset is not None else len(chars) + 1
        offset = offset if offset is not None else []
        bytesPerChar = int(byte_length / length)
        password = ""
        #print(offset)
        #for each char in pw
        for i in range(0, length):
            index = (int.from_bytes(key_data[i:i + bytesPerChar], byteorder="little") + offset[i]) % modulus
            if index < len(chars):
                password += chars[index]

        return password


    # private func generatePasswordCandidate(index passwordIndex: Int, length: Int, offset: [Int]?) throws -> String {
    #     let chars = offset != nil ? PasswordValidator.MAXIMAL_CHARACTER_SET.sorted() : characters
    #     let key = try generateKey(index: passwordIndex)
    #     let bitLength = length * Int(ceil(log2(Double(chars.count)))) + (128 + length - (128 % length))
    #     let byteLength = roundUp(n: bitLength, m: (length * 8)) / 8 // Round to nearest multiple of L * 8, so we can use whole bytes
    #     let keyData = try Crypto.shared.deterministicRandomBytes(seed: key, length: byteLength)
    #     let modulus = offset == nil ? chars.count : chars.count + 1
    #     let offset = offset ?? Array<Int>(repeatElement(0, count: length))
    #
    #
    #
    #
    #     return (0..<length).reduce("") { (pw, index) -> String in
    #         let charIndex = (keyData[index..<index + (byteLength / length)].reduce(0) { ($0 << 8 + Int($1)).mod(modulus) } + offset[index]).mod(modulus)
    #         return charIndex == chars.count ? pw : pw + String(chars[charIndex])
    #     }
    # }
    #
    #
    #


    def round_up(self, x, base):
        return base * round(x / base)

    @staticmethod
    def characters():
        return "blablalasdlksajdlasjdenhierkomtnogmeerbij"

    def generate_key(self, index):
        return crypto.password_key(self.seed, self.site_id, index, self.username)
