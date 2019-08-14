import secrets
from tests import test_helper
from keyn import password_validator, password_generator


class PasswordGeneratorTest:
    seed = test_helper.TestHelper().create_seed()

    def test_generate_password_should_return_password(self):
        ppd = test_helper.TestHelper().sample_ppd(8, 32)
        password_generator_instance = password_generator.PasswordGenerator("test", test_helper.linked_in_ppd_handle,
                                                                           self.seed, ppd)
        password, index = password_generator_instance.generate(0, None)
        assert "RMMbQu1QVLIAchpgm7!.<CcL9EM[KFJ(" == password, "String and password are not the same."
        assert index == 0, "Index is not Null."

    def test_calculate_password_offset_should_result_in_same_password(self):
        site = test_helper.TestHelper().sample_site()
        random_index = secrets.randbelow(100000000)
        password_generator_instance = password_generator.PasswordGenerator("test", site["id"], self.seed, site["ppd"])
        random_password, index = password_generator_instance.generate(random_index, None)
        offset = password_generator_instance.calculate_offset(index, random_password)
        calculated_password, new_index = password_generator_instance.generate(index, offset)
        assert random_password == calculated_password, "Random password is not the same as the calculated password."
        assert index == new_index, "Index does not match new Index."

    def test_calculate_password_offset_throws_error_when_password_too_long(self):
        ppd = test_helper.TestHelper().sample_ppd(8, 32)
        password = "Ver8aspdisd8nad8*(&sa8d97mjaVer8a"  # 33 characters
        password_generator_instance = password_generator.PasswordGenerator("test", test_helper.linked_in_ppd_handle,
                                                                           self.seed, ppd)
        assert password_generator_instance.calculate_offset(0, password), "Password too long"

    def test_calculate_password_offset_throws_error_when_password_too_long_using_fallback(self):
        ppd = test_helper.TestHelper().sample_ppd(8, None)
        password = ("a" * password_validator.MAX_PASSWORD_LENGTH_BOUND + 1)
        password_generator_instance = password_generator.PasswordGenerator("test", test_helper.linked_in_ppd_handle,
                                                                           self.seed, ppd)
        assert password_generator_instance.calculate_offset(0, password)
