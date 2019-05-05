import argparse
import crypto
import api
from password_generator import PasswordGenerator

def generate():
    seed = crypto.generate_seed()
    mnemonic = crypto.mnemonic(seed)
    print(" ".join(mnemonic))


def recover(mnemonic):
    seed = crypto.recover(mnemonic)
    password_key, signing_keypair, decryption_key = crypto.derive_keys_from_seed(seed)
    # accounts = api.get_backup_data(signing_keypair)
    # for id, account in accounts.items():
    #     print(crypto.decrypt(account, decryption_key))
    generator = PasswordGenerator("test", "test", seed, None)
    generator.generate_key(0)

def import_csv(file, mnemonic):
    print("lets import")


def export_csv(file, mnemonic):
    print(file)
    print(mnemonic)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate, recover and modify Keyn backup data.')
    parser.add_argument("action",
                        help="The action you want to execute: generate / recover / import / export")
    parser.add_argument("-m", "--mnemonic", nargs=12,
                        help="The 12-word mnemonic, e.g. -m "
                             "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12")
    parser.add_argument("-o", "--output", nargs=1,
                        help="The path to where the csv file should be written. Prints to stdout if not provided")
    parser.add_argument("-i", "--input", nargs=1,
                        help="The path to where the csv file should be read from. "
                             "Expects input on stdin if not provided")

    args = parser.parse_args()
    if args.action == "generate":
        generate()
    elif args.action == "recover":
        if args.mnemonic:
            recover(args.mnemonic)
        else:
            print("The mnemonic should be provided with -m or --mnemonic. "
                  "E.g. keyn recover -m word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12")
    elif args.action == "import":
        if args.input:
            import_csv(args.input[0], args.mnemonic)
        else:
            print("TODO: reead stdin")
    elif args.action == "export":
        if not args.mnemonic:
            print("The mnemonic should be provided with -m or --mnemonic. "
                  "E.g. keyn recover -m word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12")
        elif args.output:
            export_csv(args.output[0], mnemonic=args.mnemonic)
        else:
            print("TODO: output stdout")
