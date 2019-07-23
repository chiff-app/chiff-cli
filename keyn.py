import argparse
import crypto
import api
import json
import csv
from password_generator import PasswordGenerator


def generate():
    seed = crypto.generate_seed()
    mnemonic = crypto.mnemonic(seed)
    print(" ".join(mnemonic))


def print_accounts(mnemonic):
    accounts = recover(mnemonic)
    for account in accounts:
        print("-------------------------")
        print("Username:\t%s" % account["username"])
        print("Password:\t%s" % account["password"])
        print("Site:\t\t%s" % account["site_name"])
        print("URL:\t\t%s" % account["url"])

    print("-------------------------")


def recover(mnemonic):
    seed = crypto.recover(mnemonic)
    password_key, signing_keypair, decryption_key = crypto.derive_keys_from_seed(seed)
    accounts = api.get_backup_data(signing_keypair)
    accounts_export = []
    for id, account in accounts.items():
        decrypted_account_byte = crypto.decrypt(account, decryption_key)
        decrypted_account_string = decrypted_account_byte.decode('utf-8').replace("'", '"')
        decrypted_account = json.loads(decrypted_account_string)

        username = decrypted_account["username"]
        site = decrypted_account["sites"][0]

        generator = PasswordGenerator(username, site["id"], password_key, None)
        password, index = generator.generate(decrypted_account["passwordIndex"], decrypted_account["passwordOffset"])

        accounts_export.append({"username": username, "password": password, "url": site["url"], "site_name": site["name"]})

    return accounts_export


def import_csv(file, mnemonic):
    print("lets import")


def export_csv(mnemonic):
    accounts = recover(mnemonic)

    with open('account_data.csv', mode='w') as account_data:
        account_data_writer = csv.writer(account_data, delimiter=',')
        account_data_writer.writerow(['URL', 'Username', 'Password', 'Site'])
        for account in accounts:
            account_data_writer.writerow([account["url"], account["username"], account["password"], account["site_name"]])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate, recover and modify Keyn backup data.')
    parser.add_argument("action",
                        help="The action you want to execute: generate / recover / import / export")
    parser.add_argument("-m", "--mnemonic", nargs=12,
                        help="The 12-word mnemonic, e.g. -m "
                             "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12")
    parser.add_argument("-f", "--format", nargs=1,
                        help="The output format"),
    parser.add_argument("-o", "--output", nargs=1,
                        help="The path to where the csv file should be written. Prints to stdout if not provided")
    parser.add_argument("-i", "--input", nargs=1,
                        help="The path to where the csv file should be read from. "
                             "Expects input on stdin if not provided")

    args = parser.parse_args()
    args.format = "csv"

    if args.action == "generate":
        generate()
    elif args.action == "recover":
        if args.mnemonic:
            if args.format == "csv":
                export_csv(args.mnemonic)
            elif args.format == "json":
                print("export_json(args.mnemonic)")
            elif args.format == "kdbx":
                print("export_kdbx(args.mnemonic)")
            else:
                print_accounts(args.mnemonic)
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
