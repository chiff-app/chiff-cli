import argparse
import crypto
import api
import json
import csv
import sys
import getpass
from password_generator import PasswordGenerator
from pykeepass import PyKeePass


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


def import_csv(mnemonic, path):
    if mnemonic is None:
        generate()
    else:
        print("lets import")


def export_csv(mnemonic, path):
    accounts = recover(mnemonic)

    with open(path, mode='w') if path is not None else sys.stdout as file:
        csv_writer = csv.writer(file, delimiter=',', quoting=csv.QUOTE_MINIMAL)
        csv_writer.writerow(['URL', 'Username', 'Password', 'Site'])
        for account in accounts:
            csv_writer.writerow([account["url"], account["username"], account["password"], account["site_name"]])


def import_json(mnemonic, path):
    if mnemonic is None:
        generate()
    else:
        print("lets import")


def export_json(mnemonic, path):
    accounts = recover(mnemonic)

    with open(path, mode='w') if path is not None else sys.stdout as file:
        json.dump(accounts, file)


def import_kdbx(mnemonic, path):
    if mnemonic is None:
        generate()
    else:
        print("lets import")


def export_kdbx(mnemonic, path):
    accounts = recover(mnemonic)

    password = getpass.getpass(prompt='Please provide your .kdbx database password: ')

    with PyKeePass(path, password=password) as kp:
        for account in accounts:
            kp.add_entry(kp.root_group, account["site_name"], account["username"], account["password"], account["url"])
            kp.save(path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate, recover and modify Keyn backup data.')
    parser.add_argument("action",
                        help="The action you want to execute: generate / recover / import")
    parser.add_argument("-m", "--mnemonic", nargs=12,
                        help="The 12-word mnemonic, e.g. -m "
                             "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12")
    parser.add_argument("-f", "--format",
                        help="The output format. If data is written to a .kdbx database, the path to an existing .kdbx database file needs to be provided with -p"),
    parser.add_argument("-p", "--path",
                        help="The path to where the csv file should be written / read from. Prints or reads from stdout if not provided")

    args = parser.parse_args()

    if args.action == "generate":
        generate()
    elif args.action == "recover":
        if args.mnemonic:
            if args.format == "csv":
                export_csv(args.mnemonic, args.path)
            elif args.format == "json":
                export_json(args.mnemonic, args.path)
            elif args.format == "kdbx":
                export_kdbx(args.mnemonic, args.path)
            else:
                print_accounts(args.mnemonic)
        else:
            print("The mnemonic should be provided with -m or --mnemonic. "
                  "E.g. keyn recover -m word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12")
    elif args.action == "import":
        if args.format == "csv":
            import_csv(args.mnemonic, args.path)
        else:
            print("i dunno")
