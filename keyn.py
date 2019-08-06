import argparse
import crypto
import api
import json
import csv
import sys
import getpass
import time
from password_generator import PasswordGenerator
from pykeepass import PyKeePass


def main():
    parser = argparse.ArgumentParser(prog='keyn', description='Generate, recover and modify Keyn backup data.')
    subparsers = parser.add_subparsers(help='The action you want to execute: generate / recover / import / delete')

    # generate
    parser_generate = subparsers.add_parser('generate')
    parser_generate.set_defaults(func=generate, name='generate')

    # recover
    parser_recover = subparsers.add_parser('recover')
    parser_recover.set_defaults(func=export_accounts, name='recover')
    parser_recover.add_argument("-f", "--format", choices=['csv', 'json', 'kdbx'],
                                help="The output format. If data is written to a .kdbx database, "
                                     "the path to an existing .kdbx database file needs to be provided with -p")
    parser_recover.add_argument("-p", "--path", type=argparse.FileType(mode='w'),
                               help="The path to where the file should be written to. "
                                    "Accepts '-' for writing to stdout")
    parser_recover.add_argument("-m", dest="mnemonic", metavar=crypto.random_example_seed(), nargs=12,
                                help="The 12-word mnemonic")

    # import
    parser_import = subparsers.add_parser('import')
    parser_import.set_defaults(func=import_accounts, name='import')
    parser_import.add_argument("-m", dest="mnemonic", metavar=crypto.random_example_seed(), nargs=12,
                              help="The 12-word mnemonic")
    parser_import.add_argument("-f", "--format", choices=['csv', 'json', 'kdbx'],
                               help="The input format. If data is written to a .kdbx database, the path to an existing "
                                    ".kdbx database file needs to be provided with -fi or file")
    parser_import.add_argument("-p", "--path", type=argparse.FileType(mode='r'),
                               help="The path to where the file should be written to. "
                                    "Accepts '-' for reading from stdin")

    # delete
    parser_delete = subparsers.add_parser('delete')
    parser_delete.set_defaults(func=delete_accounts, name='delete')
    group = parser_delete.add_mutually_exclusive_group(required=True)
    parser_delete.add_argument("-m", dest="mnemonic", metavar=crypto.random_example_seed(), nargs=12, required=True,
                               help="The 12-word mnemonic")
    group.add_argument("-i", "--id",
                               help="The account id of the account that should be deleted")
    group.add_argument("--delete-seed", dest="delete_seed", action="store_true",
                       help="Delete the backup data for this seed")

    args = parser.parse_args()
    if args.name == "recover" and ((args.path is None) != (args.format is None)):
        parser.error("If the path is provided, format should be given as well and vice versa.")
    args.func(args)


def generate(_):
    mnemonic = crypto.mnemonic(create_seed())
    print("The seed has been generated. Please write it down and store it in a safe place:")
    print(" ".join(mnemonic))


def create_seed():
    seed = crypto.generate_seed()
    _, signing_keypair, _ = crypto.derive_keys_from_seed(seed)
    api.create_backup_data(signing_keypair)

    return seed


def export_accounts(args):
    if args.mnemonic is None:
        seed = obtain_mnemonic()
    else:
        seed = crypto.recover(args.mnemonic)
    password_key, signing_keypair, decryption_key = crypto.derive_keys_from_seed(seed)
    encrypted_accounts_data = api.get_backup_data(signing_keypair)
    accounts = []

    if not encrypted_accounts_data.items():
        raise Exception("Seed does not exist")

    # Recovers the backup data from the server and decrypts it
    for id, encrypted_account in encrypted_accounts_data.items():
        decrypted_account_byte = crypto.decrypt(encrypted_account, decryption_key)
        decrypted_account_string = decrypted_account_byte.decode('utf-8')
        decrypted_account = json.loads(decrypted_account_string)

        username = decrypted_account["username"]
        site = decrypted_account["sites"][0]
        offset = decrypted_account["passwordOffset"] if "passwordOffset" in decrypted_account else None
        ppd = site["ppd"] if "ppd" in site else None

        generator = PasswordGenerator(username, site["id"], password_key, ppd)
        password, index = generator.generate(decrypted_account["passwordIndex"], offset)
        accounts.append({"id": id, "username": username, "password": password, "url": site["url"],
                         "site_name": site["name"]})

    # Exports the account data
    if args.format == "csv":
        csv_writer = csv.writer(args.path, delimiter=',', quoting=csv.QUOTE_MINIMAL)
        csv_writer.writerow(['url', 'username', 'password', 'site_name'])
        for account in accounts:
            csv_writer.writerow([account["url"], account["username"], account["password"], account["site_name"]])
    elif args.format == "json":
        json.dump(accounts, args.path, indent=4)
    elif args.format == "kdbx":
        password = getpass.getpass(prompt='Please provide your .kdbx database password: ')
        with PyKeePass(args.path.name, password=password) as kp:
            for account in accounts:
                kp.add_entry(kp.root_group, account["site_name"], account["username"], account["password"],
                             account["url"])
            kp.save(args.path.name)
    else:
        print_accounts(accounts)


def import_accounts(args):
    # if args.mnemonic is None:
    #     obtain_mnemonic()
    # else:
        seed = crypto.recover(args.mnemonic) if args.mnemonic is not None else create_seed()
        password_key, signing_keypair, encryption_key = crypto.derive_keys_from_seed(seed)
        if args.format == "csv":
            accounts = csv.DictReader(args.path, fieldnames=["url", "username", "password", "site_name"])
            next(accounts, None)
            for account in accounts:
                upload_account_data(account["url"], account["username"], account["password"], account["site_name"],
                                    password_key, signing_keypair, encryption_key)
        elif args.format == "json":
            accounts = json.load(args.path)
            for account in accounts:
                upload_account_data(account["url"], account["username"], account["password"], account["site_name"],
                                    password_key, signing_keypair, encryption_key)
        elif args.format == "kdbx":
            password = getpass.getpass(prompt='Please provide your .kdbx database password: ')
            with PyKeePass(args.path.name, password=password) as kp:
                for account in kp.entries:
                    upload_account_data(account.url, account.username, account.password,
                                        account.title, password_key, signing_keypair, encryption_key)
        else:
            print("The format of the imported file should be provided with -f or --format")
        print("Your accounts have been uploaded")
        print("Please write down your mnemonic: %s" % (args.mnemonic if args.mnemonic is not None else " ".join(crypto.mnemonic(seed))))


def delete_accounts(args):
    password_key, signing_keypair, encryption_key = crypto.derive_keys_from_seed(crypto.recover(args.mnemonic))
    if args.id is not None:
        api.delete_account(args.id, signing_keypair)
    elif args.delete_seed:
        api.delete_seed(signing_keypair)


def print_accounts(accounts):
    for account in accounts:
        print("-------------------------")
        print("Id:\t\t%s" % account["id"])
        print("Username:\t%s" % account["username"])
        print("Password:\t%s" % account["password"])
        print("Site:\t\t%s" % account["site_name"])
        print("URL:\t\t%s" % account["url"])
    print("-------------------------")


def upload_account_data(url, username, password, site_name, password_key, signing_keypair, encryption_key):
    site_id, secondary_site_id = crypto.get_site_ids(url)
    site_id = site_id.decode("utf-8")
    ppd = api.get_ppd(site_id)
    account_id = crypto.generic_hash_string(("%s_%s" % (site_id, username)))
    generator = PasswordGenerator(username, site_id, password_key, ppd)
    offset = generator.calculate_offset(0, password)
    account = {
        'id': account_id,
        'sites': [{
            'id': site_id,
            'url': url,
            'name': site_name,
            'ppd': ppd}],
        'username': username,
        'passwordIndex': 0,
        'lastPasswordUpdateTryIndex': 0,
        'passwordOffset': offset,
        'enabled': False,
    }
    ciphertext = crypto.encrypt(json.dumps(account).encode("utf-8"), encryption_key)
    api.set_backup_data(account_id, ciphertext, signing_keypair)


def obtain_mnemonic():
    print("Please enter the twelve word mnemonic")
    mnemonic = getpass.getpass(prompt="mnemonic:")
    try:
        words = mnemonic.split(" ")
        if len(words) != 12:
            raise Exception("the mnemonic should consist of 12 words")
        return crypto.recover(words)
    except Exception as exception:
        print("An error occurred: %s" % exception.args)
        return obtain_mnemonic()
    else:
        print("it works!")

    # print("The mnemonic is not provided. Please select one of the 2 options")
    # print("(1) create a new mnemonic")
    # print("(2) use an existing one")
    # answer = input("answer: ")
    #
    # if answer == '1':
    #     generate()
    # elif answer == '2':
    # print("Please enter the twelve word mnumonic")
    # mnumonic = input("mnumonic:")
    # try:
    #     print(crypto.recover(mnumonic))
    # except:
    #     raise Exception("Invalid mnemonic")


if __name__ == '__main__':
    main()
