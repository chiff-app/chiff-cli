import argparse
import crypto
import api
import json
import csv
import sys
import getpass
from password_generator import PasswordGenerator
from pykeepass import PyKeePass


def main():
    parser = argparse.ArgumentParser(prog='keyn', description='Generate, recover and modify Keyn backup data.')
    subparsers = parser.add_subparsers(help='The action you want to execute: generate / recover / import / delete')

    # generate
    parser_generate = subparsers.add_parser('generate')
    parser_generate.set_defaults(func=generate)
    parser_generate.add_argument('generate', help='calls for the generator action')

    # recover
    parser_recover = subparsers.add_parser('recover')
    parser_recover.set_defaults(func=export_accounts)
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
    parser_import.set_defaults(func=import_accounts)
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
    parser_delete.set_defaults(func=delete_accounts)
    group = parser_delete.add_mutually_exclusive_group(required=True)
    group.add_argument("-m", dest="mnemonic", metavar=crypto.random_example_seed(), nargs=12,
                               help="The 12-word mnemonic")
    group.add_argument("-i", "--id",
                               help="The account id of the account that should be deleted")

    #misc
    args = parser.parse_args()
    args.func(args)


def generate():
    seed = crypto.generate_seed()
    # _, signing_keypair, _ = crypto.derive_keys_from_seed(seed)
    # api.create_backup_data(signing_keypair)
    mnemonic = crypto.mnemonic(seed)
    print("The seed has been generated. Please write it down and store it in a safe place:")
    print(" ".join(mnemonic))


def print_accounts(mnemonic):
    accounts = recover(mnemonic)
    for account in accounts:
        print("-------------------------")
        print("Id:\t\t%s" % account["id"])
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
        decrypted_account_string = decrypted_account_byte.decode('utf-8')
        decrypted_account = json.loads(decrypted_account_string)

        username = decrypted_account["username"]
        site = decrypted_account["sites"][0]
        offset = decrypted_account["passwordOffset"] if "passwordOffset" in decrypted_account else None
        ppd = site["ppd"] if "ppd" in site else None

        generator = PasswordGenerator(username, site["id"], password_key, ppd)
        password, index = generator.generate(decrypted_account["passwordIndex"],
                                             offset)
        accounts_export.append({"id": id, "username": username, "password": password,
                                "url": site["url"], "site_name": site["name"]})

    return accounts_export


def import_accounts(args):
    seed = crypto.recover(args.mnemonic) if args.mnemonic is not None else crypto.generate_seed()
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


def export_accounts(args):
    if args.format == "csv":
        accounts = recover(args.mnemonic)
        csv_writer = csv.writer(args.path, delimiter=',', quoting=csv.QUOTE_MINIMAL)
        csv_writer.writerow(['url', 'username', 'password', 'site_name'])
        for account in accounts:
            csv_writer.writerow([account["url"], account["username"], account["password"], account["site_name"]])
    elif args.format == "json":
        accounts = recover(args.mnemonic)
        json.dump(accounts, args.path, indent=4)
    elif args.format == "kdbx":
        accounts = recover(args.mnemonic)
        password = getpass.getpass(prompt='Please provide your .kdbx database password: ')
        with PyKeePass(args.path.name, password=password) as kp:
            for account in accounts:
                kp.add_entry(kp.root_group, account["site_name"], account["username"], account["password"],
                             account["url"])
            kp.save(args.path.name)
    else:
        print_accounts(args.mnemonic)


def delete_accounts(args):
    if args.id is not None:
        # delete account
        print("none")
    else:
        # delete seed
        print("one")


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
            'ppd': None}],
        'username': username,
        'passwordIndex': 0,
        'lastPasswordUpdateTryIndex': 0,
        'passwordOffset': offset,
        'enabled': False,
    }
    ciphertext = crypto.encrypt(json.dumps(account).encode("utf-8"), encryption_key)
    api.set_backup_data(account_id, ciphertext, signing_keypair)


if __name__ == '__main__':
    main()
