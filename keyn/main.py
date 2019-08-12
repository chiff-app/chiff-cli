from keyn import api, crypto
import json
import csv
import getpass
import click
import sys
from keyn.password_generator import PasswordGenerator
from pykeepass import PyKeePass


@click.group()
def main():
    click.echo("Welcome to the Keyn CLI! You can use this program to create, update and delete Keyn seeds and the "
               "accounts on it.")


@main.command()
def generate():
    mnemonic = crypto.mnemonic(create_seed())
    click.echo("The seed has been generated:\n")
    click.echo(" ".join(mnemonic))
    click.echo("\nPlease write it down and store it in a safe place.")


@main.command(name='recover')
@click.option('-m', '--mnemonic', nargs=12, help='The 12-word mnemonic')
@click.option('-f', '--format', type=click.Choice(['csv', 'json', 'kdbx']),
              help='The output format. If data is written to a .kdbx database, '
                   'the path to an existing .kdbx database file needs to be provided with -p.')
@click.option('-p', '--path', type=click.Path(writable=True, allow_dash=True),
              help='The path to where the file should be written to.')
def export_accounts(mnemonic, format, path):
    click.echo("Starting account export...")
    if mnemonic:
        seed = crypto.recover(mnemonic)
    else:
        seed = crypto.recover(obtain_mnemonic())

    password_key, signing_keypair, decryption_key = crypto.derive_keys_from_seed(seed)
    encrypted_accounts_data = api.get_backup_data(signing_keypair)

    if not encrypted_accounts_data.items():
        click.echo("This seed does not exist or does not have any accounts linked to it.")
        sys.exit(1)

    accounts = decrypt_accounts(encrypted_accounts_data.items(), password_key, decryption_key)

    # Exports the account data
    if format == "csv":
        with open(path, mode='w') as file:
            csv_writer = csv.writer(file, delimiter=',', quoting=csv.QUOTE_MINIMAL)
            csv_writer.writerow(['url', 'username', 'password', 'site_name'])
            for account in accounts:
                csv_writer.writerow([account["url"], account["username"], account["password"], account["site_name"]])
    elif format == "json":
        with open(path, mode='w') as file:
            json.dump(accounts, file, indent=4)
    elif format == "kdbx":
        password = getpass.getpass(prompt='Please provide your .kdbx database password: ')
        with PyKeePass(path, password=password) as kp:
            for account in accounts:
                kp.add_entry(kp.root_group, account["site_name"], account["username"], account["password"],
                             account["url"], "Imported from Keyn")
            kp.save(path)
    else:
        for account in accounts:
            click.echo("-------------------------")
            click.echo("Id:\t\t%s" % account["id"])
            click.echo("Username:\t%s" % account["username"])
            click.echo("Password:\t%s" % account["password"])
            click.echo("Site:\t\t%s" % account["site_name"])
            click.echo("URL:\t\t%s" % account["url"])
        click.echo("-------------------------")
        click.echo("Account export completed!")


@main.command(name='import')
@click.option('-m', '--mnemonic', nargs=12, help='The 12-word mnemonic')
@click.option('-f', '--format', type=click.Choice(['csv', 'json', 'kdbx']),
              help='The input format. If data is written to a .kdbx database, the path to an existing '
                   '.kdbx database file needs to be provided with -p.', required=True)
@click.option('-p', '--path', type=click.Path(writable=True, allow_dash=True),
              help='The path to where the file should be read from.', required=True)
def import_accounts(mnemonic, format, path):
    if mnemonic:
        seed = crypto.recover(mnemonic)
    else:
        seed = select_seed()

    click.echo("Starting account recovery...")
    password_key, signing_keypair, encryption_key = crypto.derive_keys_from_seed(seed)

    if format == "csv":
        with open(path, mode='r') as file:
            accounts = csv.DictReader(file, fieldnames=["url", "username", "password", "site_name"])
            next(accounts, None)
            for account in accounts:
                upload_account_data(account["url"], account["username"], account["password"], account["site_name"],
                                    password_key, signing_keypair, encryption_key)
    elif format == "json":
        with open(path, mode='r') as file:
            for account in json.load(file):
                upload_account_data(account["url"], account["username"], account["password"], account["site_name"],
                                    password_key, signing_keypair, encryption_key)
    elif format == "kdbx":
        password = getpass.getpass(prompt='Please provide your .kdbx database password: ')
        with PyKeePass(path.name, password=password) as kp:
            for account in kp.entries:
                upload_account_data(account.url, account.username, account.password,
                                    account.title, password_key, signing_keypair, encryption_key)
    click.echo("Your accounts have been uploaded successfully!")
    click.echo("Please write down your mnemonic: %s" % " ".join(crypto.mnemonic(seed)))


@main.command(name='delete')
@click.option('-m', '--mnemonic', nargs=12, help='The 12-word mnemonic', prompt="Please enter the mnemonic: ",
              hide_input=True)
@click.confirmation_option(prompt='Are you sure you want to delete this seed and all its associated accounts?')
def delete_accounts(mnemonic):
    click.echo("Deleting seed...")
    _, signing_keypair, _ = crypto.derive_keys_from_seed(crypto.recover(mnemonic))
    api.delete_seed(signing_keypair)
    click.echo("The seed was successfully deleted.")


@main.group()
def account():
    pass


@account.command(name='edit')
@click.option('-m', '--mnemonic', nargs=12, help='The 12-word mnemonic')
@click.option('-id', help='The id of the account you want to edit.')
def edit_account(mnemonic, id):
    if mnemonic:
        seed = crypto.recover(mnemonic)
    else:
        seed = crypto.recover(obtain_mnemonic())

    password_key, signing_keypair, decryption_key = crypto.derive_keys_from_seed(seed)
    encrypted_accounts_data = api.get_backup_data(signing_keypair)
    if not encrypted_accounts_data.items():
        click.echo("This seed does not exist. Exiting..")
        sys.exit(1)

    accounts = decrypt_accounts(encrypted_accounts_data.items(), password_key, decryption_key)
    if not id:
        account = pick_account(accounts)
    else:
        account = next(x for x in accounts if x["id"] == id)

    new_username = click.prompt('Enter a new username or press enter to skip (current: %s)' % account["username"],
                                default="", show_default=False)
    if new_username and click.confirm("Are you sure you want to update the username to \"%s\"?" % new_username):
        account["username"] = new_username
        click.echo("Username updated!")

    new_password = click.prompt('Enter a new password or press enter to skip', confirmation_prompt=True, default="",
                                show_default=False, hide_input=True)
    if new_password:
        account["index"] += 1
        account["password"] = new_password
        click.echo("Password updated!")

    new_site_name = click.prompt('Enter a new site name or press enter to skip (current: %s)' % account["site_name"],
                                 default="", show_default=False)
    if new_site_name and click.confirm("Are you sure you want to update the username to \"%s\"?" % new_site_name):
        account["site_name"] = new_site_name
        click.echo("Site name updated!")

    new_url = click.prompt('Enter a new URL or press enter to skip (current: %s)' % account["url"], default="",
                           show_default=False)
    if new_url and click.confirm("Are you sure you want to update the username to \"%s\"?" % new_url):
        account["url"] = new_url
        click.echo("URL updated!")

    upload_account_data(account["url"], account["username"], account["password"], account["site_name"],
                        password_key, signing_keypair, decryption_key, account["id"], account["index"])


@account.command(name='delete')
@click.option('-m', '--mnemonic', nargs=12, help='The 12-word mnemonic')
@click.option('-id', help='The id of the account you want to edit / delete.')
def delete_account(mnemonic, id):
    if mnemonic:
        seed = crypto.recover(mnemonic)
    else:
        seed = crypto.recover(obtain_mnemonic())

    password_key, signing_keypair, decryption_key = crypto.derive_keys_from_seed(seed)
    encrypted_accounts_data = api.get_backup_data(signing_keypair)
    if not encrypted_accounts_data.items():
        click.echo("This seed does not exist. Exiting..")
        sys.exit(1)

    accounts = decrypt_accounts(encrypted_accounts_data.items(), password_key, decryption_key)
    if not id:
        account = pick_account(accounts)
    else:
        account = next(x for x in accounts if x["id"] == id)

    click.echo("Deleting account...")
    _, signing_keypair, _ = crypto.derive_keys_from_seed(seed)
    api.delete_account(account["id"], signing_keypair)
    click.echo("The account was successfully deleted.")


def pick_account(accounts):
    click.echo("Which account do you want to edit / delete?")
    for i, account in enumerate(accounts, start=1):
        click.echo("[%d]: %s" % (i, account["site_name"]))
    choices = list(map(lambda x: "%d" % x, range(1, len(accounts) + 1)))
    selection = click.prompt('Answer', type=click.Choice(choices), show_choices=False)
    return accounts[int(selection) - 1]


def create_seed():
    seed = crypto.generate_seed()
    _, signing_keypair, _ = crypto.derive_keys_from_seed(seed)
    api.create_backup_data(signing_keypair)

    return seed


def decrypt_accounts(encrypted_accounts, password_key, decryption_key):
    accounts = []

    # Recovers the backup data from the server and decrypts it
    for id, encrypted_account in encrypted_accounts:
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
                         "site_name": site["name"], "index": index})

    return accounts


def upload_account_data(url, username, password, site_name, password_key, signing_keypair, encryption_key,
                        account_id = None, password_index = 0):
    site_id, secondary_site_id = crypto.get_site_ids(url)
    site_id = site_id.decode("utf-8")
    ppd = api.get_ppd(site_id)
    if account_id is None:
        account_id = crypto.generic_hash_string(("%s_%s" % (site_id, username)))
    generator = PasswordGenerator(username, site_id, password_key, ppd)
    offset = generator.calculate_offset(password_index, password)
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
    mnemonic = click.prompt("Please enter the twelve word mnemonic")
    try:
        words = mnemonic.split(" ")
        if len(words) != 12:
            raise Exception("The mnemonic should consist of 12 words")
        return words
    except Exception as exception:
        print("\nError: %s\n" % exception.args)
        return obtain_mnemonic()


def select_seed():
    selection = click.prompt('''
The mnemonic was not provided. What do you want to do?

[1] Generate a new seed
[2] Enter an existing mnemonic

Answer''', type=click.Choice(['1', '2']), show_choices=False)
    if selection == '1':
        return create_seed()
    else:
        return crypto.recover(obtain_mnemonic())


if __name__ == '__main__':
    main()
