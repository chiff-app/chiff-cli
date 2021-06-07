from chiff.setup import chiff_setup
from chiff.ssh_key import Key, KeyType
from chiff.utils import check_response
from chiff.crypto import from_base64
import click
import json
import csv
import getpass

from pykeepass import PyKeePass
from construct import ChecksumError


from chiff import crypto
from chiff.constants import MessageType

from tabulate import tabulate
from chiff.session import Session
from pathlib import Path
from chiff.constants import APP_NAME


@click.group()
def main():
    """This application can be paired with the Chiff app for iOS or Android,
    allowing you to fetch password or notes from your accounts or sign ssh requests.
    Pair it with your app by using `chiff pair`.
    """
    pass


@main.command()
def pair():
    """Pair with a new device."""
    Path(click.get_app_dir(APP_NAME)).mkdir(parents=True, exist_ok=True)
    session = Session.get()
    if session:
        if click.confirm(
            "A session already exists. Do you want to end the current session?"
        ):
            session.end()
            Session.pair()
        else:
            click.echo("Exiting...")
            return
    else:
        Session.pair()
        click.echo("\nSession successfully created!")


@main.command()
def unpair():
    """Unpair from a currently paired device."""
    session = Session.get()
    if session:
        if click.confirm("Are you sure you want to end the current session?"):
            session.end()
        else:
            click.echo("Exiting...")
    else:
        click.echo("There currently does not seem to be an active session.")


@main.command(short_help="Get data from a currently paired device.")
@click.option(
    "-i", "--id", required=True, help="The id of the account you want the data for"
)
@click.option("-n", "--notes", is_flag=True, help="Return the notes of the account")
@click.option(
    "-j",
    "--format-json",
    is_flag=True,
    help='Return account in JSON format ({ "username": "example",'
    ' "password": "secret", "notes": "important note" })',
)
@click.option(
    "-s",
    "--skip",
    is_flag=True,
    help="Skip fetching the accounts first to check if the account exists.",
)
def get(id, notes, format_json, skip):
    """Get data from a currently paired device. Only returns the password by default,
    but you can retrieve the notes by setting the -n flag or
    all data with the -j flag as JSON."""
    session, accounts = get_session(skip)
    request = {"a": id, "r": MessageType.GET_DETAILS.value}
    if not skip:
        request["n"] = accounts[id]["sites"][0]["name"]
    else:
        request["n"] = "Unknown"
    response = session.send_request(request)
    if not check_response(response):
        return
    if notes:
        if "y" in response:
            print(response["y"], end="")
        else:
            raise Exception("No notes found in response")
    elif format_json:
        result = {"username": accounts[id]["username"], "password": response["p"]}
        if "y" in response:
            result["notes"] = response["y"]
        print(json.dumps(result))
    else:
        if "p" in response:
            print(response["p"], end="")
        else:
            raise Exception("No password found in response.")


@main.command(short_help="Add a new account.")
@click.option(
    "-u",
    "--username",
    required=True,
    help="The username of the account you want to add",
)
@click.option(
    "-l", "--url", required=True, help="The URL of the account you want to add"
)
@click.option(
    "-s", "--name", required=True, help="The name of the account you want to add"
)
@click.option(
    "-p",
    "--password",
    help="The password of the account you want to add. Will be prompted"
    "for if not provided",
)
@click.option("-n", "--notes", help="The notes of the account you want to add")
def add(username, url, name, password, notes):
    """Get data from a currently paired device. Only returns the password by default"""
    session = get_session(True)
    if not password:
        password = click.prompt(
            "Enter a new password",
            default="",
            show_default=False,
            confirmation_prompt=True,
            hide_input=True,
        )
    site_id = crypto.get_site_ids(url)[0].decode("utf-8")
    request = {
        "s": site_id,
        "r": MessageType.ADD.value,
        "n": name,
        "l": url,
        "u": username,
        "p": password,
    }
    if notes:
        request["y"] = notes
    response = session.send_request(request)
    if check_response(response):
        click.echo(
            "Account created with id {id}".format(
                id=crypto.generic_hash_string(("%s_%s" % (site_id, username)))
            )
        )


@main.command(short_help="Update an existing account")
@click.option(
    "-i", "--id", required=True, help="The id of the account you want the data for"
)
@click.option("-u", "--username", help="The username of the account you want to update")
@click.option("-l", "--url", help="The URL of the account you want to update")
@click.option("-s", "--name", help="The name of the account you want to update")
@click.option(
    "-p",
    "--password",
    help="The password of the account you want to update. Will be prompted for if "
    "argument is not provided",
)
@click.option("-n", "--notes", help="The notes of the account you want to update")
def update(id, username, url, name, password, notes):
    """Get data from a currently paired device. Only returns the password by default"""
    session, accounts = get_session(False)
    request = {
        "a": id,
        "r": MessageType.UPDATE_ACCOUNT.value,
    }
    request["n"] = accounts[id]["sites"][0]["name"]
    if notes:
        request["y"] = notes
    if username:
        request["u"] = username
    if password:
        request["p"] = password
    if name:
        request["nn"] = name
    if url:
        request["l"] = url
    response = session.send_request(request)
    if check_response(response):
        click.echo("Account successfully updated.")


@main.command(short_help="Shows the status of the current session.")
def status():
    """Shows the status of the current session and an overview of all accounts."""
    session = Session.get()
    if session:
        click.echo("There is an active session with id {id}.\n", format(id=session.id))
        click.echo("Accounts:")
        accounts = list(
            map(
                lambda x: {
                    "ID": x["id"],
                    "Username": x["username"],
                    "Name": x["sites"][0]["name"],
                    "URL": x["sites"][0]["url"],
                },
                session.get_accounts().values(),
            )
        )
        print(tabulate(accounts, headers="keys", tablefmt="psql"))
        click.echo("")
        identities = list(
            map(
                lambda x: {
                    "Fingerprint": x.fingerprint(),
                    "Public key": str(x),
                },
                session.get_ssh_identities(),
            )
        )
        if len(identities) > 0:
            click.echo("SSH keys:")
            print(tabulate(identities, headers="keys", tablefmt="psql"))
    else:
        click.echo("There is no active session.")


@main.command(
    name="import", short_help="Import accounts from a csv, json or kdbx file."
)
@click.option(
    "-f",
    "--format",
    type=click.Choice(["csv", "json", "kdbx"]),
    help="The input format. If data is written to a .kdbx database, the path to an"
    "existing .kdbx database file needs to be provided with -p.",
    required=True,
)
@click.option(
    "-p",
    "--path",
    type=click.Path(writable=True, allow_dash=True),
    help="The path to where the file should be read from.",
    required=True,
)
@click.option(
    "-s",
    "--skip",
    is_flag=True,
    help="Whether the first row should be skipped. Only relevant when format is CSV.",
)
def import_accounts(format, path, skip):
    """Import accounts from csv, json or kdbx (KeePass) file."""
    click.echo("Starting account import...")
    session = get_session(False)[0]
    new_accounts = []
    if format == "csv":
        with click.open_file(path, mode="r") as file:
            accounts = csv.DictReader(
                file, fieldnames=["site_name", "url", "username", "password", "notes"]
            )
            if skip:
                next(accounts, None)
            for account in accounts:
                site_id = crypto.get_site_ids(account["url"])[0]
                new_accounts.append(
                    {
                        "u": account["username"],
                        "p": account["password"],
                        "n": account["site_name"],
                        "s": site_id.decode("utf-8"),
                        "l": account["url"],
                        "y": account["notes"],
                    }
                )
    elif format == "json":
        with click.open_file(path, mode="r") as file:
            for account in json.load(file):
                site_id = crypto.get_site_ids(account["url"])[0]
                new_accounts.append(
                    {
                        "u": account["username"],
                        "p": account["password"],
                        "n": account["title"],
                        "s": site_id.decode("utf-8"),
                        "l": account["url"],
                        "y": account["notes"],
                    }
                )
    elif format == "kdbx":
        password = getpass.getpass(
            prompt="Please provide your .kdbx database password: "
        )
        try:
            with PyKeePass(path, password=password) as kp:
                for account in kp.entries:
                    site_id = crypto.get_site_ids(account.url)[0]
                    new_accounts.append(
                        {
                            "u": account.username,
                            "p": account.password,
                            "n": account.title,
                            "s": site_id.decode("utf-8"),
                            "l": account.url,
                            "y": account.notes,
                        }
                    )
        except ChecksumError:
            print("The keepass password appears to be incorrect. Exiting")
            exit(1)
    click.echo("Sending %d accounts to phone..." % len(new_accounts))
    response = session.send_bulk_accounts(new_accounts)
    if check_response(response):
        click.echo("%d accounts successfully imported!" % len(new_accounts))


@main.command(name="ssh-keygen", short_help="Generate a new SSH key on your phone.")
@click.option("-n", "--name", required=True, help="The label for this SSH key.")
@click.option(
    "-e",
    "--enclave",
    is_flag=True,
    help="Whether the key should be created in the Secure Enclave (only applies to iOS). \
        This implies that you will be unable to recover the key with your seed!",
)
def create_ssh_key(name, enclave):
    click.echo("Requesting to generate new SSH key {name}".format(name=name))
    session = get_session(False)[0]
    request = {
        "r": MessageType.SSH_CREATE.value,
        "n": name,
    }
    key_type = None
    if enclave:
        key_type = KeyType.ECDSA256
        request["g"] = [-7]  # Cose identifier for ECDSA256
    else:
        key_type = KeyType.ED25519
        request["g"] = [-8]  # Cose identifier for EdDSA
    response = session.send_request(request)
    if check_response(response):
        click.echo("SSH key created:")
        identity = Key(response["a"], from_base64(response["pk"]), key_type, name)
        click.echo(str(identity))


main.add_command(chiff_setup, "setup")


def get_session(skip):
    session = Session.get()
    if not session:
        if click.confirm(
            "There does not seem to be an active session. Do you want to pair now?"
        ):
            return Session.pair()
        else:
            click.echo("Exiting...")
            exit(0)
    elif not skip:
        accounts = session.get_accounts()
        return session, accounts
    else:
        return session


if __name__ == "__main__":
    main()
