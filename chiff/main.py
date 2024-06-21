from chiff.setup import chiff_init
from chiff.ssh_key import Key, KeyType
from chiff.utils import check_response
from chiff.crypto import from_base64
from chiff.utils import get_site_ids
import click
import json
import csv

from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError


from chiff import crypto
from chiff.constants import MessageType

from tabulate import tabulate
from chiff.session import Session
from pathlib import Path
from chiff.constants import APP_NAME


@click.version_option()
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
            click.echo("\nNew session successfully created!")
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
    if not check_response(response, click.echo):
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
    prompt="Enter a the password",
    hide_input=True,
    required=True,
    confirmation_prompt=True,
    help="The password of the account you want to add. Will be prompted"
    "for if not provided",
)
@click.option("-n", "--notes", help="The notes of the account you want to add")
def add(username, url, name, password, notes):
    """Add a new account with the provided data."""
    session = get_session(True)[0]
    site_id = get_site_ids(url)[0]
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
    if check_response(response, click.echo):
        id = crypto.generic_hash_string(("%s_%s" % (site_id, username)))
        click.echo(f"Account created with id {id}")


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
    prompt=True,
    hide_input=True,
    prompt_required=False,
    default=None,
    confirmation_prompt=True,
    help="The password of the account you want to update. Will be prompted for if "
    "argument is not provided",
)
@click.option("-n", "--notes", help="The notes of the account you want to update")
def update(id, username, url, name, password, notes):
    """Get data from a currently paired device. Only returns the password by default"""
    session, accounts = get_session(False)
    if id not in accounts:
        raise Exception("Account not found.")
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
    if check_response(response, click.echo):
        click.echo("Account successfully updated.")


@main.command(short_help="Shows the status of the current session.")
def status():
    """Shows the status of the current session and an overview of all accounts."""
    session = Session.get()
    if session:
        click.echo(f"There is an active session with id {session.id}.\n")
        accounts, identities = session.get_session_data()
        click.echo("Accounts:")
        accounts = list(
            map(
                lambda x: {
                    "ID": x["id"],
                    "Username": x["username"],
                    "Name": x["sites"][0]["name"],
                    "URL": x["sites"][0]["url"],
                },
                accounts.values(),
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
                identities,
            )
        )
        if len(identities) > 0:
            click.echo("SSH keys:")
            print(tabulate(identities, headers="keys", tablefmt="psql"))
    else:
        click.echo("There is no active session.")


@main.command(short_help="Gets all accounts of the current session.")
@click.option(
    "-a",
    "--alfred",
    is_flag=True,
    help="Return account in JSON format that Alfred understands",
)
def accounts(alfred):
    session = Session.get()
    accounts, _ = session.get_session_data()
    if alfred:
        accounts = list(
            map(
                lambda x: {
                    "uid": x["id"],
                    "title": x["sites"][0]["name"],
                    "subtitle": x["username"],
                    "match": "%s %s %s"
                    % (
                        x["sites"][0]["name"],
                        x["sites"][0]["url"],
                        x["username"],
                    ),
                    "arg": x["id"],
                },
                accounts.values(),
            )
        )
        output = {"items": accounts}
        print(json.dumps(output))
    else:
        print(json.dumps(accounts))


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
        new_accounts.extend(parse_csv(path, skip))
    elif format == "json":
        new_accounts.extend(parse_json(path))
    elif format == "kdbx":
        new_accounts.extend(parse_kdbx(path))
    click.echo(f"Sending {len(new_accounts)} accounts to phone...")
    response = session.send_bulk_accounts(new_accounts)
    if check_response(response, click.echo):
        click.echo(f"{len(new_accounts)} accounts successfully imported!")


@main.command(name="ssh-keygen", short_help="Generate a new SSH key on your phone.")
@click.option("-n", "--name", required=True, help="The label for this SSH key.")
@click.option(
    "-a",
    "--algorithm",
    type=click.Choice(
        [
            KeyType.ED25519.name.lower(),
            KeyType.ECDSA256.name.lower(),
        ]
    ),
    help="The algorithm to use. On iOS, ECDSA256 is generated in the secure enclave. "
    "This implies that you will be unable to recover the key with your seed! "
    "This also applies to Android to maintain interoperability. "
    "Default algorithm is ed25519.",
)
def create_ssh_key(name, algorithm):
    click.echo(f"Requesting to generate new SSH key {name}")
    session = get_session(False)[0]
    request = {
        "r": MessageType.SSH_CREATE.value,
        "n": name,
    }
    key_type = None
    if algorithm == KeyType.ECDSA256.name.lower():
        key_type = KeyType.ECDSA256
        request["g"] = [-7]  # Cose identifier for ECDSA256
    else:
        key_type = KeyType.ED25519
        request["g"] = [-8]  # Cose identifier for EdDSA
    response = session.send_request(request)
    if check_response(response, click.echo):
        click.echo("SSH key created:")
        identity = Key(response["a"], from_base64(response["pk"]), key_type, name)
        click.echo(str(identity))


main.add_command(chiff_init, "init")


def parse_csv(path, skip):
    new_accounts = []
    with click.open_file(path, mode="r") as file:
        accounts = csv.DictReader(
            file, fieldnames=["site_name", "url", "username", "password", "notes"]
        )
        if skip:
            next(accounts, None)
        for account in accounts:
            site_id = get_site_ids(account["url"])[0]
            new_accounts.append(
                {
                    "u": account["username"],
                    "p": account["password"],
                    "n": account["site_name"],
                    "s": site_id,
                    "l": account["url"],
                    "y": account["notes"],
                }
            )
    return new_accounts


def parse_json(path):
    new_accounts = []
    with click.open_file(path, mode="r") as file:
        for account in json.load(file):
            site_id = get_site_ids(account["url"])[0]
            new_accounts.append(
                {
                    "u": account["username"],
                    "p": account["password"],
                    "n": account["title"],
                    "s": site_id,
                    "l": account["url"],
                    "y": account["notes"],
                }
            )
    return new_accounts


def parse_kdbx(path):
    new_accounts = []
    password = click.prompt(
        "Please provide your .kdbx database password",
        default="",
        show_default=False,
        hide_input=True,
    )
    try:
        with PyKeePass(path, password=password) as kp:
            for account in kp.entries:
                site_id = get_site_ids(account.url)[0]
                new_accounts.append(
                    {
                        "u": account.username,
                        "p": account.password,
                        "n": account.title,
                        "s": site_id,
                        "l": account.url,
                        "y": account.notes,
                    }
                )
        return new_accounts
    except CredentialsError:
        print("The keepass password appears to be incorrect. Exiting")
        exit(1)


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
        return session, {}


if __name__ == "__main__":
    main()
