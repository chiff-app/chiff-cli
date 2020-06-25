import click
import time
import json

from tabulate import tabulate
from chiff.session import Session
from pathlib import Path
from chiff.seed import seed


APP_NAME = 'Chiff'


@click.group()
def main():
    """This application can be paired with the Chiff app for iOS or Android,
    allowing you to fetch password or notes from your accounts.
    Pair it with your app by using chiff pair.
    """
    pass


@main.command()
def pair():
    """Pair with a new device."""
    Path(click.get_app_dir(APP_NAME)).mkdir(parents=True, exist_ok=True)
    session = Session.get()
    if session:
        if click.confirm("A session already exists. Do you want to end the current session?"):
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


@main.command(short_help="Get data from a currently paired device. Only returns the password by default")
@click.option('-i', '--id',
              help='The id of the account you want the data for')
@click.option('-n', '--notes', is_flag=True,
              help='Return the notes of the account')
@click.option('-j', '--format-json', is_flag=True,
              help='Return account in JSON format ({ "username": "example", "password": "secret", '
                   '"notes": "important note" | undefined })')
@click.option('-s', '--skip', is_flag=True,
              help='Skip fetching the accounts first to check if the account exists.')
def get(id, notes, format_json, skip):
    """Get data from a currently paired device. Only returns the password by default"""
    session = Session.get()
    accounts = None
    if not session:
        if click.confirm("There does not seem to be an active session. Do you want to pair now?"):
            session, accounts = Session.pair()
        else:
            click.echo("Exiting...")
            return
    request = {"a": id, "r": 19, "b": 42, "z": int(time.time() * 1000)}
    if not skip:
        if not accounts:
            accounts = session.get_accounts()
        request["n"] = accounts[id]["sites"][0]["name"]
    else:
        request["n"] = "Unknown"
    response = session.send_request(request)
    if notes:
        if "y" in response:
            print(response["y"], end='')
        else:
            raise Exception("No notes found in response")
    elif format_json:
        result = {"username": accounts[id]["username"], "password": response["p"]}
        if "y" in response:
            result["notes"] = response["y"]
        print(json.dumps(result))
    else:
        if "p" in response:
            print(response["p"], end='')
        else:
            raise Exception("No password found in response.")


@main.command(short_help="Shows the status of the current session and an overview of all accounts.")
def status():
    """Shows the status of the current session and an overview of all accounts."""
    session = Session.get()
    if session:
        click.echo("There is an active session with id %s.\n" % session.id)
        click.echo("Accounts:\n")
        accounts = list(map(lambda x: {"id": x["id"],
                                       "username": x["username"],
                                       "name": x["sites"][0]["name"],
                                       "URL": x["sites"][0]["url"]},
                            session.get_accounts().values()))
        print(tabulate(accounts, headers="keys", tablefmt="github"))
        click.echo("")
    else:
        click.echo("There is no active session.")


main.add_command(seed)

if __name__ == '__main__':
    main()
