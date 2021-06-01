from chiff.constants import MessageType
import click


def check_response(response):
    if response["t"] == MessageType.REJECT.value:
        click.echo("Request rejected on phone..")
        return False
    elif response["t"] == MessageType.ERROR.value:
        if "e" in response:
            click.echo("Request failed: %s." % response["e"])
            return False
        else:
            click.echo("Request failed.")
            return False
    return True


def length_and_data(data):
    return len(data).to_bytes(4, "big", signed=False) + data
