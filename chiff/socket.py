from chiff.ssh_key import KeyType
from chiff.crypto import from_base64, to_base64
from chiff.utils import check_response, length_and_data, ssh_reader
from chiff.session import Session
import click
from daemon import DaemonContext
from pathlib import Path
import socket
import os
import logging
import errno

from chiff.constants import APP_NAME, SOCKET_NAME, MessageType, SSHMessageType


@click.command()
@click.option("-d", "--daemon", is_flag=True, help="Run as a daemon process.")
@click.option("-v", "--verbose", count=True)
def main(daemon, verbose):
    level = logging.WARNING
    if verbose == 1:
        level = logging.INFO
    elif verbose > 1:
        level = logging.DEBUG
    logging.basicConfig(format="[%(levelname)s]\t%(asctime)s\t%(message)s", level=level)
    if daemon:
        with DaemonContext():
            start()
    else:
        start()


def start():
    """Start the Chiff daemon."""
    Path(click.get_app_dir(APP_NAME)).mkdir(parents=True, exist_ok=True)
    filename = f"{click.get_app_dir(APP_NAME)}/{SOCKET_NAME}"
    if os.path.exists(filename):
        os.remove(filename)
    org_file_name = os.environ.get("SSH_AUTH_SOCK")
    if org_file_name and org_file_name.endswith(SOCKET_NAME):
        org_file_name = None
    logging.info(f"Original ssh-agent socket: {org_file_name}")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(filename)
    sock.listen(1)
    logging.info("Starting Chiff daemon.")
    while True:
        connection = sock.accept()[0]
        try:
            org_sock = None
            if org_file_name:
                logging.info("Setting up original socket.")
                org_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                org_sock.connect(org_file_name)
            else:
                logging.info("Original socket not found.")
            handle_connection(connection, org_sock)
        except OSError as err:
            if err.errno == errno.EPIPE:
                logging.error(err)
            else:
                raise
        except Exception as err:
            logging.error(err)
            connection.sendall(length_and_data(SSHMessageType.SSH_AGENT_FAILURE.raw))
        finally:
            if org_sock:
                org_sock.close()
            connection.close()
            logging.info("Closing connection.")


def forward(data, connection, org_sock):
    """Forward a message the original ssh agent."""
    if data and len(data) >= 5:
        logging.info(
            "Forwarding message of type {type} to original agent.".format(type=data[4])
        )
        org_sock.sendall(data)
        resp = org_sock.recv(2048)
        connection.sendall(resp)
        return forward(connection.recv(2048), connection, org_sock)


def get_original_identities(org_sock, data):
    """Get all SSH identities from the original agent."""
    if not org_sock:
        return 0, None
    logging.info("Getting all SSH identities from the original agent.")
    org_sock.sendall(data)
    resp = org_sock.recv(2048)
    type = resp and len(resp) >= 5 and resp[4]
    if type == SSHMessageType.SSH_AGENT_IDENTITIES_ANSWER.value:
        length = int.from_bytes(resp[5:9], "big")
        logging.info(
            "Obtained {count} identities from original agent".format(count=length)
        )
        return length, resp[9:]
    else:
        logging.info("Obtained no identities from original agent")
        return 0, None


def handle_identities_request(connection, data, org_sock):
    """Get all Chiff SSH identities from the session and append the
    original SSH identities."""
    session = Session.get()
    if not session:
        if org_sock:
            logging.info("No active session, forwarding request.")
            return forward(data, connection, org_sock)
        else:
            logging.info("No active session and no original agent, ending.")
            return
    identities = session.get_ssh_identities()
    logging.info("Obtained {count} identities from Chiff".format(count=len(identities)))
    original_count, original_identities = get_original_identities(org_sock, data)
    total_count = len(identities) + original_count
    logging.info("Obtained {count} identities in total".format(count=total_count))
    response = SSHMessageType.SSH_AGENT_IDENTITIES_ANSWER.raw + total_count.to_bytes(
        4, "big", signed=False
    )
    for identity in identities:
        response += identity.ssh_identity()
    if original_count > 0:
        response += original_identities
    connection.sendall(length_and_data(response))
    return handle_connection(connection, org_sock)


def handle_signing(connection, data, org_sock):
    """Handle a signing request. First checks if the key is present in Chiff,
    otherwise forwards to the original ssh-agent."""
    hash_data, challenge, flags = ssh_reader(data[5:])
    hash_reader = ssh_reader(hash_data)
    key = None
    key_type = KeyType(next(hash_reader).decode("utf-8"))
    if key_type is KeyType.ECDSA256:
        next(hash_reader)  # Curve
    key = next(hash_reader)
    session = Session.get()
    if not session:
        if org_sock:
            logging.info("No active session, forwarding request.")
            return forward(data, connection, org_sock)
        else:
            logging.info("No active session and no original agent, ending.")
            return
    identity = session.get_ssh_identity(key, key_type)
    if not identity:
        if org_sock:
            logging.info("Request key not found in session, forwarding request.")
            return forward(data, connection, org_sock)
        else:
            logging.info(
                "Request key not found in session and no original agent, ending."
            )
            return
    request = {
        "a": identity.id,
        "r": MessageType.SSH_LOGIN.value,
        "n": identity.name,
        "c": to_base64(challenge),
    }
    logging.info("Sending request to phone.")
    response = session.send_request(request, 9)
    if check_response(response, logging.info):
        response = (
            SSHMessageType.SSH_AGENT_SIGN_RESPONSE.raw
            + identity.encode_signature(from_base64(response["s"]))
        )
        logging.info("Response received from phone.")
        connection.sendall(length_and_data(response))
        return handle_connection(connection, org_sock)
    else:
        raise Exception("Request failed")


def handle_connection(connection, org_sock):
    """Handle socket connection. Forwards to original socket if Chiff doesn't
    support the type of request"""
    data = connection.recv(2048)
    type = data and len(data) >= 5 and data[4]
    if not type:
        return
    elif type == SSHMessageType.SSH_AGENTC_REQUEST_IDENTITIES.value:
        return handle_identities_request(connection, data, org_sock)
    elif type == SSHMessageType.SSH_AGENTC_SIGN_REQUEST.value:
        return handle_signing(connection, data, org_sock)
    elif type == SSHMessageType.SSH_AGENTC_EXTENSION.value:
        # Chiff doesn't support extensions.
        connection.sendall(length_and_data(SSHMessageType.SSH_AGENT_FAILURE.raw))
        return handle_connection(connection, org_sock)
    elif org_sock:
        # Chiff doesn't support this request type, delegate to original SSH agent.
        return forward(data, connection, org_sock)
    else:
        # Chiff doesn't support this request type, send failure message.
        connection.sendall(length_and_data(SSHMessageType.SSH_AGENT_FAILURE.raw))
        return handle_connection(connection, org_sock)


if __name__ == "__main__":
    main()
