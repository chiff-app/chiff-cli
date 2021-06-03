from chiff.ssh_key import KeyType
from chiff.crypto import from_base64, to_base64
from chiff.utils import check_response, length_and_data, ssh_reader
from chiff.session import Session
import click
from daemon import DaemonContext
import socket
import os


from chiff.constants import APP_NAME, FILE_NAME, MessageType, SSHMessageType


def start():
    """Start the SSH socket"""
    with DaemonContext():
        filename = "%s/%s" % (click.get_app_dir(APP_NAME), FILE_NAME)
        if os.path.exists(filename):
            os.remove(filename)
        org_file_name = os.environ.get("SSH_AUTH_SOCK")
        if org_file_name.endswith(FILE_NAME):
            org_file_name = None
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(filename)
        sock.listen(1)
        print("Starting Chiff daemon...")
        while True:
            connection = sock.accept()[0]
            try:
                org_sock = None
                if org_file_name:
                    org_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    org_sock.connect(org_file_name)
                handle_connection(connection, org_sock)
            except Exception as err:
                connection.sendall(
                    length_and_data(SSHMessageType.SSH_AGENT_FAILURE.raw)
                )
                raise err
            finally:
                if org_sock:
                    org_sock.close()
                connection.close()


def forward(connection, org_sock):
    """Forward a message the original ssh agent."""
    data = connection.recv(2048)
    if data and len(data) >= 5:
        org_sock.sendall(data)
        resp = org_sock.recv(2048)
        connection.sendall(resp)
        return forward(connection, org_sock)


def get_original_identities(org_sock, data):
    """Get all SSH identities from the original agent."""
    if not org_sock:
        return 0, None
    org_sock.sendall(data)
    resp = org_sock.recv(2048)
    type = resp and len(resp) >= 5 and resp[4]
    if type == SSHMessageType.SSH_AGENT_IDENTITIES_ANSWER.value:
        length = int.from_bytes(resp[5:9], "big")
        return length, resp[9:]
    else:
        return 0, None


def handle_identities_request(connection, data, org_sock):
    """Get all Chiff SSH identities from the session and append the
    original SSH identities."""
    session = Session.get()
    identities = session.get_ssh_identities()
    original_count, original_identities = get_original_identities(org_sock, data)
    total_count = len(identities) + original_count
    response = SSHMessageType.SSH_AGENT_IDENTITIES_ANSWER.raw + total_count.to_bytes(
        4, "big", signed=False
    )
    for identity in identities:
        response += identity.ssh_identity()
    if original_count > 0:
        response += original_identities
    connection.sendall(length_and_data(response))


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
    identity = session.get_ssh_identity(key, key_type)
    if not identity and org_sock:
        org_sock.sendall(data)
        resp = org_sock.recv(2048)
        connection.sendall(resp)
        return
    request = {
        "a": identity.id,
        "r": MessageType.SSH_LOGIN.value,
        "n": identity.name,
        "c": to_base64(challenge),
    }
    response = session.send_request(request)
    if check_response(response):
        response = (
            SSHMessageType.SSH_AGENT_SIGN_RESPONSE.raw
            + identity.encode_signature(from_base64(response["s"]))
        )
        connection.sendall(length_and_data(response))
    else:
        raise Exception("Request denied")


def handle_connection(connection, org_sock):
    """Handle socket connection. Forwards to original socket if Chiff doesn't
    support the type of request"""
    data = connection.recv(2048)
    type = data and len(data) >= 5 and data[4]
    if not type:
        return
    elif type == SSHMessageType.SSH_AGENTC_REQUEST_IDENTITIES.value:
        handle_identities_request(connection, data, org_sock)
        return handle_connection(connection, org_sock)
    elif type == SSHMessageType.SSH_AGENTC_SIGN_REQUEST.value:
        handle_signing(connection, data, org_sock)
        return handle_connection(connection, org_sock)
    elif org_sock:
        # Chiff doesn't support this request type, delegate to original SSH agent.
        return forward(connection, org_sock)


if __name__ == "__main__":
    start()
