from chiff.ssh_key import KeyType
from chiff.crypto import from_base64, to_base64
from chiff.utils import check_response, length_and_data
from chiff.session import Session
import click
import daemon
import socket
import os


from chiff.constants import APP_NAME, MessageType, SSHMessageType


def start():
    with daemon.DaemonContext():
        filename = "%s/socket.ssh" % click.get_app_dir(APP_NAME)
        if os.path.exists(filename):
            os.remove(filename)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(filename)
        sock.listen(1)
        print("Starting Chiff daemon...")
        while True:
            connection, client_address = sock.accept()
            try:
                handle_connection(connection)
            except Exception as err:
                connection.sendall(
                    length_and_data(SSHMessageType.SSH_AGENT_FAILURE.raw)
                )
                raise err
            finally:
                # Clean up the connection
                connection.close()


def handle_connection(connection):
    data = connection.recv(2048)
    type = data and len(data) >= 5 and data[4]
    if type == SSHMessageType.SSH_AGENTC_REQUEST_IDENTITIES.value:
        session = Session.get()
        identities = session.get_ssh_identities()
        response = SSHMessageType.SSH_AGENT_IDENTITIES_ANSWER.raw + len(
            identities
        ).to_bytes(4, "big", signed=False)
        for identity in identities:
            response += identity.ssh_identity()
        connection.sendall(length_and_data(response))
        return handle_connection(connection)
    elif type == SSHMessageType.SSH_AGENTC_SIGN_REQUEST.value:
        hash_data, challenge, flags = ssh_reader(data[5:])
        hash_reader = ssh_reader(hash_data)
        key = None
        key_type = KeyType(next(hash_reader).decode("utf-8"))
        if key_type is KeyType.ECDSA256:
            next(hash_reader)  # Curve
        key = next(hash_reader)
        session = Session.get()
        identity = session.get_ssh_identity(key, key_type)
        if not identity:
            raise Exception("SSH key not found")
        request = {
            "a": identity.id,
            "r": MessageType.SSH_LOGIN.value,
            "c": to_base64(challenge),
        }
        response = session.send_request(request)
        if check_response(response):
            response = (
                SSHMessageType.SSH_AGENT_SIGN_RESPONSE.raw
                + identity.encode_signature(from_base64(response["s"]))
            )
            connection.sendall(length_and_data(response))
            return handle_connection(connection)
        else:
            raise Exception("Request denied")


def ssh_reader(data):
    remaining = data
    while len(remaining) > 0:
        length_chunk = remaining[:4]
        length = int.from_bytes(length_chunk, "big")
        data_chunk = remaining[4 : length + 4]
        yield data_chunk
        remaining = remaining[length + 4 :]


if __name__ == "__main__":
    start()
