from enum import Enum

APP_NAME = "Chiff"
SOCKET_NAME = "chiff-socket.ssh"

systemd_service = """\
[Unit]
Description=Chiff Daemon

[Service]
Type=simple
Restart=always
RestartSec=1
ExecStart=%h/{path}

[Install]
WantedBy=multi-user.target
"""

launchagent_plist = """\
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" \
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>co.chiff.chiffd</string>
        <key>ProgramArguments</key>
        <array>
            <string>{path}</string>
        </array>
        <key>StandardErrorPath</key>
        <string>{app_dir}/chiffd.log</string>
        <key>KeepAlive</key>
        <true/>
    </dict>
</plist>
"""

ssh_config = """\

# Added by Chiff
Host *
   IdentityAgent "{app_dir}/{socket}"

"""


class MessageType(Enum):
    PAIR = 0
    LOGIN = 1
    REGISTER = 2
    CHANGE = 3
    ADD = 4
    ADD_BULK = 5
    ADD_AND_LOGIN = 6
    END = 7
    ACKNOWLEDGE = 8
    FILL = 9
    REJECT = 10
    ERROR = 11
    PREFERENCES = 12
    ADD_TO_EXISTING = 13
    DISABLED = 14
    ADMIN_LOGIN = 15
    WEBAUTHN_CREATE = 16
    WEBAUTHN_LOGIN = 17
    BULK_LOGIN = 18
    GET_DETAILS = 19
    UPDATE_ACCOUNT = 20
    SSH_CREATE = 23
    SSH_LOGIN = 24


class SSHMessageType(Enum):
    SSH_AGENTC_REQUEST_IDENTITIES = 11
    SSH_AGENTC_SIGN_REQUEST = 13
    SSH_AGENTC_ADD_IDENTITY = 17
    SSH_AGENTC_REMOVE_IDENTITY = 18
    SSH_AGENTC_REMOVE_ALL_IDENTITIES = 19
    SSH_AGENTC_ADD_ID_CONSTRAINED = 25
    SSH_AGENTC_ADD_SMARTCARD_KEY = 20
    SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21
    SSH_AGENTC_LOCK = 22
    SSH_AGENTC_UNLOCK = 23
    SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26
    SSH_AGENTC_EXTENSION = 27
    SSH_AGENT_FAILURE = 5
    SSH_AGENT_SUCCESS = 6
    SSH_AGENT_IDENTITIES_ANSWER = 12
    SSH_AGENT_SIGN_RESPONSE = 14

    @property
    def raw(self):
        return int.to_bytes(self.value, 1, "big")
