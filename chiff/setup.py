import io
import os
import click
from chiff.constants import (
    APP_NAME,
    SOCKET_NAME,
    launchagent_plist,
    ssh_config,
    systemd_service,
)
from pathlib import Path
import subprocess
from sys import platform


@click.command("init", short_help="Set-up the ssh-agent")
def chiff_init():
    """Set up the ssh-agent for Chiff. This starts a background process that forwards
    SSH-requests to your phone."""
    if platform != "linux" and platform != "linux2" and platform != "darwin":
        click.echo("Your platform is not supported yet :(.")
        return
    app_dir = click.get_app_dir(APP_NAME)
    click.echo(
        "This script sets up the Chiff ssh-agent for your shell. Alternatively, "
        + "you can run chiffd to start the Chiff daemon manually. "
    )  # IdentityAgent "{app_dir}/{socket}"
    if click.confirm(
        "Do you want start the ssh-agent automatically after every reboot?",
        default=True,
    ):
        if platform == "darwin":
            setup_boot_darwin(app_dir)
        else:
            setup_boot_linux()
    if click.confirm(
        "Do you want add set Chiff as the IdentityAgent \
for all hosts in your ~/.ssh/config file?",
        default=True,
    ):
        add_to_ssh_config(app_dir)
    click.echo("All set up!")


def add_to_ssh_config(app_dir):
    ssh_path = Path.home() / ".ssh" / "config"
    content = ssh_config.format(app_dir=app_dir, socket=SOCKET_NAME)
    with click.open_file(ssh_path, mode="a+") as f:
        f.seek(0)
        if content not in f.read():
            f.seek(0, io.SEEK_END)
            f.write(content)


def setup_boot_darwin(app_dir):
    launchagent_path = (
        Path.home() / "Library" / "LaunchAgents" / "co.chiff.chiffd.plist"
    )
    with click.open_file(launchagent_path, mode="w+") as f:
        f.write(
            launchagent_plist.format(
                path=Path.home() / ".local" / "bin" / "chiffd", app_dir=app_dir
            )
        )
    subprocess.run(["launchctl", "load", "-w", launchagent_path])
    click.echo("Chiff daemon installed!")


def setup_boot_linux():
    systemd_path = Path.home() / ".config" / "systemd" / "user"
    os.makedirs(systemd_path, exist_ok=True)
    with click.open_file(systemd_path / "chiff.service", mode="w+") as f:
        f.write(systemd_service.format(path=Path(".local", "bin", "chiffd")))
    subprocess.run(["systemctl", "--user", "--now", "enable", "chiff"])
    click.echo("Chiff daemon installed!")


def check_ssh_config(app_dir):
    ssh_path = Path.home() / ".ssh" / "config"
    content = ssh_config.format(app_dir=app_dir, socket=SOCKET_NAME)
    with click.open_file(ssh_path, mode="r") as f:
        return content in f.read()
