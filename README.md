# Chiff CLI

![Current version](https://img.shields.io/github/v/tag/chiff-app/chiff-cli?sort=semver) ![PyPI](https://img.shields.io/pypi/v/chiff) [![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![Python](https://github.com/chiff-app/chiff-cli/actions/workflows/test.yml/badge.svg)](https://github.com/chiff-app/chiff-cli/actions/workflows/test.yml) ![Twitter Follow](https://img.shields.io/twitter/follow/Chiff_App?style=social)

![Chiff logo](https://chiff.app/assets/images/logo.svg)

Chiff is a tool that allows you to store secrets in the secure storage of your phone and retrieve them when you need them by authorizing a request.
You can pair the app with multiple clients (browser extension or shell).

## Motivation

SSH keys are stored in plaintext on your computer by default, unless you choose a passphrase. However, it can be cumbersome to retype your password every time you need to decrypt your keys. The same applies to credentials for various CLIs. For example, [official AWS CLI documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html) recommends to store your credentials in `~/.aws/credentials`.

With Chiff, you can leverage the biometric capabilities and secure storage of your phone to authenticate to services on your computer. You can pair with multiple shells to be able to retrieve credentials there.

## Security model

All sensitive data is stored encrypted on your phone. When needed, it is decrypted (by authenticating to your phone with biometrics) and sent to the browser/cli, where it is filled in the website. An end-to-end encrypted channel is established between browser/cli by scanning a QR-code. This means confidentiality is ensured, even though the server (mainly serving as message broker and backup storage) is modelled as an untrusted entity.

## Related projects

This is the repository for the _CLI_.  
For the _Android app_, see [chiff-android](https://github.com/chiff-app/chiff-android) (_Coming soon_).  
For the _Browser extension_, see [chiff-browser](https://github.com/chiff-app/chiff-browser) (_Coming soon_).  
For the _iOS app_, see [chiff-ios](https://github.com/chiff-app/chiff-ios).
For the _iOS app core_, see [chiff-ios](https://github.com/chiff-app/chiff-ios-core).

## Installation

Package is available on PyPi.
The easiest way is to use [pipx](https://github.com/pypa/pipx): `pipx install chiff`. This should install `chiff` and `chiffd` to your shell.

## Installation from source

After cloning the project, you can build it using [poetry](https://python-poetry.org).
Run `poetry build` to build the source package and wheel binary. Install the script with `pipx install ./`. This should install `chiff` and `chiffd` to your shell.

## Set-up

To set up the ssh-agent, you can run `chiff init`. This sets up `chiffd` as a background script and adds the following to your `~/.ssh/config`:

```
Host *
   IdentityAgent "~/Library/Application Support/Chiff/chiff-socket.ssh"
```

You can also set this up manually. For example, if you only want to use Chiff for specific hosts you can set

`IdentityAgent "~/Library/Application Support/Chiff/chiff-socket.ssh"`

for hosts that should use Chiff.

### Get the Chiff app

Get the Chiff app on App Store or Play Store:

[<img src="https://chiff.app/assets/images/app-store.svg" />](https://apps.apple.com/app/id1361749715)
[<img src="https://chiff.app/assets/images/play-store.svg" height="40" />](https://play.google.com/store/apps/details?id=io.keyn.keyn)

Follow the onboarding instructions in the app. When the app asks you to pair with your browser, you can pair with this CLI instead (see [Pairing](#pairing)).

## Usage

### Pairing

The first thing you should do is pair with your phone with `chiff pair`. This generates a QR-code that you can scan with
the Chiff app. After pairing, you can see your accounts with `chiff status`.
You can pair with one app at the same time, so if you want to pair with another phone, run `chiff unpair` to delete the
session.

### Generating an SSH key

You can generate an SSH key on your phone with `chiff ssh-keygen -n <name>`. This sends a request to your phone to generate the key.
Chiff can generate two types of keys:

1. **Ed25519**: This is the default algorithm. The key is backed up on your chiff seed and can be restored. _The key is not generated in the Secure Enclave_.
2. **ECDSA256**: This key can be generated with the `-e` flag and is generated in the Secure Enclave (iOS only). This is more secure, _but the key won't be restored with your backup_.

Pick whatever suits your needs. Generating the key will directly print out the ssh public key, but you can always find this by running `chiff status`.

### Logging in with ssh

Make sure `chiffd` is running and the `IdentityAgent` is set up in your `~/.ssh/config` and the host has a public set in `~/.ssh/authorized_keys`. Then just log in with `ssh user@host` and you should get a push message on your phone. If the key is not present in Chiff, the request is being forwarded to the original `ssh-agent`.

### Retrieving passwords

The Chiff CLI allows you to get passwords and notes from your accounts with `chiff get`. It takes the following arguments:

```bash
  -i, --id TEXT      The id of the account you want the data for  [required]
  -n, --notes        Return the notes of the account
  -j, --format-json  Return account in JSON format ({ "username": "example",
                     "password": "secret", "notes": "important note" |
                     undefined })
```

By default, it just return the password without any extra output, so it can be easily used in scripts.
The account id is required and can be found by checking the overview with `chiff status`.

### Adding accounts

Add new accounts with `chiff add`. It takes the following arguments:

```bash
  -u, --username TEXT  The username of the account you want to add  [required]
  -l, --url TEXT       The URL of the account you want to add  [required]
  -s, --name TEXT      The name of the account you want to add  [required]
  -p, --password TEXT  The password of the account you want to add. Will be
                       prompted for if not provided
  -n, --notes TEXT     The notes of the account you want to add
```

This will send a request to your phone, where you can authorize the account.

### Updating accounts

Similarly, you can update existing accounts with `chiff update`.

```bash
  -i, --id TEXT        The id of the account you want the data for  [required]
  -u, --username TEXT  The username of the account you want to update
  -l, --url TEXT       The URL of the account you want to update
  -s, --name TEXT      The name of the account you want to update
  -p, --password TEXT  The password of the account you want to update. Will be
                       prompted for if argument is not provided
  -n, --notes TEXT     The notes of the account you want to update
```

The account id is required and can be found by checking the overview with `chiff status`.

### Importing

You can import accounts from a CSV, JSON or kdbx file with `chiff import`.

```bash
  -f, --format [csv|json|kdbx]  The input format. If data is written to a
                                .kdbx database, the path to anexisting .kdbx
                                database file needs to be provided with -p.
                                [required]
  -p, --path PATH               The path to where the file should be read
                                from.  [required]
  -s, --skip                    Whether the first row should be skipped. Only
                                relevant when format is CSV.
```

#### Importing from CSV

Import from a csv file with `chiff import -f csv -p <path>`. You can skip the first row with the `-s` flag. The data is expected to be separated with commas, for example:

```
"title", "url", "username", "password", "notes"
"Google", "https://google.com", "john_doe@gmail.com", "p@ssword", "important note"
```

#### Importing from JSON

Import from a json file with `chiff import -f json -p <path>`. The data is expected to be formatted as follows:

```json
[
  {
    "title": "Google",
    "url": "https://google.com",
    "username": "john_doe@gmail.com",
    "password": "p@ssword",
    "notes": "important note"
  }
]
```

#### Importing from kdbx

Import from a json file with `chiff import -f kdbx -p <path>`. You will have to enter your password. Note that Chiff relies on the URL being present and correct, so it's necessary to make sure each account has the URL set, as well as the title, username and password. Notes are optional.

## FAQ

### I'd like to forward requests to another SSH agent

By default, Chiff forwards the requests to the ssh-agent that is present in the `SSH_AUTH_SOCK`, environment variable. If you have changed this in `~/.bashrc` or equivalent, it may not be available to the background process. You can adjust the LaunchAgent plist or systemd service manually to set. For example, if you would like to use Chiff in combination with [secretive](https://github.com/maxgoedjen/secretive), you add the following to `~/Library/LaunchAgents/co.chiff.chiffd.plist`:

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>SSH_AUTH_SOCK</key>
    <string>/Users/username/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh</string>
</dict>
```

Then reload it with `launchctl load -w ~/Library/LaunchAgents/co.chiff.chiffd.plist`. If the key is present in Chiff, they request will be handled by Chiff. If not, it will be forwarded to the secretive ssh agent.

## Contributing

To contribute, follow these steps:

1. Fork this repository.
2. Create a branch from the `main` branch: `git checkout -b <branch_name>`.
3. Make your changes and commit them: `git commit -m '<commit_message>'`
4. Push to the original branch: `git push origin <project_name>/<location>`
5. Create the pull request to the `main` branch.

Alternatively see the GitHub documentation on [creating a pull request](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request).

## License

This project is licensed under the terms of the GNU GPLv3.
