# Chiff CLI ![Current version](https://img.shields.io/github/v/tag/chiff-app/chiff-cli?sort=semver) ![Twitter Follow](https://img.shields.io/twitter/follow/Chiff_App?style=social)

![Chiff logo](https://chiff.app/assets/images/logo.svg)

Chiff is a tool that allows you to store secrets in the secure storage of your phone and retrieve them when you need them by authorizing a request.
You can pair the app with multiple clients (browser extension or shell).

### Motivation

SSH keys are stored in plaintext on your computer by default, unless you choose a passphrase. However, it can be cumbersome to retype your password every time you need to decrypt your keys. The same applies to credentials for various CLIs. For example, [official AWS CLI documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html) recommends to store your credentials in `~/.aws/credentials`.

With Chiff, you can leverage the biometric capabilities and secure storage of your phone to authenticate to services on your computer. You can pair with multiple shells to be able to retrieve credentials there.

### Security model

All sensitive data is stored encrypted on your phone. When needed, it is decrypted (by authenticating to your phone with biometrics) and sent to the browser/cli, where it is filled in the website. An end-to-end encrypted channel is established between browser/cli by scanning a QR-code. This means confidentiality is ensured, even though the server (mainly serving as message broker and backup storage) is modelled as an untrusted entity. For a more detailed analysis of the security of this model, please see [TODO](https://chiff.app/todo)

### Related projects

This is the repository for the _CLI_.
For the _Android app_, please see [chiff-android](https://github.com/chiff-app/chiff-android).
For the _Browser extension_, please see [chiff-browser](https://github.com/chiff-app/chiff-browser).
For the _iOS app_, please see [chiff-ios](https://github.com/chiff-app/chiff-ios).

## Installation

Package is available on pypi, it can be installed with `pip install chiff`. This should install `chiff` to your shell.

## Installation from source

After cloning the project, you can build it using [_poetry_](https://python-poetry.org).
Run `poetry build` to build the source package and wheel binary. Install the wheel binary with `pip install <wheel binary>`, e.g. `pip install dist/chiff-0.1.0-py3-none-any.whl`. This should install `chiff` to your shell.

## Usage

### Pairing

The first thing you should do is pair with your phone with `chiff pair`. This generate a QR-code that you can scan with
the Chiff app. After pairing, you can see your accounts with `chiff status`.
You can pair with one app at the same time, so if you want to pair with another phone, run `chiff unpair` to delete the
session.

### Getting passwords

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

#### Importing

TODO

#### Exporting

TODO

## Contributing

To contribute, follow these steps:

1. Fork this repository.
2. Create a branch from the `main` branch: `git checkout -b <branch_name>`.
3. Make your changes and commit them: `git commit -m '<commit_message>'`
4. Push to the original branch: `git push origin <project_name>/<location>`
5. Create the pull request to the `main` branch.

Alternatively see the GitHub documentation on [creating a pull request](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request).

## License

This project is licensed under the terms of the GNU LGPLv3.
