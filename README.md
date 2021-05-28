## Chiff

This program can be used to retrieve passwords and notes from the Chiff app. In addition, it provides some commands
to operate directly on chiff seeds.

### Building

The project can be built using [_poetry_](https://python-poetry.org).
Run `poetry build` to build the source package and wheel binary.

### Installing

Install the wheel binary with `pip install <wheel binary>`, e.g. `pip install dist/chiff-0.1.0-py3-none-any.whl`.
This should install the `chiff` script to your shell.

### Usage

#### Pairing

The first thing you should do is pair with your phone with `chiff pair`. This generate a QR-code that you can scan with
the Chiff app. After pairing, you can see your accounts with `chiff status`.
You can pair with one app at the same time, so if you want to pair with another phone, run `chiff unpair` to delete the
session.

#### Getting passwords

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

#### Adding accounts

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

#### Updating accounts

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
