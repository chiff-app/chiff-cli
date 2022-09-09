from __future__ import print_function

from pathlib import Path
from os import path

from chiff import crypto
from urllib.parse import urlparse

from chiff.constants import MessageType, APP_NAME
import tldextract
import click

TLD_CACHE = Path(click.get_app_dir(APP_NAME), "cache")

extract = tldextract.TLDExtract(cache_dir=TLD_CACHE)
if not path.exists(TLD_CACHE):
    extract.update(fetch_now=True)


def check_response(response, logger):
    """Check whether the response is a reject or error message."""
    if not response or "t" not in response:
        logger("Request failed.")
        return False
    elif response["t"] == MessageType.REJECT.value:
        logger("Request rejected on phone..")
        return False
    elif response["t"] == MessageType.ERROR.value:
        if "e" in response:
            logger("Request failed: {error}.".format(error=response["e"]))
            return False
        else:
            logger("Request failed.")
            return False
    return True


def length_and_data(data):
    """Prepends the length of the data before the data in 4 bytes."""
    return len(data).to_bytes(4, "big", signed=False) + data


def ssh_reader(data):
    """Generator for SSH messages."""
    remaining = data
    while len(remaining) > 0:
        length = int.from_bytes(remaining[:4], "big")
        data_chunk = remaining[4 : length + 4]
        yield data_chunk
        remaining = remaining[length + 4 :]


def get_site_ids(url):
    """Get primary and secondary siteID for an url."""
    parsed_domain = urlparse(url)  # contains the protocol
    extracted_domain = extract(url)

    top_domain = ""

    if parsed_domain is None and url is None:
        raise ValueError("Invalid / empty URL")

    if extracted_domain.subdomain == "":
        full_domain = crypto.sha256(
            (
                parsed_domain.scheme
                + "://"
                + extracted_domain.domain
                + "."
                + extracted_domain.suffix
            ).encode("utf-8")
        )
    else:
        full_domain = crypto.sha256(
            (
                parsed_domain.scheme
                + "://"
                + extracted_domain.subdomain
                + "."
                + extracted_domain.domain
                + "."
                + extracted_domain.suffix
            ).encode("utf-8")
        )
        top_domain = crypto.sha256(
            (
                parsed_domain.scheme
                + "://"
                + extracted_domain.domain
                + "."
                + extracted_domain.suffix
            ).encode("utf-8")
        )

    return full_domain, top_domain
