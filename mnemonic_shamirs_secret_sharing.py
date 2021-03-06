#!/usr/bin/env python3
# Variation of Shamir's Secret Sharing that uses bunch of words to express
# the secret and the shared secrets.
# The generated shared mnemonic secrets additionally contain
# - minimum number of secrets
# - index of shared secret.
# - crc32 checksum
#
# Usage:
#
#   Create a mnemonic secret that can be recovered using 3 of 6 shared mnemonic secrets :
#
#       mnemonic_shamirs_secret_sharing.py generate -m 3 -s 6
#
#   Recover mnemonic secret from given number of shared mnemonic secret, stored in given file, multiple
#   shared secrets separated by empty line(s).
#
#       mnemonic_shamirs_secret_sharing.py recover shared_secrets.txt
#
import math
import os
import random
import re
import textwrap
import sys
import time
import zlib
from io import StringIO

import click
from click import Abort
import pyperclip

try:
    import qrcode
except:
    qrcode = None

from sss import recover_secret, PRIME_12TH_MERSENNE, PRIME_13TH_MERSENNE, make_random_shares
from wordlist import words_from_indices, mnemonic_to_indices, RADIX, RADIX_BITS

CLIPBOARD_TIMEOUT_SEC = 10


def log(text, is_err=False, is_warn=False):
    if is_err:
        c = "red"
    elif is_warn:
        c = "yellow"
    else:
        c = None
    click.secho(text, fg=c, err=is_err or is_warn)


def number_to_mnemonic(n):
    """Convert given integer to a string of equivalent mnemonic words"""
    indices = []
    while n:
        indices.append(n % RADIX)
        n >>= RADIX_BITS
    return " ".join(words_from_indices(indices))


def mnemonic_to_number(words):
    """Convert given string containing mnemonic words to integer"""
    share = 0
    for idx in reversed(mnemonic_to_indices(words)):
        if share:
            share <<= RADIX_BITS
        share += idx
    return share


def checksum(n):
    """Generate CRC32 checksum from given integer number"""
    return zlib.crc32(n.to_bytes(int(math.log2(n)), "big"))


def shift_left(n, b, d):
    """
    Shift given number by number of bits and add data
    :param n: The number to be shifted left
    :param b: Shift by given bits
    :param d: Add this int data
    """
    if (1 << b) - 1 < d:
        raise ValueError(f"{b} bits too small for data {hex(d)}")
    return (n << b) + d


def pad_number(n, a, b):
    """Insert padding data into given number by shifting it left."""
    padded = shift_left(n, 8, a)
    padded = shift_left(padded, 8, b)
    crc = checksum(padded)
    padded = shift_left(padded, 32, crc)
    return padded


def shift_right(n, b):
    """
    Shift given number by number of bits and return remainder and padded data
    :param n: The number to be shifted right
    :param b: Shift by given bits
    """
    return (n >> b), n & ((1 << b) - 1)


def unpad_number(n):
    """Get padding data from given number by shifting it right."""
    unpadded, crc = shift_right(n, 32)
    expect_crc = checksum(unpadded)
    unpadded, b = shift_right(unpadded, 8)
    unpadded, a = shift_right(unpadded, 8)
    if crc != expect_crc:
        raise ValueError("Checksum mismatch")
    return unpadded, a, b


def bits_in_number(n):
    return len(bin(n)[2:])


def make_random_mnemonic_shares(minimum_shares, nof_shares, prime=PRIME_12TH_MERSENNE):
    """
    Generate random master secret and derive shared secrets from it.

    :param minimum_shares: number of shared secrets to recover master secret
    :param nof_shares: number shared secrets to generate
    :param prime: using prime number to derive random master secret
    :return: tuple of mnemonic representation of master secret and list of shared secrets
    """
    if minimum_shares > 255 or nof_shares > 255:
        raise ValueError("Can only create up to 255 shares")
    secret, shares = make_random_shares(
        minimum=minimum_shares, shares=int(nof_shares), prime=prime
    )
    secret_bits = bits_in_number(secret)
    mnemonic_secret = number_to_mnemonic(secret)
    mnemonic_shares = [number_to_mnemonic(pad_number(s, minimum_shares, i)) for i, s in shares]
    return mnemonic_secret, secret_bits, mnemonic_shares,


def recover_mnemonic_secret(mnemonic_shares):
    shares = []
    need_shares = 0
    prime = PRIME_12TH_MERSENNE
    for ms in mnemonic_shares:
        ms = ms.strip()
        try:
            share = mnemonic_to_number(ms)
            if math.log2(share) > 256:
                prime = PRIME_13TH_MERSENNE
            share, min_shares, idx = unpad_number(share)
        except Exception as e:
            raise ValueError(f"Invalid share ({e}): {ms}") from e
        need_shares = max(need_shares, min_shares)
        shares.append((idx, share))
    if len(shares) < need_shares:
        raise ValueError(
            f"Got only {len(shares)} shared secrets, need at least {need_shares} shares"
        )
    return recover_secret(shares, prime)


def read_shared_secrets_from_file(f):
    """
    Read multiple shared mnemonic secrets from given file-like object.
    One shared secret is build of multiple words.
    Shared secrets are separated by empty lines.
    """
    shares = []
    words = []
    for line in f.readlines():
        line = line.strip()
        if line and not re.match(r"\s*\w+", line):
            continue
        if line:
            words.extend(line.split())
        elif words:
            shares.append(" ".join(words))
            words = []
    if words:
        shares.append(" ".join(words))
    return shares


def copy_to_clipboard_and_clear(descr, content, timeout=CLIPBOARD_TIMEOUT_SEC):
    log(f"{descr} copied to clipboard.")
    pyperclip.copy(content)
    for countdown in range(timeout, 0, -1):
        log(f"Clearing clipboard in {countdown}...", is_warn=True)
        time.sleep(1)
    pyperclip.copy("")
    log("Clipboard cleared")


def generate_qrcode(payload, out_path, fg="black", bg="white"):
    """
    Generate QR code PNG and save it to given output path.

    :param payload: Encode given text in QR code
    :param fg: Named foreground color
    :param bg: Named background color
    :param out_path: Save output PNG to path, extension is added automatically
    """
    if qrcode is None:
        log("Unable to generate qr code, python package 'qrcode' not installed", is_err=True)
        raise NotImplementedError()

    qr = qrcode.QRCode(
        version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=16, border=8
    )
    qr.add_data(payload)
    qr.make(fit=True)
    out_path = os.path.abspath(os.path.splitext(out_path)[0] + ".png")
    img = qr.make_image(fill_color=fg, back_color=bg)
    img.save(out_path)
    log(f"QR code saved to {out_path}")


@click.group()
def main():
    pass


@main.command()
@click.option(
    "-s",
    "--nof-shares",
    type=int,
    metavar="N",
    help="Create number of shares from generated secret (max 255)",
)
@click.option(
    "-m",
    "--min-shares",
    type=int,
    metavar="N",
    help="Recovering generated secret will require at least N shares ( N must be >= 2 )",
)
@click.option(
    "-c",
    "--clipboard",
    is_flag=True,
    default=False,
    help="Paste generated secret and shared secrets into clipboard instead of printing them on console",
)
@click.option(
    "-q",
    "--qr-code",
    is_flag=True,
    default=False,
    help="Generate QR code PNGs in current directory of generated secret and shared secrets",
)
@click.option("-l", "--long", is_flag=True, default=False, help="Generate longer secrets")
def generate(nof_shares, min_shares, clipboard, qr_code, long):
    """
    Generate random mnemonic secret that can be distributed via given number
    of shared mnemonic secrets.
    Select number of shared secrets that need to be provided to be able to recover
    original mnemonic secret.
    """
    w = int(math.log10(nof_shares)) + 1

    print(f"Generating random shared secrets using '{min_shares} of {nof_shares}' config...")
    mnemonic_secret, secret_bits, mnemonic_shares = make_random_mnemonic_shares(
        minimum_shares=min_shares,
        nof_shares=nof_shares,
        prime=PRIME_13TH_MERSENNE if long else PRIME_12TH_MERSENNE,
    )

    if qr_code:
        generate_qrcode(mnemonic_secret, "master")

    mnemonic_secret_wrapped = "\n\t".join(textwrap.wrap(mnemonic_secret))
    msg = f"""Generated secret ( equivalent of {secret_bits} bits ):
\t{mnemonic_secret_wrapped}
Use at least {min_shares} of the following {nof_shares} shared secrets to recover secret:"""
    for i, ms in enumerate(mnemonic_shares):
        ms_wrapped = "\n\t".join(textwrap.wrap(ms))
        msg += f"\n{i + 1:{w}d}:\n\t{ms_wrapped}"
        if qr_code:
            generate_qrcode(ms, f"{i+1:0{w}d}")

    if clipboard:
        copy_to_clipboard_and_clear("Generated secret and shared secret", msg)
    else:
        print(msg)

    # test recovering the secret
    for _ in range(nof_shares * 10):
        k = random.randint(min_shares, nof_shares)
        test_mnemonic_shares = random.sample(mnemonic_shares, k=k)
        test_mnemonic_secret = number_to_mnemonic(recover_mnemonic_secret(test_mnemonic_shares))
        assert test_mnemonic_secret == mnemonic_secret
    print("Done.")


@main.command()
@click.option(
    "-c",
    "--clipboard-paste",
    is_flag=True,
    default=False,
    help="Paste shared secrets from clipboard instead of reading from file or stdin",
)
@click.option(
    "-C",
    "--clipboard-copy",
    is_flag=True,
    default=False,
    help="Copy recovered secret to clipboard instead of printing it on console",
)
@click.option(
    "-i",
    "--interactive",
    is_flag=True,
    default=False,
    help="Read shared secrets interactively from console, hiding entered input",
)
@click.argument(
    "input_path",
    default=None,
    type=click.Path(file_okay=True, dir_okay=False, allow_dash=True),
    required=False,
)
def recover(input_path, clipboard_paste, clipboard_copy, interactive):
    """
    Recover secret from shared secrets read from given file ( use '-' to read from stdin ).
    Reading multiple shared mnemonic secrets from given file.
    One shared secret is build of multiple words.
    Multiple shared secrets are separated by empty line(s).
    """
    if input_path == "-":
        print(f"Recovering secret from stdin...")
        mnemonic_shares = read_shared_secrets_from_file(sys.stdin)
    elif input_path:
        print(f"Recovering secret from {input_path}...")
        with open(input_path) as f:
            mnemonic_shares = read_shared_secrets_from_file(f)
    elif clipboard_paste:
        try:
            print(f"Recovering secret from shared secrets in clipboard...")
            mnemonic_shares = read_shared_secrets_from_file(StringIO(pyperclip.paste()))
        finally:
            pyperclip.copy("")
            print(f"Clipboard cleared")
    elif interactive:
        mnemonic_shares = []
        while True:
            try:
                s = click.prompt(
                    f"Enter {'next' if mnemonic_shares else 'a'} shared secret ( hit ctrl+c to continue recovering )",
                    hide_input=True,
                ).strip()
            except Abort:
                break
            mnemonic_shares.append(s)
    else:
        print("Either provide an input file or use --clipboard or --interactive option !")
        sys.exit(1)

    print(f"Using {len(mnemonic_shares)} shared secrets for recovering...")
    mnemonic_secret = number_to_mnemonic(recover_mnemonic_secret(mnemonic_shares))
    if clipboard_copy:
        copy_to_clipboard_and_clear("Recovered Secret", mnemonic_secret)
    else:
        mnemonic_secret_wrapped = "\n\t".join(textwrap.wrap(mnemonic_secret))
        print(f"Recovered Secret :\n\t{mnemonic_secret_wrapped}")


if __name__ == "__main__":
    main()
