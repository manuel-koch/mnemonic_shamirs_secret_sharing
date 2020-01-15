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
#   Recover mnemonic secret from given number of shared mnemonic secret, stored line-by-line in given file.
#
#       mnemonic_shamirs_secret_sharing.py recover shared_secrets.txt
#
import math
import random
import re
import textwrap
import sys
import zlib

import click

from sss import recover_secret, PRIME_12TH_MERSENNE, PRIME_13TH_MERSENNE, make_random_shares
from wordlist import words_from_indices, mnemonic_to_indices, RADIX, RADIX_BITS


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
    if (1 << b) - 1 <= d:
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


def make_random_mnemonic_shares(minimum_shares, nof_shares, prime=PRIME_12TH_MERSENNE):
    if minimum_shares > 255 or nof_shares > 255:
        raise ValueError("Can only create up to 255 shares")
    secret, shares = make_random_shares(
        minimum=minimum_shares, shares=int(nof_shares), prime=prime
    )
    mnemonic_secret = number_to_mnemonic(secret)
    mnemonic_shares = [number_to_mnemonic(pad_number(s, minimum_shares, i)) for i, s in shares]
    return mnemonic_secret, mnemonic_shares


def recover_mnemonic_secret(mnemonic_shares, prime=PRIME_12TH_MERSENNE):
    shares = []
    need_shares = 0
    for ms in mnemonic_shares:
        ms = ms.strip()
        share = mnemonic_to_number(ms)
        share, min_shares, idx = unpad_number(share)
        need_shares = max(need_shares, min_shares)
        shares.append((idx, share))
    assert (
        len(shares) >= need_shares
    ), f"Got only {len(shares)} shared secrets, need at least {need_shares} shares !"
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
def generate(nof_shares, min_shares):
    """
    Generate random mnemonic secret that can be distributed via given number
    of shared mnemonic secrets.
    Select number of shared secrets that need to be provided to be able to recover
    original mnemonic secret.
    """
    w = int(math.log10(nof_shares)) + 1
    print(f"Generating random shared secrets using '{min_shares} of {nof_shares}' config...")
    mnemonic_secret, mnemonic_shares = make_random_mnemonic_shares(
        minimum_shares=min_shares, nof_shares=nof_shares
    )
    print(f"Generated Secret :")
    mnemonic_secret_wrapped = "\n\t".join(textwrap.wrap(mnemonic_secret))
    print(f"\t{mnemonic_secret_wrapped}")
    print(
        f"Use at least {min_shares} of the following {nof_shares} shared secrets to recover secret :"
    )
    for i, ms in enumerate(mnemonic_shares):
        ms_wrapped = "\n\t".join(textwrap.wrap(ms))
        print(f"{i + 1:{w}d}:\n\t{ms_wrapped}")

    # test recovering the secret
    for _ in range(nof_shares * 10):
        k = random.randint(min_shares, nof_shares)
        test_mnemonic_shares = random.sample(mnemonic_shares, k=k)
        test_mnemonic_secret = number_to_mnemonic(recover_mnemonic_secret(test_mnemonic_shares))
        assert test_mnemonic_secret == mnemonic_secret
    print("Done.")


@main.command()
@click.argument("input", type=click.Path(file_okay=True, dir_okay=False, allow_dash=True))
def recover(input):
    """
    Recover secret from shared secrets read from given file ( use '-' to read from stdin ).
    Reading multiple shared mnemonic secrets from given file.
    One shared secret is build of multiple words.
    Shared secrets are separated by empty lines.
    """
    if input == "-":
        print(f"Recovering secret from stdin...")
        mnemonic_shares = read_shared_secrets_from_file(sys.stdin)
    else:
        print(f"Recovering secret from {input}...")
        with open(input) as f:
            mnemonic_shares = read_shared_secrets_from_file(f)
    print(f"Found {len(mnemonic_shares)} shared secrets...")
    mnemonic_secret = number_to_mnemonic(recover_mnemonic_secret(mnemonic_shares))
    mnemonic_secret_wrapped = "\n\t".join(textwrap.wrap(mnemonic_secret))
    print(f"Recovered Secret :\n\t{mnemonic_secret_wrapped}")


if __name__ == "__main__":
    main()
