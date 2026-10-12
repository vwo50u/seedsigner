import os

import pytest

from seedsigner.helpers import embit_utils
from seedsigner.helpers.descriptor_file import (MAX_DESCRIPTOR_FILE_SIZE, DescriptorFileError,
    list_descriptor_files, parse_descriptor_text, read_descriptor_file)


# Legacy p2sh 2-of-3 descriptor from test_psbt_parser.py
KEYS = [
    "[0f889044/45h]tpubD8NkS3Gngj7L4FJRYrwojKhsx2seBhrNrXVdvqaUyvtVe1YDCVcziZVa9g3KouXz7FN5CkGBkoC16nmNu2HcG9ubTdtCbSW8DEXSMHmmu62",
    "[03cd0a2b/45h]tpubD8HkLLgkdJkVitn1i9CN4HpFKJdom48iKm9PyiXYz5hivn1cGz6H3VeS6ncmCEgamvzQA2Qofu2YSTwWzvuaYWbJDEnvTUtj5R96vACdV6L",
    "[769f695c/45h]tpubD98hRDKvtATTM8hy5Vvt5ZrvDXwJvrUZm1p1mTKDmd7FqUHY9Wj2k4X1CvxjjtTf3JoChWqYbnWjfkRJ65GQnpVJKbbMfjnGzCwoBUXafyM",
]
P2SH_DESCRIPTOR = "sh(sortedmulti(2," + ",".join(k + "/<0;1>/*" for k in KEYS) + "))#uardwtq4"

# Bitcoin Core style receive-only descriptor of the same wallet
P2SH_RECEIVE_DESCRIPTOR = "sh(sortedmulti(2," + ",".join(k + "/0/*" for k in KEYS) + "))#hyn4p44n"

# Receive/change addrs @ index 5 from test_psbt_parser.py
RECEIVE_ADDR_5 = "2N5eN5vUpgsLHAGzKm2VfmYyvNwXmCug5dH"
CHANGE_ADDR_5 = "2N69URrRc9LGgwJZrBWwCJE7CjsVof3tm5z"


def addr(descriptor, index, is_change=False):
    return embit_utils.get_multisig_address(descriptor, index=index, is_change=is_change, embit_network="regtest")



def test_parse_bip389_descriptor():
    descriptor = parse_descriptor_text(P2SH_DESCRIPTOR)
    assert embit_utils.get_multisig_policy(descriptor) == ("2", "3")
    assert addr(descriptor, 5) == RECEIVE_ADDR_5
    assert addr(descriptor, 5, is_change=True) == CHANGE_ADDR_5


def test_parse_receive_only_descriptor_also_derives_change():
    descriptor = parse_descriptor_text(P2SH_RECEIVE_DESCRIPTOR)
    assert addr(descriptor, 5) == RECEIVE_ADDR_5
    assert addr(descriptor, 5, is_change=True) == CHANGE_ADDR_5


def test_parse_descriptor_without_checksum():
    descriptor = parse_descriptor_text(P2SH_DESCRIPTOR.split("#")[0])
    assert addr(descriptor, 5) == RECEIVE_ADDR_5


def test_parse_skips_comments_and_uses_first_descriptor_line():
    text = "\n".join([
        "# Receive and change descriptor (BIP389):",
        "",
        "  " + P2SH_DESCRIPTOR + "  ",
        "",
        "# Some other descriptor",
        P2SH_DESCRIPTOR.replace(KEYS[0], KEYS[1]).split("#")[0],
    ])
    descriptor = parse_descriptor_text("﻿" + text)
    assert addr(descriptor, 5) == RECEIVE_ADDR_5


def test_parse_rejects_bad_checksum():
    with pytest.raises(DescriptorFileError, match="checksum"):
        parse_descriptor_text(P2SH_DESCRIPTOR[:-1] + "x")


def test_parse_rejects_tampered_key_with_stale_checksum():
    # Swapping a single cosigner xpub without recomputing the checksum is caught...
    tampered = P2SH_DESCRIPTOR.replace(KEYS[2].split("]")[1], KEYS[1].split("]")[1])
    with pytest.raises(DescriptorFileError, match="checksum"):
        parse_descriptor_text(tampered)


def test_parse_rejects_singlesig():
    with pytest.raises(DescriptorFileError, match="No descriptor found"):
        parse_descriptor_text("wpkh([0f889044/84h/1h/0h]" + KEYS[0].split("]")[1] + "/<0;1>/*)")

    with pytest.raises(DescriptorFileError, match="Not a multisig"):
        parse_descriptor_text("sh(wpkh([0f889044/49h/1h/0h]" + KEYS[0].split("]")[1] + "/<0;1>/*))")


def test_parse_rejects_garbage():
    for text in ["", "hello", "wsh(sortedmulti(2,notakey,notakey))"]:
        with pytest.raises(DescriptorFileError):
            parse_descriptor_text(text)


def test_parse_multisig_setup_file():
    xpubs = [k.split("]")[1] for k in KEYS]
    text = "\n".join([
        "# Coldcard Multisig setup file",
        "Name: Test Wallet",
        "Policy: 2 of 3",
        "Derivation: m/48'/1'/0'/2'",
        "Format: P2WSH",
        "",
    ] + [f"{k[1:9].upper()}: {xpub}" for k, xpub in zip(KEYS, xpubs)])

    descriptor = parse_descriptor_text(text)

    expected = parse_descriptor_text(
        "wsh(sortedmulti(2," + ",".join(f"[{k[1:9]}/48h/1h/0h/2h]{xpub}/<0;1>/*" for k, xpub in zip(KEYS, xpubs)) + "))"
    )
    for i in range(3):
        assert addr(descriptor, i) == addr(expected, i)
        assert addr(descriptor, i, is_change=True) == addr(expected, i, is_change=True)


def test_parse_rejects_bad_multisig_setup_file():
    with pytest.raises(DescriptorFileError, match="setup file"):
        parse_descriptor_text("Policy: 2 of 3\nFormat: P2WSH\n")



def test_list_descriptor_files(tmp_path):
    (tmp_path / "wallet.txt").write_text(P2SH_DESCRIPTOR)
    (tmp_path / "B-wallet.DESCRIPTOR").write_text(P2SH_RECEIVE_DESCRIPTOR)
    (tmp_path / "setup.txt").write_text("Policy: 2 of 3\n")

    # Boot partition files and other noise that must not be offered
    (tmp_path / "config.txt").write_text("arm_64bit=0\ndtoverlay=spi0-1cs\n")
    (tmp_path / "cmdline.txt").write_text("console=tty1 quiet\n")
    (tmp_path / "._wallet.txt").write_text(P2SH_DESCRIPTOR)
    (tmp_path / "wallet.json").write_text(P2SH_DESCRIPTOR)
    (tmp_path / "binary.txt").write_bytes(b"\xff\xfe multi(")
    (tmp_path / "huge.txt").write_text(P2SH_DESCRIPTOR + " " * MAX_DESCRIPTOR_FILE_SIZE)
    (tmp_path / "dir.txt").mkdir()
    os.symlink(tmp_path / "wallet.txt", tmp_path / "link.txt")

    assert list_descriptor_files(str(tmp_path)) == ["B-wallet.DESCRIPTOR", "setup.txt", "wallet.txt"]


def test_list_descriptor_files_missing_dir(tmp_path):
    assert list_descriptor_files(str(tmp_path / "nope")) == []


def test_read_descriptor_file(tmp_path):
    (tmp_path / "wallet.txt").write_text(P2SH_DESCRIPTOR)
    descriptor = read_descriptor_file(str(tmp_path), "wallet.txt")
    assert addr(descriptor, 5) == RECEIVE_ADDR_5


def test_read_descriptor_file_rejects_bad_input(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (tmp_path / "outside.txt").write_text(P2SH_DESCRIPTOR)
    (sub / "huge.txt").write_text(P2SH_DESCRIPTOR + " " * MAX_DESCRIPTOR_FILE_SIZE)
    (sub / "binary.txt").write_bytes(b"\xff\xfe")
    os.symlink(tmp_path / "outside.txt", sub / "link.txt")

    for filename, match in [
        ("../outside.txt", "Invalid filename"),
        ("missing.txt", "not found"),
        ("link.txt", "not found"),
        ("huge.txt", "too large"),
        ("binary.txt", "not a text file"),
    ]:
        with pytest.raises(DescriptorFileError, match=match):
            read_descriptor_file(str(sub), filename)
