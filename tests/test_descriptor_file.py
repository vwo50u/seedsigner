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



"""
Real-world export formats, checked against addresses computed independently of embit
(see tests/descriptor_files/generate_vectors.py).
"""
DESCRIPTOR_FILES_DIR = os.path.join(os.path.dirname(__file__), "descriptor_files")

INDEPENDENT_VECTORS = {
    "wsh_mainnet": dict(
        network="main",
        paths=["48h/0h/0h/2h"] * 3,
        receive=[
            "bc1qea2gkgeszr7wm66x2ejkgdxm9nhg9462sszn75zmkhazev0t02vs70kkll",
            "bc1qa0sj5tjwunnxyhmkgd85548gwqv2r0tc6vjs9c3yy2j7gjea72hs9dvptd",
            "bc1qmes7qgkj4fedgj86er5z2yx2hyfjwaw9rmhsap30ul42xl4eayrsx3qsm0",
        ],
        change=[
            "bc1qc6p3lpt2e2wv0vukgyykx3ca8fhy6pvlfg7sgv8e3qej473jjmxs29860y",
            "bc1qzvuv76wjgsspr2ywcddjz0rgxyxwy8sjtfx0a8jdtp5r9jjp7jzskczr28",
            "bc1q9hsxg4h09d2hecdkv3wzfack6htfw6kqg024ccu7473ararx25csjcvw92",
        ],
    ),
    "sh_wsh_mainnet": dict(
        network="main",
        paths=["48h/0h/0h/1h"] * 3,
        receive=[
            "36ZrDZ9nkw5G83zYBmzQneVjErgkfN6RDD",
            "3HpstT3q6fBTEfuQvndkU2Z9eUyyYhz5BU",
            "39LPfWzeCQMMQnFPmKeKx1ZUt5hkUJbo6A",
        ],
        change=[
            "3EZGPrkM4bZDYuNSTmBZXDEaEConRxFFgn",
            "3HJsitiWxaxrw2Y5JUTQhNXCMkZQBBzgy1",
            "33P1ZcEeuT45N3U6Aq4hrDYPpdTP1jo5Sy",
        ],
    ),
    "wsh_mixed_paths_mainnet": dict(
        network="main",
        paths=["48h/0h/0h/2h", "48h/0h/1h/2h", "48h/0h/7h/2h"],
        receive=[
            "bc1qw07uvms6sj353v0z2yfrh3xe7r7l5wp4tg35nv8cv5ch6kss9teqk5lv7l",
            "bc1qqcfps4zutydujxw5ea3ufsexynrq9a48f6sppps976kmtfdm9h0s0sf5ce",
            "bc1qtyl5vy8wy40gadtwycrfxuv40wkz4jwxt7g9fwlalp67lv23ss7qg6k4nt",
        ],
        change=[
            "bc1qnhny9z0dymyu72ma7es9cdlamglz0w5kwa99gf5zvegheg03py5saf6gya",
            "bc1q5u85p5thzr6p8hgnjzs7xw9keyejchtdzprqtfdy9avuhwcl0utqm6aw7y",
            "bc1qk0frr2f5kpt8jyld5gm0xy6kthqddy76kexgactegpc50cl527sqjq86e0",
        ],
    ),
    "wsh_testnet": dict(
        network="test",
        paths=["48h/1h/0h/2h"] * 3,
        receive=[
            "tb1qmv9kucx4tjtyfwddc3698p2flxqvts89n8kllr0hvdv7qs4z476s70nuf5",
            "tb1q80kfzwjz9cu95wgvpd9qr8pmkasr8en00ldsy4f9fqryhug4swns0eek2a",
            "tb1q82yt0ypaqzf4fhesr3zpqm3cxw29l4ep2he8tjtgqczgwc8c5yjsu6r8sa",
        ],
        change=[
            "tb1qp58f8l2cmpl8wx5ms7gcr7zfamsspr47rn45j4z3v6drakeffk6q6ezllu",
            "tb1q4p97zsp4e8emyqtruzvefap66nrmkhmy76uat3a45pznmp8hj6hqfjljt6",
            "tb1qq2tzrj967nj85dnp8plx9hra3pd3saeur72ydcaw2zrwflvfzjnstrmn79",
        ],
    ),
}
# Master fingerprints of the three BIP39 test mnemonics used as cosigners
COSIGNER_FINGERPRINTS = ["73c5da0a", "3f635a63", "b8688df1"]


@pytest.mark.parametrize("export_format", ["sparrow_descriptor", "sparrow_coldcard"])
@pytest.mark.parametrize("wallet", INDEPENDENT_VECTORS.keys())
def test_sparrow_exports_match_independent_addresses(wallet, export_format):
    expected = INDEPENDENT_VECTORS[wallet]
    descriptor = read_descriptor_file(DESCRIPTOR_FILES_DIR, f"{wallet}_{export_format}.txt")

    for i in range(3):
        assert embit_utils.get_multisig_address(descriptor, index=i, embit_network=expected["network"]) == expected["receive"][i]
        assert embit_utils.get_multisig_address(descriptor, index=i, is_change=True, embit_network=expected["network"]) == expected["change"][i]

    # Key origins must survive too (PSBT change verification matches on them). The
    # Coldcard format lists a "Derivation:" line per cosigner when their paths differ.
    origins = sorted(str(k.origin) for k in descriptor.keys)
    assert origins == sorted(f"{fp}/{path}" for fp, path in zip(COSIGNER_FINGERPRINTS, expected["paths"]))


def test_sparrow_exports_are_listed():
    expected = sorted(
        (f"{wallet}_{export_format}.txt" for wallet in INDEPENDENT_VECTORS for export_format in ["sparrow_descriptor", "sparrow_coldcard"]),
        key=str.lower,
    )
    assert list_descriptor_files(DESCRIPTOR_FILES_DIR) == expected
