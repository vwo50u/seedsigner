"""
Generates the Sparrow-format export files in this directory and the expected
addresses hardcoded in tests/test_descriptor_file.py.

Not run by the test suite. To regenerate/re-verify (needs `pip install coincurve
bitcoin-utils`):
    python tests/descriptor_files/generate_vectors.py > vectors.json

The export files mirror Sparrow's io/Descriptor.java and io/ColdcardMultisig.java
exportWallet() output. Addresses are computed with code that does NOT use embit:
  - BIP32 CKDpub implemented here from the spec on top of coincurve (libsecp256k1)
  - sortedmulti script + P2WSH / P2SH-P2WSH address via bitcoin-utils
  - BIP380 descriptor checksum implemented here from the spec
embit is only used to derive the cosigner xpubs from public BIP39 test mnemonics.
"""
import hashlib, hmac, json, sys

import coincurve
from base58check import b58decode
from bitcoinutils.setup import setup
from bitcoinutils.script import Script
from bitcoinutils.keys import P2wshAddress, P2shAddress

# ---- BIP380 checksum (from the BIP's reference algorithm) ----
INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def _polymod(c, val):
    c0 = c >> 35
    c = ((c & 0x7ffffffff) << 5) ^ val
    for i, g in enumerate([0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd]):
        if c0 & (1 << i): c ^= g
    return c
def desc_checksum(s):
    c, cls, clscount = 1, 0, 0
    for ch in s:
        pos = INPUT_CHARSET.find(ch)
        assert pos >= 0
        c = _polymod(c, pos & 31)
        cls = cls * 3 + (pos >> 5)
        clscount += 1
        if clscount == 3:
            c = _polymod(c, cls); cls = 0; clscount = 0
    if clscount > 0: c = _polymod(c, cls)
    for _ in range(8): c = _polymod(c, 0)
    c ^= 1
    return "".join(CHECKSUM_CHARSET[(c >> (5 * (7 - i))) & 31] for i in range(8))

# ---- BIP32 public derivation ----
def parse_xpub(xpub):
    raw = b58decode(xpub)
    data, check = raw[:-4], raw[-4:]
    assert hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4] == check
    assert len(data) == 78
    return data[13:45], data[45:78]  # chaincode, pubkey

def ckd_pub(chaincode, pubkey, index):
    assert index < 2**31
    I = hmac.new(chaincode, pubkey + index.to_bytes(4, "big"), hashlib.sha512).digest()
    child = coincurve.PublicKey.combine_keys([
        coincurve.PublicKey.from_secret(I[:32]),
        coincurve.PublicKey(pubkey),
    ])
    return I[32:], child.format(compressed=True)

def child_pubkey(xpub, branch, index):
    cc, pk = parse_xpub(xpub)
    cc, pk = ckd_pub(cc, pk, branch)
    _, pk = ckd_pub(cc, pk, index)
    return pk

def addresses(xpubs, m, script_format, branch, count):
    out = []
    for i in range(count):
        pks = sorted(child_pubkey(x, branch, i) for x in xpubs)
        ws = Script([m] + [pk.hex() for pk in pks] + [len(pks), "OP_CHECKMULTISIG"])
        if script_format == "P2WSH":
            out.append(P2wshAddress.from_script(ws).to_string())
        elif script_format == "P2WSH-P2SH":
            out.append(P2shAddress.from_script(ws.to_p2wsh_script_pub_key()).to_string())
        else:
            raise ValueError(script_format)
    return out

# ---- test wallets ----
MNEMONICS = [
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
]

def cosigners(paths, network):
    from embit import bip32, bip39
    from embit.networks import NETWORKS
    res = []
    for mnemonic, path in zip(MNEMONICS, paths):
        root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(mnemonic), version=NETWORKS[network]["xprv"])
        xpub = root.derive(path).to_public().to_string(version=NETWORKS[network]["xpub"])
        res.append((root.my_fingerprint.hex(), path, xpub))
    return res

def origin(fp, path):
    return f"[{fp}{path[1:].replace(chr(39), 'h')}]"

def sparrow_descriptor_export(script_format, m, keys):
    """ Mirrors sparrow io/Descriptor.java exportWallet() for a multisig wallet """
    wrap = {"P2WSH": ("wsh(", ")"), "P2WSH-P2SH": ("sh(wsh(", "))")}[script_format]
    def desc(child):
        body = wrap[0] + "sortedmulti(" + ",".join([str(m)] + [origin(fp, p) + x + child for fp, p, x in keys]) + ")" + wrap[1]
        return body + "#" + desc_checksum(body)
    return (
        "# Receive and change descriptor:\n" + desc("/<0;1>/*") + "\n\n\n"
        + "# Receive descriptor:\n" + desc("/0/*") + "\n\n"
        + "# Change descriptor:\n" + desc("/1/*") + "\n"
    )

def sparrow_coldcard_export(script_format, m, keys, name="Test Wallet"):
    """ Mirrors sparrow io/ColdcardMultisig.java exportWallet() """
    multiple = len({p for _, p, _ in keys}) > 1
    s = "# Coldcard Multisig setup file (created by Sparrow)\n#\n"
    s += f"Name: {name}\nPolicy: {m} of {len(keys)}\n"
    if not multiple:
        s += f"Derivation: {keys[0][1]}\n"
    s += f"Format: {script_format}\n\n"
    for fp, p, x in keys:
        if multiple:
            s += f"Derivation: {p}\n"
        s += f"{fp.upper()}: {x}\n"
        if multiple:
            s += "\n"
    return s

WALLETS = {
    "wsh_mainnet": ("main", "P2WSH", 2, ["m/48'/0'/0'/2'"] * 3),
    "sh_wsh_mainnet": ("main", "P2WSH-P2SH", 2, ["m/48'/0'/0'/1'"] * 3),
    "wsh_mixed_paths_mainnet": ("main", "P2WSH", 2, ["m/48'/0'/0'/2'", "m/48'/0'/1'/2'", "m/48'/0'/7'/2'"]),
    "wsh_testnet": ("test", "P2WSH", 2, ["m/48'/1'/0'/2'"] * 3),
}

result = {}
for name, (network, fmt, m, paths) in WALLETS.items():
    setup("mainnet" if network == "main" else "testnet")
    keys = cosigners(paths, network)
    result[name] = dict(
        network=network,
        descriptor_file=sparrow_descriptor_export(fmt, m, keys),
        coldcard_file=sparrow_coldcard_export(fmt, m, keys),
        receive=addresses([k[2] for k in keys], m, fmt, 0, 3),
        change=addresses([k[2] for k in keys], m, fmt, 1, 3),
    )

json.dump(result, sys.stdout, indent=1)
