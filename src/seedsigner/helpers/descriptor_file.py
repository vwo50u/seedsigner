"""
Load a multisig wallet descriptor from a text file on the microSD card instead of
scanning it as a QR code.

The file is untrusted input, exactly like a scanned descriptor QR: anyone who could
write to the card could have swapped a cosigner's xpub. The user is expected to
compare the resulting receive address #0 against their wallet backup before relying
on it (see `MultisigWalletDescriptorFirstAddressView`).
"""
import logging
import os
import re

from embit.descriptor import Descriptor
from embit.descriptor.checksum import checksum as descriptor_checksum

logger = logging.getLogger(__name__)


DESCRIPTOR_FILE_EXTENSIONS = (".txt", ".descriptor")

# A 15-of-15 descriptor is roughly 2KB; anything much bigger isn't a descriptor file.
MAX_DESCRIPTOR_FILE_SIZE = 16 * 1024



class DescriptorFileError(Exception):
    pass



def normalize_multisig_descriptor_str(descriptor_str: str) -> str:
    """
    Replace `/0/*` wildcards with `/{0,1}/*` (or append `/{0,1}/*` when there's no
    wildcard at all) so that the Descriptor can also be used to verify change.
    """
    orig_descriptor_str = descriptor_str
    try:
        if len(re.findall (r'\[([0-9,a-f,A-F]+?)(\/[0-9,\/,h\']+?)\].*?(\/0\/\*)', descriptor_str)) > 0:
            p = re.compile(r'(\[[0-9,a-f,A-F]+?\/[0-9,\/,h\']+?\].*?)(\/0\/\*)')
            descriptor_str = p.sub(r'\1/{0,1}/*', descriptor_str)
        elif len(re.findall (r'(\[[0-9,a-f,A-F]+?\/[0-9,\/,h,\']+?\][a-z,A-Z,0-9]*?)([\,,\)])', descriptor_str)) > 0:
            p = re.compile(r'(\[[0-9,a-f,A-F]+?\/[0-9,\/,h,\']+?\][a-z,A-Z,0-9]*?)([\,,\)])')
            descriptor_str = p.sub(r'\1/{0,1}/*\2', descriptor_str)
    except Exception as e:
        logger.info(repr(e), exc_info=True)
        descriptor_str = orig_descriptor_str
    return descriptor_str



def _read_text(path: str) -> str:
    with open(path, "rb") as f:
        raw = f.read(MAX_DESCRIPTOR_FILE_SIZE + 1)
    if len(raw) > MAX_DESCRIPTOR_FILE_SIZE:
        raise DescriptorFileError("File is too large")
    try:
        # "utf-8-sig" also strips a BOM, which some Windows editors add
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise DescriptorFileError("File is not a text file")



def _looks_like_descriptor_file(text: str) -> bool:
    """
    Cheap pre-filter so that unrelated .txt files on the card (e.g. the boot
    partition's config.txt and cmdline.txt) aren't offered to the user.
    """
    return bool(
        re.search(r"multi\(", text)
        or re.search(r"^\s*policy\s*:", text, re.IGNORECASE | re.MULTILINE)
    )



def parse_descriptor_text(text: str) -> Descriptor:
    """
    Accepts either a raw output descriptor (the first `sh(`/`wsh(` line is used;
    blank lines and `#` comments are ignored) or a Coldcard-style multisig setup
    file ("Policy: 2 of 3", "Derivation: ...", "<xfp>: <xpub>").
    """
    if re.search(r"^\s*policy\s*:", text, re.IGNORECASE | re.MULTILINE):
        from seedsigner.models.decode_qr import DecodeQR
        try:
            descriptor_str = DecodeQR.multisig_setup_file_to_descriptor(text)
        except Exception as e:
            raise DescriptorFileError(f"Invalid multisig setup file: {e}")

    else:
        descriptor_str = None
        for line in text.splitlines():
            line = line.strip()
            # Skip a change-only descriptor (`/1/*`, e.g. listed before the receive
            # one): its address #0 would be shown to the user as receive #0.
            is_change_only = "/1/*" in line and not re.search(r"/0/\*|<0;1>|\{0,1\}", line)
            if re.match(r"^(sh|wsh)\(", line) and not is_change_only:
                descriptor_str = line
                break

        if descriptor_str is None:
            raise DescriptorFileError("No descriptor found")

        if "#" in descriptor_str:
            # embit doesn't validate the checksum, so we do it ourselves. This only
            # catches typos/corruption; anyone who can edit the file can recompute it.
            desc, check = descriptor_str.split("#", 1)
            try:
                # raises on characters outside the descriptor charset (e.g. curly quotes)
                computed = descriptor_checksum(desc)
            except Exception as e:
                logger.info(repr(e), exc_info=True)
                raise DescriptorFileError("Invalid descriptor")
            if computed != check:
                raise DescriptorFileError("Descriptor checksum mismatch")

    try:
        descriptor = Descriptor.from_string(normalize_multisig_descriptor_str(descriptor_str))
    except Exception as e:
        logger.info(repr(e), exc_info=True)
        raise DescriptorFileError("Invalid descriptor")

    if not descriptor.is_basic_multisig:
        raise DescriptorFileError("Not a multisig descriptor")

    return descriptor



def list_descriptor_files(directory: str) -> list:
    """ Returns the sorted filenames in `directory` that look like descriptor files. """
    try:
        entries = os.listdir(directory)
    except OSError:
        return []

    filenames = []
    for filename in sorted(entries, key=str.lower):
        # Skip hidden files, including the "._*" files macOS litters onto FAT volumes
        if filename.startswith(".") or not filename.lower().endswith(DESCRIPTOR_FILE_EXTENSIONS):
            continue

        path = os.path.join(directory, filename)
        if os.path.islink(path) or not os.path.isfile(path):
            continue

        try:
            if _looks_like_descriptor_file(_read_text(path)):
                filenames.append(filename)
        except (OSError, DescriptorFileError):
            continue

    return filenames



def read_descriptor_file(directory: str, filename: str) -> Descriptor:
    if os.path.basename(filename) != filename:
        raise DescriptorFileError("Invalid filename")

    path = os.path.join(directory, filename)
    if os.path.islink(path) or not os.path.isfile(path):
        raise DescriptorFileError("File not found")

    try:
        text = _read_text(path)
    except OSError:
        raise DescriptorFileError("Could not read file")

    return parse_descriptor_text(text)
