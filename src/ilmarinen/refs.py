"""File references: unambiguous, reversible, privacy-preserving identifiers for entries.

    ref = "file:" + root_id + ":" + "/".join(encode(segment) for segment in relative path)

Each path segment's raw bytes are percent-encoded, except the unreserved ASCII characters
A-Z a-z 0-9 - . _ ~ (uppercase hex). Refs are therefore pure ASCII, never contain control
characters, and ':' inside a name can never be confused with the prefix. No Unicode
normalisation is applied to names, so names that differ only in NFC/NFD form stay distinct.

- Linux: raw bytes are the name as stored (os.fsencode), so any name is representable.
- Windows: the UTF-16 name is encoded as strict UTF-8; a name with an unpaired surrogate
  cannot be represented and is reported as an error instead (never silently skipped).
"""

from __future__ import annotations

import os
import unicodedata

UNRESERVED = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
WINDOWS = os.name == "nt"


class UnrepresentableName(ValueError):
    pass


def segment_bytes(name: str, windows: bool = WINDOWS) -> bytes:
    if windows:
        try:
            return name.encode("utf-8")
        except UnicodeEncodeError:
            raise UnrepresentableName("name contains an unpaired surrogate") from None
    return os.fsencode(name)


def encode_segment(raw: bytes) -> str:
    return "".join(chr(b) if b in UNRESERVED else f"%{b:02X}" for b in raw)


def decode_segment(text: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(text):
        if text[i] == "%":
            out.append(int(text[i + 1:i + 3], 16))
            i += 3
        else:
            out.append(ord(text[i]))
            i += 1
    return bytes(out)


def make_ref(root_id: str, segments: list[bytes]) -> str:
    return "file:" + root_id + ":" + "/".join(encode_segment(s) for s in segments)


def make_key(root_id: str, names: list[str], segments: list[bytes], windows: bool = WINDOWS) -> str:
    """Baseline matching key: the ref itself on Linux; on Windows (case-insensitive
    directories) the ref of the lower-cased names."""
    if not windows:
        return make_ref(root_id, segments)
    return make_ref(root_id, [segment_bytes(n.lower(), windows=True) for n in names])


def display_segment(raw: bytes) -> str:
    """Form used for exclusion matching: UTF-8 with invalid sequences replaced, NFC, casefold."""
    return unicodedata.normalize("NFC", raw.decode("utf-8", "replace")).casefold()
