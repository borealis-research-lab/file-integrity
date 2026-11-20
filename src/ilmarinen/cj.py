"""Borealis Canonical JSON v1 and strict JSON parsing, implemented independently.

Spec: https://github.com/borealis-research-lab/.github/blob/main/standards/canonical-json-v1.md
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from typing import Any

MAX_INT = 2**53 - 1
_MAX_INT_DIGITS = len(str(MAX_INT))
_SURROGATE = re.compile("[\ud800-\udfff]")


class CanonicalJsonError(ValueError):
    pass


class StrictJsonError(ValueError):
    pass


def _normalise(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > MAX_INT:
            raise CanonicalJsonError("integer outside +-(2^53-1)")
        return value
    if isinstance(value, float):
        raise CanonicalJsonError("floats are not permitted")
    if isinstance(value, str):
        if _SURROGATE.search(value):
            raise CanonicalJsonError("unpaired surrogate")
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_normalise(v) for v in value]
    if isinstance(value, dict):
        out = {}
        for key, v in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise CanonicalJsonError("object keys must be ASCII strings")
            out[key] = _normalise(v)
        return out
    raise CanonicalJsonError(f"unsupported type {type(value).__name__}")


def canonical(value: Any) -> bytes:
    return json.dumps(
        _normalise(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StrictJsonError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _reject_constant(name):
    raise StrictJsonError(f"non-standard value {name}")


def _reject_float(text):
    raise StrictJsonError("floats are not permitted")


def _checked_int(text):
    digits = text[1:] if text.startswith("-") else text
    if len(digits) > _MAX_INT_DIGITS:
        raise StrictJsonError("integer out of range")
    value = int(text)
    if abs(value) > MAX_INT:
        raise StrictJsonError("integer out of range")
    return value


def strict_loads(data: bytes) -> Any:
    if data.startswith(b"\xef\xbb\xbf"):
        raise StrictJsonError("byte order mark is not permitted")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise StrictJsonError("not valid UTF-8") from None
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant,
                           parse_float=_reject_float, parse_int=_checked_int)
    except json.JSONDecodeError as exc:
        raise StrictJsonError(f"invalid JSON: {exc.msg}") from None
    except (RecursionError, ValueError) as exc:
        if isinstance(exc, StrictJsonError):
            raise
        raise StrictJsonError("invalid JSON") from None
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if _SURROGATE.search(item):
                raise StrictJsonError("unpaired surrogate")
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
    return value
