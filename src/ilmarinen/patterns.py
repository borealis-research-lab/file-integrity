"""Exclusion patterns: identical semantics on Windows and Linux.

A pattern is matched against an entry's relative path from its root (display form:
UTF-8 with invalid bytes replaced, NFC, casefold), with '/' separators, anchored to the
whole path.

    *    any characters except '/'
    ?    exactly one character except '/'
    **   a whole segment only; zero or more whole segments
    everything else is literal (no classes, braces, negation or escapes)

A pattern ending in '/' matches directories only; a matched directory is not traversed.
Matching is case-insensitive on every platform.
"""

from __future__ import annotations

import re
import unicodedata

MAX_PATTERNS = 100
MAX_LENGTH = 256
_FORBIDDEN = set("\\[]{}!")


class PatternError(ValueError):
    pass


def _norm(text: str) -> str:
    return unicodedata.normalize("NFC", text).casefold()


class Pattern:
    def __init__(self, text: str) -> None:
        validate(text)
        self.text = text
        self.dir_only = text.endswith("/")
        body = text[:-1] if self.dir_only else text
        self.segments = [_compile_segment(s) for s in _norm(body).split("/")]

    def matches(self, path_segments: list[str], is_dir: bool) -> bool:
        if self.dir_only and not is_dir:
            return False
        return _match(self.segments, path_segments)


def validate(text: str) -> None:
    if not isinstance(text, str) or not 1 <= len(text) <= MAX_LENGTH:
        raise PatternError("pattern must be 1-256 characters")
    if any(c in _FORBIDDEN for c in text):
        raise PatternError("pattern contains a forbidden character (\\ [ ] { } !)")
    if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in text):
        raise PatternError("pattern contains a control character")
    if text.startswith("/"):
        raise PatternError("pattern must not start with '/'")
    body = text[:-1] if text.endswith("/") else text
    for segment in body.split("/"):
        if segment in ("", ".", ".."):
            raise PatternError("pattern has an empty, '.' or '..' segment")
        if "**" in segment and segment != "**":
            raise PatternError("'**' must be a whole segment")


def _compile_segment(segment: str):
    if segment == "**":
        return "**"
    regex = "".join("[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c) for c in segment)
    return re.compile(regex, re.DOTALL)


def _match(pattern: list, path: list[str]) -> bool:
    if not pattern:
        return not path
    head = pattern[0]
    if head == "**":
        return any(_match(pattern[1:], path[i:]) for i in range(len(path) + 1))
    if not path:
        return False
    return head.fullmatch(path[0]) is not None and _match(pattern[1:], path[1:])


def compile_all(texts: list[str]) -> list[Pattern]:
    if len(texts) > MAX_PATTERNS:
        raise PatternError("at most 100 exclude patterns per root")
    return [Pattern(t) for t in texts]


def excluded(patterns: list[Pattern], display_segments: list[str], is_dir: bool) -> bool:
    return any(p.matches(display_segments, is_dir) for p in patterns)
