"""Configuration (ilmarinen.json). Absolute paths exist only here, never in reports.

    {
      "roots": [{"id": "documents", "path": "C:/Users/me/Documents/important",
                 "recursive": true, "exclude": ["**/*.tmp"]}],
      "baseline": "C:/ProgramData/ilmarinen/baseline.json"
    }

Validation refuses to run rather than guessing: duplicate ids, duplicate or nested roots,
a root that is a link or reparse point, a missing root, a baseline inside a root, too many
roots, or invalid exclude patterns.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from ilmarinen import cj
from ilmarinen.patterns import Pattern, PatternError, compile_all

MAX_ROOTS = 50  # report scope holds at most 100 items: one per root plus one per root's exclusions
RE_ROOT_ID = re.compile(r"[a-z][a-z0-9-]{0,31}")


class ConfigError(ValueError):
    pass


@dataclass
class Root:
    id: str
    path: str  # absolute; local only
    recursive: bool
    exclude: list[str]
    patterns: list[Pattern] = field(default_factory=list)


@dataclass
class Config:
    roots: list[Root]
    baseline: str  # absolute; local only


def _norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def is_link_or_reparse(path: str) -> bool:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _inside(child: str, parent: str) -> bool:
    return child != parent and child.startswith(parent.rstrip(os.sep) + os.sep)


def load(path: str | Path) -> Config:
    try:
        data = cj.strict_loads(Path(path).read_bytes())
    except OSError as exc:
        raise ConfigError(f"cannot read config: {exc.strerror or exc}") from None
    except cj.StrictJsonError as exc:
        raise ConfigError(f"config is not valid JSON: {exc}") from None
    return parse(data)


def parse(data: object) -> Config:
    if not isinstance(data, dict) or set(data) != {"roots", "baseline"}:
        raise ConfigError("config must be an object with exactly 'roots' and 'baseline'")
    roots_data, baseline = data["roots"], data["baseline"]
    if not isinstance(baseline, str) or not baseline:
        raise ConfigError("'baseline' must be a file path")
    if not isinstance(roots_data, list) or not 1 <= len(roots_data) <= MAX_ROOTS:
        raise ConfigError(f"'roots' must list 1-{MAX_ROOTS} roots")

    roots: list[Root] = []
    for i, item in enumerate(roots_data):
        where = f"roots[{i}]"
        if not isinstance(item, dict) or set(item) != {"id", "path", "recursive", "exclude"}:
            raise ConfigError(f"{where} must have exactly id, path, recursive, exclude")
        if not isinstance(item["id"], str) or not RE_ROOT_ID.fullmatch(item["id"]):
            raise ConfigError(f"{where}.id must match [a-z][a-z0-9-]{{0,31}}")
        if not isinstance(item["path"], str) or not item["path"]:
            raise ConfigError(f"{where}.path must be a path")
        if not isinstance(item["recursive"], bool):
            raise ConfigError(f"{where}.recursive must be true or false")
        if not isinstance(item["exclude"], list) or not all(isinstance(p, str) for p in item["exclude"]):
            raise ConfigError(f"{where}.exclude must be a list of patterns")
        try:
            compiled = compile_all(item["exclude"])
        except PatternError as exc:
            raise ConfigError(f"{where}.exclude: {exc}") from None
        roots.append(Root(item["id"], os.path.abspath(item["path"]), item["recursive"], list(item["exclude"]), compiled))

    ids = [r.id for r in roots]
    if len(ids) != len(set(ids)):
        raise ConfigError("root ids must be unique")
    normed = [_norm(r.path) for r in roots]
    for i, root in enumerate(roots):
        if not os.path.lexists(root.path):
            raise ConfigError(f"root {root.id!r} does not exist")
        if is_link_or_reparse(root.path):
            raise ConfigError(f"root {root.id!r} is a link or reparse point; configure the real path")
        for j in range(len(roots)):
            if i != j and (normed[i] == normed[j] or _inside(normed[i], normed[j])):
                raise ConfigError(f"roots {root.id!r} and {roots[j].id!r} overlap (duplicate or nested)")
    baseline_norm = _norm(baseline)
    for root, n in zip(roots, normed):
        if baseline_norm == n or _inside(baseline_norm, n):
            raise ConfigError(f"the baseline must not be inside root {root.id!r}")
    return Config(roots, os.path.abspath(baseline))
