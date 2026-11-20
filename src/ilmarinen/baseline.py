"""Baseline: one JSON file, written atomically, never replaced silently.

    {format: "fi-baseline/1", created_at, agent_version, roots[], config_fingerprint,
     entries[], replaced?, digest}

- roots[] = {id, path_identity, object_identity, recursive, exclude[]}; path_identity is a
  SHA-256 of the normalised configured path (the path itself is never stored);
  object_identity is the root directory's actual identity (dev/ino or volume/file id).
- config_fingerprint = SHA-256 of CJ(roots without object_identity).
- digest = SHA-256 of CJ(everything except "digest"). It detects accidental corruption.
  Protection against deliberate tampering needs a digest stored somewhere else and passed
  to `check --expected-digest`: an attacker who can modify both the files and the
  baseline can otherwise recompute it.
"""

from __future__ import annotations

import hashlib
import os
import re
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ilmarinen import __version__, cj
from ilmarinen.config import Config
from ilmarinen.scanner import Entry, ScanResult

FORMAT = "fi-baseline/1"
RE_HEX64 = re.compile(r"[0-9a-f]{64}")


class BaselineError(Exception):
    """A baseline problem that prevents comparison. `code` is the report error code."""

    def __init__(self, code: str, message: str, integrity: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.integrity = integrity  # True: also raise a baseline-integrity-failure finding


@dataclass
class Baseline:
    data: dict
    digest: str

    @property
    def entries(self) -> dict[str, dict]:
        return {e["key"]: e for e in self.data["entries"]}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def path_identity(path: str) -> str:
    """hex(sha256(utf8(NFC(normcase(abspath(path)))))): binds the baseline to the configured
    path without storing it."""
    norm = unicodedata.normalize("NFC", os.path.normcase(os.path.abspath(path)))
    return hashlib.sha256(norm.encode("utf-8", "surrogatepass")).hexdigest()


def _roots(config: Config, scan: ScanResult, with_identity: bool = True) -> list[dict]:
    roots = []
    for root in config.roots:
        item = {"id": root.id, "path_identity": path_identity(root.path), "recursive": root.recursive,
                "exclude": list(root.exclude)}
        if with_identity:
            item["object_identity"] = scan.root_identities.get(root.id, {})
        roots.append(item)
    return roots


def fingerprint(roots: list[dict]) -> str:
    return cj.digest([{k: v for k, v in r.items() if k != "object_identity"} for r in roots])


def build(config: Config, scan: ScanResult, replaced: dict | None = None) -> dict:
    roots = _roots(config, scan)
    data = {
        "format": FORMAT,
        "created_at": now(),
        "agent_version": __version__,
        "roots": roots,
        "config_fingerprint": fingerprint(roots),
        "entries": [scan.entries[k].to_baseline() for k in sorted(scan.entries)],
    }
    if replaced:
        data["replaced"] = replaced
    data["digest"] = cj.digest(data)
    return data


def serialise(data: dict) -> bytes:
    return cj.canonical(data) + b"\n"


def _write_temp(target: Path, content: bytes) -> Path:
    tmp = target.parent / f".{target.name}.{uuid.uuid4().hex}.tmp"
    with open(tmp, "xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    return tmp


def write_new(target: Path, data: dict) -> None:
    """Atomically create the baseline; refuses if one already exists."""
    tmp = _write_temp(target, serialise(data))
    try:
        if os.name == "nt":
            os.rename(tmp, target)  # fails if target exists
        else:
            os.link(tmp, target)  # fails if target exists
            os.unlink(tmp)
    except FileExistsError:
        raise BaselineError("baseline-exists", "a baseline already exists; use 'baseline replace'") from None
    finally:
        if tmp.exists():
            tmp.unlink()


def write_replacement(target: Path, data: dict) -> Path:
    """Write the new baseline, archive the old one, then move the new one into place."""
    tmp = _write_temp(target, serialise(data))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive = target.with_name(f"{target.stem}.{stamp}.replaced{target.suffix or '.json'}")
    try:
        os.rename(target, archive)
        os.replace(tmp, target)
    finally:
        if tmp.exists():
            tmp.unlink()
    return archive


def _archives(target: Path) -> list[str]:
    return sorted(p.name for p in target.parent.glob(f"{target.stem}.*.replaced*"))


def load(target: Path) -> Baseline:
    """Read and verify a baseline's structure and self-digest."""
    if not target.exists():
        archives = _archives(target)
        if archives:
            raise BaselineError("baseline-missing",
                                f"no baseline, but an archived one exists ({archives[-1]}); a replace may have been interrupted")
        raise BaselineError("baseline-missing", "no baseline found; run 'ilmarinen baseline create'")
    try:
        data = cj.strict_loads(target.read_bytes())
    except OSError:
        raise BaselineError("baseline-unreadable", "the baseline could not be read") from None
    except cj.StrictJsonError:
        raise BaselineError("baseline-integrity-failure", "the baseline is not valid JSON", integrity=True) from None
    required = {"format", "created_at", "agent_version", "roots", "config_fingerprint", "entries", "digest"}
    if not isinstance(data, dict) or not required <= set(data) or set(data) - required - {"replaced"}:
        raise BaselineError("baseline-integrity-failure", "the baseline has an unexpected structure", integrity=True)
    if data["format"] != FORMAT:
        raise BaselineError("baseline-integrity-failure", "unsupported baseline format", integrity=True)
    stored = data["digest"]
    try:
        computed = cj.digest({k: v for k, v in data.items() if k != "digest"})
    except cj.CanonicalJsonError:
        raise BaselineError("baseline-integrity-failure", "the baseline contains invalid values", integrity=True) from None
    if not isinstance(stored, str) or stored != computed:
        raise BaselineError("baseline-integrity-failure", "the baseline's digest does not match its content",
                            integrity=True)
    if not isinstance(data["entries"], list) or not all(isinstance(e, dict) and "key" in e for e in data["entries"]):
        raise BaselineError("baseline-integrity-failure", "the baseline entries are malformed", integrity=True)
    return Baseline(data, computed)


def verify_against(baseline: Baseline, config: Config, scan: ScanResult, expected_digest: str | None) -> None:
    """Checks that must pass before any comparison. Raises BaselineError."""
    if expected_digest is not None and expected_digest.lower() != baseline.digest:
        raise BaselineError("baseline-integrity-failure",
                            "the baseline's digest differs from the independently supplied digest", integrity=True)
    by_id = {r.get("id"): r for r in baseline.data["roots"] if isinstance(r, dict)}
    for root in config.roots:
        stored = by_id.get(root.id)
        if stored is None:
            continue  # reported below as a configuration change
        if stored.get("path_identity") != path_identity(root.path):
            raise BaselineError("root-changed", f"root '{root.id}' now points at a different path")
        current = scan.root_identities.get(root.id)
        if current is not None and stored.get("object_identity") != current:
            raise BaselineError("root-replaced", f"root '{root.id}' is a different directory than when the baseline was made")
    if baseline.data["config_fingerprint"] != fingerprint(_roots(config, scan)):
        raise BaselineError("config-changed-since-baseline",
                            "roots or exclusions changed since the baseline; review and use 'baseline replace'")
