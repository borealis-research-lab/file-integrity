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
    raw: bytes = b""  # the exact bytes that were validated (archived on replace)

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


def _publish_exclusive(tmp: Path, dest: Path) -> None:
    """Atomically give a fully written temporary file its final name, never replacing an
    existing file: os.rename refuses an existing target on Windows; os.link refuses on POSIX."""
    try:
        if os.name == "nt":
            os.rename(tmp, dest)
        else:
            os.link(tmp, dest)
            os.unlink(tmp)
    finally:
        if tmp.exists():
            tmp.unlink()


def write_new(target: Path, data: dict) -> None:
    """Atomically create the baseline; refuses if one already exists."""
    tmp = _write_temp(target, serialise(data))
    try:
        _publish_exclusive(tmp, target)
    except FileExistsError:
        raise BaselineError("baseline-exists", "a baseline already exists; use 'baseline replace'") from None


def archive_name(target: Path) -> Path:
    """Unique by construction: microsecond timestamp plus 64 random bits."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    return target.with_name(f"{target.stem}.{stamp}.{uuid.uuid4().hex[:16]}.replaced{target.suffix or '.json'}")


def write_replacement(target: Path, data: dict, current: bytes) -> Path:
    """Replace the baseline without ever losing the current one.

    1. Write the new baseline to a temporary file (fsync).
    2. Write a copy of the current baseline to a temporary file and publish it under a
       unique archive name, never overwriting an existing file.
    3. Only then atomically replace the current baseline with the new one.
    If step 1 or 2 fails, the current baseline is untouched and the replacement is refused.
    """
    new_tmp = _write_temp(target, serialise(data))
    try:
        archive = archive_name(target)
        try:
            _publish_exclusive(_write_temp(target, current), archive)
        except OSError as exc:
            raise BaselineError("archive-failed", f"the current baseline could not be archived safely "
                                                  f"({exc.strerror or exc}); nothing was changed") from None
        os.replace(new_tmp, target)
    finally:
        if new_tmp.exists():
            new_tmp.unlink()
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
        raw = target.read_bytes()
        data = cj.strict_loads(raw)
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
    problem = structure_problem(data)
    if problem:
        raise BaselineError("baseline-integrity-failure", f"the baseline is malformed: {problem}", integrity=True)
    return Baseline(data, computed, raw)


# --- full structural validation ---------------------------------------------------------------

RE_ROOT_ID = re.compile(r"[a-z][a-z0-9-]{0,31}")
RE_REF = re.compile(r"file:([a-z][a-z0-9-]{0,31}):(?:[A-Za-z0-9._~/-]|%[0-9A-F]{2})*")
RE_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z")
RE_DECIMAL = re.compile(r"[0-9]{1,20}")
RE_HEX32 = re.compile(r"[0-9a-f]{32}")
RE_PRINTABLE = re.compile(r"[ -~]{1,32}")


def _is_str(value, regex) -> bool:
    return isinstance(value, str) and regex.fullmatch(value) is not None


def _valid_identity(value) -> bool:
    if not isinstance(value, dict):
        return False
    if set(value) == {"dev", "ino"}:
        return _is_str(value["dev"], RE_DECIMAL) and _is_str(value["ino"], RE_DECIMAL)
    if set(value) == {"volume_serial", "file_id"}:
        return _is_str(value["volume_serial"], RE_DECIMAL) and _is_str(value["file_id"], RE_HEX32)
    return False


def structure_problem(data: dict) -> str | None:
    """Return a description of the first structural problem, or None if the whole baseline is
    well-formed. Never raises: malformed data must fail safely, not crash."""
    from ilmarinen.patterns import PatternError, validate as validate_pattern

    if not _is_str(data.get("created_at"), RE_TIMESTAMP):
        return "created_at"
    if not _is_str(data.get("agent_version"), RE_PRINTABLE):
        return "agent_version"
    if not _is_str(data.get("config_fingerprint"), RE_HEX64):
        return "config_fingerprint"
    if "replaced" in data:
        rep = data["replaced"]
        if not (isinstance(rep, dict) and set(rep) == {"at", "previous_digest"}
                and _is_str(rep["at"], RE_TIMESTAMP) and _is_str(rep["previous_digest"], RE_HEX64)):
            return "replaced"

    roots = data.get("roots")
    if not isinstance(roots, list) or not 1 <= len(roots) <= 50:
        return "roots"
    root_ids = set()
    for root in roots:
        if not isinstance(root, dict) or set(root) != {"id", "path_identity", "object_identity", "recursive", "exclude"}:
            return "root record fields"
        if not _is_str(root["id"], RE_ROOT_ID) or root["id"] in root_ids:
            return "root id"
        root_ids.add(root["id"])
        if not _is_str(root["path_identity"], RE_HEX64):
            return "root path_identity"
        if not _valid_identity(root["object_identity"]):
            return "root object_identity"
        if not isinstance(root["recursive"], bool):
            return "root recursive"
        if not isinstance(root["exclude"], list) or len(root["exclude"]) > 100:
            return "root exclude"
        for pattern in root["exclude"]:
            try:
                validate_pattern(pattern)
            except PatternError:
                return "root exclude pattern"
    if data["config_fingerprint"] != fingerprint(roots):
        return "config_fingerprint does not match the roots"

    entries = data.get("entries")
    if not isinstance(entries, list):
        return "entries"
    keys = set()
    for entry in entries:
        if not isinstance(entry, dict):
            return "entry record"
        kind = entry.get("kind")
        fields = {"file": {"key", "ref", "kind", "sha256", "size", "mtime"},
                  "link": {"key", "ref", "kind", "link_target_sha256"}}.get(kind) if isinstance(kind, str) else None
        if fields is None or set(entry) != fields:
            return "entry fields or kind"
        key, ref = entry["key"], entry["ref"]
        if not _is_str(key, RE_REF) or not _is_str(ref, RE_REF):
            return "entry key or ref"
        if RE_REF.fullmatch(key).group(1) not in root_ids or RE_REF.fullmatch(ref).group(1) not in root_ids:
            return "entry belongs to an unknown root"
        if key in keys:
            return "duplicate entry key"
        keys.add(key)
        if kind == "file":
            if not _is_str(entry["sha256"], RE_HEX64) or not _is_str(entry["mtime"], RE_TIMESTAMP):
                return "entry sha256 or mtime"
            size = entry["size"]
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                return "entry size"
        elif not _is_str(entry["link_target_sha256"], RE_HEX64):
            return "entry link_target_sha256"
    return None


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
