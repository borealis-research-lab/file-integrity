"""Walks the configured roots and produces entries and errors. Nothing is silently omitted:
every entry is either recorded, counted as excluded, or reported as an error."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ilmarinen import refs
from ilmarinen.config import Config, Root
from ilmarinen.fsaccess import FsError, Listed, Node, UnsafePlatform
from ilmarinen.patterns import excluded


@dataclass
class Entry:
    key: str
    ref: str
    kind: str  # file | link | special
    sha256: str = ""
    size: int = 0
    mtime: str = ""
    link_target_sha256: str = ""
    special_type: str = ""

    def to_baseline(self) -> dict:
        data = {"key": self.key, "ref": self.ref, "kind": self.kind}
        if self.kind == "file":
            data.update(sha256=self.sha256, size=self.size, mtime=self.mtime)
        elif self.kind == "link":
            data.update(link_target_sha256=self.link_target_sha256)
        return data


@dataclass
class ScanError:
    code: str
    ref: str
    message: str
    key: str = ""  # entry key when the error concerns one entry


@dataclass
class ScanResult:
    entries: dict[str, Entry] = field(default_factory=dict)
    errors: list[ScanError] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)  # root id -> entries recorded
    excluded: dict[str, int] = field(default_factory=dict)  # root id -> directly excluded entries
    root_identities: dict[str, dict] = field(default_factory=dict)
    unsafe_platform: str = ""

    @property
    def complete(self) -> bool:
        return not self.errors and not self.unsafe_platform


def _timestamp(mtime_ns: int) -> str:
    dt = datetime.fromtimestamp(mtime_ns // 1_000_000_000, tz=timezone.utc)
    micro = (mtime_ns // 1000) % 1_000_000
    text = dt.strftime("%Y-%m-%dT%H:%M:%S")
    return text + (f".{micro:06d}" if micro else "") + "Z"


class Scanner:
    def __init__(self, fs) -> None:
        self.fs = fs
        self.result = ScanResult()

    def scan(self, config: Config) -> ScanResult:
        for root in config.roots:
            self.result.counts[root.id] = 0
            self.result.excluded[root.id] = 0
            self._scan_root(root)
        return self.result

    # --- helpers -----------------------------------------------------------------------

    def _error(self, code: str, ref: str, message: str, key: str = "") -> None:
        self.result.errors.append(ScanError(code, ref, message, key))

    def _scan_root(self, root: Root) -> None:
        root_ref = f"file:{root.id}:"
        if os.path.isdir(root.path):
            try:
                node = self.fs.open_root(root.path)
            except FsError as exc:
                self._error(exc.code, root_ref, exc.message)
                return
            try:
                self.result.root_identities[root.id] = self.fs.root_identity(node)
                self._walk(root, node, [], [], [])
            finally:
                self.fs.close(node)
            return
        # A single-file root: open its (trusted, configured) parent, then the file type-first.
        parent_path, name = os.path.split(root.path)
        try:
            parent = self.fs.open_root(parent_path)
        except FsError as exc:
            self._error(exc.code, root_ref, exc.message)
            return
        try:
            listed = next((e for e in self.fs.list_dir(parent) if e.name == name), None)
            if listed is None:
                self._error("vanished", root_ref, "configured file is missing")
                return
            if listed.kind == "dir":
                self._error("changed-during-scan", root_ref, "configured file is now a directory")
                return
            node = self.fs.open_child(parent, listed)
            try:
                self.result.root_identities[root.id] = self.fs.root_identity(node)
            finally:
                self.fs.close(node)
            self._entry(root, parent, listed, [name], [refs.segment_bytes(name)])
        except FsError as exc:
            self._error(exc.code, root_ref, exc.message)
        finally:
            self.fs.close(parent)

    def _walk(self, root: Root, node: Node, names: list[str], segments: list[bytes], display: list[str]) -> None:
        dir_ref = refs.make_ref(root.id, segments)
        try:
            listing = self.fs.list_dir(node)
        except FsError as exc:
            self._error(exc.code, dir_ref, exc.message)
            return

        # Names that collide on the matching key (e.g. per-directory case sensitivity on
        # Windows) are all reported; none is silently chosen over another.
        keys: dict[str, list[Listed]] = {}
        encoded: dict[str, bytes] = {}
        for position, listed in enumerate(listing):
            try:
                encoded[listed.name] = refs.segment_bytes(listed.name)
            except refs.UnrepresentableName:
                self._error("unrepresentable-name", dir_ref,
                            f"entry {position + 1} in this directory has a name that cannot be represented")
                continue
            key = refs.make_key(root.id, names + [listed.name], segments + [encoded[listed.name]])
            keys.setdefault(key, []).append(listed)

        for key, group in sorted(keys.items()):
            if len(group) > 1:
                for listed in group:
                    ref = refs.make_ref(root.id, segments + [encoded[listed.name]])
                    self._error("name-collision", ref, "several entries share the same matching key", key)
                continue
            listed = group[0]
            seg = encoded[listed.name]
            disp = display + [refs.display_segment(seg)]
            if excluded(root.patterns, disp, listed.kind == "dir"):
                self.result.excluded[root.id] += 1
                continue
            if listed.kind == "dir":
                if not root.recursive:
                    continue  # non-recursive roots monitor only entries directly inside them
                ref = refs.make_ref(root.id, segments + [seg])
                try:
                    child = self.fs.open_child(node, listed)
                except FsError as exc:
                    self._error(exc.code, ref, exc.message)
                    continue
                try:
                    self._walk(root, child, names + [listed.name], segments + [seg], disp)
                finally:
                    self.fs.close(child)
                continue
            self._entry(root, node, listed, names + [listed.name], segments + [seg])

    def _entry(self, root: Root, parent: Node, listed: Listed, names: list[str], segments: list[bytes]) -> None:
        ref = refs.make_ref(root.id, segments)
        key = refs.make_key(root.id, names, segments)
        if listed.kind == "special":
            # Never opened for reading: identified from the listing / non-reading handle only.
            self.result.entries[key] = Entry(key, ref, "special", special_type=listed.special_type or "other")
            self.result.counts[root.id] += 1
            self._error("unsupported-entry", ref, f"special file ({listed.special_type or 'other'}) is not hashed", key)
            return
        try:
            node = self.fs.open_child(parent, listed)
        except FsError as exc:
            self._error(exc.code, ref, exc.message, key)
            return
        try:
            if node.kind == "file":
                digest, size, mtime_ns = self.fs.hash_file(node)
                entry = Entry(key, ref, "file", sha256=digest, size=size, mtime=_timestamp(mtime_ns))
            elif node.kind == "link":
                import hashlib

                target = self.fs.link_target(parent, node, listed)
                entry = Entry(key, ref, "link", link_target_sha256=hashlib.sha256(target).hexdigest())
            else:
                entry = Entry(key, ref, "special", special_type=node.special_type or "other")
                self._error("unsupported-entry", ref, "special file is not hashed", key)
            self.result.entries[key] = entry
            self.result.counts[root.id] += 1
        except FsError as exc:
            self._error(exc.code, ref, exc.message, key)
        finally:
            self.fs.close(node)


def scan(config: Config, fs=None) -> ScanResult:
    if fs is None:
        from ilmarinen.fsaccess import platform

        try:
            fs = platform()
        except UnsafePlatform as exc:
            result = ScanResult(unsafe_platform=str(exc))
            for root in config.roots:
                result.counts[root.id] = 0
                result.excluded[root.id] = 0
            return result
    return Scanner(fs).scan(config)
