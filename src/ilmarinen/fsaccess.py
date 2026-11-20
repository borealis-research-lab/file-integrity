"""Type-first, race-aware filesystem access.

Principle: an entry's type and identity are established on a handle that cannot read the
object or trigger its open behaviour. Only after that is a readable handle obtained to the
SAME already-resolved object (no new pathname lookup), and its identity re-verified.
Only regular files are ever read. Where a platform cannot guarantee this, Ilmarinen fails
closed (UnsafePlatform) instead of claiming a safe check.

- Windows: CreateFileW with no access rights + FILE_FLAG_OPEN_REPARSE_POINT (the entry
  itself, never a reparse target), GetFileType / GetFileInformationByHandle /
  GetFinalPathNameByHandleW checks, then ReOpenFile(GENERIC_READ) on that handle.
- Linux: directories opened O_DIRECTORY|O_NOFOLLOW relative to the parent descriptor;
  candidates opened O_PATH|O_NOFOLLOW (no I/O open); the readable descriptor comes from
  /proc/self/fd/<n> (a magic link to the already-resolved object, deliberately followed).
"""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from dataclasses import dataclass, field
from typing import Callable

CHUNK = 1024 * 1024
STABILITY_RETRIES = 2

# Test hook: called with the entry name between listing and opening (used to simulate races).
BEFORE_OPEN: Callable[[str], None] | None = None
# Test hook: called with the entry name after enumeration returned it, before its metadata is read.
AFTER_ENUMERATE: Callable[[str], None] | None = None


class FsError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class UnsafePlatform(Exception):
    pass


@dataclass
class Listed:
    name: str
    kind: str  # file | dir | link | special | vanished (enumerated, then gone before inspection)
    identity: tuple | None = None
    special_type: str = ""


@dataclass
class Node:
    kind: str
    identity: tuple
    size: int = 0
    mtime_ns: int = 0
    special_type: str = ""
    native: object = None  # platform handle/descriptor
    path: str = ""  # Windows: full path (local only, never reported)
    extra: dict = field(default_factory=dict)


def _sha256_stream(read: Callable[[int], bytes]) -> str:
    h = hashlib.sha256()
    while True:
        chunk = read(CHUNK)
        if not chunk:
            return h.hexdigest()
        h.update(chunk)


# =========================================================================================
# Linux
# =========================================================================================


class LinuxFs:
    def __init__(self) -> None:
        if not hasattr(os, "O_PATH") or not os.path.isdir("/proc/self/fd"):
            raise UnsafePlatform("O_PATH or /proc/self/fd is unavailable")
        self.base = os.O_CLOEXEC | os.O_NOFOLLOW

    @staticmethod
    def _kind(mode: int) -> tuple[str, str]:
        if stat.S_ISREG(mode):
            return "file", ""
        if stat.S_ISDIR(mode):
            return "dir", ""
        if stat.S_ISLNK(mode):
            return "link", ""
        for test, name in ((stat.S_ISFIFO, "fifo"), (stat.S_ISSOCK, "socket"), (stat.S_ISCHR, "char-device"),
                           (stat.S_ISBLK, "block-device")):
            if test(mode):
                return "special", name
        return "special", "other"

    @staticmethod
    def _errno_code(exc: OSError) -> str:
        import errno

        if exc.errno == errno.ENOENT:
            return "vanished"
        if exc.errno in (errno.ENOTDIR, errno.ELOOP):
            return "changed-during-scan"
        return "unreadable"

    def open_root(self, path: str) -> Node:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | self.base)
        except OSError as exc:
            raise FsError(self._errno_code(exc), "root directory could not be opened") from None
        st = os.fstat(fd)
        return Node("dir", (st.st_dev, st.st_ino), native=fd)

    def root_identity(self, node: Node) -> dict:
        return {"dev": str(node.identity[0]), "ino": str(node.identity[1])}

    def list_dir(self, node: Node) -> list[Listed]:
        out = []
        try:
            with os.scandir(node.native) as it:
                for entry in it:
                    if AFTER_ENUMERATE:
                        AFTER_ENUMERATE(entry.name)
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        # Enumerated, then gone: report it, never skip it silently.
                        out.append(Listed(entry.name, "vanished"))
                        continue
                    kind, special = self._kind(st.st_mode)
                    out.append(Listed(entry.name, kind, (st.st_dev, st.st_ino), special))
        except OSError as exc:
            raise FsError(self._errno_code(exc), "directory could not be listed") from None
        return sorted(out, key=lambda e: os.fsencode(e.name))

    def open_child(self, parent: Node, listed: Listed) -> Node:
        if BEFORE_OPEN:
            BEFORE_OPEN(listed.name)
        flags = (os.O_RDONLY | os.O_DIRECTORY) if listed.kind == "dir" else os.O_PATH
        try:
            fd = os.open(listed.name, flags | self.base, dir_fd=parent.native)
        except OSError as exc:
            raise FsError(self._errno_code(exc), "entry could not be opened") from None
        st = os.fstat(fd)
        kind, special = self._kind(st.st_mode)
        if kind != listed.kind or (st.st_dev, st.st_ino) != listed.identity:
            os.close(fd)
            raise FsError("changed-during-scan", "entry changed between listing and opening")
        return Node(kind, (st.st_dev, st.st_ino), st.st_size, st.st_mtime_ns, special, native=fd)

    def hash_file(self, node: Node) -> tuple[str, int, int]:
        try:
            rfd = os.open(f"/proc/self/fd/{node.native}", os.O_RDONLY | os.O_CLOEXEC)  # magic link: follow
        except OSError as exc:
            raise FsError(self._errno_code(exc), "file could not be read") from None
        try:
            for _ in range(STABILITY_RETRIES + 1):
                before = os.fstat(rfd)
                if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) != node.identity:
                    raise FsError("changed-during-scan", "readable handle does not match the inspected entry")
                os.lseek(rfd, 0, os.SEEK_SET)
                digest = _sha256_stream(lambda n: os.read(rfd, n))
                after = os.fstat(rfd)
                if (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns):
                    return digest, after.st_size, after.st_mtime_ns
            raise FsError("unstable", "file kept changing while being hashed")
        except OSError:
            raise FsError("unreadable", "file could not be read") from None
        finally:
            os.close(rfd)

    def link_target(self, parent: Node, node: Node, listed: Listed) -> bytes:
        try:
            return os.fsencode(os.readlink(listed.name, dir_fd=parent.native))
        except OSError:
            raise FsError("link-unreadable", "link target could not be read") from None

    def close(self, node: Node) -> None:
        if isinstance(node.native, int):
            os.close(node.native)
            node.native = None


# =========================================================================================
# Windows
# =========================================================================================


class WindowsFs:
    GENERIC_READ = 0x80000000
    SHARE_ALL = 0x7
    OPEN_EXISTING = 3
    FLAG_OPEN_REPARSE_POINT = 0x00200000
    FLAG_BACKUP_SEMANTICS = 0x02000000
    ATTR_DIRECTORY = 0x10
    ATTR_REPARSE_POINT = 0x400
    FILE_TYPE_DISK = 1
    INVALID = -1

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        self.ctypes = ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        HANDLE = wintypes.HANDLE

        class FILETIME(ctypes.Structure):
            _fields_ = [("lo", wintypes.DWORD), ("hi", wintypes.DWORD)]

        class INFO(ctypes.Structure):
            _fields_ = [("attrs", wintypes.DWORD), ("created", FILETIME), ("accessed", FILETIME),
                        ("written", FILETIME), ("volume", wintypes.DWORD), ("size_hi", wintypes.DWORD),
                        ("size_lo", wintypes.DWORD), ("links", wintypes.DWORD), ("index_hi", wintypes.DWORD),
                        ("index_lo", wintypes.DWORD)]

        class FILE_ID_INFO(ctypes.Structure):
            _fields_ = [("volume", ctypes.c_ulonglong), ("file_id", ctypes.c_ubyte * 16)]

        self.INFO, self.FILE_ID_INFO = INFO, FILE_ID_INFO
        try:
            self.CreateFileW = k32.CreateFileW
            self.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                         wintypes.DWORD, wintypes.DWORD, HANDLE]
            self.CreateFileW.restype = HANDLE
            self.ReOpenFile = k32.ReOpenFile
            self.ReOpenFile.argtypes = [HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
            self.ReOpenFile.restype = HANDLE
            self.GetFileType = k32.GetFileType
            self.GetFileType.argtypes = [HANDLE]
            self.GetFileType.restype = wintypes.DWORD
            self.GetInfo = k32.GetFileInformationByHandle
            self.GetInfo.argtypes = [HANDLE, ctypes.POINTER(INFO)]
            self.GetInfo.restype = wintypes.BOOL
            self.GetInfoEx = k32.GetFileInformationByHandleEx
            self.GetInfoEx.argtypes = [HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
            self.GetInfoEx.restype = wintypes.BOOL
            self.GetFinalPath = k32.GetFinalPathNameByHandleW
            self.GetFinalPath.argtypes = [HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
            self.GetFinalPath.restype = wintypes.DWORD
            self.CloseHandle = k32.CloseHandle
            self.CloseHandle.argtypes = [HANDLE]
        except AttributeError as exc:
            raise UnsafePlatform(f"required Windows API unavailable: {exc}") from None
        import msvcrt

        self.msvcrt = msvcrt

    # --- helpers -------------------------------------------------------------------------

    @staticmethod
    def _long(path: str) -> str:
        path = os.path.abspath(path)
        return path if path.startswith("\\\\?\\") else "\\\\?\\" + path

    def _err(self, default: str = "unreadable") -> str:
        code = self.ctypes.get_last_error()
        if code in (2, 3):  # file / path not found
            return "vanished"
        return default

    def _query(self, path: str):
        h = self.CreateFileW(self._long(path), 0, self.SHARE_ALL, None, self.OPEN_EXISTING,
                             self.FLAG_OPEN_REPARSE_POINT | self.FLAG_BACKUP_SEMANTICS, None)
        if h is None or h == self.INVALID or (isinstance(h, int) and h & 0xFFFFFFFFFFFFFFFF == 0xFFFFFFFFFFFFFFFF):
            raise FsError(self._err(), "entry could not be opened")
        return h

    def _info(self, h):
        info = self.INFO()
        if not self.GetInfo(h, self.ctypes.byref(info)):
            raise FsError("unreadable", "file information unavailable")
        return info

    def _final_path(self, h) -> str:
        buf = self.ctypes.create_unicode_buffer(32768)
        n = self.GetFinalPath(h, buf, 32768, 0)
        if n == 0 or n >= 32768:
            raise FsError("changed-during-scan", "final path unavailable")
        return buf.value

    @staticmethod
    def _canon(path: str) -> str:
        if path.startswith("\\\\?\\UNC\\"):
            path = "\\\\" + path[8:]
        elif path.startswith("\\\\?\\"):
            path = path[4:]
        return os.path.normcase(path.rstrip("\\"))

    def _node(self, h, path: str) -> Node:
        if self.GetFileType(h) != self.FILE_TYPE_DISK:
            return Node("special", (0, 0), special_type="non-disk", native=h, path=path)
        info = self._info(h)
        identity = (info.volume, (info.index_hi << 32) | info.index_lo)
        if info.attrs & self.ATTR_REPARSE_POINT:
            kind = "link"
        elif info.attrs & self.ATTR_DIRECTORY:
            kind = "dir"
        else:
            kind = "file"
        size = (info.size_hi << 32) | info.size_lo
        mtime_ns = (((info.written.hi << 32) | info.written.lo) - 116444736000000000) * 100
        return Node(kind, identity, size, mtime_ns, native=h, path=path)

    # --- interface -----------------------------------------------------------------------

    def open_root(self, path: str) -> Node:
        h = self._query(path)
        node = self._node(h, path)
        if node.kind != "dir":
            self.CloseHandle(h)
            raise FsError("changed-during-scan", "root is not a directory")
        node.extra["final"] = self._canon(self._final_path(h))
        return node

    def root_identity(self, node: Node) -> dict:
        info = self.FILE_ID_INFO()
        if self.GetInfoEx(node.native, 0x12, self.ctypes.byref(info), self.ctypes.sizeof(info)):  # FileIdInfo
            return {"volume_serial": str(info.volume), "file_id": bytes(info.file_id).hex()}
        return {"volume_serial": str(node.identity[0]), "file_id": f"{node.identity[1]:032x}"}

    def list_dir(self, node: Node) -> list[Listed]:
        out = []
        try:
            with os.scandir(self._long(node.path)) as it:
                for entry in it:
                    if AFTER_ENUMERATE:
                        AFTER_ENUMERATE(entry.name)
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        # Enumerated, then gone: report it, never skip it silently.
                        out.append(Listed(entry.name, "vanished"))
                        continue
                    attrs = getattr(st, "st_file_attributes", 0)
                    if attrs & self.ATTR_REPARSE_POINT:
                        kind = "link"
                    elif stat.S_ISDIR(st.st_mode):
                        kind = "dir"
                    elif stat.S_ISREG(st.st_mode):
                        kind = "file"
                    else:
                        kind = "special"
                    out.append(Listed(entry.name, kind))
        except FileNotFoundError:
            raise FsError("vanished", "directory vanished") from None
        except OSError:
            raise FsError("unreadable", "directory could not be listed") from None
        return sorted(out, key=lambda e: e.name)

    def open_child(self, parent: Node, listed: Listed) -> Node:
        if BEFORE_OPEN:
            BEFORE_OPEN(listed.name)
        path = os.path.join(parent.path, listed.name)
        h = self._query(path)
        try:
            node = self._node(h, path)
            if node.kind != listed.kind:
                raise FsError("changed-during-scan", "entry changed between listing and opening")
            expected = os.path.normcase(os.path.join(parent.extra["final"], listed.name))
            final = self._canon(self._final_path(h))
            if final != expected:
                raise FsError("changed-during-scan", "entry path resolved somewhere unexpected")
            node.extra["final"] = final
            return node
        except FsError:
            self.CloseHandle(h)
            raise

    def hash_file(self, node: Node) -> tuple[str, int, int]:
        rh = self.ReOpenFile(node.native, self.GENERIC_READ, self.SHARE_ALL, self.FLAG_OPEN_REPARSE_POINT)
        if rh is None or (isinstance(rh, int) and rh & 0xFFFFFFFFFFFFFFFF == 0xFFFFFFFFFFFFFFFF):
            raise FsError("unreadable", "file could not be opened for reading")
        fd = self.msvcrt.open_osfhandle(rh, os.O_RDONLY | os.O_BINARY)  # fd now owns rh
        try:
            for _ in range(STABILITY_RETRIES + 1):
                before = self._node(rh, node.path)
                if before.kind != "file" or before.identity != node.identity:
                    raise FsError("changed-during-scan", "readable handle does not match the inspected entry")
                os.lseek(fd, 0, os.SEEK_SET)
                try:
                    digest = _sha256_stream(lambda n: os.read(fd, n))
                except OSError:
                    raise FsError("unreadable", "file could not be read") from None
                after = self._node(rh, node.path)
                if (before.size, before.mtime_ns) == (after.size, after.mtime_ns):
                    return digest, after.size, after.mtime_ns
            raise FsError("unstable", "file kept changing while being hashed")
        finally:
            os.close(fd)

    def link_target(self, parent: Node, node: Node, listed: Listed) -> bytes:
        try:
            target = os.readlink(self._long(node.path))
        except OSError:
            raise FsError("link-unreadable", "link target could not be read") from None
        # Confirm the entry we fingerprinted is still the inspected link.
        h = self._query(node.path)
        try:
            again = self._node(h, node.path)
        finally:
            self.CloseHandle(h)
        if again.kind != "link" or again.identity != node.identity:
            raise FsError("changed-during-scan", "link changed while being read")
        return target.encode("utf-8", "surrogatepass")

    def close(self, node: Node) -> None:
        if node.native is not None:
            self.CloseHandle(node.native)
            node.native = None


def platform():
    if os.name == "nt":
        return WindowsFs()
    if sys.platform.startswith("linux"):
        return LinuxFs()
    raise UnsafePlatform(f"no safe file-access implementation for {sys.platform}")
