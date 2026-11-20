"""Shared test helpers. All tests use temporary directories and synthetic files only."""

import contextlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / "standards"))
import check_report  # noqa: E402  (vendored reference checker, test-only)

from ilmarinen.cli import main  # noqa: E402

WINDOWS = os.name == "nt"


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def make_config(tmp_path: Path, roots: list[dict], baseline: Path | None = None) -> Path:
    cfg = {
        "roots": [{"recursive": True, "exclude": [], **r, "path": str(r["path"])} for r in roots],
        "baseline": str(baseline or tmp_path / "state" / "baseline.json"),
    }
    (tmp_path / "state").mkdir(exist_ok=True)
    path = tmp_path / "ilmarinen.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return path


def make_link_to_dir(link: Path, target: Path) -> None:
    """A directory link: an NTFS junction on Windows (no admin needed), a symlink elsewhere."""
    if WINDOWS:
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True, capture_output=True)
    else:
        os.symlink(target, link, target_is_directory=True)


def remove_link(link: Path) -> None:
    if WINDOWS:
        os.rmdir(link)  # removes the junction itself, never its target
    else:
        os.unlink(link)


@contextlib.contextmanager
def held_exclusively(path: Path):
    """Make a file unreadable for the duration: an exclusive (no-sharing) handle on
    Windows; permission 000 elsewhere."""
    if WINDOWS:
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        k32.CreateFileW.restype = wintypes.HANDLE
        h = k32.CreateFileW(str(path), 0x80000000, 0, None, 3, 0, None)
        try:
            yield
        finally:
            k32.CloseHandle(h)
    else:
        if os.geteuid() == 0:
            pytest.skip("running as root: permissions cannot make a file unreadable")
        os.chmod(path, 0)
        try:
            yield
        finally:
            os.chmod(path, 0o644)


def run(capsys, *argv):
    code = main([str(a) for a in argv])
    out, err = capsys.readouterr()
    return code, out, err


def check_json(capsys, config: Path, *extra):
    code, out, err = run(capsys, "check", "--config", config, *extra)
    assert code == 0, err
    data = out.encode("utf-8")
    report = check_report.strict_loads(data)
    assert check_report.validate_agent_report(report, len(data)) == [], "report must conform to the standard"
    return report


def create_baseline(capsys, config: Path) -> str:
    code, out, err = run(capsys, "baseline", "create", "--config", config)
    assert code == 0, err
    return out.split("Baseline digest: ")[1].split()[0]


def rules(report) -> list[tuple[str, str]]:
    return sorted((f["rule_id"], f["evidence"][0]["ref"]) for f in report["findings"])


def error_codes(report) -> dict:
    return report["error_counts"]
