"""Races between listing and opening (via a test hook), special files, unsafe platforms,
stability, and the reporting standard's limits."""

import hashlib
import os
import shutil
import threading
from datetime import datetime, timezone

import pytest

from conftest import (WINDOWS, check_json, check_report, create_baseline, error_codes, make_config,
                      make_link_to_dir, run, write)
from ilmarinen import fsaccess, report, scanner


@pytest.fixture(autouse=True)
def clear_hook():
    yield
    fsaccess.BEFORE_OPEN = None


def _scan(config_path):
    from ilmarinen import config

    return scanner.scan(config.load(config_path))


# --- races -----------------------------------------------------------------------------


def test_file_swapped_for_link_between_listing_and_opening(tmp_path):
    root = tmp_path / "monitored"
    write(root / "target.txt", "original")
    elsewhere = tmp_path / "elsewhere"
    write(elsewhere / "planted.txt", "planted")
    config = make_config(tmp_path, [{"id": "docs", "path": root}])

    def swap(name):
        if name == "target.txt":
            (root / "target.txt").unlink()
            make_link_to_dir(root / "target.txt", elsewhere)

    fsaccess.BEFORE_OPEN = swap
    result = _scan(config)
    assert [(e.code, e.ref) for e in result.errors] == [("changed-during-scan", "file:docs:target.txt")]
    assert "file:docs:target.txt" not in {e.ref for e in result.entries.values()}


def test_directory_swapped_for_link_is_not_traversed(tmp_path):
    root = tmp_path / "monitored"
    write(root / "sub" / "inner.txt", "inner")
    elsewhere = tmp_path / "elsewhere"
    write(elsewhere / "outside.txt", "outside")
    config = make_config(tmp_path, [{"id": "docs", "path": root}])

    def swap(name):
        if name == "sub":
            (root / "sub").rename(tmp_path / "moved")
            make_link_to_dir(root / "sub", elsewhere)

    fsaccess.BEFORE_OPEN = swap
    result = _scan(config)
    assert [(e.code, e.ref) for e in result.errors] == [("changed-during-scan", "file:docs:sub")]
    assert not any("outside" in e.ref for e in result.entries.values())


def test_intermediate_directory_swap_never_reads_through_the_link(tmp_path):
    root = tmp_path / "monitored"
    write(root / "sub" / "inner.txt", "genuine")
    elsewhere = tmp_path / "elsewhere"
    write(elsewhere / "inner.txt", "planted")
    config = make_config(tmp_path, [{"id": "docs", "path": root}])
    planted = hashlib.sha256(b"planted").hexdigest()
    genuine = hashlib.sha256(b"genuine").hexdigest()

    def swap(name):
        if name == "inner.txt" and not (tmp_path / "moved").exists():
            (root / "sub").rename(tmp_path / "moved")  # the directory already being walked
            make_link_to_dir(root / "sub", elsewhere)

    fsaccess.BEFORE_OPEN = swap
    result = _scan(config)
    entry = result.entries.get(next(iter(result.entries), ""), None)
    hashes = {e.sha256 for e in result.entries.values()}
    assert planted not in hashes  # content behind the swapped-in link is never read
    if WINDOWS:  # path-based open: detected by the final-path check
        assert [e.code for e in result.errors] == ["changed-during-scan"]
    else:  # descriptor-relative open: still reads the genuine, already-opened directory
        assert hashes == {genuine} and entry is not None


def test_file_that_vanishes_before_opening(tmp_path):
    root = tmp_path / "monitored"
    write(root / "gone.txt", "x")
    config = make_config(tmp_path, [{"id": "docs", "path": root}])
    fsaccess.BEFORE_OPEN = lambda name: (root / "gone.txt").unlink() if name == "gone.txt" else None
    assert [e.code for e in _scan(config).errors] == ["vanished"]


def test_file_changing_while_hashed_is_unstable(tmp_path, monkeypatch):
    root = tmp_path / "monitored"
    target = write(root / "busy.log", "start")
    config = make_config(tmp_path, [{"id": "docs", "path": root}])
    original = fsaccess._sha256_stream

    def growing(read):
        digest = original(read)
        with open(target, "a") as handle:  # another writer appends during every read
            handle.write("more")
        return digest

    monkeypatch.setattr(fsaccess, "_sha256_stream", growing)
    assert [e.code for e in _scan(config).errors] == ["unstable"]


@pytest.mark.skipif(WINDOWS, reason="FIFOs are POSIX-only")
def test_file_swapped_for_fifo_never_blocks(tmp_path):
    root = tmp_path / "monitored"
    write(root / "data.bin", "x")
    config = make_config(tmp_path, [{"id": "docs", "path": root}])

    def swap(name):
        if name == "data.bin":
            (root / "data.bin").unlink()
            os.mkfifo(root / "data.bin")

    fsaccess.BEFORE_OPEN = swap
    done = []
    worker = threading.Thread(target=lambda: done.append(_scan(config)), daemon=True)
    worker.start()
    worker.join(timeout=20)
    assert done, "scan blocked on a FIFO"
    assert [e.code for e in done[0].errors] == ["changed-during-scan"]


@pytest.mark.skipif(WINDOWS, reason="FIFOs are POSIX-only")
def test_fifo_is_never_opened_and_blocks_baseline(capsys, tmp_path):
    root = tmp_path / "monitored"
    write(root / "ok.txt", "x")
    os.mkfifo(root / "pipe")
    config = make_config(tmp_path, [{"id": "docs", "path": root}])
    code, _, err = run(capsys, "baseline", "create", "--config", config)  # would hang if the FIFO were opened
    assert code == 1 and "unsupported-entry" in err


@pytest.mark.skipif(WINDOWS or os.geteuid() != 0 if hasattr(os, "geteuid") else True,
                    reason="creating a device node needs root on Linux")
def test_device_node_is_never_opened(tmp_path):
    import stat as st

    root = tmp_path / "monitored"
    root.mkdir()
    os.mknod(root / "null", st.S_IFCHR | 0o600, os.makedev(1, 3))
    config = make_config(tmp_path, [{"id": "docs", "path": root}])
    result = _scan(config)
    assert [e.code for e in result.errors] == ["unsupported-entry"]


# --- unsafe platform: fail closed --------------------------------------------------------


def test_unsafe_platform_fails_closed(capsys, tmp_path, monkeypatch):
    root = tmp_path / "monitored"
    write(root / "a.txt", "x")
    config = make_config(tmp_path, [{"id": "docs", "path": root}])

    def unsafe():
        raise fsaccess.UnsafePlatform("simulated: no O_PATH")

    monkeypatch.setattr(fsaccess, "platform", unsafe)
    code, _, err = run(capsys, "baseline", "create", "--config", config)
    assert code == 1 and "unsafe-platform" in err
    report_ = check_json(capsys, config)
    assert report_["status"] == "error" and error_codes(report_) == {"unsafe-platform": 1}
    assert report_["findings"] == []


# --- reporting limits ----------------------------------------------------------------------

START = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
SCOPE = [{"kind": "root", "id": "docs", "count": 1}]


def _raw(i, rule="file-added", text="x"):
    from ilmarinen import compare

    return compare.finding(rule, f"file:docs:f{i:06d}.txt", text, {"current": {"kind": "file"}})


def test_more_than_100_errors_and_codes_are_aggregated():
    errors = [report.error(f"code-{i % 130:03d}", "problem", f"file:docs:e{i}") for i in range(400)]
    result = report.build([], errors, SCOPE, "test", START)
    assert check_report.validate_agent_report(result) == []
    assert result["status"] == "partial" and result["errors_total"] == 400
    assert len(result["errors"]) == 100 and len(result["error_counts"]) == 100
    assert sum(result["error_counts"].values()) == 400 and "other-codes" in result["error_counts"]


def test_more_than_1000_findings_are_truncated_with_an_error():
    result = report.build([_raw(i) for i in range(1200)], [], SCOPE, "test", START)
    assert check_report.validate_agent_report(result) == []
    assert result["status"] == "partial" and len(result["findings"]) == 1000
    assert result["findings_total"] == 1200 and "findings-truncated" in result["error_counts"]


def test_size_limit_keeps_report_valid():
    big = "y" * 1900
    raws = [_raw(i, "file-changed", big) for i in range(1000)]
    for raw in raws:
        raw["evidence"][0]["details"] = {"blob": "z" * 9000}
    result = report.build(raws, [], SCOPE, "test", START)
    text = report.serialise(result).encode("utf-8")
    assert len(text) <= report.MAX_REPORT_BYTES
    assert check_report.validate_agent_report(check_report.strict_loads(text), len(text)) == []
    assert result["status"] == "partial" and "details-omitted-for-size" in result["error_counts"]


def test_text_rendering_escapes_untrusted_values():
    raw = _raw(1, "file-changed", "line1\nFinding 9: High (fake)\n\tindented")
    text = report.to_text(report.build([raw], [], SCOPE, "test", START))
    assert not any(line.startswith("Finding 9") for line in text.splitlines())
    assert "\t" not in text
