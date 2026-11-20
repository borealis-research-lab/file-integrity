"""End-to-end detection on temporary directories: create, modify, delete, add, rename, links,
exclusions, unreadable files and privacy."""

import getpass
import json
import os

import pytest

from conftest import (WINDOWS, check_json, create_baseline, error_codes, held_exclusively, make_config,
                      make_link_to_dir, remove_link, rules, run, write)


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "monitored"
    write(root / "a.txt", "alpha")
    write(root / "sub" / "b.txt", "bravo")
    write(root / "notes.tmp", "scratch")
    config = make_config(tmp_path, [{"id": "docs", "path": root, "exclude": ["*.tmp"]}])
    return root, config


def test_unchanged_files_give_ok_with_no_findings(capsys, tree):
    root, config = tree
    create_baseline(capsys, config)
    report = check_json(capsys, config)
    assert report["status"] == "ok" and report["findings"] == []
    assert report["source"]["scope"] == [{"kind": "root", "id": "docs", "count": 2},
                                         {"kind": "excluded", "id": "docs", "count": 1}]


def test_modify_delete_add_are_reported(capsys, tree):
    root, config = tree
    create_baseline(capsys, config)
    write(root / "a.txt", "alpha changed")
    (root / "sub" / "b.txt").unlink()
    write(root / "c.txt", "charlie")
    report = check_json(capsys, config)
    assert rules(report) == [("file-added", "file:docs:c.txt"), ("file-changed", "file:docs:a.txt"),
                             ("file-deleted", "file:docs:sub/b.txt")]
    changed = next(f for f in report["findings"] if f["rule_id"] == "file-changed")
    details = changed["evidence"][0]["details"]
    assert details["baseline"]["sha256"] != details["current"]["sha256"]
    assert {f["severity"] for f in report["findings"]} == {"medium", "low"}


def test_rename_is_deleted_plus_added(capsys, tree):
    root, config = tree
    create_baseline(capsys, config)
    (root / "a.txt").rename(root / "renamed.txt")
    assert rules(check_json(capsys, config)) == [("file-added", "file:docs:renamed.txt"),
                                                 ("file-deleted", "file:docs:a.txt")]


def test_excluded_entries_are_ignored_but_counted(capsys, tree):
    root, config = tree
    create_baseline(capsys, config)
    write(root / "another.tmp", "x")
    report = check_json(capsys, config)
    assert report["findings"] == []
    assert {"kind": "excluded", "id": "docs", "count": 2} in report["source"]["scope"]


def test_directory_link_is_recorded_not_followed(capsys, tmp_path):
    root = tmp_path / "monitored"
    write(root / "real" / "x.txt", "x")
    elsewhere = tmp_path / "elsewhere"
    write(elsewhere / "secret.txt", "outside the root")
    make_link_to_dir(root / "link", elsewhere)
    config = make_config(tmp_path, [{"id": "docs", "path": root}])
    create_baseline(capsys, config)
    report = check_json(capsys, config)
    assert report["status"] == "ok"
    baseline = json.loads((tmp_path / "state" / "baseline.json").read_text())
    kinds = {e["ref"]: e["kind"] for e in baseline["entries"]}
    assert kinds == {"file:docs:link": "link", "file:docs:real/x.txt": "file"}  # target never hashed

    # Repointing the link is detected; content behind it never is.
    remove_link(root / "link")
    other = tmp_path / "other"
    other.mkdir()
    make_link_to_dir(root / "link", other)
    assert rules(check_json(capsys, config)) == [("link-changed", "file:docs:link")]


def test_file_replaced_by_link_is_entry_type_changed(capsys, tmp_path):
    root = tmp_path / "monitored"
    write(root / "config", "settings")
    config = make_config(tmp_path, [{"id": "docs", "path": root}])
    create_baseline(capsys, config)
    (root / "config").unlink()
    make_link_to_dir(root / "config", tmp_path)
    report = check_json(capsys, config)
    [finding] = report["findings"]
    assert finding["rule_id"] == "entry-type-changed" and finding["severity"] == "high"


def test_unreadable_file_is_partial_not_a_finding(capsys, tree):
    root, config = tree
    create_baseline(capsys, config)
    with held_exclusively(root / "a.txt"):
        report = check_json(capsys, config)
    assert report["status"] == "partial"
    assert error_codes(report) == {"unreadable": 1}
    assert report["errors"][0]["ref"] == "file:docs:a.txt"
    assert report["findings"] == []  # an unreadable file is not claimed as changed or deleted


def test_non_recursive_root_ignores_subdirectories(capsys, tmp_path):
    root = tmp_path / "monitored"
    write(root / "top.txt", "t")
    write(root / "sub" / "deep.txt", "d")
    config = make_config(tmp_path, [{"id": "docs", "path": root, "recursive": False}])
    create_baseline(capsys, config)
    baseline = json.loads((tmp_path / "state" / "baseline.json").read_text())
    assert [e["ref"] for e in baseline["entries"]] == ["file:docs:top.txt"]


def test_single_file_root(capsys, tmp_path):
    target = write(tmp_path / "hosts", "127.0.0.1 localhost")
    config = make_config(tmp_path, [{"id": "hosts", "path": target}])
    create_baseline(capsys, config)
    write(target, "203.0.113.9 bank.example")
    assert rules(check_json(capsys, config)) == [("file-changed", "file:hosts:hosts")]


def test_reports_contain_no_absolute_paths_or_user_name(capsys, tree, tmp_path):
    root, config = tree
    create_baseline(capsys, config)
    write(root / "a.txt", "changed")
    code, out, _ = run(capsys, "check", "--config", config)
    code_text, text, _ = run(capsys, "check", "--config", config, "--text")
    for output in (out, text):
        assert str(tmp_path) not in output and str(tmp_path).replace("\\", "\\\\") not in output
        assert str(root) not in output
        user = getpass.getuser()
        if user not in ("root",):  # "root" is also the report's scope kind, so it can't be checked by substring
            assert user.lower() not in output.lower()


def test_describe_declares_personal_data(capsys):
    code, out, _ = run(capsys, "describe")
    info = json.loads(out)
    assert info["name"] == "ilmarinen" and info["standard"] == "borealis-agent-report/1"
    assert info["personal_data"] == ["file-names", "relative-file-paths"]
    assert len(info["responsibility"]) <= 200


def test_never_modifies_monitored_files(capsys, tree):
    root, config = tree
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in root.rglob("*") if p.is_file()}
    create_baseline(capsys, config)
    check_json(capsys, config)
    after = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in root.rglob("*") if p.is_file()}
    assert before == after


def test_text_output_is_opt_in_and_safe(capsys, tree):
    root, config = tree
    create_baseline(capsys, config)
    write(root / "a.txt", "changed")
    _, text, _ = run(capsys, "check", "--config", config, "--text")
    assert text.startswith("Ilmarinen File Integrity Report")
    assert "Finding 1: Medium (file-changed)" in text
    _, default, _ = run(capsys, "check", "--config", config)
    assert json.loads(default)["standard"] == "borealis-agent-report/1"


@pytest.mark.skipif(WINDOWS, reason="POSIX-only: names with newlines and special files")
def test_posix_newline_names_cannot_spoof_text(capsys, tmp_path):
    root = tmp_path / "monitored"
    write(root / "ok.txt", "x")
    config = make_config(tmp_path, [{"id": "docs", "path": root}])
    create_baseline(capsys, config)
    write(root / "evil\n\nFinding 9: High (file-changed)", "x")
    _, text, _ = run(capsys, "check", "--config", config, "--text")
    assert not any(line.startswith("Finding 9") for line in text.splitlines())
