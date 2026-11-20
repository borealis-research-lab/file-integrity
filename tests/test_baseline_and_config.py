"""Baseline protection (complete scans only, atomic writes, tamper detection, root identity)
and configuration refusals."""

import json
import os
import shutil

import pytest

from conftest import (check_json, create_baseline, error_codes, held_exclusively, make_config,
                      make_link_to_dir, run, write)
from ilmarinen import baseline as baseline_mod
from ilmarinen import refs


@pytest.fixture
def setup(tmp_path):
    root = tmp_path / "monitored"
    write(root / "a.txt", "alpha")
    write(root / "sub" / "b.txt", "bravo")
    config = make_config(tmp_path, [{"id": "docs", "path": root}])
    return root, config, tmp_path / "state" / "baseline.json"


# --- creation only from a complete scan -------------------------------------------------


def test_create_refuses_when_a_file_is_unreadable(capsys, setup):
    root, config, target = setup
    with held_exclusively(root / "a.txt"):
        code, out, err = run(capsys, "baseline", "create", "--config", config)
    assert code == 1 and not target.exists()
    assert "incomplete scan" in err and "unreadable" in err and "file:docs:a.txt" in err


def test_create_refuses_unrepresentable_names(capsys, setup, monkeypatch):
    root, config, target = setup
    original = refs.segment_bytes

    def fake(name, windows=refs.WINDOWS):
        if name == "a.txt":
            raise refs.UnrepresentableName("simulated unpaired surrogate")
        return original(name, windows)

    monkeypatch.setattr(refs, "segment_bytes", fake)
    code, _, err = run(capsys, "baseline", "create", "--config", config)
    assert code == 1 and "unrepresentable-name" in err and not target.exists()


def test_create_refuses_name_collisions(capsys, setup, monkeypatch):
    root, config, target = setup
    write(root / "A2.txt", "one")
    write(root / "a3.txt", "two")
    original = refs.make_key

    def colliding(root_id, names, segments, windows=refs.WINDOWS):
        if names[-1].lower() in ("a2.txt", "a3.txt"):
            return "file:docs:collision"  # simulate per-directory case sensitivity
        return original(root_id, names, segments, windows)

    monkeypatch.setattr(refs, "make_key", colliding)
    code, _, err = run(capsys, "baseline", "create", "--config", config)
    assert code == 1 and err.count("name-collision") == 2 and not target.exists()


def test_create_is_atomic_and_never_overwrites(capsys, setup):
    root, config, target = setup
    create_baseline(capsys, config)
    original = target.read_bytes()
    code, _, err = run(capsys, "baseline", "create", "--config", config)
    assert code == 1 and "already exists" in err
    assert target.read_bytes() == original
    assert not list(target.parent.glob("*.tmp"))  # no temporary files left behind


def test_write_new_refuses_existing_target_even_if_racing(tmp_path):
    target = tmp_path / "baseline.json"
    target.write_text("{}")
    with pytest.raises(baseline_mod.BaselineError):
        baseline_mod.write_new(target, {"format": "fi-baseline/1"})
    assert target.read_text() == "{}" and not list(tmp_path.glob("*.tmp"))


# --- replacement -----------------------------------------------------------------------


def test_replace_requires_current_digest_and_archives(capsys, setup):
    root, config, target = setup
    digest = create_baseline(capsys, config)
    write(root / "a.txt", "accepted change")
    code, _, err = run(capsys, "baseline", "replace", "--config", config, "--confirm-replace", "0" * 64)
    assert code == 1 and "does not match" in err
    code, out, _ = run(capsys, "baseline", "replace", "--config", config, "--confirm-replace", digest)
    assert code == 0 and "archived as" in out
    assert len(list(target.parent.glob("baseline.*.replaced.json"))) == 1
    report = check_json(capsys, config)
    assert report["findings"] == [] and report["extensions"]["baseline_replaced_at"]


def test_interrupted_replace_reports_baseline_missing(capsys, setup, monkeypatch):
    root, config, target = setup
    digest = create_baseline(capsys, config)

    def fail(*args, **kwargs):
        raise OSError("simulated power loss")

    monkeypatch.setattr(os, "replace", fail)
    code, _, _ = run(capsys, "baseline", "replace", "--config", config, "--confirm-replace", digest)
    assert code == 1
    monkeypatch.undo()
    report = check_json(capsys, config)
    assert report["status"] == "error" and error_codes(report) == {"baseline-missing": 1}
    assert "replaced" in report["errors"][0]["message"]  # names the archive to restore
    assert report["findings"] == []


# --- validation before every check -----------------------------------------------------


def test_tampered_baseline_is_an_integrity_failure(capsys, setup):
    root, config, target = setup
    create_baseline(capsys, config)
    data = json.loads(target.read_text())
    data["entries"][0]["sha256"] = "0" * 64  # attacker hides a change without fixing the digest
    target.write_text(json.dumps(data))
    report = check_json(capsys, config)
    assert report["status"] == "error"
    [finding] = report["findings"]
    assert finding["rule_id"] == "baseline-integrity-failure" and finding["severity"] == "high"


def test_recomputed_digest_is_caught_by_expected_digest(capsys, setup):
    root, config, target = setup
    digest = create_baseline(capsys, config)
    # A capable attacker edits the baseline AND recomputes its embedded digest.
    data = json.loads(target.read_text())
    data["entries"][0]["sha256"] = "0" * 64
    data.pop("digest")
    from ilmarinen import cj

    data["digest"] = cj.digest(data)
    target.write_bytes(baseline_mod.serialise(data))
    assert check_json(capsys, config)["status"] != "error"  # undetectable without an outside digest...
    report = check_json(capsys, config, "--expected-digest", digest)
    assert report["status"] == "error"  # ...but caught with the independently stored one
    assert report["findings"][0]["rule_id"] == "baseline-integrity-failure"


def test_expected_digest_match_is_recorded(capsys, setup):
    root, config, target = setup
    digest = create_baseline(capsys, config)
    report = check_json(capsys, config, "--expected-digest", digest)
    assert report["extensions"]["digest_verified_independently"] is True
    assert check_json(capsys, config)["extensions"]["digest_verified_independently"] is False


def test_corrupt_baseline_json_is_an_integrity_failure(capsys, setup):
    root, config, target = setup
    create_baseline(capsys, config)
    target.write_bytes(b'{"format": "fi-baseline/1", "format": "x"}')
    report = check_json(capsys, config)
    assert report["status"] == "error" and report["findings"][0]["rule_id"] == "baseline-integrity-failure"


def test_root_pointing_elsewhere_is_root_changed(capsys, setup, tmp_path):
    root, config, target = setup
    create_baseline(capsys, config)
    other = tmp_path / "other"
    shutil.copytree(root, other)
    make_config(tmp_path, [{"id": "docs", "path": other}])
    report = check_json(capsys, config)
    assert report["status"] == "error" and error_codes(report) == {"root-changed": 1}
    assert "other" not in json.dumps(report)  # root id only, never the path


def test_recreated_root_directory_is_root_replaced(capsys, setup):
    root, config, target = setup
    create_baseline(capsys, config)
    old_inode = os.stat(root).st_ino
    shutil.rmtree(root)
    write(root / "a.txt", "alpha")  # same path, same content, different directory
    write(root / "sub" / "b.txt", "bravo")
    if os.name != "nt" and os.stat(root).st_ino == old_inode:
        pytest.skip("this filesystem reused the deleted root's inode number: root-replaced cannot be "
                    "detected (documented Linux limitation; file contents are still compared)")
    report = check_json(capsys, config)
    assert report["status"] == "error" and error_codes(report) == {"root-replaced": 1}


def test_changed_exclusions_are_config_changed(capsys, setup, tmp_path):
    root, config, target = setup
    create_baseline(capsys, config)
    make_config(tmp_path, [{"id": "docs", "path": root, "exclude": ["*.log"]}])
    report = check_json(capsys, config)
    assert error_codes(report) == {"config-changed-since-baseline": 1}


# --- configuration refusals --------------------------------------------------------------


@pytest.mark.parametrize("case", ["duplicate-id", "nested", "same-path", "missing", "baseline-inside",
                                  "too-many", "bad-pattern", "bad-id", "unknown-key", "link-root"])
def test_config_refusals(capsys, tmp_path, case):
    a = tmp_path / "a"
    a.mkdir()
    write(a / "x.txt", "x")
    roots = [{"id": "one", "path": a}]
    baseline = None
    if case == "duplicate-id":
        (tmp_path / "b").mkdir()
        roots.append({"id": "one", "path": tmp_path / "b"})
    elif case == "nested":
        roots.append({"id": "two", "path": a / "inner"})
        (a / "inner").mkdir()
    elif case == "same-path":
        roots.append({"id": "two", "path": str(a).upper() if os.name == "nt" else a})
    elif case == "missing":
        roots = [{"id": "one", "path": tmp_path / "nope"}]
    elif case == "baseline-inside":
        baseline = a / "baseline.json"
    elif case == "too-many":
        for i in range(51):
            (tmp_path / f"r{i}").mkdir()
        roots = [{"id": f"r{i}", "path": tmp_path / f"r{i}"} for i in range(51)]
    elif case == "bad-pattern":
        roots[0]["exclude"] = ["/absolute"]
    elif case == "bad-id":
        roots[0]["id"] = "Bad_ID"
    elif case == "link-root":
        make_link_to_dir(tmp_path / "linked", a)
        roots = [{"id": "one", "path": tmp_path / "linked"}]
    config = make_config(tmp_path, roots, baseline)
    if case == "unknown-key":
        data = json.loads(config.read_text())
        data["roots"][0]["follow_links"] = True
        config.write_text(json.dumps(data))
    code, out, err = run(capsys, "check", "--config", config)
    assert code == 2 and out == "" and err.startswith("ilmarinen:")
