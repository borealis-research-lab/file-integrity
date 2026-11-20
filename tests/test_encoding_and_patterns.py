"""Reference encoding, exclusion semantics and canonical JSON, against published vectors."""

import json
import os
from pathlib import Path

import pytest

from conftest import check_report
from ilmarinen import cj, patterns, refs, report

HERE = Path(__file__).parent
REF_VECTORS = json.loads((HERE / "ref-vectors.json").read_text())
EXCLUDE_VECTORS = json.loads((HERE / "exclude-vectors.json").read_text())
STANDARD_VECTORS = check_report.strict_loads((HERE / "standards" / "test-vectors-v1.json").read_bytes())


@pytest.mark.parametrize("vector", REF_VECTORS["encode"], ids=lambda v: v["name"])
def test_ref_encoding_vectors(vector):
    segments = [bytes.fromhex(h) for h in vector.get("path_hex", [vector.get("name_hex")])]
    ref = refs.make_ref("docs", segments)
    assert ref == vector["ref"]
    assert ref.isascii() and all(0x20 < ord(c) < 0x7F for c in ref)
    encoded = ref.split(":", 2)[2].split("/")
    assert [refs.decode_segment(e) for e in encoded] == segments  # reversible


def test_nfc_and_nfd_names_stay_distinct():
    nfc = refs.make_ref("docs", [refs.segment_bytes("caf" + chr(0xE9), windows=True)])
    nfd = refs.make_ref("docs", [refs.segment_bytes("cafe" + chr(0x301), windows=True)])
    assert nfc != nfd


def test_linux_names_with_invalid_utf8_are_representable():
    name = os.fsdecode(b"bad\xff.bin") if os.name != "nt" else b"bad\xff.bin".decode("utf-8", "surrogateescape")
    if os.name == "nt":
        pytest.skip("POSIX byte names only")
    assert refs.make_ref("docs", [refs.segment_bytes(name, windows=False)]) == "file:docs:bad%FF.bin"


@pytest.mark.parametrize("vector", REF_VECTORS["windows_errors"], ids=lambda v: v["name"])
def test_windows_unrepresentable_names_raise(vector):
    name = "".join(chr(c) for c in vector["name_codepoints"])
    with pytest.raises(refs.UnrepresentableName):
        refs.segment_bytes(name, windows=True)


def test_windows_keys_are_case_insensitive_linux_keys_are_exact():
    names = REF_VECTORS["windows_keys"][0]["names"]
    seg = [refs.segment_bytes(n, windows=True) for n in names]
    win = {refs.make_key("docs", [n], [s], windows=True) for n, s in zip(names, seg)}
    lin = {refs.make_key("docs", [n], [s], windows=False) for n, s in zip(names, seg)}
    assert len(win) == 1 and len(lin) == 2


@pytest.mark.parametrize("case", EXCLUDE_VECTORS["cases"], ids=lambda c: f"{c['pattern']}|{c['path']}|{c['is_dir']}")
def test_exclude_vectors(case):
    pattern = patterns.Pattern(case["pattern"])
    display = [refs.display_segment(s.encode("utf-8")) for s in case["path"].split("/")]
    assert pattern.matches(display, case["is_dir"]) is case["excluded"]


@pytest.mark.parametrize("bad", EXCLUDE_VECTORS["invalid"])
def test_invalid_patterns_are_rejected(bad):
    with pytest.raises(patterns.PatternError):
        patterns.validate(bad)


def test_at_most_100_patterns():
    with pytest.raises(patterns.PatternError):
        patterns.compile_all(["*.x"] * 101)


@pytest.mark.parametrize("vector", STANDARD_VECTORS["canonical_json"], ids=lambda v: v["name"])
def test_canonical_json_vectors(vector):
    value = json.loads(vector["input_json"])
    if "error" in vector:
        with pytest.raises(cj.CanonicalJsonError):
            cj.canonical(value)
    else:
        assert cj.canonical(value).decode("utf-8") == vector["output"]


@pytest.mark.parametrize("vector", STANDARD_VECTORS["strict_parsing"], ids=lambda v: v["name"])
def test_strict_parsing_vectors(vector):
    data = bytes.fromhex(vector["input_hex"])
    if vector["valid"]:
        cj.strict_loads(data)
    else:
        with pytest.raises(cj.StrictJsonError):
            cj.strict_loads(data)


@pytest.mark.parametrize("vector", STANDARD_VECTORS["finding_ids"], ids=lambda v: v["name"])
def test_finding_id_vectors(vector):
    assert report.canonical_refs(vector["refs"]) == vector["canonical_refs"]
    digest = report.refs_digest(vector["refs"])
    assert digest == vector["evidence_refs_digest"]
    expected_suffix = vector["finding_id"].rsplit(":", 1)[1]
    assert report.finding_id(vector["rule_id"], digest).rsplit(":", 1)[1] == expected_suffix


@pytest.mark.parametrize("vector", [v for v in STANDARD_VECTORS["error_aggregation"] if "counts" in v],
                         ids=lambda v: v["name"])
def test_error_aggregation_vectors(vector):
    assert report.aggregate_counts(vector["counts"]) == vector["expected_error_counts"]


def test_error_aggregation_generated_vectors():
    for vector in STANDARD_VECTORS["error_aggregation"]:
        if "generate" in vector:
            counts = check_report._generated_counts(vector["generate"])
            assert report.aggregate_counts(counts) == vector["expected_error_counts"]
