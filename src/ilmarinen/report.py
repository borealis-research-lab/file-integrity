"""Ilmarinen's implementation of the Borealis agent report standard (borealis-agent-report/1),
written independently of other agents, plus the human-readable --text rendering.
https://github.com/borealis-research-lab/.github/tree/main/standards
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
import uuid
from datetime import datetime, timezone
from typing import Any

from ilmarinen import __version__

STANDARD = "borealis-agent-report/1"
AGENT_NAME = "ilmarinen"
RESPONSIBILITY = (
    "Detects unexpected content changes to user-selected files by comparing SHA-256 hashes "
    "with a protected baseline."
)
PERSONAL_DATA = ["file-names", "relative-file-paths"]

MAX_ERRORS = 100
MAX_ERROR_CODES = 100
MAX_EVIDENCE = 500
MAX_FINDINGS = 1000
MAX_REPORT_BYTES = 10 * 1024 * 1024
SIZE_EVIDENCE = 100
MAX_TEXT = 2000
RESERVED = ("findings-truncated", "evidence-truncated-for-size", "details-omitted-for-size", "report-too-large")
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
_FORBIDDEN_TEXT = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def timestamp(value: datetime) -> str:
    utc = value.astimezone(timezone.utc)
    text = utc.strftime("%Y-%m-%dT%H:%M:%S")
    return text + (f".{utc.microsecond:06d}" if utc.microsecond else "") + "Z"


def plain(value: str, limit: int) -> str:
    cleaned = _FORBIDDEN_TEXT.sub(" ", value)
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 3] + "..."


def canonical_refs(refs: list[str]) -> list[str]:
    return sorted({unicodedata.normalize("NFC", r) for r in refs})


def refs_digest(refs: list[str]) -> str:
    return hashlib.sha256("\n".join(canonical_refs(refs)).encode("utf-8")).hexdigest()


def finding_id(rule_id: str, digest: str) -> str:
    return AGENT_NAME + ":" + rule_id + ":" + hashlib.sha256((rule_id + "\n" + digest).encode("utf-8")).hexdigest()[:16]


# --- errors ---------------------------------------------------------------------------------


def aggregate_counts(counts: dict[str, int]) -> dict[str, int]:
    if len(counts) <= MAX_ERROR_CODES:
        return dict(counts)
    reserved = [c for c in RESERVED if c in counts]
    others = sorted((c for c in counts if c not in RESERVED), key=lambda c: (-counts[c], c))
    keep = reserved + others[: 99 - len(reserved)]
    result = {c: counts[c] for c in keep}
    result["other-codes"] = sum(n for c, n in counts.items() if c not in result)
    return result


def _set_errors(report: dict[str, Any], errors: list[dict[str, Any]], fatal: bool) -> None:
    reserved = [e for c in RESERVED for e in errors if e["code"] == c]
    rest = sorted((e for e in errors if e["code"] not in RESERVED),
                  key=lambda e: (e["code"], e.get("ref", ""), e["message"]))
    counts: dict[str, int] = {}
    for e in errors:
        counts[e["code"]] = counts.get(e["code"], 0) + 1
    report["errors"] = (reserved + rest)[:MAX_ERRORS]
    report["errors_total"] = len(errors)
    report["error_counts"] = aggregate_counts(counts)
    too_large = any(e["code"] == "report-too-large" for e in errors)
    report["status"] = "error" if (fatal or too_large) else ("partial" if errors else "ok")


def error(code: str, message: str, ref: str = "") -> dict[str, Any]:
    item = {"code": code, "message": plain(message, 500)}
    if ref:
        item["ref"] = ref
    return item


# --- findings -----------------------------------------------------------------------------


def _finding(raw: dict[str, Any], created: str) -> dict[str, Any]:
    unique: dict[str, dict] = {}
    for item in raw["evidence"]:
        unique.setdefault(item["ref"], item)
    canon = canonical_refs(list(unique))
    digest = refs_digest(list(unique))
    evidence = list(unique.values())
    if len(evidence) > MAX_EVIDENCE:
        evidence = [unique[r] for r in canon[:MAX_EVIDENCE]]
    return {
        "finding_id": finding_id(raw["rule_id"], digest),
        "created_at": created,
        "rule_id": raw["rule_id"],
        "severity": raw["severity"],
        "observation": plain(raw["observation"], MAX_TEXT),
        "assessment": plain(raw["assessment"], MAX_TEXT),
        "recommendation": plain(raw["recommendation"], MAX_TEXT),
        "limitations": plain(raw["limitations"], MAX_TEXT),
        "evidence": evidence,
        "evidence_total": len(canon),
        "evidence_refs_digest": digest,
    }


def _rank(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (SEVERITY_RANK[f["severity"]], f["finding_id"]))


def serialise(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2) + "\n"


def _size(report: dict[str, Any]) -> int:
    return len(serialise(report).encode("utf-8"))


def build(
    raw_findings: list[dict[str, Any]],
    errors: list[dict[str, Any]],
    scope: list[dict[str, Any]],
    description: str,
    started_at: datetime,
    fatal: bool = False,
    extensions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    created = timestamp(started_at)
    seen: set[str] = set()
    items = []
    for raw in raw_findings:
        f = _finding(raw, created)
        if f["finding_id"] not in seen:
            seen.add(f["finding_id"])
            items.append(f)
    findings_total = len(items)
    errors = list(errors)
    if len(items) > MAX_FINDINGS:
        items = _rank(items)[:MAX_FINDINGS]
        errors.append(error("findings-truncated", f"{findings_total - MAX_FINDINGS} findings dropped (count limit)"))
    report: dict[str, Any] = {
        "standard": STANDARD,
        "agent": {"name": AGENT_NAME, "version": __version__},
        "run": {"id": str(uuid.uuid4()), "started_at": created,
                "finished_at": timestamp(datetime.now(timezone.utc))},
        "source": {"type": "file-hashes", "description": plain(description, 500), "scope": scope[:100]},
        "status": "ok", "errors": [], "errors_total": 0, "error_counts": {},
        "findings": items, "findings_total": findings_total,
    }
    if extensions:
        report["extensions"] = extensions
    _set_errors(report, errors, fatal)
    if _size(report) > MAX_REPORT_BYTES:
        _fit(report, errors, fatal)
    return report


def _fit(report: dict[str, Any], errors: list[dict[str, Any]], fatal: bool) -> None:
    report["findings"] = _rank(report["findings"])
    cut = False
    for f in report["findings"]:
        if len(f["evidence"]) > SIZE_EVIDENCE:
            by_ref = {e["ref"]: e for e in f["evidence"]}
            f["evidence"] = [by_ref[r] for r in sorted(by_ref)[:SIZE_EVIDENCE]]
            cut = True
    if cut:
        errors.append(error("evidence-truncated-for-size", "evidence lists cut to 100 items to meet the size limit"))
        _set_errors(report, errors, fatal)
        if _size(report) <= MAX_REPORT_BYTES:
            return
    for f in report["findings"]:
        for e in f["evidence"]:
            e.pop("details", None)
        f["evidence_details_omitted"] = True
    errors.append(error("details-omitted-for-size", "evidence details removed to meet the size limit"))
    _set_errors(report, errors, fatal)
    if _size(report) <= MAX_REPORT_BYTES:
        return
    already = report["findings_total"] - len(report["findings"])
    sizes = [len(json.dumps(f, indent=2).encode("utf-8")) + 6 for f in report["findings"]]
    keep, excess = len(sizes), _size(report) - MAX_REPORT_BYTES + 200
    while keep and excess > 0:
        keep -= 1
        excess -= sizes[keep]
    while True:
        report["findings"] = report["findings"][:keep]
        errors[:] = [e for e in errors if e["code"] != "findings-truncated"]
        errors.append(error("findings-truncated", f"{already + len(sizes) - keep} findings dropped (count and size limits)"))
        _set_errors(report, errors, fatal)
        if _size(report) <= MAX_REPORT_BYTES or keep == 0:
            break
        keep -= 1
    if not any(len(f["evidence"]) < min(MAX_EVIDENCE, f["evidence_total"]) for f in report["findings"]):
        errors[:] = [e for e in errors if e["code"] != "evidence-truncated-for-size"]
        _set_errors(report, errors, fatal)
    if _size(report) > MAX_REPORT_BYTES:
        report["findings"] = []
        errors.append(error("report-too-large", "report could not be fitted within 10 MiB"))
        _set_errors(report, errors, fatal)


def describe() -> dict[str, Any]:
    return {"standard": STANDARD, "name": AGENT_NAME, "version": __version__,
            "responsibility": RESPONSIBILITY, "personal_data": PERSONAL_DATA}


# --- human-readable output ----------------------------------------------------------------


def _safe(value: object) -> str:
    """One-line rendering of untrusted values: control characters become visible escapes."""
    out = []
    for ch in str(value):
        code = ord(ch)
        if ch == chr(10):
            out.append(chr(92) + "n")
        elif ch == chr(13):
            out.append(chr(92) + "r")
        elif ch == chr(9):
            out.append(chr(92) + "t")
        elif code < 0x20 or 0x7F <= code <= 0x9F:
            out.append(chr(92) + f"x{code:02x}")
        else:
            out.append(ch)
    return "".join(out)


def to_text(report: dict[str, Any]) -> str:
    findings = sorted(report["findings"], key=lambda f: SEVERITY_RANK[f["severity"]])
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in ("high", "medium", "low")}
    ext = report.get("extensions", {})
    lines = [
        "Ilmarinen File Integrity Report",
        "===============================",
        "",
        f"Status:          {report['status']}",
        f"Entries checked: {sum(i.get('count', 0) for i in report['source']['scope'] if i['kind'] == 'root')}",
        f"Findings:        {report['findings_total']}",
        f"  High:   {counts['high']}",
        f"  Medium: {counts['medium']}",
        f"  Low:    {counts['low']}",
    ]
    if "baseline_digest" in ext:
        verified = "yes" if ext.get("digest_verified_independently") else "NO (use --expected-digest)"
        lines += [f"Baseline digest: {ext['baseline_digest']}", f"Independently verified: {verified}"]
    if report["errors_total"]:
        lines += ["", f"Problems ({report['errors_total']}; entries with problems were not checked):"]
        lines += [f"  {_safe(e['code'])}: {_safe(e.get('ref', ''))} {_safe(e['message'])}".rstrip()
                  for e in report["errors"]]
        if report["errors_total"] > len(report["errors"]):
            lines.append(f"  ... {report['errors_total'] - len(report['errors'])} more (see the JSON report)")
    if not findings:
        lines += ["", "No changes found. This does not mean the system is safe: only content of the",
                  "configured files is compared, and only if the baseline itself is trustworthy."]
        return "\n".join(lines) + "\n"
    lines.append("Severity is a rule label, not a probability.")
    for number, f in enumerate(findings, start=1):
        heading = f"Finding {number}: {f['severity'].capitalize()} ({f['rule_id']})"
        lines += ["", heading, "-" * len(heading),
                  "What happened:", f"  {_safe(f['observation'])}",
                  "Why it matters:", f"  {_safe(f['assessment'])}",
                  "Recommended action:", f"  {_safe(f['recommendation'])}",
                  "Evidence:", *[f"  {_safe(e['ref'])}" for e in f["evidence"]],
                  "Limitations:", f"  {_safe(f['limitations'])}"]
    return "\n".join(lines) + "\n"
