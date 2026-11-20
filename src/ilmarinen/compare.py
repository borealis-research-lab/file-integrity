"""Compares a scan with the baseline and produces findings. Each finding's evidence is
exactly one entry ref, so findings are unique by construction."""

from __future__ import annotations

from ilmarinen.scanner import Entry, ScanResult

LIMIT_CONTENT = (
    "Only file content is compared (SHA-256). Permissions, ACLs, ownership, timestamps and "
    "alternate data streams are not monitored. Legitimate updates and edits also change files."
)

RULES = {
    "file-changed": ("medium",
                     "Unexpected changes to important files can indicate tampering or unauthorised modification.",
                     "Confirm the change was expected (an update or an edit by the file's owner). If it was not, "
                     "investigate who changed it and restore the file from a trusted copy."),
    "file-deleted": ("medium",
                     "Missing important files can indicate tampering, or an attempt to disable something.",
                     "Confirm the removal was intended. If not, investigate and restore the file from a trusted copy."),
    "file-added": ("low",
                   "New files in a monitored location may be expected, but can also be planted content.",
                   "Confirm the new file was expected. If not, investigate where it came from before opening it."),
    "entry-type-changed": ("high",
                           "A file replaced by a link or special file can redirect programs to other content.",
                           "Investigate immediately: find out who replaced the file and where the new entry points."),
    "link-changed": ("medium",
                     "A link that points somewhere new can redirect programs to different content.",
                     "Confirm the link change was intended. If not, investigate who changed it."),
    "baseline-integrity-failure": ("high",
                                   "If the baseline was altered, changes to the monitored files could be hidden.",
                                   "Do not trust this baseline. Compare it with your independently stored digest, "
                                   "investigate how it changed, and only then create a new one."),
}

OBSERVATIONS = {
    "file-changed": "The content of {ref} differs from the baseline (SHA-256 changed).",
    "file-deleted": "{ref} is in the baseline but no longer exists.",
    "file-added": "{ref} exists but is not in the baseline.",
    "entry-type-changed": "{ref} was a {old} in the baseline and is now a {new}.",
    "link-changed": "The target of link {ref} differs from the baseline.",
}


def _state(entry: dict | Entry | None) -> dict:
    if entry is None:
        return {}
    data = entry if isinstance(entry, dict) else entry.to_baseline()
    if isinstance(entry, Entry) and entry.kind == "special":
        data = {**data, "special_type": entry.special_type}
    return {k: v for k, v in data.items() if k not in ("key", "ref")}


def finding(rule_id: str, ref: str, observation: str, details: dict, timestamp: str = "") -> dict:
    severity, assessment, recommendation = RULES[rule_id]
    evidence = {"ref": ref, "details": details}
    if timestamp:
        evidence["timestamp"] = timestamp
    limitations = LIMIT_CONTENT if rule_id != "baseline-integrity-failure" else (
        "The embedded digest only detects accidental corruption. Without an independently stored digest "
        "(--expected-digest), an attacker who can change both the files and the baseline can hide changes."
    )
    return {"rule_id": rule_id, "severity": severity, "observation": observation, "assessment": assessment,
            "recommendation": recommendation, "limitations": limitations, "evidence": [evidence]}


def integrity_finding(message: str) -> dict:
    return finding("baseline-integrity-failure", "ilmarinen-baseline:configured-baseline",
                   f"Baseline integrity check failed: {message}.", {"problem": message})


def compare(baseline_entries: dict[str, dict], scan: ScanResult) -> list[dict]:
    errored = {e.key for e in scan.errors if e.key and e.code != "unsupported-entry"}
    findings = []
    for key in sorted(set(baseline_entries) | set(scan.entries)):
        old = baseline_entries.get(key)
        new = scan.entries.get(key)
        if key in errored:
            continue  # the entry could not be checked; its error is reported instead
        if old is not None and new is None:
            findings.append(finding("file-deleted", old["ref"], OBSERVATIONS["file-deleted"].format(ref=old["ref"]),
                                    {"baseline": _state(old)}))
            continue
        if old is None:
            findings.append(finding("file-added", new.ref, OBSERVATIONS["file-added"].format(ref=new.ref),
                                    {"current": _state(new)}, new.mtime))
            continue
        details = {"baseline": _state(old), "current": _state(new)}
        if old["kind"] != new.kind:
            findings.append(finding("entry-type-changed", new.ref,
                                    OBSERVATIONS["entry-type-changed"].format(ref=new.ref, old=old["kind"], new=new.kind),
                                    details, new.mtime))
        elif new.kind == "file" and old.get("sha256") != new.sha256:
            findings.append(finding("file-changed", new.ref, OBSERVATIONS["file-changed"].format(ref=new.ref),
                                    details, new.mtime))
        elif new.kind == "link" and old.get("link_target_sha256") != new.link_target_sha256:
            findings.append(finding("link-changed", new.ref, OBSERVATIONS["link-changed"].format(ref=new.ref), details))
    return findings
