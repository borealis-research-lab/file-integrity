"""Command-line interface.

    ilmarinen describe
    ilmarinen baseline create  --config ilmarinen.json
    ilmarinen baseline replace --config ilmarinen.json --confirm-replace <current digest>
    ilmarinen check --config ilmarinen.json [--expected-digest <hex>] [--text] [--out REPORT.json]

`check` writes one borealis-agent-report/1 JSON report to stdout by default. Ilmarinen only
reads the monitored files; it never restores, deletes, quarantines or modifies them.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from ilmarinen import __version__, baseline, compare, config, report, scanner
from ilmarinen.report import _safe


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ilmarinen", description="Borealis File Integrity agent.")
    parser.add_argument("--version", action="version", version=f"ilmarinen {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("describe", help="print this agent's Borealis identity (JSON)")

    base = sub.add_parser("baseline", help="create or replace the baseline")
    base_sub = base.add_subparsers(dest="action", required=True)
    create = base_sub.add_parser("create", help="create the baseline (refuses if one exists)")
    create.add_argument("--config", required=True)
    replace = base_sub.add_parser("replace", help="replace the baseline after confirming its current digest")
    replace.add_argument("--config", required=True)
    replace.add_argument("--confirm-replace", required=True, metavar="CURRENT_DIGEST")

    check = sub.add_parser("check", help="compare the files with the baseline and report")
    check.add_argument("--config", required=True)
    check.add_argument("--expected-digest", metavar="HEX", help="independently stored baseline digest")
    output = check.add_mutually_exclusive_group()
    output.add_argument("--text", action="store_true", help="human-readable report instead of JSON")
    output.add_argument("--json", action="store_true", help="JSON report (the default)")
    check.add_argument("--out", metavar="REPORT.json", help="also save the JSON report (never overwrites)")
    return parser


def _err(message: str, code: int = 2) -> int:
    print(f"ilmarinen: {message}", file=sys.stderr)
    return code


def _load_config(path: str):
    try:
        return config.load(path)
    except config.ConfigError as exc:
        raise SystemExit(_err(str(exc)))


def _print_problems(scan: scanner.ScanResult) -> None:
    if scan.unsafe_platform:
        print(f"  unsafe-platform: {scan.unsafe_platform}", file=sys.stderr)
    for problem in scan.errors[:50]:
        print(f"  {problem.code}: {_safe(problem.ref)} {_safe(problem.message)}", file=sys.stderr)
    if len(scan.errors) > 50:
        print(f"  ... and {len(scan.errors) - 50} more", file=sys.stderr)


def _complete_scan_or_refuse(cfg) -> scanner.ScanResult | None:
    scan = scanner.scan(cfg)
    if scan.complete:
        return scan
    print("ilmarinen: refusing to write a baseline from an incomplete scan "
          f"({len(scan.errors) + bool(scan.unsafe_platform)} problem(s)). Fix or exclude these entries, then try again:",
          file=sys.stderr)
    _print_problems(scan)
    return None


def _digest_advice(digest: str) -> None:
    print(f"Baseline digest: {digest}")
    print("Store this digest somewhere other than this machine (e.g. a password manager or paper),")
    print("and pass it to 'ilmarinen check --expected-digest' so tampering with the baseline is detected.")


def cmd_create(args) -> int:
    cfg = _load_config(args.config)
    target = Path(cfg.baseline)
    if target.exists():
        return _err("a baseline already exists; use 'ilmarinen baseline replace'", 1)
    scan = _complete_scan_or_refuse(cfg)
    if scan is None:
        return 1
    data = baseline.build(cfg, scan)
    try:
        baseline.write_new(target, data)
    except baseline.BaselineError as exc:
        return _err(exc.message, 1)
    except OSError as exc:
        return _err(f"cannot write the baseline: {exc.strerror or exc}", 1)
    print(f"Baseline created with {len(data['entries'])} entries.")
    _digest_advice(data["digest"])
    return 0


def cmd_replace(args) -> int:
    cfg = _load_config(args.config)
    target = Path(cfg.baseline)
    try:
        current = baseline.load(target)
    except baseline.BaselineError as exc:
        return _err(f"cannot replace: {exc.message}. Investigate before removing the baseline manually.", 1)
    if args.confirm_replace.lower() != current.digest:
        return _err("--confirm-replace does not match the current baseline's digest; nothing was changed", 1)
    scan = _complete_scan_or_refuse(cfg)
    if scan is None:
        return 1
    data = baseline.build(cfg, scan, replaced={"at": baseline.now(), "previous_digest": current.digest})
    try:
        archive = baseline.write_replacement(target, data)
    except OSError as exc:
        return _err(f"cannot replace the baseline: {exc.strerror or exc}", 1)
    print(f"Baseline replaced ({len(data['entries'])} entries). Previous baseline archived as {archive.name}.")
    _digest_advice(data["digest"])
    return 0


def cmd_check(args) -> int:
    started = datetime.now(timezone.utc)
    cfg = _load_config(args.config)
    out_path = Path(args.out) if args.out else None
    if out_path is not None and out_path.exists():
        return _err(f"{out_path} already exists; refusing to overwrite it")

    scan = scanner.scan(cfg)
    scope = [{"kind": "root", "id": r.id, "count": scan.counts.get(r.id, 0)} for r in cfg.roots]
    scope += [{"kind": "excluded", "id": r.id, "count": scan.excluded[r.id]} for r in cfg.roots if scan.excluded.get(r.id)]
    extensions: dict = {"digest_verified_independently": False}
    findings: list[dict] = []
    errors: list[dict] = []
    fatal = False
    digest_text = "unavailable"

    if scan.unsafe_platform:
        fatal = True
        errors.append(report.error("unsafe-platform", f"no safe file-access method: {scan.unsafe_platform}"))
    else:
        try:
            base = baseline.load(Path(cfg.baseline))
            digest_text = base.digest
            extensions["baseline_digest"] = base.digest
            extensions["baseline_created_at"] = base.data["created_at"]
            if isinstance(base.data.get("replaced"), dict):
                extensions["baseline_replaced_at"] = base.data["replaced"].get("at")
            baseline.verify_against(base, cfg, scan, args.expected_digest)
            extensions["digest_verified_independently"] = args.expected_digest is not None
            findings = compare.compare(base.entries, scan)
            errors = [report.error(e.code, e.message, e.ref) for e in scan.errors]
        except baseline.BaselineError as exc:
            fatal = True
            errors = [report.error(exc.code, exc.message)]
            if exc.integrity:
                findings = [compare.integrity_finding(exc.message)]

    result = report.build(
        findings, errors, scope,
        f"SHA-256 content hashes of the configured roots, compared with baseline {digest_text}.",
        started, fatal=fatal, extensions=extensions,
    )
    if out_path is not None:
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with out_path.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(report.serialise(result))
        except OSError as exc:
            return _err(f"cannot write report to {out_path}: {exc.strerror or exc}")
        print(f"ilmarinen: report saved to {out_path}", file=sys.stderr)
    sys.stdout.write(report.to_text(result) if args.text else report.serialise(result))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "describe":
        sys.stdout.write(json.dumps(report.describe(), indent=2) + "\n")
        return 0
    try:
        if args.command == "baseline":
            return cmd_create(args) if args.action == "create" else cmd_replace(args)
        return cmd_check(args)
    except SystemExit as exc:
        return int(exc.code or 0)


if __name__ == "__main__":
    sys.exit(main())
