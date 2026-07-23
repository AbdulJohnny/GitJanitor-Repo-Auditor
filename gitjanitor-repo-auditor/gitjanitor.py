#!/usr/bin/env python3
"""
GitJanitor CLI / pre-commit gate
================================
Headless front-end to the same scanner engine the dashboard uses. Prints a
CVSS-scored report and, crucially for CI, exits non-zero when findings meet or
exceed a chosen severity — so it can block a commit or fail a pipeline.

Examples
--------
    # Scan the current repo, fail the commit on any High/Critical finding
    python gitjanitor.py .

    # Scan a public repo including history, save a timestamped JSON report
    python gitjanitor.py https://github.com/owner/repo --history --save-report

    # Report only, never fail (exit 0 regardless)
    python gitjanitor.py . --fail-on none

Use as a pre-commit hook (.git/hooks/pre-commit):
    #!/bin/sh
    python /path/to/gitjanitor.py . --fail-on high || exit 1

Exit codes:  0 = clean/below threshold   1 = findings at/above --fail-on   2 = error
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import scanner as sc

_ICON = {"Critical": "[CRIT]", "High": "[HIGH]", "Medium": "[MED ]",
         "Low": "[LOW ]", "None": "[ -- ]"}
_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _force_utf8_output() -> None:
    """Emit UTF-8 on our own streams so the ≥ / — / • glyphs we print don't turn
    to mojibake when stdout/stderr is piped or captured. Windows defaults piped
    streams to a legacy code page (e.g. cp1252) that can't encode them; a real
    interactive console already handles Unicode, so this only helps the CI /
    redirected case, which is exactly where it was breaking."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass


def _sev_order(band: str) -> int:
    return _ORDER.get(band.lower(), 0)


def print_report(label: str, report: sc.ScanReport) -> None:
    line = "=" * 66
    print(line)
    print(f" {label}")
    print(f" Grade: {report.grade}   Top CVSS: {report.risk_score:.1f}   "
          f"Risks: {report.total_risks}   Size: {sc.human_size(report.total_bytes)}")
    if report.suppressed:
        print(f" Suppressed: {report.suppressed} (.gitjanitorignore)")
    print(line)

    def section(title: str, items: list[str]) -> None:
        print(f"\n{title}")
        if items:
            for it in items:
                print(f"  {it}")
        else:
            print("  (none)")

    section("Secrets (working tree):", [
        f"{_ICON[f.severity]} {f.score:>4}  {f.file}:{f.line_no}  {f.label} -> {f.preview}"
        for f in report.secrets])

    if report.history_scanned:
        section("Secrets (git history):", [
            f"{_ICON[h.severity]} {h.score:>4}  {h.commit} {h.file}  {h.label} -> {h.preview}"
            for h in report.history])
        if report.history_truncated:
            print("  (history truncated at the commit cap — raise --max-commits for full coverage)")

    section("Prohibited files:", [
        f"{_ICON[sc.BANDS['prohibited_pii' if k == 'pii' else 'prohibited_secret']]} "
        f"{sc.SCORES['prohibited_pii' if k == 'pii' else 'prohibited_secret']:>4}  {rel}  {reason}"
        for rel, reason, k in report.prohibited])

    section("Committed clutter:", [f"{_ICON['Low']} {sc.SCORES['clutter']:>4}  {rel}  {reason}"
                                    for rel, reason in report.junk])

    section("Bloat files:", [f"{_ICON['Low']} {sc.SCORES['bloat']:>4}  {rel}  {sc.human_size(sz)}"
                             for rel, sz in report.bloat])

    if not report.gitignore_exists:
        section(".gitignore:", ["MISSING — no .gitignore present"])
    else:
        section(".gitignore drift:", [f"missing rule: {rule}" for rule, _ in report.gitignore_missing])
    print()


def worst_band(report: sc.ScanReport) -> str:
    return sc.severity_band(report.risk_score)


def save_report(row: dict) -> Path:
    out_dir = Path("reports")
    out_dir.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = out_dir / f"gitjanitor-{stamp}.json"
    path.write_text(json.dumps(row, indent=2), encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    _force_utf8_output()
    parser = argparse.ArgumentParser(
        prog="gitjanitor",
        description="CVSS-scored repository hygiene scanner (CLI / pre-commit gate).")
    parser.add_argument("target", help="Local folder path or a public GitHub repo URL.")
    parser.add_argument("--history", action="store_true",
                        help="Also scan git history for secrets (full clone for remotes).")
    parser.add_argument("--no-entropy", action="store_true",
                        help="Disable high-entropy string detection.")
    parser.add_argument("--threshold-mb", type=int, default=50,
                        help="Flag files at/above this size as bloat (default 50).")
    parser.add_argument("--fail-on", choices=list(_ORDER), default="high",
                        help="Exit non-zero if any finding is at/above this severity "
                             "(default: high). Use 'none' to report only.")
    parser.add_argument("--json", metavar="PATH",
                        help="Write the JSON report to PATH.")
    parser.add_argument("--save-report", action="store_true",
                        help="Also save a timestamped JSON report under ./reports/.")
    parser.add_argument("--max-commits", type=int, default=2000,
                        help="Cap commits scanned in history mode (default 2000).")
    args = parser.parse_args(argv)

    entropy = not args.no_entropy
    threshold_bytes = args.threshold_mb * 1024 * 1024
    target = args.target.strip()
    temp_clone: Path | None = None

    try:
        if target.startswith("http://") or target.startswith("https://"):
            try:
                url = sc.normalize_repo_url(target)
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            try:
                print(f"Cloning {url} …", file=sys.stderr)
                repo = sc.clone_public_repo(url, deep=args.history)
                temp_clone = repo
            except FileNotFoundError:
                print("error: git is not installed or not on PATH.", file=sys.stderr)
                return 2
            except subprocess.TimeoutExpired:
                print("error: clone timed out.", file=sys.stderr)
                return 2
            except subprocess.CalledProcessError as exc:
                msg = (exc.stderr or "").strip().splitlines()
                print(f"error: clone failed. {msg[-1] if msg else ''}", file=sys.stderr)
                return 2
            label = url
        else:
            repo = Path(target).expanduser().resolve()
            if not repo.is_dir():
                print(f"error: '{repo}' is not a directory.", file=sys.stderr)
                return 2
            label = str(repo)

        report = sc.scan_repository(repo, threshold_bytes, detect_entropy=entropy)
        if args.history:
            res = sc.scan_history_for_secrets(repo, detect_entropy=entropy,
                                              max_commits=args.max_commits)
            report.history = res.findings
            report.history_scanned = True
            report.history_truncated = res.truncated
            report.suppressed += res.suppressed
    finally:
        if temp_clone is not None:
            shutil.rmtree(temp_clone, ignore_errors=True)

    print_report(label, report)
    row = sc.report_to_row(label, report)

    if args.json:
        Path(args.json).write_text(json.dumps(row, indent=2), encoding="utf-8")
        print(f"Wrote JSON report to {args.json}", file=sys.stderr)
    if args.save_report:
        saved = save_report(row)
        print(f"Saved timestamped report to {saved}", file=sys.stderr)

    # ---- exit-code gate ---------------------------------------------------
    band = worst_band(report)
    if args.fail_on != "none" and _sev_order(band) >= _ORDER[args.fail_on]:
        print(f"FAIL: worst finding is {band} (CVSS {report.risk_score:.1f}) "
              f"≥ threshold '{args.fail_on}'. Grade {report.grade}.", file=sys.stderr)
        return 1
    print(f"PASS: worst finding {band} is below threshold '{args.fail_on}'. "
          f"Grade {report.grade}.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
