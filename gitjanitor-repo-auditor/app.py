"""
GitJanitor — Repo Auditor (Streamlit UI)
========================================
Thin presentation layer over scanner.py. All detection/scoring lives in the
engine module so the exact same logic backs this dashboard and the CLI
(gitjanitor.py).

Run with:
    streamlit run app.py
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import streamlit as st

import scanner as sc

# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

_GRADE_COLOR = {"A": "🟢", "B": "🟢", "C": "🟡", "D": "🟠", "F": "🔴"}
_SEV_ICON = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "None": "⚪"}


def sev_tag(severity: str, score: float) -> str:
    return f"{_SEV_ICON.get(severity, '⚪')} `{severity} {score}`"


def render_report_sections(report: sc.ScanReport, threshold_mb: int) -> None:
    """Render summary + the six detection sections for one repository."""
    st.subheader("Summary")
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Grade", f"{_GRADE_COLOR.get(report.grade, '')} {report.grade}")
    col2.metric("Top CVSS", f"{report.risk_score:.1f}")
    col3.metric("Total risks", report.total_risks)
    col4.metric("Repo size", sc.human_size(report.total_bytes))
    col5.metric("Secrets", len(report.secrets) + len(report.history))

    if report.suppressed:
        st.caption(f"🔕 {report.suppressed} finding(s) suppressed via .gitjanitorignore.")
    if report.total_risks == 0:
        st.success("✨ Clean bill of health — no hygiene issues detected.")
    st.divider()

    # 1. secrets (working tree)
    st.subheader("🔑 Exposed secrets (working tree)")
    if report.secrets:
        st.error(f"{len(report.secrets)} hardcoded credential(s) found. Rotate immediately.")
        for f in report.secrets:
            st.markdown(f"- {sev_tag(f.severity, f.score)} · `{f.file}` line {f.line_no} "
                        f"— **{f.label}** → `{f.preview}`")
    else:
        st.success("No hardcoded secrets detected in scanned text files.")
    st.divider()

    # 2. secrets in history
    st.subheader("🕓 Secrets in Git history")
    if not report.history_scanned:
        st.info("History scan not run. Enable it to catch secrets deleted in a later commit.")
    elif report.history:
        st.error(f"{len(report.history)} secret(s) in past commits — deletion does NOT purge "
                 "history. Rotate the credentials and rewrite history (git filter-repo / BFG).")
        for h in report.history:
            st.markdown(f"- {sev_tag(h.severity, h.score)} · commit `{h.commit}` `{h.file}` "
                        f"— **{h.label}** → `{h.preview}`")
    else:
        st.success("No secrets found in scanned commit history.")
    st.divider()

    # 3. prohibited files
    st.subheader("🚫 Prohibited files")
    if report.prohibited:
        st.error(f"{len(report.prohibited)} sensitive file(s) in the working tree.")
        for rel, reason, kind in report.prohibited:
            key = "prohibited_pii" if kind == "pii" else "prohibited_secret"
            st.markdown(f"- {sev_tag(sc.BANDS[key], sc.SCORES[key])} · `{rel}` — {reason}")
    else:
        st.success("No prohibited files (.env, key material, DB dumps) found.")
    st.divider()

    # 4. committed clutter
    st.subheader("🧹 Committed clutter")
    if report.junk:
        st.warning(f"{len(report.junk)} item(s) that shouldn't be committed. "
                   "`git rm --cached` them and add to .gitignore.")
        for rel, reason in report.junk:
            st.markdown(f"- {sev_tag(sc.BANDS['clutter'], sc.SCORES['clutter'])} · `{rel}` — {reason}")
    else:
        st.success("No committed clutter (IDE dirs, archives, node_modules, …) detected.")
    st.divider()

    # 5. bloat
    st.subheader(f"🐘 Bloat files (≥ {threshold_mb} MB)")
    if report.bloat:
        st.warning(f"{len(report.bloat)} oversized file(s). Use Git LFS or external storage.")
        for rel, size in report.bloat:
            st.markdown(f"- {sev_tag(sc.BANDS['bloat'], sc.SCORES['bloat'])} · `{rel}` "
                        f"— **{sc.human_size(size)}**")
    else:
        st.success("No oversized files above the current threshold.")
    st.divider()

    # 6. gitignore drift
    st.subheader("📄 .gitignore drift")
    if not report.gitignore_exists:
        st.error("No `.gitignore` file found — every generated artifact is committable.")
    elif report.gitignore_missing:
        st.warning(f"`.gitignore` exists but is missing {len(report.gitignore_missing)} "
                   "common exclusion(s):")
    else:
        st.success("`.gitignore` present and covers all common exclusions.")
    if report.gitignore_missing:
        for rule, why in report.gitignore_missing:
            st.markdown(f"- `{rule}` — {why}")
        with st.expander("Suggested lines to append to .gitignore"):
            st.code("\n".join(rule for rule, _ in report.gitignore_missing), language="text")


def run_single_scan(repo: Path, history: bool, entropy: bool, threshold_bytes: int) -> sc.ScanReport:
    report = sc.scan_repository(repo, threshold_bytes, detect_entropy=entropy)
    if history:
        report.history = sc.scan_history_for_secrets(repo, detect_entropy=entropy)
        report.history_scanned = True
    return report


# ---------------------------------------------------------------------------
# Streamlit UI
# ---------------------------------------------------------------------------

st.set_page_config(page_title="GitJanitor — Repo Auditor", page_icon="🧹", layout="wide")
st.title("🧹 GitJanitor — Repo Auditor")
st.caption("Repository hygiene scanner with CVSS-scored findings. Scan a local folder, "
           "a public repo, or a whole GitHub org. Analysis runs locally.")

with st.sidebar:
    st.header("Scan settings")
    bloat_threshold_mb = st.slider("Flag files larger than (MB)", 1, 500, 50, 1,
                                   help="Lower to 5 MB for the bundled test_dirty_repo.")
    st.divider()
    max_repos = st.slider("Batch: max repos per run", 1, 100, 20, 1)
    if sc._github_token():
        st.success("GITHUB_TOKEN detected — 5000 API req/hr + private repos.")
    else:
        st.caption("Set GITHUB_TOKEN env var for higher API limits + private repos.")
    st.divider()
    st.markdown("**Checks (CVSS-scored)**\n"
                "1. 🔑 Secrets — tree\n2. 🕓 Secrets — history\n3. 🚫 Prohibited files\n"
                "4. 🧹 Committed clutter\n5. 🐘 Bloat\n6. 📄 `.gitignore` drift")

source = st.radio("What do you want to scan?",
                  ["📁 Local folder", "🌐 Public GitHub repo", "📦 Batch scan"], horizontal=True)

col_h, col_e = st.columns(2)
scan_history = col_h.checkbox("🕓 Also scan Git history for secrets", value=False,
                              help="Catches secrets deleted in a later commit. Full clone for remotes.")
detect_entropy = col_e.checkbox("🎲 Detect high-entropy strings", value=True,
                                help="Flags random-looking tokens even without a keyword. May add false positives.")

threshold_bytes = bloat_threshold_mb * 1024 * 1024

# === MODE 1 & 2: single local / single remote ==============================
if source in ("📁 Local folder", "🌐 Public GitHub repo"):
    if source == "📁 Local folder":
        target = st.text_input("Path to a local repository",
                               placeholder="e.g. ./test_dirty_repo  or  /home/you/projects/app")
    else:
        target = st.text_input("Public GitHub repository URL",
                               placeholder="https://github.com/owner/repo")
        st.caption("Cloned to a temp folder, scanned, then deleted. Requires `git` on PATH.")

    if st.button("Run audit", type="primary"):
        if not target.strip():
            st.warning("Enter a path or URL first.")
            st.stop()
        temp_clone: Path | None = None
        try:
            if source == "📁 Local folder":
                repo = Path(target.strip()).expanduser().resolve()
                if not repo.is_dir():
                    st.error(f"`{repo}` is not a directory.")
                    st.stop()
                scanned_label = str(repo)
            else:
                try:
                    url = sc.normalize_repo_url(target)
                except ValueError as exc:
                    st.error(str(exc))
                    st.stop()
                try:
                    with st.spinner(f"Cloning {url} …"):
                        repo = sc.clone_public_repo(url, deep=scan_history)
                        temp_clone = repo
                except FileNotFoundError:
                    st.error("`git` isn't installed or isn't on your PATH.")
                    st.stop()
                except subprocess.TimeoutExpired:
                    st.error("Clone timed out — the repo may be very large.")
                    st.stop()
                except subprocess.CalledProcessError as exc:
                    msg = (exc.stderr or "").strip().splitlines()
                    st.error(f"Couldn't clone (is it public?). git said: {msg[-1] if msg else 'failed'}")
                    st.stop()
                scanned_label = url

            with st.spinner(f"Scanning {scanned_label} …"):
                report = run_single_scan(repo, scan_history, detect_entropy, threshold_bytes)
        finally:
            if temp_clone is not None:
                shutil.rmtree(temp_clone, ignore_errors=True)

        if not report.is_git_repo:
            st.info("No `.git` directory found — auditing as a plain directory.")

        render_report_sections(report, bloat_threshold_mb)

        row = sc.report_to_row(scanned_label, report)
        st.divider()
        d1, d2 = st.columns(2)
        d1.download_button("⬇️ Download report (Markdown)", sc.build_markdown_report([row]),
                           file_name="gitjanitor_report.md", mime="text/markdown")
        d2.download_button("⬇️ Download report (JSON)", json.dumps(row, indent=2),
                           file_name="gitjanitor_report.json", mime="application/json")

# === MODE 3: batch =========================================================
else:
    st.caption("Scan many repos and export one combined report. Each is cloned, scanned, deleted.")
    batch_mode = st.radio("Batch input",
                          ["Paste repo URLs", "All repos of a GitHub user/org"], horizontal=True)
    urls_text = owner = ""
    if batch_mode == "Paste repo URLs":
        urls_text = st.text_area("One repository URL per line",
                                 placeholder="https://github.com/owner/repo-a\n"
                                             "https://github.com/owner/repo-b", height=140)
    else:
        owner = st.text_input("GitHub username or organisation", placeholder="e.g. octocat")

    if st.button("Run batch audit", type="primary"):
        if batch_mode == "Paste repo URLs":
            raw = [ln.strip() for ln in urls_text.splitlines() if ln.strip()]
            targets, bad = [], []
            for ln in raw:
                try:
                    targets.append(sc.normalize_repo_url(ln))
                except ValueError:
                    bad.append(ln)
            if bad:
                st.warning("Skipped invalid URLs: " + ", ".join(bad))
        else:
            try:
                with st.spinner(f"Listing repos for {owner} …"):
                    targets = sc.list_public_repos(owner, limit=max_repos)
            except ValueError as exc:
                st.error(str(exc))
                st.stop()

        targets = targets[:max_repos]
        if not targets:
            st.warning("Nothing to scan.")
            st.stop()

        st.info(f"Scanning {len(targets)} repositor{'y' if len(targets) == 1 else 'ies'} …")
        rows: list[dict] = []
        reports: list[tuple[str, sc.ScanReport]] = []
        progress = st.progress(0.0)
        status = st.empty()

        for i, url in enumerate(targets, start=1):
            status.write(f"({i}/{len(targets)}) {url}")
            temp_clone = None
            try:
                temp_clone = sc.clone_public_repo(url, deep=scan_history)
                rep = sc.scan_repository(temp_clone, threshold_bytes, detect_entropy=detect_entropy)
                if scan_history:
                    rep.history = sc.scan_history_for_secrets(temp_clone, detect_entropy=detect_entropy)
                    rep.history_scanned = True
                rows.append(sc.report_to_row(url, rep))
                reports.append((url, rep))
            except FileNotFoundError:
                st.error("`git` isn't installed or isn't on your PATH.")
                st.stop()
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                rows.append({"repo": url, "grade": "—", "risk_score": 0.0, "risks": "—",
                             "secrets": "—", "history": "—", "prohibited": "—", "junk": "—",
                             "bloat": "—", "gitignore_exists": True, "gitignore_missing": 0,
                             "suppressed": 0, "size": "clone failed", "files": 0,
                             "secret_items": [], "history_items": [], "prohibited_items": [],
                             "junk_items": [], "bloat_items": []})
            finally:
                if temp_clone is not None:
                    shutil.rmtree(temp_clone, ignore_errors=True)
            progress.progress(i / len(targets))
        status.empty()

        scanned = [r for r in rows if isinstance(r["risks"], int)]
        worst = max(scanned, key=lambda r: r["risk_score"], default=None)
        st.subheader("Batch summary")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Repos scanned", len(scanned))
        c2.metric("Total risks", sum(r["risks"] for r in scanned))
        c3.metric("Secrets (tree+history)",
                  sum(r["secrets"] + r["history"] for r in scanned))
        c4.metric("Worst grade", worst["grade"] if worst else "—")

        st.dataframe([{
            "Repository": r["repo"].replace("https://github.com/", "").rstrip(".git"),
            "Grade": r["grade"], "Top CVSS": r["risk_score"], "Risks": r["risks"],
            "Secrets": r["secrets"], "History": r["history"], "Prohibited": r["prohibited"],
            "Junk": r["junk"], "Bloat": r["bloat"],
            ".gitignore": ("missing" if not r["gitignore_exists"] else f"{r['gitignore_missing']} gaps"),
            "Size": r["size"]} for r in rows], use_container_width=True)

        md = sc.build_markdown_report(rows)
        js = json.dumps(rows, indent=2)
        d1, d2 = st.columns(2)
        d1.download_button("⬇️ Download report (Markdown)", md,
                           file_name="gitjanitor_report.md", mime="text/markdown")
        d2.download_button("⬇️ Download report (JSON)", js,
                           file_name="gitjanitor_report.json", mime="application/json")

        st.subheader("Per-repository detail")
        for label, rep in reports:
            title = label.replace("https://github.com/", "").rstrip(".git")
            with st.expander(f"{_GRADE_COLOR.get(rep.grade,'')} {rep.grade} · {title} "
                             f"— {rep.total_risks} risk(s), top CVSS {rep.risk_score}"):
                render_report_sections(rep, bloat_threshold_mb)
