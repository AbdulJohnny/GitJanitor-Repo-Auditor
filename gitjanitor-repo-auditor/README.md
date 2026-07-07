# 🧹 GitJanitor — Repo Auditor

**A repository hygiene scanner that catches leaked secrets — in the working tree *and* buried in Git history — plus sensitive files, committed clutter, bloat, and `.gitignore` drift. Every finding is scored with a CVSS-inspired model and rolled up into a letter grade. Scan a local folder, any public repo, or a whole GitHub org from a dashboard *or* the command line.**

Built with **pure Python + Streamlit**. No API keys required, no paid services, no telemetry. Analysis runs on your machine — nothing you scan is ever uploaded.

---

## Why this exists

Most credential leaks aren't sophisticated attacks — they're a `git push` that quietly included a `.env` file or a hardcoded `API_KEY`. Worse, developers often "fix" a leak by deleting the file in a later commit and assume it's gone. **It isn't** — the secret still lives in Git history forever, and automated scrapers harvest public pushes within minutes. GitJanitor is a pre-push safety net that audits a repo in seconds, grades it, and renders findings as an interactive dashboard or a CI-friendly CLI gate.

## What it detects

| # | Check | Typical severity | Examples caught |
|---|-------|------------------|-----------------|
| 1 | 🔑 **Exposed secrets** (working tree) | 🔴 Critical / 🟠 High | Labeled assignments incl. prefixes (`DB_PASSWORD`, `AWS_API_KEY`), vendor tokens (AWS `AKIA…`, `ghp_…`, Slack `xox…`, Stripe `sk_live_…`, Google `AIza…`, npm, JWTs), DB URIs with creds, `-----BEGIN PRIVATE KEY-----`, **plus high-entropy strings with no keyword at all** |
| 2 | 🕓 **Secrets in Git history** (optional) | 🔴 Critical / 🟠 High | The same patterns across every past commit — catches credentials committed once and deleted later |
| 3 | 🚫 **Prohibited files** | 🟠 High | `.env`, `config.json`, `credentials.json`, `*.pem`, `*.key`, `id_rsa`, `*.tfstate`, and `*.sql` / `*.dump` / `*.bak` (DB dumps with PII) |
| 4 | 🧹 **Committed clutter** | 🔵 Low | IDE metadata (`.idea/`, `.vscode/`, `*.suo`), archives (`*.zip`, `*.7z`), compiled binaries (`*.exe`, `*.dll`, `*.so`), committed `node_modules/` / `venv/` |
| 5 | 🐘 **Bloat files** | 🔵 Low | Files over a configurable threshold (default 50 MB) that degrade clone/fetch performance |
| 6 | 📄 **`.gitignore` drift** | 🔵 Low | Missing `.gitignore`, or one lacking staples like `node_modules/`, `__pycache__/`, `.env`, `.idea/`, `.vscode/` |

All secret values are **redacted in the UI and in exports** (`dh92••••••••23hf`) — the report itself is safe to share.

## CVSS-inspired severity scoring

Every finding is scored by running the **real CVSS 3.1 base-score formula**, not an arbitrary weight. Each finding *type* is mapped to CVSS base metrics (Attack Vector, Attack Complexity, Privileges Required, User Interaction, Confidentiality/Integrity/Availability, Scope) and the genuine formula produces a 0.0–10.0 score:

```
Exploitability = 8.22 × AV × AC × PR × UI
ISS            = 1 − (1−C)(1−I)(1−A)
Impact         = 6.42 × ISS            (scope unchanged)
BaseScore      = Roundup(min(Impact + Exploitability, 10))
```

| Finding | Score | Band |
|---|---|---|
| Vendor / private key (AWS, `ghp_`, private key block) | **10.0** | Critical |
| PII data dump (`*.sql`) | 8.6 | High |
| Generic labeled secret / password / entropy hit | 8.2 | High |
| Prohibited file present (`.env`, `*.pem`) | 7.5 | High |
| Committed clutter · bloat · `.gitignore` drift | 2.9 | Low |

The worst finding drives a repo **letter grade (A–F)**. It's labeled *CVSS-inspired* on purpose: the numbers come from the official formula, but a leaked secret isn't a formal CVE, so no official vector string is claimed. (Verification: the canonical vector `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` returns exactly `9.8`, matching the spec.)

## Three ways to scan, two ways to run

**Sources:** 📁 local folder · 🌐 public repo (temp-cloned, scanned, deleted) · 📦 batch (paste URLs or enumerate a GitHub user/org).

**Interfaces:**
- **Dashboard** — `streamlit run app.py` for interactive triage with metrics, grades, and downloadable Markdown/JSON reports.
- **CLI / pre-commit gate** — `python gitjanitor.py` for headless scans that **exit non-zero** when findings meet a severity threshold, so they can block a commit or fail a pipeline.

## Architecture

```
   ┌──────────────────────────────────────────────────────────────────┐
   │                          YOUR MACHINE                             │
   │                                                                   │
   │   INPUT (pick one)                                                │
   │   📁 Local path     🌐 Public repo URL      📦 Batch (URLs/org)   │
   │        │             │ git clone --depth 1        │ GitHub API    │
   │        │             ▼                            ▼               │
   │        └────────►  temp clone (auto-deleted)  ◄───┘               │
   │                          │                                        │
   │                          ▼                                        │
   │   ┌──────────────────────────────────────────────────────────┐   │
   │   │            scanner.py  —  ENGINE (no UI, stdlib)         │   │
   │   │  os.walk ─► regex + vendor + entropy secrets ·          │   │
   │   │             filename globs · size · .gitignore diff ·    │   │
   │   │             git ls-files gating · suppression ·          │   │
   │   │  git log -p ─► history secret scan · CVSS scoring        │   │
   │   └───────────────┬──────────────────────────┬───────────────┘   │
   │                   ▼                          ▼                    │
   │        app.py (Streamlit)          gitjanitor.py (CLI)            │
   │        dashboard + reports         exit codes for CI             │
   │                                                                   │
   │   Nothing scanned is uploaded. Outbound calls: git clone +       │
   │   GitHub API (list repos). Local scans are fully offline.         │
   └──────────────────────────────────────────────────────────────────┘
```

The detection logic lives in **one UI-free engine (`scanner.py`)** imported by both front-ends, so the dashboard and the CI gate can never drift apart.

## Quick start

**Prerequisites:** Python 3.10+ and `git` on your PATH.

```bash
git clone https://github.com/<your-username>/GitJanitor-Repo-Auditor.git
cd GitJanitor-Repo-Auditor
pip install streamlit                 # the only dependency (CLI needs none)

python create_mock_repo.py            # build a deliberately dirty demo repo
streamlit run app.py                  # launch the dashboard
```

In the browser tab (`http://localhost:8501`): keep **📁 Local folder**, enter `./test_dirty_repo`, lower the sidebar **bloat threshold to 5 MB**, tick **🕓 scan history**, and click **Run audit**. You'll get **grade F**, a top CVSS of **10.0**, vendor-key + entropy + history detections, the prohibited `.env`/`.sql`, clutter, bloat, and `.gitignore` drift.

### Command line / pre-commit

```bash
# Scan the current repo; exit 1 if any High/Critical finding exists
python gitjanitor.py .

# Public repo, include history, save a timestamped JSON report under ./reports/
python gitjanitor.py https://github.com/owner/repo --history --save-report

# Report only, never fail the build
python gitjanitor.py . --fail-on none
```

Wire it into `.git/hooks/pre-commit` to block commits that introduce secrets:

```sh
#!/bin/sh
python /path/to/gitjanitor.py . --fail-on high || exit 1
```

**Exit codes:** `0` clean/below threshold · `1` findings at/above `--fail-on` · `2` error.

### Suppressing false positives

- **Per line:** append `# gitjanitor:ignore` to a line (e.g. a test fixture) to skip it.
- **Per path:** add glob patterns to a `.gitjanitorignore` file in the repo root (same syntax as `.gitignore`).

Suppressed findings are counted, not hidden silently, so nothing disappears without a trace.

### Private repos & higher rate limits

Set `GITHUB_TOKEN` (or `GH_TOKEN`) in your environment to raise the GitHub API limit from 60 to 5,000 requests/hour and to clone private repos you can access. The token is injected only into the clone URL and is **scrubbed from all output and logs**.

## Project structure

```
GitJanitor-Repo-Auditor/
├── scanner.py           # UI-free engine: detection, CVSS scoring, clone/history, reports
├── app.py               # Streamlit dashboard (imports scanner)
├── gitjanitor.py        # CLI / pre-commit gate with exit codes (imports scanner)
├── create_mock_repo.py  # Builds ./test_dirty_repo seeded to trip every check
└── README.md
```

## Design decisions

- **Engine split from UI.** All logic lives in `scanner.py`; `app.py` and `gitjanitor.py` are thin front-ends. The dashboard and the CI gate share identical detection and scoring.
- **Real CVSS formula, honestly labeled.** Scores come from the genuine CVSS 3.1 base equation; it's called *CVSS-inspired* rather than emitting fake official vectors.
- **Git history via plumbing, not packfile parsing.** History scanning streams `git log -p`; Git decompresses objects for us. Hand-inflating packfiles would reinvent a maintained tool badly — the plumbing is what gitleaks/trufflehog use.
- **`git ls-files` gating for clutter.** A local, gitignored `node_modules/` shouldn't be flagged; junk is only reported when it's actually *tracked*.
- **Entropy as a second net.** Labeled patterns catch known shapes; Shannon-entropy scoring (≥ 4.0 bits/char, length ≥ 20) catches random tokens with no keyword — de-duplicated against labeled hits.
- **Shallow by default, full only for history.** Remote scans use `--depth 1`; history mode fetches full history. `GIT_TERMINAL_PROMPT=0` fails fast instead of hanging.
- **Temp-clone lifecycle + redaction.** Every clone is `mkdtemp`'d and removed in a `finally`; findings are redacted in UI and exports.

## Remediation

- **Exposed secret (tree or history):** treat as compromised — **rotate the credential first**. Deleting the file is not enough.
- **Purge from history:** rewrite with [`git filter-repo`](https://github.com/newren/git-filter-repo) or the [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/), then force-push and have collaborators re-clone. Assume anything ever pushed was scraped.
- **Prohibited / clutter file:** `git rm --cached <file>`, add to `.gitignore`, commit.
- **Bloat:** move large binaries to [Git LFS](https://git-lfs.com/); purge existing blobs from history.
- **`.gitignore` drift:** copy the suggested lines from the dashboard's expander.

## Why this matters for supply-chain hygiene

Modern supply-chain security starts inside the repository, before CI/CD runs. Leaked cloud keys are harvested within minutes of a public push; frameworks like NIST SSDF and SOC 2 expect controls that keep credentials and PII out of source control; repository bloat is an availability problem; and `.gitignore` drift is the root cause of most accidental commits. GitJanitor mirrors the detection philosophy of enterprise tools like *gitleaks* and *trufflehog* in a small, readable, offline codebase — demonstrating secure-SDLC thinking, detection engineering, and practical DevSecOps automation.

## Responsible use

Scanning public repositories is standard security practice. But if you find a **live** credential in a repo you don't own, don't use it — report it responsibly (a private issue with the maintainer, or GitHub's private vulnerability reporting). "Found a leak and disclosed it properly" is a far stronger story than "found a leak."

## Roadmap

- [x] Entropy-based detection for unlabeled high-randomness strings
- [x] `GITHUB_TOKEN` support for higher API limits and private repos
- [x] Pre-commit hook mode (headless CLI with exit codes for CI gates)
- [x] CVSS-inspired severity scoring and repo letter grades
- [ ] Per-commit blame attribution in history findings
- [ ] Filename detection in history (a `.env` committed then deleted)

## License

MIT — free to use, fork, and extend.

---

*Built as a portfolio project demonstrating defensive security automation: detection engineering, Git internals, CVSS scoring, and secure development lifecycle tooling.*
