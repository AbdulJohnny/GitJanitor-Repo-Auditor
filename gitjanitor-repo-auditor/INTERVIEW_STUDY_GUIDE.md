# GitJanitor — Interview Study Guide

Everything you need to defend this project in an interview. Read the pitches, memorise the workflow, then drill the Q&A bank.

---

## 1. The pitches (memorise these)

**30-second version:**
> "GitJanitor is a repository hygiene scanner. It finds leaked secrets — both in the current code and buried in Git history — plus sensitive files, committed junk, oversized files, and `.gitignore` gaps. Every finding gets a CVSS-based score and the repo gets an A–F grade. It runs as a Streamlit dashboard for triage, or as a headless CLI that can block a commit or fail a CI pipeline."

**60-second technical version:**
> "The detection logic lives in one UI-free engine, `scanner.py`, imported by two front-ends — a Streamlit dashboard and a CLI. A scan resolves the input (local folder, a cloned public repo, or a whole GitHub org), then does a single `os.walk` pass running secret regexes, vendor-token patterns, entropy analysis, filename policy checks, and size checks all at once. History scanning uses `git log -p` to stream every past commit's diff and re-run secret detection on it. Each finding maps to CVSS 3.1 base metrics, I run the real formula to get a 0–10 score, and the worst score sets the grade. The CLI returns an exit code so it works as a pre-commit hook."

---

## 2. The end-to-end workflow (the #1 thing to know cold)

When someone runs a scan, here's exactly what happens:

**Step 1 — Input resolution.**
Three sources: a local path, a public repo URL, or batch mode (a list of URLs or a GitHub user/org enumerated via the GitHub API). For a remote repo, the URL is validated first (rejects `ssh://`, `git@`, and any URL carrying credentials), then `git clone` drops it into a temp directory created with `mkdtemp`. It's a **shallow clone (`--depth 1`)** by default; if history scanning is on, it does a **full clone**. The temp dir is always deleted in a `finally` block — even if the scan crashes, nothing lingers.

**Step 2 — Single-pass traversal.**
The engine walks the tree **once** with `os.walk`. In that one pass, every file is checked for all issues: secrets (line by line), prohibited filenames, junk filenames, and size. Directories like `.git`, `node_modules`, and `venv` are pruned in place so they're never descended into. One traversal instead of one-per-check = faster and simpler.

**Step 3 — Secret detection (three layers, per line).**
1. **Labeled patterns** — regexes for `API_KEY = "..."`, `password = "..."`, tokens, etc. These now allow prefixes, so `DB_PASSWORD` and `AWS_API_KEY` are caught (but not substrings like `compass`).
2. **Vendor patterns** — fixed-prefix formats: AWS `AKIA…`, GitHub `ghp_…`, Slack `xox…`, Stripe `sk_live_…`, Google `AIza…`, npm, JWTs, DB connection URIs with credentials, private-key blocks. Fixed prefixes mean **near-zero false positives**.
3. **Entropy detection** — Shannon entropy on quoted tokens ≥ 20 chars; flagged if ≥ 4.0 bits/char. This catches random secrets that have **no keyword at all**, deduplicated against anything the labeled patterns already caught.

Anything containing `# gitjanitor:ignore` on the line is skipped; paths matching `.gitjanitorignore` globs are skipped too. Every match is **redacted** (`dh92••••••••23hf`) so the report is safe to share.

**Step 4 — Git-awareness for clutter.**
`git ls-files` gives the set of **tracked** (committed) files. Junk like a `node_modules/` folder is only flagged if it's actually committed — so a developer's local, gitignored `node_modules` doesn't produce a false positive.

**Step 5 — History scan (optional).**
`git log --all -p` streams the diff of every commit. The engine reads the **added (`+`) lines**, attributes each to a commit SHA and file, and runs the same secret detection. This is the **"History Trap"**: a secret that was committed once and deleted later is still in history — this catches it.

**Step 6 — Scoring.**
Each finding type maps to CVSS 3.1 base metrics; the real formula produces a 0.0–10.0 score. The **worst** finding sets the severity band and the repo's **A–F letter grade**.

**Step 7 — Output.**
The dashboard renders each section with grades and scores and offers Markdown/JSON export. The CLI prints a text report **and returns an exit code** — `0` clean, `1` findings at/above the chosen severity, `2` error — so CI or a pre-commit hook can gate on it.

---

## 3. Architecture — say this, it sounds senior

```
scanner.py   ← the engine. All detection, scoring, cloning, reporting. No UI.
   ├── app.py         ← Streamlit dashboard (imports scanner)
   └── gitjanitor.py  ← CLI / pre-commit gate with exit codes (imports scanner)
```

**The line to say:** *"I separated the engine from the UI so the dashboard and the CI gate share one detection core — they can never drift apart or disagree on a verdict."* That's a real software-design principle (separation of concerns / single source of truth), and it's exactly what an interviewer wants to hear.

---

## 4. CVSS scoring, explained simply

CVSS 3.1 has a real published formula with two halves:

- **Exploitability** = `8.22 × AV × AC × PR × UI` — how easy it is to abuse (Attack Vector, Attack Complexity, Privileges Required, User Interaction).
- **Impact** — from Confidentiality/Integrity/Availability via `ISS = 1 − (1−C)(1−I)(1−A)`.
- **Base score** = `Roundup(min(Impact + Exploitability, 10))`.

You map each finding *type* to those metrics and run the formula:
- A **public AWS key** → Network vector, Low complexity, No privileges needed, Scope-changed (blast radius beyond the repo), High C/I/A → lands ~**10.0 Critical**.
- A **missing `.gitignore` line** → Local, High complexity, tiny impact → ~**2.9 Low**.

**Say this for credibility:** *"I call it CVSS-inspired, not official CVSS, because a leaked secret isn't a formal CVE with a real vector string — I didn't want to overclaim. I validated the formula against the canonical test vector `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, which returns exactly 9.8 per the spec."* Honesty about scope is a green flag; overclaiming is a red flag.

---

## 5. Q&A bank — drill these

**"Walk me through what happens when I scan a public repo."**
→ Give the Step 1–7 workflow above. That single answer covers 80% of what they'll ask.

**"Regex-based secret detection is noisy. How do you keep false positives down?"**
→ Layered: vendor patterns with fixed prefixes are near-zero FP; entropy hits are deduped against labeled hits; clutter is gated on `git ls-files` so gitignored local files don't trip it; the prefix regex catches `DB_PASSWORD` but not `compass`; binary files and oversized files are skipped; and there's suppression (`.gitjanitorignore` + inline pragma) for the residue.

**"Why scan history? Deleting the file fixes it, right?"**
→ No. Git keeps every version forever. A deleted secret still lives in history, and scrapers harvest public pushes within minutes. The fix is: **rotate the credential first** (assume it's already compromised), then rewrite history with `git filter-repo` or BFG, force-push, and have collaborators re-clone.

**"How does the history scan work internally?"**
→ `git log --all -p` streams every commit's diff; I parse the added lines and attribute them to a commit SHA and file. I deliberately did **not** hand-parse packfiles out of `.git/objects` — that reinvents a maintained tool badly. Using the plumbing is the correct abstraction, and it's what gitleaks and trufflehog do.

**"Explain the entropy detection."**
→ Shannon entropy measures randomness in bits per character. English text sits around 3–4; a base64 secret is 4.5–6. I flag quoted tokens ≥ 20 chars with entropy ≥ 4.0 that weren't already caught by a labeled pattern. It's the net for secrets with no obvious keyword.

**"Explain your severity scoring."**
→ The CVSS section above.

**"Why build both a dashboard and a CLI?"**
→ Different users. The dashboard is for interactive triage and demos; the CLI is for automation — a pre-commit hook or CI gate needs an **exit code**, not a browser. Both import the same engine so they stay consistent.

**"How is this different from gitleaks or trufflehog?"**
→ Same detection philosophy in a small, readable codebase. Mine adds a hygiene layer (clutter, bloat, `.gitignore` drift), CVSS grading with a repo letter grade, and a dashboard. I'm not claiming to beat production tools — I built it to demonstrate detection-engineering thinking end to end.

**"What are its limitations? What would you improve?"** *(Answer this honestly — it's a trap for overclaimers.)*
→ Regex/entropy detection has inherent FP/FN tradeoffs; there's no ML or context-aware validation. History is capped at 2000 commits for performance. It detects secrets *deleted from history* by content, but doesn't yet flag a `.env` committed-then-deleted by **filename** — that's on the roadmap, along with per-commit blame attribution and an allowlist of known-safe hashes.

**"You come from offensive security / VAPT. Why a defensive tool?"**
→ *"Offense-informed defense."* As a pentester I've seen how attackers harvest leaked credentials from public repos — so I built the control that stops the leak at the source. Knowing the attack makes the defense sharper.

**"How does this relate to a SOC role?"**
→ Leaked secrets are a real detection-and-triage scenario. The CVSS grading mirrors how a SOC prioritises alerts by severity, and the exportable reports are triage-ready artifacts. It shows I can think about detection logic, severity, and prioritisation — the core of L1 work.

---

## 6. Live demo cheat sheet (if they ask you to run it)

```bash
pip install streamlit
python create_mock_repo.py          # builds ./test_dirty_repo seeded to trip every check

# Dashboard:
streamlit run app.py                # scan ./test_dirty_repo, set bloat slider to 5 MB, tick history

# CLI (the impressive one for automation):
python gitjanitor.py ./test_dirty_repo --history --threshold-mb 5
echo $?                             # shows the exit code — proves it can gate CI
```

Expected result on the demo repo: **grade F, top CVSS 10.0**, with a vendor key, an entropy hit, a history secret, the `.env` and `.sql`, clutter, bloat, and `.gitignore` drift.

---

## 7. Know these cold (rapid-fire facts)

- **One engine, two front-ends** — `scanner.py` imported by `app.py` and `gitjanitor.py`.
- **Single `os.walk` pass** runs all file-level checks.
- **Three secret layers:** labeled regex → vendor prefixes → entropy.
- **History = `git log -p`**, not packfile parsing.
- **Clutter gated on `git ls-files`** (tracked = committed).
- **CVSS 3.1 real formula**, labeled "inspired," validated at 9.8.
- **Worst finding → A–F grade.**
- **Exit codes:** 0 clean / 1 findings ≥ threshold / 2 error.
- **Temp clones deleted in `finally`; secrets redacted; token scrubbed from logs.**
- **Remediation order:** rotate first, then rewrite history.

If you can explain the workflow (§2) and the three-layer detection (§5) without notes, you're ready.
