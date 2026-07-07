"""
GitJanitor scanner engine
=========================
Pure, UI-free scanning core shared by the Streamlit app (app.py) and the
command-line / pre-commit tool (gitjanitor.py). No Streamlit imports here, so
the same detection logic runs in a browser dashboard or in CI.

Capabilities:
  - Working-tree secret scanning (labeled patterns + vendor tokens + entropy)
  - Git history secret scanning via `git log -p` plumbing
  - Prohibited files, committed clutter (gated on `git ls-files`), bloat
  - .gitignore drift
  - CVSS-3.1-inspired severity scoring per finding + a repo letter grade
  - False-positive suppression (.gitjanitorignore globs + inline pragma)
  - Public/private clone (GITHUB_TOKEN optional) and org enumeration
"""

from __future__ import annotations

import fnmatch
import json
import math
import os
import re
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

# ===========================================================================
# Configuration & detection rules
# ===========================================================================

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__"}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp",
    ".mp4", ".mov", ".avi", ".mkv", ".mp3", ".wav", ".flac",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".dat", ".dmg", ".msi",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pyc", ".pyo", ".class", ".jar", ".war",
    ".sqlite", ".db", ".parquet", ".pkl", ".h5", ".onnx", ".pt",
}

MAX_SCAN_BYTES = 2 * 1024 * 1024          # don't read files bigger than this
CLONE_TIMEOUT_SECONDS = 120

# Inline pragma to silence a specific line, e.g.  token = "..."  # gitjanitor:ignore
INLINE_IGNORE = "gitjanitor:ignore"
SUPPRESS_FILE = ".gitjanitorignore"

# High-entropy detection
ENTROPY_MIN_LEN = 20
ENTROPY_THRESHOLD = 4.0                    # bits/char; base64 secrets score ~4.5-6
ENTROPY_TOKEN_RE = re.compile(r"""['"]([A-Za-z0-9+/=_\-]{20,})['"]""")

# Dependency lockfiles are full of integrity hashes (sha512-… base64) that look
# high-entropy but are public checksums, not secrets. We keep labeled/vendor
# pattern matching on them but skip ENTROPY here to kill the false positives —
# the same reason gitleaks/trufflehog ship lockfile allowlists by default.
LOCKFILE_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    "composer.lock", "Gemfile.lock", "poetry.lock", "Pipfile.lock", "go.sum",
    "Cargo.lock", "packages.lock.json", "bun.lockb",
}

# Template env files are meant to be committed (placeholder values, not creds),
# so they should not trip the prohibited-file check.
ENV_TEMPLATE_NAMES = {
    ".env.example", ".env.sample", ".env.template", ".env.dist",
    ".env.defaults", ".env.local.example",
}


def _is_lockfile(name: str) -> bool:
    return name in LOCKFILE_NAMES

# Secret patterns: (label, compiled regex, tier). tier drives CVSS scoring.
SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # --- generic labeled assignments (allow prefixes like DB_ / AWS_) ----
    ("Hardcoded API key",
     re.compile(r"""(?ix)\b(?:[a-z0-9]+[_-])*api[_-]?key\b\s*[:=]\s*["']([^"']{8,})["']"""), "high"),
    ("Hardcoded secret",
     re.compile(r"""(?ix)\b(?:[a-z0-9]+[_-])*secret(?:[_-]?key)?\b\s*[:=]\s*["']([^"']{8,})["']"""), "high"),
    ("Hardcoded password",
     re.compile(r"""(?ix)\b(?:[a-z0-9]+[_-])*pass(?:word|wd)?\b\s*[:=]\s*["']([^"']{6,})["']"""), "high"),
    ("Token assignment",
     re.compile(r"""(?ix)\b(?:[a-z0-9]+[_-])*(?:auth[_-]?token|access[_-]?token|token)\b\s*[:=]\s*["']([^"']{16,})["']"""), "high"),
    # --- high-confidence vendor formats (fixed prefixes = near-zero FP) ---
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
    ("GitHub personal access token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "critical"),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), "critical"),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "critical"),
    ("Stripe live secret key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"), "critical"),
    ("Google API key", re.compile(r"\bAIza[A-Za-z0-9_\-]{35}\b"), "critical"),
    ("Twilio API key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "high"),
    ("npm access token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "critical"),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), "high"),
    ("DB connection URI with credentials",
     re.compile(r"(?i)\b(?:postgres|postgresql|mysql|mongodb)(?:\+srv)?://[^\s:@/]+:[^\s@/]+@"), "critical"),
    ("Bearer token in source", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}"), "high"),
    ("Private key block",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"), "critical"),
]

PROHIBITED_PATTERNS: list[tuple[str, str, str]] = [  # (glob, reason, kind)
    (".env*",            "Environment file — commonly holds live credentials", "secret"),
    ("config.json",      "Config file — frequently contains connection strings or keys", "secret"),
    ("secrets.json",     "Secrets file", "secret"),
    ("credentials.json", "Credential file (cloud SDK / OAuth)", "secret"),
    ("*.pem",            "PEM-encoded key or certificate material", "secret"),
    ("*.key",            "Raw private key file", "secret"),
    ("*.pfx",            "PKCS#12 key store", "secret"),
    ("*.p12",            "PKCS#12 key store", "secret"),
    ("*.keystore",       "Java keystore", "secret"),
    ("id_rsa",           "SSH private key", "secret"),
    ("id_dsa",           "SSH private key", "secret"),
    ("id_ecdsa",         "SSH private key", "secret"),
    ("id_ed25519",       "SSH private key", "secret"),
    ("*.tfstate",        "Terraform state — often embeds plaintext secrets", "secret"),
    ("*.sql",            "SQL dump — can contain PII or raw customer data", "pii"),
    ("*.dump",           "Database dump — can contain PII or raw customer data", "pii"),
    ("*.bak",            "Backup file — often a copy of a config or database", "pii"),
]

JUNK_FILE_PATTERNS: list[tuple[str, str]] = [
    ("*.suo",     "Visual Studio user options — local, machine-specific"),
    ("*.user",    "IDE per-user project settings"),
    ("*.zip",     "Committed archive — hides unmanaged files, bloats history"),
    ("*.tar.gz",  "Committed archive — hides unmanaged files, bloats history"),
    ("*.tgz",     "Committed archive — hides unmanaged files, bloats history"),
    ("*.7z",      "Committed archive — hides unmanaged files, bloats history"),
    ("*.rar",     "Committed archive — hides unmanaged files, bloats history"),
    ("*.exe",     "Compiled binary — chews Git bandwidth"),
    ("*.dll",     "Compiled binary — chews Git bandwidth"),
    ("*.so",      "Compiled binary — chews Git bandwidth"),
    ("*.dmg",     "macOS disk image — large binary artifact"),
]

JUNK_DIRS: dict[str, str] = {
    ".idea":        "JetBrains IDE metadata (absolute local paths)",
    ".vscode":      "VS Code workspace settings (local, machine-specific)",
    "node_modules": "Node dependency tree — reinstallable, never commit",
    "venv":         "Python virtualenv — reinstallable, never commit",
    ".venv":        "Python virtualenv — reinstallable, never commit",
}

EXPECTED_GITIGNORE = [
    ("node_modules/", "Node dependency tree — should never be committed"),
    ("__pycache__/",  "Python bytecode cache"),
    (".env",          "Environment/credential files"),
    ("*.pyc",         "Compiled Python files"),
    (".venv/",        "Python virtual environments"),
    (".DS_Store",     "macOS metadata files"),
    (".idea/",        "JetBrains IDE metadata"),
    (".vscode/",      "VS Code workspace settings"),
    ("dist/",         "Build output"),
    ("build/",        "Build output"),
    ("*.log",         "Runtime log files"),
]

# ===========================================================================
# CVSS v3.1-inspired scoring
# ===========================================================================
# Official metric weights. We map each finding TYPE to a metric vector, then
# run the real CVSS 3.1 base-score formula. This is CVSS-*inspired*: the numbers
# come from the genuine formula, but a "leaked secret" isn't an official CVE, so
# we don't emit a formal vector string.

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}   # Attack Vector
_AC = {"L": 0.77, "H": 0.44}                          # Attack Complexity
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}             # Priv. Required (scope unchanged)
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}             # Priv. Required (scope changed)
_UI = {"N": 0.85, "R": 0.62}                          # User Interaction
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}               # C / I / A impact


def _roundup(value: float) -> float:
    """Official CVSS 3.1 integer-safe round-half-up to one decimal."""
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def cvss_base(av: str, ac: str, pr: str, ui: str,
              c: str, i: str, a: str, scope_changed: bool) -> float:
    """Compute a CVSS 3.1 base score (0.0-10.0) from metric letters."""
    iss = 1 - (1 - _CIA[c]) * (1 - _CIA[i]) * (1 - _CIA[a])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    pr_val = (_PR_C if scope_changed else _PR_U)[pr]
    exploit = 8.22 * _AV[av] * _AC[ac] * pr_val * _UI[ui]
    if impact <= 0:
        return 0.0
    raw = 1.08 * (impact + exploit) if scope_changed else (impact + exploit)
    return _roundup(min(raw, 10.0))


def severity_band(score: float) -> str:
    """CVSS qualitative rating."""
    if score <= 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


# Metric vectors per finding kind. Reasoning inline.
_SEVERITY_MODEL: dict[str, dict] = {
    # Live cloud/vendor key or private key pushed publicly: remotely harvestable,
    # trivial to abuse, full compromise, blast radius beyond the repo.
    "secret_critical":   dict(av="N", ac="L", pr="N", ui="N", c="H", i="H", a="H", scope_changed=True),
    # Generic labeled credential: high confidentiality impact, contained scope.
    "secret_high":       dict(av="N", ac="L", pr="N", ui="N", c="H", i="L", a="N", scope_changed=False),
    # Same secret, found in history (deleted from tip but still reachable).
    "history_critical":  dict(av="N", ac="L", pr="N", ui="N", c="H", i="H", a="H", scope_changed=True),
    "history_high":      dict(av="N", ac="L", pr="N", ui="N", c="H", i="L", a="N", scope_changed=False),
    # A .env / .pem sitting in the tree: likely credentials, contained scope.
    "prohibited_secret": dict(av="N", ac="L", pr="N", ui="N", c="H", i="N", a="N", scope_changed=False),
    # SQL/DB dump: PII exposure, blast radius beyond the repo (customers).
    "prohibited_pii":    dict(av="N", ac="L", pr="N", ui="N", c="H", i="N", a="N", scope_changed=True),
    # IDE dirs / archives / committed deps: hygiene, not directly exploitable.
    "clutter":           dict(av="L", ac="H", pr="N", ui="N", c="N", i="N", a="L", scope_changed=False),
    "bloat":             dict(av="L", ac="H", pr="N", ui="N", c="N", i="N", a="L", scope_changed=False),
    # Missing ignore rule: a control gap, not a direct exposure.
    "gitignore":         dict(av="L", ac="H", pr="N", ui="N", c="N", i="L", a="N", scope_changed=False),
}

# Precompute once: kind -> (score, band)
SCORES: dict[str, float] = {k: cvss_base(**m) for k, m in _SEVERITY_MODEL.items()}
BANDS: dict[str, str] = {k: severity_band(s) for k, s in SCORES.items()}

_BAND_ORDER = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_BAND_TO_GRADE = {"None": "A", "Low": "B", "Medium": "C", "High": "D", "Critical": "F"}


def kind_for_secret(tier: str, in_history: bool = False) -> str:
    prefix = "history" if in_history else "secret"
    return f"{prefix}_{'critical' if tier == 'critical' else 'high'}"


# ===========================================================================
# Result containers
# ===========================================================================

@dataclass
class SecretFinding:
    file: str
    line_no: int
    label: str
    preview: str
    tier: str = "high"

    @property
    def score(self) -> float:
        return SCORES[kind_for_secret(self.tier)]

    @property
    def severity(self) -> str:
        return BANDS[kind_for_secret(self.tier)]


@dataclass
class HistoryFinding:
    commit: str
    file: str
    label: str
    preview: str
    tier: str = "high"

    @property
    def score(self) -> float:
        return SCORES[kind_for_secret(self.tier, in_history=True)]

    @property
    def severity(self) -> str:
        return BANDS[kind_for_secret(self.tier, in_history=True)]


@dataclass
class ScanReport:
    secrets: list[SecretFinding] = field(default_factory=list)
    prohibited: list[tuple[str, str, str]] = field(default_factory=list)  # (path, reason, kind)
    junk: list[tuple[str, str]] = field(default_factory=list)
    bloat: list[tuple[str, int]] = field(default_factory=list)
    gitignore_exists: bool = False
    gitignore_missing: list[tuple[str, str]] = field(default_factory=list)
    history: list[HistoryFinding] = field(default_factory=list)
    history_scanned: bool = False
    suppressed: int = 0
    total_bytes: int = 0
    files_scanned: int = 0
    is_git_repo: bool = False

    @property
    def total_risks(self) -> int:
        drift = len(self.gitignore_missing) if self.gitignore_exists else 1
        return (len(self.secrets) + len(self.prohibited) + len(self.junk)
                + len(self.bloat) + drift + len(self.history))

    def all_scores(self) -> list[float]:
        """Every finding's CVSS score, for aggregation."""
        scores: list[float] = [f.score for f in self.secrets]
        scores += [h.score for h in self.history]
        scores += [SCORES["prohibited_pii" if k == "pii" else "prohibited_secret"]
                   for _, _, k in self.prohibited]
        scores += [SCORES["clutter"]] * len(self.junk)
        scores += [SCORES["bloat"]] * len(self.bloat)
        drift = len(self.gitignore_missing) if self.gitignore_exists else 1
        scores += [SCORES["gitignore"]] * drift
        return scores

    @property
    def risk_score(self) -> float:
        """The single worst CVSS score in the repo (0.0 if clean)."""
        scores = self.all_scores()
        return max(scores) if scores else 0.0

    @property
    def grade(self) -> str:
        """Letter grade A-F driven by the worst severity present."""
        return _BAND_TO_GRADE[severity_band(self.risk_score)]


# ===========================================================================
# Helpers
# ===========================================================================

def human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:,.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{num_bytes} B"


def redact(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return value[:2] + "•" * 6
    return f"{value[:4]}{'•' * 8}{value[-4:]}"


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def looks_binary(path: Path) -> bool:
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with open(path, "rb") as fh:
            return b"\x00" in fh.read(1024)
    except OSError:
        return True


# ===========================================================================
# Suppression (.gitjanitorignore + inline pragma)
# ===========================================================================

def load_suppressions(repo: Path) -> list[str]:
    """Read glob patterns from .gitjanitorignore (blank lines / # comments skipped)."""
    path = repo / SUPPRESS_FILE
    if not path.is_file():
        return []
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [ln.strip() for ln in raw.splitlines()
            if ln.strip() and not ln.strip().startswith("#")]


def is_suppressed(rel_path: str, patterns: list[str]) -> bool:
    norm = rel_path.replace(os.sep, "/")
    for pat in patterns:
        if fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(norm, pat.rstrip("/") + "/*"):
            return True
    return False


# ===========================================================================
# Secret scanning (labeled + vendor + entropy)
# ===========================================================================

def scan_line_for_secrets(line: str, detect_entropy: bool) -> list[tuple[str, str, str]]:
    """Return (label, tier, evidence) for every secret hit on one line.

    Honors the inline pragma. Entropy hits are suppressed for values already
    caught by a labeled pattern, to avoid double counting.
    """
    if INLINE_IGNORE in line:
        return []

    hits: list[tuple[str, str, str]] = []
    seen_values: set[str] = set()

    for label, pattern, tier in SECRET_PATTERNS:
        m = pattern.search(line)
        if not m:
            continue
        evidence = m.group(1) if m.groups() else m.group(0)
        hits.append((label, tier, evidence))
        seen_values.add(evidence)

    if detect_entropy:
        for m in ENTROPY_TOKEN_RE.finditer(line):
            token = m.group(1)
            if token in seen_values or len(token) < ENTROPY_MIN_LEN:
                continue
            # Real credentials (base64/hex/keys) almost always contain a digit or
            # a base64 symbol. Pure-letter camelCase identifiers (e.g. a long
            # tsconfig option name) don't — so require one to cut those FPs.
            if not any(c.isdigit() or c in "+/=" for c in token):
                continue
            if shannon_entropy(token) >= ENTROPY_THRESHOLD:
                hits.append(("High-entropy string", "high", token))
                seen_values.add(token)
    return hits


def scan_file_for_secrets(path: Path, rel: str, detect_entropy: bool) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings
    # Lockfiles: keep labeled/vendor detection, drop entropy (integrity hashes).
    file_entropy = detect_entropy and not _is_lockfile(path.name)
    for line_no, line in enumerate(text.splitlines(), start=1):
        for label, tier, evidence in scan_line_for_secrets(line, file_entropy):
            findings.append(SecretFinding(rel, line_no, label, redact(evidence), tier))
    return findings


def check_gitignore(repo: Path, report: ScanReport) -> None:
    gi_path = repo / ".gitignore"
    if not gi_path.is_file():
        report.gitignore_exists = False
        report.gitignore_missing = list(EXPECTED_GITIGNORE)
        return
    report.gitignore_exists = True
    try:
        raw = gi_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        raw = ""
    entries = {ln.strip().rstrip("/") for ln in raw.splitlines()
               if ln.strip() and not ln.strip().startswith("#")}
    for rule, why in EXPECTED_GITIGNORE:
        if rule.rstrip("/") not in entries:
            report.gitignore_missing.append((rule, why))


# ===========================================================================
# Git-awareness helpers
# ===========================================================================

def get_tracked_paths(repo: Path) -> set[str] | None:
    if not (repo / ".git").exists():
        return None
    try:
        out = subprocess.run(["git", "-C", str(repo), "ls-files"],
                             check=True, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return {ln.strip() for ln in out.stdout.splitlines() if ln.strip()}


def _is_committed(rel: str, tracked: set[str] | None, is_dir: bool) -> bool:
    if tracked is None:
        return True
    if is_dir:
        prefix = rel.rstrip("/") + "/"
        return any(t == rel.rstrip("/") or t.startswith(prefix) for t in tracked)
    return rel in tracked


# ===========================================================================
# Main working-tree scan
# ===========================================================================

def scan_repository(repo: Path, bloat_threshold_bytes: int,
                    detect_entropy: bool = True) -> ScanReport:
    """Walk the tree once and populate a full ScanReport."""
    report = ScanReport()
    report.is_git_repo = (repo / ".git").is_dir()
    tracked = get_tracked_paths(repo)
    suppress = load_suppressions(repo)

    def suppressed(rel: str) -> bool:
        if is_suppressed(rel, suppress):
            report.suppressed += 1
            return True
        return False

    for root, dirs, files in os.walk(repo):
        for d in dirs:
            if d in JUNK_DIRS:
                rel_dir = str((Path(root) / d).relative_to(repo))
                if _is_committed(rel_dir, tracked, is_dir=True) and not suppressed(rel_dir + "/"):
                    report.junk.append((rel_dir + "/", JUNK_DIRS[d]))
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and d not in JUNK_DIRS]

        for name in files:
            path = Path(root) / name
            rel = str(path.relative_to(repo))

            try:
                size = path.stat().st_size
            except OSError:
                continue

            report.total_bytes += size
            report.files_scanned += 1

            if suppressed(rel):
                continue

            matched = False
            if name not in ENV_TEMPLATE_NAMES:      # .env.example etc. are meant to be committed
                for pattern, reason, kind in PROHIBITED_PATTERNS:
                    if fnmatch.fnmatch(name, pattern):
                        report.prohibited.append((rel, reason, kind))
                        matched = True
                        break

            if not matched:
                for pattern, reason in JUNK_FILE_PATTERNS:
                    if fnmatch.fnmatch(name, pattern) and _is_committed(rel, tracked, is_dir=False):
                        report.junk.append((rel, reason))
                        break

            if size >= bloat_threshold_bytes:
                report.bloat.append((rel, size))

            if size <= MAX_SCAN_BYTES and not looks_binary(path):
                report.secrets.extend(scan_file_for_secrets(path, rel, detect_entropy))

    check_gitignore(repo, report)
    report.bloat.sort(key=lambda item: item[1], reverse=True)
    report.junk.sort()
    return report


# ===========================================================================
# Remote clone / history / enumeration
# ===========================================================================

def _github_token() -> str | None:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def _scrub(text: str) -> str:
    """Strip any embedded token from git output before it is shown/logged."""
    token = _github_token()
    if token and token in text:
        text = text.replace(token, "***")
    return re.sub(r"x-access-token:[^@]+@", "x-access-token:***@", text)


def normalize_repo_url(url: str) -> str:
    url = url.strip()
    if url.startswith("git@") or url.startswith("ssh://"):
        raise ValueError("SSH URLs aren't supported — paste the https:// URL instead.")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Enter a full URL, e.g. https://github.com/owner/repo")
    if parsed.username or parsed.password:
        raise ValueError("Remove credentials from the URL.")
    if not parsed.netloc or not parsed.path.strip("/"):
        raise ValueError("That doesn't look like a repository URL.")
    if not url.endswith(".git"):
        url = url.rstrip("/") + ".git"
    return url


def _auth_url(url: str) -> str:
    """Inject GITHUB_TOKEN for github.com so private repos clone (kept out of logs)."""
    token = _github_token()
    if token and url.startswith("https://github.com/"):
        return url.replace("https://", f"https://x-access-token:{token}@", 1)
    return url


def clone_public_repo(url: str, deep: bool = False) -> Path:
    """Clone into a fresh temp dir. deep=False → shallow (--depth 1). Caller cleans up."""
    dest = Path(tempfile.mkdtemp(prefix="gitjanitor_"))
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    cmd = ["git", "clone", "--single-branch", _auth_url(url), str(dest)]
    if not deep:
        cmd[2:2] = ["--depth", "1"]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True,
                       timeout=CLONE_TIMEOUT_SECONDS, env=env)
    except subprocess.CalledProcessError as exc:
        raise subprocess.CalledProcessError(
            exc.returncode, "git clone",
            output=_scrub(exc.output or ""), stderr=_scrub(exc.stderr or "")) from None
    return dest


def scan_history_for_secrets(repo: Path, detect_entropy: bool = True,
                             max_commits: int = 2000) -> list[HistoryFinding]:
    """Scan added lines of every past commit for secrets (the History Trap)."""
    if not (repo / ".git").exists():
        return []
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "log", "--all", "-p", "--no-color", "--no-merges",
             f"--max-count={max_commits}", "--format=__COMMIT__%H"],
            check=True, capture_output=True, text=True,
            timeout=CLONE_TIMEOUT_SECONDS, errors="replace")
    except (OSError, subprocess.SubprocessError):
        return []

    findings: list[HistoryFinding] = []
    seen: set[tuple[str, str, str]] = set()
    commit = ""
    current_file = "<unknown>"
    for line in proc.stdout.splitlines():
        if line.startswith("__COMMIT__"):
            commit = line[len("__COMMIT__"):][:8]
            continue
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        line_entropy = detect_entropy and not _is_lockfile(Path(current_file).name)
        for label, tier, evidence in scan_line_for_secrets(line[1:], line_entropy):
            key = (commit, current_file, label)
            if key in seen:
                continue
            seen.add(key)
            findings.append(HistoryFinding(commit, current_file, label, redact(evidence), tier))
    return findings


def list_public_repos(owner: str, limit: int = 30) -> list[str]:
    """Clone URLs for a user's/org's repos via the GitHub API.

    Unauthenticated: 60 req/hour, public only. With GITHUB_TOKEN: 5000 req/hour
    and private repos you can access are included.
    """
    from urllib.error import HTTPError
    from urllib.request import Request, urlopen

    owner = owner.strip().strip("/")
    if owner.startswith("http"):
        owner = urlparse(owner).path.strip("/").split("/")[0]
    if not owner:
        raise ValueError("Enter a GitHub username or organisation.")

    token = _github_token()
    headers = {"User-Agent": "GitJanitor", "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    repo_type = "all" if token else "public"

    for kind in ("orgs", "users"):
        api = (f"https://api.github.com/{kind}/{owner}/repos"
               f"?per_page=100&type={repo_type}&sort=updated")
        try:
            with urlopen(Request(api, headers=headers), timeout=30) as resp:
                data = json.load(resp)
        except HTTPError as exc:
            if exc.code == 404:
                continue
            if exc.code == 403:
                raise ValueError("GitHub API rate limit hit. Set GITHUB_TOKEN, wait, "
                                 "or paste repo URLs directly.") from exc
            raise ValueError(f"GitHub API error {exc.code} for '{owner}'.") from exc
        urls = [r["clone_url"] for r in data if r.get("clone_url")]
        if urls:
            return urls[:limit]
    raise ValueError(f"No repos found for '{owner}'.")


# ===========================================================================
# Report serialisation (shared by UI + CLI)
# ===========================================================================

def report_to_row(label: str, report: ScanReport) -> dict:
    """Flatten a ScanReport into a serialisable, redacted summary row."""
    drift = len(report.gitignore_missing) if report.gitignore_exists else len(EXPECTED_GITIGNORE)
    return {
        "repo": label,
        "grade": report.grade,
        "risk_score": report.risk_score,
        "risks": report.total_risks,
        "secrets": len(report.secrets),
        "history": len(report.history),
        "prohibited": len(report.prohibited),
        "junk": len(report.junk),
        "bloat": len(report.bloat),
        "gitignore_exists": report.gitignore_exists,
        "gitignore_missing": drift,
        "suppressed": report.suppressed,
        "size": human_size(report.total_bytes),
        "files": report.files_scanned,
        "secret_items": [
            {"file": f.file, "line": f.line_no, "label": f.label,
             "score": f.score, "severity": f.severity} for f in report.secrets],
        "history_items": [
            {"commit": h.commit, "file": h.file, "label": h.label,
             "score": h.score, "severity": h.severity} for h in report.history],
        "prohibited_items": [
            {"file": rel, "reason": reason,
             "score": SCORES["prohibited_pii" if k == "pii" else "prohibited_secret"],
             "severity": BANDS["prohibited_pii" if k == "pii" else "prohibited_secret"]}
            for rel, reason, k in report.prohibited],
        "junk_items": [rel for rel, _ in report.junk],
        "bloat_items": [{"file": rel, "size": human_size(sz)} for rel, sz in report.bloat],
    }


def build_markdown_report(rows: list[dict]) -> str:
    lines = [
        "# GitJanitor audit report", "",
        f"Scanned **{len(rows)}** repositor{'y' if len(rows) == 1 else 'ies'}.", "",
        "| Repository | Grade | Top CVSS | Risks | Secrets | History | Prohibited | Junk | Bloat | .gitignore |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        gi = "missing" if not r["gitignore_exists"] else f"{r['gitignore_missing']} gaps"
        lines.append(
            f"| {r['repo']} | {r['grade']} | {r['risk_score']} | {r['risks']} | "
            f"{r['secrets']} | {r['history']} | {r['prohibited']} | {r['junk']} | "
            f"{r['bloat']} | {gi} |")
    lines += ["", "## Details", ""]
    for r in rows:
        lines.append(f"### {r['repo']} — grade {r['grade']} (top CVSS {r['risk_score']})")
        lines.append(f"- Risks: {r['risks']} · Size: {r['size']} · Files: {r['files']} "
                     f"· Suppressed: {r['suppressed']}")
        for f in r["secret_items"]:
            lines.append(f"  - 🔑 [{f['severity']} {f['score']}] `{f['file']}` "
                         f"line {f['line']} — {f['label']}")
        for h in r["history_items"]:
            lines.append(f"  - 🕓 [{h['severity']} {h['score']}] commit `{h['commit']}` "
                         f"`{h['file']}` — {h['label']} (in history)")
        for p in r["prohibited_items"]:
            lines.append(f"  - 🚫 [{p['severity']} {p['score']}] `{p['file']}` — {p['reason']}")
        for j in r["junk_items"]:
            lines.append(f"  - 🧹 `{j}`")
        for b in r["bloat_items"]:
            lines.append(f"  - 🐘 `{b['file']}` — {b['size']}")
        lines.append("")
    return "\n".join(lines)
