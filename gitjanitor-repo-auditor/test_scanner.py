"""
Unit tests for the GitJanitor scanner engine.

Run with:  pytest -q

These lock in the claims the README makes (e.g. the canonical CVSS vector scores
9.8), the redaction/entropy behaviour, false-positive guards, and each vendor
secret pattern. Pure-stdlib + pytest; no network or git required.
"""

from __future__ import annotations

import scanner as sc


# --- CVSS scoring ----------------------------------------------------------

def test_cvss_canonical_vector_is_9_8():
    # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  → exactly 9.8 in the CVSS 3.1 spec.
    assert sc.cvss_base("N", "L", "N", "N", "H", "H", "H", scope_changed=False) == 9.8


def test_cvss_scope_changed_full_impact_is_10():
    assert sc.cvss_base("N", "L", "N", "N", "H", "H", "H", scope_changed=True) == 10.0


def test_cvss_no_impact_is_zero():
    assert sc.cvss_base("N", "L", "N", "N", "N", "N", "N", scope_changed=False) == 0.0


def test_roundup_rounds_half_up_to_one_decimal():
    assert sc._roundup(4.0) == 4.0
    assert sc._roundup(4.00001) == 4.1
    assert sc._roundup(3.999999) == 4.0


def test_severity_bands():
    assert sc.severity_band(0.0) == "None"
    assert sc.severity_band(3.9) == "Low"
    assert sc.severity_band(6.9) == "Medium"
    assert sc.severity_band(8.9) == "High"
    assert sc.severity_band(9.8) == "Critical"


def test_critical_secret_scores_10_and_grades_f():
    assert sc.SCORES["secret_critical"] == 10.0
    assert sc.BANDS["secret_critical"] == "Critical"


# --- redaction -------------------------------------------------------------

def test_redact_masks_the_middle():
    assert sc.redact("supersecretvalue123") == "supe••••••••e123"


def test_redact_short_value_keeps_only_a_hint():
    r = sc.redact("hunter")
    assert r.startswith("hu") and "•" in r and "hunter" not in r


# --- entropy ---------------------------------------------------------------

def test_entropy_low_for_repeated_char():
    assert sc.shannon_entropy("aaaaaaaa") < 1.0


def test_entropy_high_for_random_mix():
    assert sc.shannon_entropy("A1b2C3d4E5f6G7h8I9j0") >= sc.ENTROPY_THRESHOLD


def test_entropy_skips_pure_letter_identifier():
    # long camelCase name, no digit/base64 symbol → must NOT be flagged.
    hits = sc.scan_line_for_secrets('name = "someVeryLongCamelCaseIdentifierName"',
                                    detect_entropy=True)
    assert hits == []


def test_entropy_flags_unlabeled_random_string():
    # No secret keyword in the variable name, so only the entropy net can catch it.
    hits = sc.scan_line_for_secrets('blob = "aZ3kP9wQ1mB7xC2vN8dR4tE6"', detect_entropy=True)
    assert any(h[0] == "High-entropy string" for h in hits)


# --- labeled + vendor patterns --------------------------------------------

def test_labeled_api_key():
    hits = sc.scan_line_for_secrets('api_key = "abcdef1234567890"', detect_entropy=False)
    assert "Hardcoded API key" in [h[0] for h in hits]


def test_prefixed_label_still_matches():
    hits = sc.scan_line_for_secrets('DB_PASSWORD = "s3cr3tpassword"', detect_entropy=False)
    assert "Hardcoded password" in [h[0] for h in hits]


def test_vendor_patterns_each_fire():
    samples = {
        "AWS access key ID": "AKIAIOSFODNN7EXAMPLE",
        "GitHub personal access token": "ghp_" + "a" * 36,
        "GitHub OAuth/app token": "gho_" + "b" * 36,
        "OpenAI API key": "sk-" + "a" * 40,
        "GitLab personal access token": "glpat-" + "x" * 24,
        "SendGrid API key": "SG." + "a" * 22 + "." + "b" * 43,
        "Stripe live secret key": "sk_live_" + "a" * 24,
        "Google API key": "AIza" + "a" * 35,
        "npm access token": "npm_" + "c" * 36,
    }
    for expected, token in samples.items():
        hits = sc.scan_line_for_secrets(f'x = "{token}"', detect_entropy=False)
        assert expected in [h[0] for h in hits], (expected, hits)


def test_openai_pattern_ignores_hyphenated_identifier():
    # `sk-` followed by a hyphenated identifier (not a key) must not match.
    hits = sc.scan_line_for_secrets('cls = "sk-button-primary-large-rounded-icon"',
                                    detect_entropy=False)
    assert "OpenAI API key" not in [h[0] for h in hits]


def test_inline_pragma_suppresses_line():
    line = 'password = "hunter2000" # gitjanitor:ignore'
    assert sc.scan_line_for_secrets(line, detect_entropy=True) == []


# --- repo label helper (the rstrip('.git') bug) ---------------------------

def test_short_repo_label_strips_suffix_not_characters():
    assert sc.short_repo_label("https://github.com/owner/digit.git") == "owner/digit"
    assert sc.short_repo_label("https://github.com/owner/gitkit.git") == "owner/gitkit"
    assert sc.short_repo_label("https://github.com/owner/repo") == "owner/repo"


# --- suppression globs -----------------------------------------------------

def test_suppression_matches_glob_and_dir():
    assert sc.is_suppressed("tests/fixtures/fake.env", ["tests/*"])
    assert sc.is_suppressed("secrets/key.pem", ["secrets/"])
    assert not sc.is_suppressed("src/app.py", ["tests/*"])


# --- working-tree scan on a temp dir --------------------------------------

def test_env_template_not_prohibited(tmp_path):
    (tmp_path / ".env.example").write_text("API_KEY=changeme\n")
    report = sc.scan_repository(tmp_path, bloat_threshold_bytes=10 ** 12)
    assert not any(rel.endswith(".env.example") for rel, _, _ in report.prohibited)


def test_real_env_is_prohibited(tmp_path):
    (tmp_path / ".env").write_text("API_KEY=live-value-here\n")
    report = sc.scan_repository(tmp_path, bloat_threshold_bytes=10 ** 12)
    assert any(rel == ".env" for rel, _, _ in report.prohibited)


def test_lockfile_entropy_is_skipped(tmp_path):
    # Integrity hashes in a lockfile look high-entropy but aren't secrets.
    (tmp_path / "package-lock.json").write_text(
        '{ "integrity": "sha512-aZ3kP9wQ1mB7xC2vN8dR4tE6uY0iO5pL8kJ7hG6fD5s" }\n')
    report = sc.scan_repository(tmp_path, bloat_threshold_bytes=10 ** 12, detect_entropy=True)
    assert not any(f.label == "High-entropy string" for f in report.secrets)


def test_clean_repo_grades_a(tmp_path):
    (tmp_path / "main.py").write_text("print('hello')\n")
    (tmp_path / ".gitignore").write_text(
        "\n".join(rule for rule, _ in sc.EXPECTED_GITIGNORE) + "\n")
    report = sc.scan_repository(tmp_path, bloat_threshold_bytes=10 ** 12)
    assert report.grade == "A"
    assert report.risk_score == 0.0
