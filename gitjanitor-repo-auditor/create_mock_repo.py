"""
create_mock_repo.py
===================
Builds a deliberately messy local git repo named `test_dirty_repo/` so every
GitJanitor check lights up — including CVSS scoring, vendor-token detection,
high-entropy detection, committed clutter, suppression, and the History Trap.

Everything here is FAKE (dummy strings, no real services). Run:
    python create_mock_repo.py
Then either:
    streamlit run app.py            # dashboard, scan ./test_dirty_repo (bloat slider -> 5 MB)
    python gitjanitor.py ./test_dirty_repo --history   # CLI / pre-commit view
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO = Path("test_dirty_repo")
BLOAT_SIZE_BYTES = 6 * 1024 * 1024  # over the 5 MB demo threshold


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"  [+] wrote {path}")


def git(*args: str) -> None:
    subprocess.run(["git", "-C", str(REPO), *args], check=True, capture_output=True, text=True)


def main() -> None:
    print(f"Creating mock repository at ./{REPO}/ ...")
    REPO.mkdir(exist_ok=True)

    # Source with a labeled key + a vendor token (Critical) + a high-entropy blob
    write(REPO / "src" / "settings.py",
          '"""App settings — intentionally bad example."""\n\n'
          'DEBUG = True\n'
          '# labeled credential (High)\n'
          'API_KEY = "dh928h398h9238h923hf"\n'
          '# vendor token, fixed prefix (Critical)\n'
          'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
          '# random-looking token caught by entropy, no keyword\n'
          'blob = "aGVsbG8gd29ybGQgc2VjcmV0IHRva2VuMTIzNDU2Nzg5"\n'
          '# a deliberately allow-listed test fixture\n'
          'TEST_TOKEN = "not_a_real_key_ignore_me"  # gitjanitor:ignore\n')

    # .env prohibited file
    write(REPO / ".env",
          "# FAKE environment file\nAPP_ENV=production\n"
          'SECRET = "super_secret_session_value_123"\n'
          "SMTP_PASSWORD=not-a-real-password\n")

    # SQL dump -> prohibited (PII)
    write(REPO / "backup.sql",
          "INSERT INTO customers (name, phone) VALUES ('Jane Doe', '555-0100');\n")

    # committed clutter: IDE dir + archive
    write(REPO / ".vscode" / "settings.json", "{}\n")
    write(REPO / "release.zip", "PK\x03\x04 fake archive bytes\n")

    # oversized bloat file
    bloat = REPO / "data" / "training_dump.bin"
    bloat.parent.mkdir(parents=True, exist_ok=True)
    with open(bloat, "wb") as fh:
        fh.write(b"\x00" * BLOAT_SIZE_BYTES)
    print(f"  [+] wrote {bloat} ({BLOAT_SIZE_BYTES // (1024 * 1024)} MB)")

    # empty .gitignore -> drift
    write(REPO / ".gitignore", "")

    # suppression file: silence a known test fixture path
    write(REPO / ".gitjanitorignore", "# GitJanitor suppression list\nsrc/fixtures/*\n")

    # normal files
    write(REPO / "README.md", "# test_dirty_repo\n\nDeliberately messy repo for the demo.\n")
    write(REPO / "src" / "main.py", 'print("hello from the mock repo")\n')

    # --- History Trap: commit a secret, then "remove" it in a later commit ---
    git("init", "-q")
    git("config", "user.email", "demo@example.com")
    git("config", "user.name", "demo")
    write(REPO / "old_config.py", 'DB_PASSWORD = "leaked_prod_password_9x8y7z"\n')
    git("add", "-A")
    git("commit", "-q", "-m", "initial commit (contains a secret)")
    (REPO / "old_config.py").unlink()
    write(REPO / "old_config.py", "# cleaned up, nothing to see here\n")
    git("add", "-A")
    git("commit", "-q", "-m", "remove secret (but it lives on in history)")

    print("\nDone. Try:")
    print("    streamlit run app.py         # scan ./test_dirty_repo, set bloat slider to 5 MB, tick history")
    print("    python gitjanitor.py ./test_dirty_repo --history")


if __name__ == "__main__":
    main()
