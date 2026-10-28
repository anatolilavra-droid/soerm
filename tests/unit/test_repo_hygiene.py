"""Repository hygiene: no secrets or generated data in the project tree."""

import fnmatch
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

REQUIRED_IGNORE_ENTRIES = (
    ".venv-py312/",
    ".venv-py313/",
    "soerm-workspace/",
    ".soerm.lock",
    "*.db",
    "*.db-wal",
    "*.db-shm",
    "*.sqlite",
    "*.sqlite3",
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "secrets/",
    "__pycache__/",
    ".pytest_cache/",
    ".mypy_cache/",
    ".ruff_cache/",
)
FORBIDDEN_FILE_PATTERNS = (
    "*.db",
    "*.db-*",
    "*.sqlite",
    "*.sqlite3",
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
)
SKIPPED_DIRECTORIES = frozenset(
    {
        ".git", ".venv", ".venv-py312", ".venv-py313", "venv", "__pycache__",
        ".pytest_cache", ".mypy_cache", ".ruff_cache", "build", "dist",
    }
)  # fmt: skip


def test_gitignore_contains_required_entries() -> None:
    lines = {
        line.strip()
        for line in (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    }
    missing = [entry for entry in REQUIRED_IGNORE_ENTRIES if entry not in lines]
    assert not missing, f".gitignore is missing: {missing}"


def test_gitignore_does_not_hide_source_or_tests() -> None:
    lines = {
        line.strip()
        for line in (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    }
    assert not {"src/", "src", "tests/", "tests", "*.py", "*.toml", "*.md"} & lines


def test_tree_contains_no_secrets_or_generated_data() -> None:
    offenders: list[str] = []
    for directory, subdirectories, files in PROJECT_ROOT.walk():
        subdirectories[:] = [name for name in subdirectories if name not in SKIPPED_DIRECTORIES]
        offenders.extend(
            str((directory / name).relative_to(PROJECT_ROOT))
            for name in files
            if any(fnmatch.fnmatch(name, pattern) for pattern in FORBIDDEN_FILE_PATTERNS)
        )
    assert not offenders, f"forbidden files in the project tree: {offenders}"
