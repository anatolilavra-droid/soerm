# Repository guide

SOERM (Security Operations Evidence & Response Manager) is a private, offline-first findings
management tool: assets, findings, incidents, tasks, approvals, playbooks and reports in one
local SQLite workspace. Product direction and stages: `ROADMAP.md`. Feature history and
security model: `README.md`.

## Authorship

- The sole author and owner of this project is otanatoliy.
- Commit messages, PR titles and descriptions, CHANGELOG, README, release notes and
  documentation contain no co-author trailers, session links or tool attribution.
- Never change the Git identity, commit, push or open a pull request without the owner's
  explicit approval.
- Before every commit show: `git config user.name`, `git config user.email`, the full commit
  message, and a check that it has no co-author trailer and no tool attribution.

## Principles (do not change without an explicit decision)

- Local-first and offline: no network access in the application or the tests; external data
  (feeds, keys) comes only from local files.
- SQLite, one workspace directory per workspace; CLI for changes, TUI read-only.
- Fail closed; redaction before anything is persisted; append-only audit with a hash chain;
  deterministic reports; approvals for risk-acceptance decisions.
- Out of scope: PostgreSQL, web or API server, authentication/RBAC, cloud mode,
  multi-tenancy, network integrations.

## Layers

```
cli -> services -> domain, storage, importers, outputs, config
tui -> services, domain            (read-only; no storage, sqlite3, subprocess or network)
```

- `domain`: Pydantic models and pure functions, no I/O.
- `storage`: the only package that uses `sqlite3`; parameterized literal SQL only.
- File I/O lives only in `importers/safe_file.py` (reads), `outputs/safe_write.py` (report
  writes), `config/loader.py` (`soerm.yaml`) and `storage/` (database and lock).
- The rules are enforced by `tests/unit/test_layering.py`, `tests/unit/test_static_policy.py`,
  `tests/unit/tui/test_tui_policy.py` and ruff `TID251` (banned network, process, dynamic
  import and unsafe deserialization APIs).

## Environment and checks

Python 3.12 and 3.13, POSIX only, managed with uv.

```bash
UV_PROJECT_ENVIRONMENT=.venv-py312 uv sync --frozen --python python3.12 --no-python-downloads
UV_PROJECT_ENVIRONMENT=.venv-py313 uv sync --frozen --python python3.13 --no-python-downloads
```

For each environment:

```bash
.venv-py312/bin/python -m pytest
.venv-py312/bin/python -m ruff check .
.venv-py312/bin/python -m ruff format --check .
.venv-py312/bin/python -m mypy
```

For 3.13 also run `mypy --python-version 3.13`. Release checks (`uv lock --check`, wheel
build, `scripts/release_tools.py check-wheel` and `sbom`) are described in `README.md`.

## Conventions

- Migrations are append-only: never edit an applied migration; add a new numbered one.
- Errors carry stable reason codes, never user values or paths.
- Mutating commands require `--actor`, take the workspace lock and write an audit entry in
  the same transaction as the change.
- Tests never write databases into the repository (use `tmp_path`).
- Never commit `*.db*`, `.soerm.lock`, virtual environments, caches or real secrets.
- After each stage run every check above on both Python versions, then stop until the owner
  confirms the next step.
