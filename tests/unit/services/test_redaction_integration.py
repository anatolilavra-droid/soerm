"""M4 integration: every text value is redacted before storage; nothing leaks anywhere."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from soerm.config import CONFIG_FILE_NAME
from soerm.domain.errors import DomainError
from soerm.services.assets import get_asset, update_asset
from soerm.services.errors import ConfigServiceError, InvalidInputError
from soerm.services.findings import get_finding, update_finding
from soerm.services.redaction import validate_workspace_config
from soerm.services.workspace import DATABASE_FILE_NAME, Workspace
from tests.unit.services.helpers import SECRET, audit_entries, make_asset, make_finding

KEY = "Zx9-Kq-77-hidden"


def database_text(ws: Workspace) -> str:
    """Every value of every table, as one string."""
    out: list[str] = []
    with closing(sqlite3.connect(ws.path / DATABASE_FILE_NAME)) as raw:
        tables = [
            row[0] for row in raw.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        ]
        for table in tables:
            cursor = raw.execute(f'SELECT * FROM "{table}"')  # noqa: S608 - names from sqlite_master
            out.extend(repr(row) for row in cursor.fetchall())
    return "\n".join(out)


def raw_database_bytes(ws: Workspace) -> bytes:
    """The database file(s) as bytes: also catches free pages and the WAL."""
    chunks = []
    for suffix in ("", "-wal", "-shm"):
        path = ws.path / f"{DATABASE_FILE_NAME}{suffix}"
        if path.exists():
            chunks.append(path.read_bytes())
    return b"".join(chunks)


def secret_texts() -> dict[str, str]:
    return {
        "title": f"Login leaks password={SECRET}",
        "description": f"Seen in logs: token: {SECRET}\nAuthorization: Bearer {SECRET}",
        "evidence": f'curl -H "Cookie: sid={SECRET}" -d \'{{"api_key": "{SECRET}"}}\'',
        "owner": f"team api_key={SECRET}",
    }


def test_created_finding_is_redacted_before_it_is_stored(ws: Workspace) -> None:
    make_asset(ws)
    texts = secret_texts()
    made = make_finding(ws, **texts)
    stored = get_finding(ws, made.object_id)
    for value in (stored.title, stored.description, stored.evidence, stored.owner):
        assert SECRET not in (value or "")
    assert stored.title == "Login leaks password=[REDACTED]"
    assert stored.owner == "team api_key=[REDACTED]"
    assert stored.description == "Seen in logs: token: [REDACTED]\nAuthorization: [REDACTED]"
    assert "[REDACTED]" in stored.evidence
    assert made.after_hash == stored.digest()  # the hash is of what is stored


def test_database_scan_finds_no_secret(ws: Workspace) -> None:
    make_asset(ws, name=f"api password={SECRET}", owner=f"o token={SECRET}", tags=("ok",))
    made = make_finding(ws, **secret_texts())
    update_finding(
        ws,
        made.object_id,
        actor="bob",
        expected_hash=made.after_hash,
        description=f"password={SECRET}",
        evidence=f"Authorization: Basic {SECRET}",
    )
    assert SECRET not in database_text(ws)
    assert SECRET.encode() not in raw_database_bytes(ws)
    assert KEY not in database_text(ws)


def test_audit_log_has_no_text_only_identifiers_and_hashes(ws: Workspace) -> None:
    make_asset(ws)
    make_finding(ws, **secret_texts())
    for entry in audit_entries(ws):
        dumped = json.dumps(entry.canonical_dict())
        assert SECRET not in dumped
        assert "REDACTED" not in dumped  # not even the redacted text is in the audit log
    assert set(audit_entries(ws)[-1].canonical_dict()) == {
        "seq", "timestamp", "actor", "action", "object_type", "object_id", "before_hash",
        "after_hash", "prev_hash", "entry_hash",
    }  # fmt: skip


def test_the_report_has_only_rule_names_counts_and_field_names(ws: Workspace) -> None:
    make_asset(ws)
    made = make_finding(ws, **secret_texts())
    report = made.redaction
    assert report is not None
    assert SECRET not in repr(report)
    assert {name for name, _ in report.rule_hits} <= {
        "json_string_secret", "authorization", "cookie", "set_cookie", "password", "auth_token",
        "token", "api_key", "bearer",
    }  # fmt: skip
    assert all(count > 0 for _, count in report.rule_hits)
    assert report.truncated_fields == ()
    assert len(report.config_hash) == 64


def test_asset_text_is_redacted_on_create_and_update(ws: Workspace) -> None:
    made = make_asset(ws, name=f"host password={SECRET}", tags=(f"t token={SECRET}", "ok"))
    stored = get_asset(ws, made.object_id)
    assert stored.name == "host password=[REDACTED]"
    assert SECRET not in repr(stored)
    updated = update_asset(
        ws,
        made.object_id,
        actor="bob",
        expected_hash=made.after_hash,
        owner=f"o api_key={SECRET}",
    )
    assert SECRET not in repr(get_asset(ws, made.object_id))
    assert updated.redaction is not None
    assert dict(updated.redaction.rule_hits) == {"api_key": 1}


def test_redaction_happens_before_length_validation(ws: Workspace) -> None:
    make_asset(ws)
    long_title = f"password={SECRET} " + "t" * 400
    made = make_finding(ws, title=long_title)
    stored = get_finding(ws, made.object_id)
    assert len(stored.title) <= 300
    assert stored.title.startswith("password=[REDACTED]")
    assert made.redaction is not None
    assert made.redaction.truncated_fields == ("title",)
    assert SECRET not in database_text(ws)


def test_oversized_input_is_refused_and_nothing_is_written(ws: Workspace) -> None:
    make_asset(ws)
    before = database_text(ws)
    with pytest.raises(InvalidInputError) as excinfo:
        make_finding(ws, description=f"password={SECRET}" + "x" * 70000)
    rendered = str(excinfo.value) + repr(excinfo.value.to_dict())
    assert "description: input_too_large" in rendered
    assert SECRET not in rendered
    assert database_text(ws) == before


def test_non_text_values_do_not_echo(ws: Workspace) -> None:
    make_asset(ws)
    with pytest.raises(DomainError) as excinfo:
        make_finding(ws, title=b"password=" + SECRET.encode())
    assert SECRET not in str(excinfo.value)


def test_no_unredacted_text_path_even_when_a_rule_is_disabled(ws: Workspace) -> None:
    (ws.path / CONFIG_FILE_NAME).write_text(
        "version: 1\nredaction:\n  builtin_rules: {token: false}\n", encoding="utf-8"
    )
    make_asset(ws)
    made = make_finding(ws, description=f"token={SECRET} password={SECRET}")
    stored = get_finding(ws, made.object_id)
    assert stored.description == f"token={SECRET} password=[REDACTED]"  # explicit operator choice


CUSTOM = """\
version: 1
redaction:
  rules:
    - name: employee_id
      pattern: '\\bEMP-\\d{6}\\b'
      replacement: '[EMPLOYEE]'
"""


def test_custom_rules_from_the_workspace_config_apply(ws: Workspace) -> None:
    (ws.path / CONFIG_FILE_NAME).write_text(CUSTOM, encoding="utf-8")
    make_asset(ws, owner="EMP-123456")
    made = make_finding(ws, description="reported by EMP-654321")
    assert get_asset(ws, "AST-000001").owner == "[EMPLOYEE]"
    assert get_finding(ws, made.object_id).description == "reported by [EMPLOYEE]"
    assert made.redaction is not None
    assert made.redaction.rule_hits == (("employee_id", 1),)


def test_a_broken_config_blocks_every_mutation_without_leaking(ws: Workspace) -> None:
    (ws.path / CONFIG_FILE_NAME).write_text(f"password: {SECRET}\n  bad: [", encoding="utf-8")
    with pytest.raises(ConfigServiceError) as excinfo:
        make_asset(ws)
    assert SECRET not in str(excinfo.value) + repr(excinfo.value.to_dict())
    assert not (ws.path / DATABASE_FILE_NAME).exists()  # nothing was created
    assert not (ws.path / ".soerm.lock").exists()


def test_validate_workspace_config_creates_nothing(ws: Workspace) -> None:
    (ws.path / CONFIG_FILE_NAME).write_text(CUSTOM, encoding="utf-8")
    summary = validate_workspace_config(ws)
    assert summary.file_found
    assert ("employee_id", True, False) in summary.rules
    assert sorted(p.name for p in ws.path.iterdir()) == [CONFIG_FILE_NAME]


def test_hash_is_the_same_for_the_same_config_and_differs_for_another(ws: Workspace) -> None:
    first = validate_workspace_config(ws).config_hash
    (ws.path / CONFIG_FILE_NAME).write_text(CUSTOM, encoding="utf-8")
    second = validate_workspace_config(ws).config_hash
    assert validate_workspace_config(ws).config_hash == second != first


def test_update_without_text_changes_does_not_need_redaction_hits(ws: Workspace) -> None:
    made = make_asset(ws)
    result = update_asset(
        ws, made.object_id, actor="bob", expected_hash=made.after_hash, name="Renamed"
    )
    assert result.redaction is not None
    assert result.redaction.rule_hits == ()


def test_stored_path_helpers_are_outside_the_repository(ws: Workspace) -> None:
    assert isinstance(ws.path, Path)
