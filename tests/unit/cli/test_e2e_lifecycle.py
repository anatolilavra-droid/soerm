"""End-to-end: the whole product lifecycle through the CLI only (M11).

create workspace -> asset -> redaction config -> import (SARIF, JSON, CSV) -> dedup -> risk/SLA
-> task -> incident -> playbook -> gated step -> checklist -> report -> audit verification.
"""

import json
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from soerm.services.workspace import DATABASE_FILE_NAME
from soerm.storage.lock import LOCK_FILE_NAME
from tests.unit.cli.conftest import Result, Runner, assert_terminal_safe
from tests.unit.storage.conftest import PROJECT_ROOT

SAMPLE = PROJECT_ROOT / "examples" / "sample_workspace"
SECRET = "hunter2-TOP-SECRET-token"
AT = "2026-11-01T00:00:00Z"
EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_INTEGRITY, EXIT_APPROVAL = 0, 1, 2, 3, 4


class Lifecycle:
    """Runs commands against one workspace and checks every output for control characters."""

    def __init__(self, cli: Runner, path: Path) -> None:
        self.cli = cli
        self.path = path
        self.outputs: list[str] = []

    def __call__(
        self, *argv: str, actor: str | None = "alice", code: int | None = EXIT_OK
    ) -> Result:
        extra = ["--actor", actor] if actor else []
        result = self.cli(*argv, "--workspace", str(self.path), *extra)
        self.outputs += [result.out, result.err]
        assert_terminal_safe(result.out)
        assert_terminal_safe(result.err)
        if code is not None:
            assert result.code == code, f"{argv}: {result.code}\n{result.err}"
        return result

    def read(self, *argv: str, code: int | None = EXIT_OK) -> Result:
        return self(*argv, actor=None, code=code)

    def data(self, *argv: str) -> object:
        return self.read(*argv, "--json").json()

    def hash_of(self, kind: str, object_id: str) -> str:
        value = self.data(kind, "show", object_id)["hash"]  # type: ignore[index]
        assert isinstance(value, str)
        return value


@pytest.fixture
def sample(tmp_path: Path) -> Path:
    target = tmp_path / "sample"
    shutil.copytree(SAMPLE, target)
    return target


@pytest.fixture
def life(cli: Runner, sample: Path) -> Lifecycle:
    return Lifecycle(cli, sample)


def import_all(life: Lifecycle) -> None:
    common = ("--asset-id", "AST-000001")
    life("import", "run", "--format", "sarif", *common, "scan.sarif")
    life("import", "run", "--format", "json", "--mapping", "json-mapping.yaml", *common,
         "findings.json")  # fmt: skip
    life("import", "run", "--format", "csv", "--mapping", "csv-mapping.yaml", *common,
         "findings.csv")  # fmt: skip


def seed(life: Lifecycle) -> None:
    life.read("config", "validate")
    life("asset", "add", "--name", "Billing API", "--owner", "platform", "--environment",
         "production", "--criticality", "high", "--classification", "confidential",
         "--exposure", "internet")  # fmt: skip
    import_all(life)
    life("risk", "recalculate", "--all")


def db_text(path: Path) -> str:
    """Every row of every table plus the raw bytes of the database files, as text."""
    parts: list[str] = []
    with closing(sqlite3.connect(path / DATABASE_FILE_NAME)) as raw:
        names = [r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        parts += [repr(raw.execute(f"SELECT * FROM {n}").fetchall()) for n in names]  # noqa: S608
    for item in path.glob(f"{DATABASE_FILE_NAME}*"):
        parts.append(item.read_bytes().decode("latin-1"))
    return "\n".join(parts)


def snapshot(path: Path) -> list[tuple[str, str]]:
    with closing(sqlite3.connect(path / DATABASE_FILE_NAME)) as raw:
        names = sorted(
            r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type='table'")
        )
        return [(n, repr(raw.execute(f"SELECT * FROM {n}").fetchall())) for n in names]  # noqa: S608


def test_sample_files_exist_and_are_safe() -> None:
    names = {p.name for p in SAMPLE.iterdir()}
    assert {"soerm.yaml", "scan.sarif", "findings.json", "findings.csv"} <= names
    assert not any(n.startswith(DATABASE_FILE_NAME) or n == LOCK_FILE_NAME for n in names)


def test_full_lifecycle(life: Lifecycle) -> None:
    # 1-3. workspace, asset, redaction config
    assert "configuration valid" in life.read("config", "validate").out
    life("asset", "add", "--name", "Billing API", "--owner", "platform", "--environment",
         "production", "--criticality", "high", "--classification", "confidential",
         "--exposure", "internet")  # fmt: skip

    # 4-5. preview then import of all three formats
    preview = life.read("import", "preview", "--format", "sarif", "scan.sarif")
    assert "preview only" in preview.out
    assert life.read("finding", "list", code=None).code in (EXIT_OK, EXIT_ERROR)
    import_all(life)
    findings = life.data("finding", "list")["findings"]  # type: ignore[index]
    assert len(findings) == 6

    # 6. dedup: the same files again change nothing
    audit_before = life.data("audit", "verify")
    again = life("import", "run", "--format", "sarif", "--asset-id", "AST-000001", "scan.sarif")
    assert "unchanged" in again.out
    assert life.data("audit", "verify") == audit_before

    # 7. risk and SLA
    first = life("risk", "recalculate", "--all", "--json").json()
    assert first["changed"] == 6
    head = life.data("audit", "verify")
    second = life("risk", "recalculate", "--all", "--json").json()
    assert second["changed"] == 0
    assert life.data("audit", "verify") == head  # nothing written

    # 8-9. task and incident
    life("task", "create", "--title", "Fix SQLi", "--owner", "dev", "--finding-id", "FND-000001")
    life("incident", "create", "--title", "Phish campaign", "--severity", "high", "--owner", "ir")

    # 10. playbook
    life("playbook", "load", "phishing-playbook.yaml")
    life("incident", "playbook", "attach", "INC-000001", "phishing-triage")
    life("incident", "playbook", "step", "INC-000001", "step-001")

    # 11. gated step: needs approval, request, approval by someone else, then it is allowed
    blocked = life("incident", "playbook", "step", "INC-000001", "step-004", code=EXIT_APPROVAL)
    assert "step_requires_approval" in blocked.err
    life("incident", "playbook", "request-approval", "INC-000001", "step-004", "--reason", "block")
    self_approve = life("approval", "approve", "CHG-000001", code=EXIT_ERROR)
    assert "self_approval" in self_approve.err
    life("approval", "approve", "CHG-000001", actor="bob")
    life("incident", "playbook", "step", "INC-000001", "step-004", "--change-id", "CHG-000001")

    # 12. checklist
    life("incident", "playbook", "step", "INC-000001", "step-002")
    life("incident", "playbook", "step", "INC-000001", "step-003")
    status = life.read("incident", "playbook", "status", "INC-000001").out
    assert "4/4" in status
    assert "ready_for_closure_review: yes" in status
    assert life.data("incident", "show", "INC-000001")["status"] == "new"  # type: ignore[index]

    # 13. report (both formats) and audit verification
    life.read("report", "generate", "--output", "report.md", "--generated-at", AT)
    life.read("report", "generate", "--output", "report.json", "--format", "json",
              "--generated-at", AT)  # fmt: skip
    report = json.loads((life.path / "report.json").read_text(encoding="utf-8"))
    assert report["executive_summary"]["active_findings"] == 6
    assert report["executive_summary"]["open_incidents"] == 1
    assert report["playbooks"]["completed_steps"] == 4
    assert report["audit"]["status"] == "intact"
    verified = life.data("audit", "verify")
    assert verified["status"] == "intact"  # type: ignore[index]
    assert verified["head_hash"] == report["audit"]["head_hash"]  # type: ignore[index]
    text = (life.path / "report.md").read_text(encoding="utf-8")
    assert "soerm-report-v1" in text

    # nothing secret anywhere
    for blob in (*life.outputs, db_text(life.path), text, json.dumps(report)):
        assert SECRET not in blob
    assert "EMP-004711" not in db_text(life.path)


def test_reimport_creates_no_new_findings(life: Lifecycle) -> None:
    seed(life)
    before = len(life.data("finding", "list")["findings"])  # type: ignore[index]
    head = life.data("audit", "verify")
    import_all(life)
    assert len(life.data("finding", "list")["findings"]) == before  # type: ignore[index]
    assert life.data("audit", "verify") == head


def test_risk_recalculate_twice_writes_nothing(life: Lifecycle) -> None:
    seed(life)
    before = snapshot(life.path)
    result = life("risk", "recalculate", "--all", "--json").json()
    assert result["changed"] == 0
    assert snapshot(life.path) == before


def test_closed_incident_accepts_no_steps(life: Lifecycle) -> None:
    life("playbook", "load", "phishing-playbook.yaml")
    life("incident", "create", "--title", "Phish", "--severity", "high", "--owner", "ir")
    life("incident", "playbook", "attach", "INC-000001", "phishing-triage")
    for target in ("triaged", "investigating", "contained", "remediated"):
        life("incident", "transition", "INC-000001", "--status", target,
             "--expect-hash", life.hash_of("incident", "INC-000001"))  # fmt: skip
    life("incident", "transition", "INC-000001", "--status", "closed", "--reason", "done",
         "--expect-hash", life.hash_of("incident", "INC-000001"))  # fmt: skip
    refused = life("incident", "playbook", "step", "INC-000001", "step-001", code=EXIT_ERROR)
    assert "incident_closed" in refused.err
    status = life.data("incident", "playbook", "status", "INC-000001")
    assert not any(step["done"] for step in status["steps"])  # type: ignore[index]


def test_finding_approval_is_single_use_and_goes_stale(life: Lifecycle) -> None:
    seed(life)
    reason = ("--reason", "accepted by the owner")
    life("approval", "request", "FND-000001", "--status", "accepted_risk", *reason)
    life("approval", "approve", "CHG-000001", actor="bob")
    apply_args = (
        "finding", "update", "FND-000001", "--status", "accepted_risk", "--change-id", "CHG-000001"
    )  # fmt: skip
    life(*apply_args, "--expect-hash", life.hash_of("finding", "FND-000001"))
    twice = life(*apply_args, "--expect-hash", life.hash_of("finding", "FND-000001"),
                 code=EXIT_ERROR)  # fmt: skip
    assert "approval" in twice.err

    # a second approval becomes stale when the finding changes after the decision
    life("approval", "request", "FND-000002", "--status", "false_positive", *reason)
    life("approval", "approve", "CHG-000002", actor="bob")
    life("finding", "update", "FND-000002", "--title", "Changed after approval",
         "--expect-hash", life.hash_of("finding", "FND-000002"))  # fmt: skip
    stale_hash = life.hash_of("finding", "FND-000002")
    stale = life(
        "finding", "update", "FND-000002", "--status", "false_positive",
        "--change-id", "CHG-000002", "--expect-hash", stale_hash, code=EXIT_ERROR,
    )  # fmt: skip
    assert "stale" in stale.err
    assert life.data("finding", "show", "FND-000002")["status"] == "open"  # type: ignore[index]


def test_report_does_not_change_domain_objects(life: Lifecycle) -> None:
    seed(life)
    before = snapshot(life.path)
    life.read("report", "preview", "--generated-at", AT)
    life("report", "generate", "--output", "r.md", "--generated-at", AT, actor=None)
    assert snapshot(life.path) == before


def test_report_reflects_later_changes(life: Lifecycle) -> None:
    seed(life)
    life.read("report", "generate", "--output", "before.json", "--format", "json",
              "--generated-at", AT)  # fmt: skip
    life("incident", "create", "--title", "New", "--severity", "low", "--owner", "ir")
    life.read("report", "generate", "--output", "after.json", "--format", "json",
              "--generated-at", AT)  # fmt: skip
    before = json.loads((life.path / "before.json").read_text(encoding="utf-8"))
    after = json.loads((life.path / "after.json").read_text(encoding="utf-8"))
    assert after["incidents"]["total"] == before["incidents"]["total"] + 1
    assert after["audit"]["entries"] > before["audit"]["entries"]
    assert after["audit"]["head_hash"] != before["audit"]["head_hash"]


def test_secrets_never_reach_sqlite_audit_or_reports(life: Lifecycle) -> None:
    seed(life)
    life("incident", "create", "--title", f"leak password={SECRET}", "--severity", "low",
         "--owner", "ir", "--summary", f"token: {SECRET}")  # fmt: skip
    life.read("report", "generate", "--output", "r.md", "--generated-at", AT)
    life.read("report", "generate", "--output", "r.json", "--format", "json", "--generated-at", AT)
    with closing(sqlite3.connect(life.path / DATABASE_FILE_NAME)) as raw:
        audit = repr(raw.execute("SELECT * FROM audit_log").fetchall())
    assert SECRET not in audit
    assert SECRET not in db_text(life.path)
    for name in ("r.md", "r.json"):
        assert SECRET not in (life.path / name).read_text(encoding="utf-8")
    assert all(SECRET not in out for out in life.outputs)
    shown = life.read("incident", "show", "INC-000001", "--json").out
    assert SECRET not in shown


def test_preview_commands_create_no_database_or_lock(life: Lifecycle) -> None:
    before = sorted(p.name for p in life.path.iterdir())
    life.read("config", "validate")
    life.read("import", "preview", "--format", "sarif", "scan.sarif")
    life.read("import", "preview", "--format", "json", "--mapping", "json-mapping.yaml",
              "findings.json")  # fmt: skip
    life.read("import", "preview", "--format", "csv", "--mapping", "csv-mapping.yaml",
              "findings.csv")  # fmt: skip
    for command in (("report", "preview"), ("audit", "verify"), ("finding", "list"),
                    ("risk", "preview", "--all")):  # fmt: skip
        life.read(*command, code=EXIT_ERROR)
    assert sorted(p.name for p in life.path.iterdir()) == before


def test_every_write_needs_the_workspace_lock(life: Lifecycle) -> None:
    from soerm import __version__
    from soerm.storage.lock import WorkspaceLock

    seed(life)
    before = snapshot(life.path)
    with WorkspaceLock(life.path, app_version=__version__):
        for argv in (
            ("asset", "add", "--name", "X", "--owner", "o", "--environment", "production",
             "--criticality", "low", "--classification", "public", "--exposure", "internal"),
            ("task", "create", "--title", "t", "--owner", "o"),
            ("incident", "create", "--title", "t", "--severity", "low", "--owner", "o"),
            ("risk", "recalculate", "--all"),
            ("playbook", "load", "phishing-playbook.yaml"),
            ("import", "run", "--format", "sarif", "--asset-id", "AST-000001", "scan.sarif"),
        ):  # fmt: skip
            result = life(*argv, code=None)
            assert result.code != EXIT_OK, argv
    assert snapshot(life.path) == before


def test_broken_audit_chain_is_visible_everywhere(life: Lifecycle) -> None:
    seed(life)
    with closing(sqlite3.connect(life.path / DATABASE_FILE_NAME, isolation_level=None)) as raw:
        triggers = [
            r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type='trigger'")
        ]
        for name in triggers:
            if "audit" in name:
                raw.execute(f"DROP TRIGGER IF EXISTS {name}")
        raw.execute("UPDATE audit_log SET entry_hash = ? WHERE seq = 2", ("e" * 64,))
    verify = life.read("audit", "verify", code=EXIT_INTEGRITY)
    assert "broken" in verify.out
    assert life.read("audit", "verify", "--json", code=EXIT_INTEGRITY).json()["broken_at_seq"]
    report = life.read("report", "generate", "--output", "r.json", "--format", "json",
                       "--generated-at", AT, code=EXIT_INTEGRITY)  # fmt: skip
    assert "broken" in report.out
    assert json.loads((life.path / "r.json").read_text(encoding="utf-8"))["audit"]["status"] == (
        "broken"
    )
    assert "broken" in life.read("report", "preview", code=EXIT_INTEGRITY).out.lower()


def test_empty_workspace_smoke(cli: Runner, tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    life = Lifecycle(cli, empty)
    for command in (("report", "preview"), ("audit", "verify"), ("finding", "list"),
                    ("incident", "list"), ("task", "list"), ("playbook", "list")):  # fmt: skip
        life.read(*command, code=EXIT_ERROR)
    assert list(empty.iterdir()) == []
    life("asset", "add", "--name", "A", "--owner", "o", "--environment", "production",
         "--criticality", "low", "--classification", "public",
         "--exposure", "internal")  # fmt: skip
    fresh = life.data("audit", "verify")
    assert fresh["status"] == "intact"  # type: ignore[index]
    report = life.read("report", "preview", "--format", "json", "--generated-at", AT).json()
    assert report["findings"]["total"] == 0
    assert report["assets"]["total"] == 1


def test_stable_exit_codes(life: Lifecycle) -> None:
    seed(life)
    assert life.read("finding", "show", "FND-999999", code=None).code == EXIT_ERROR
    assert life.cli("finding", "show").code == EXIT_USAGE
    assert life.cli("nonsense").code == EXIT_USAGE
    assert life.cli("report", "generate", "--workspace", str(life.path), "--output", "x.md",
                    "--force").code == EXIT_USAGE  # fmt: skip
    assert life.cli("audit", "verify").code == EXIT_USAGE
    assert life.cli("--version").code == EXIT_OK


def test_audit_verify_service_is_read_only(life: Lifecycle) -> None:
    seed(life)
    before = snapshot(life.path)
    life.read("audit", "verify")
    assert snapshot(life.path) == before
