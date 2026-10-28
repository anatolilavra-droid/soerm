"""``playbook`` and ``incident playbook`` commands: flows, exit codes, safe output."""

from pathlib import Path

import pytest

from tests.unit.cli.conftest import Runner, assert_terminal_safe
from tests.unit.importers.helpers import put
from tests.unit.services.test_playbook_service import PLAYBOOK

SECRET = "hunter2-TOP-SECRET-token"


def w(path: Path) -> list[str]:
    return ["--workspace", str(path)]


def m(path: Path, actor: str = "alice") -> list[str]:
    return [*w(path), "--actor", actor]


@pytest.fixture
def ws(cli: Runner, workspace: Path) -> Path:
    put(workspace, "pb.yaml", PLAYBOOK)
    assert cli("playbook", "load", "pb.yaml", *m(workspace)).code == 0
    out = cli("incident", "create", *m(workspace), "--title", "Phish", "--severity", "high",
              "--owner", "ir")  # fmt: skip
    assert out.code == 0, out.err
    return workspace


def test_mutations_need_actor_and_workspace(cli: Runner, ws: Path) -> None:
    assert cli("playbook", "load", "pb.yaml", *w(ws)).code == 2
    assert cli("incident", "playbook", "attach", "INC-000001", "phishing-triage", *w(ws)).code == 2
    assert cli("incident", "playbook", "step", "INC-000001", "step-001", *w(ws)).code == 2
    assert cli("incident", "playbook", "status", "INC-000001").code == 2


def test_list_and_show(cli: Runner, ws: Path) -> None:
    listing = cli("playbook", "list", *w(ws))
    assert listing.code == 0
    assert "phishing-triage" in listing.out
    assert cli("playbook", "list", *w(ws), "--incident-type", "malware", "--json").json() == {
        "playbooks": []
    }
    shown = cli("playbook", "show", "phishing-triage", *w(ws))
    assert shown.code == 0
    for text in ("step-004", "required", "Credentials were entered", "Mailbox cleaned"):
        assert text in shown.out
    data = cli("playbook", "show", "phishing-triage", *w(ws), "--json").json()
    assert data["versions"][0]["version"] == "1.0"
    assert cli("playbook", "show", "nope-nope", *w(ws)).code == 1
    assert_terminal_safe(shown.out)


def test_load_is_idempotent_and_versions_are_immutable(cli: Runner, ws: Path) -> None:
    again = cli("playbook", "load", "pb.yaml", *m(ws), "--json")
    assert again.code == 0
    assert again.json()["result"] == "unchanged"
    put(ws, "pb.yaml", PLAYBOOK.replace("Confirm the report", "Confirm"))
    changed = cli("playbook", "load", "pb.yaml", *m(ws))
    assert changed.code == 1
    assert "playbook_version_immutable" in changed.err


def test_read_commands_create_nothing(cli: Runner, tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert cli("playbook", "list", *w(empty)).code != 0
    assert cli("incident", "playbook", "status", "INC-000001", *w(empty)).code != 0
    assert list(empty.iterdir()) == []


def test_flow_with_case_insensitive_ids(cli: Runner, ws: Path) -> None:
    attach = cli("incident", "playbook", "attach", "INC-000001", "PHISHING-TRIAGE", *m(ws))
    assert attach.code == 0, attach.err
    again = cli("incident", "playbook", "attach", "INC-000001", "phishing-triage", *m(ws), "--json")
    assert again.json()["result"] == "unchanged"
    first = cli("incident", "playbook", "step", "INC-000001", "STEP-001", *m(ws), "--json")
    assert first.code == 0
    assert first.json()["result"] == "completed"
    repeat = cli("incident", "playbook", "step", "INC-000001", "step-001", *m(ws, "bob"), "--json")
    assert repeat.json()["result"] == "already_completed"
    assert repeat.json()["completed_by"] == "alice"
    status = cli("incident", "playbook", "status", "INC-000001", *w(ws), "--json").json()
    assert (status["completed"], status["total"], status["next_step"]) == (1, 4, "step-002")
    assert status["ready_for_closure_review"] is False
    table = cli("incident", "playbook", "status", "INC-000001", *w(ws))
    assert "1/4" in table.out
    assert "never closed automatically" in table.out
    assert_terminal_safe(table.out)
    shown = cli("incident", "show", "INC-000001", *w(ws), "--json").json()
    assert shown["playbook_id"] == "phishing-triage"
    assert shown["status"] == "new"


def test_gated_step_exit_code_and_approval_flow(cli: Runner, ws: Path) -> None:
    assert cli("incident", "playbook", "attach", "INC-000001", "phishing-triage", *m(ws)).code == 0
    blocked = cli("incident", "playbook", "step", "INC-000001", "step-004", *m(ws))
    assert blocked.code == 4
    assert "step_requires_approval" in blocked.err
    req = cli("incident", "playbook", "request-approval", "INC-000001", "step-004", *m(ws),
              "--reason", f"token={SECRET} needed", "--json")  # fmt: skip
    assert req.code == 0, req.err
    assert SECRET not in req.out
    change = req.json()["object_id"]
    assert cli("approval", "approve", change, *m(ws, "alice")).code == 1  # self-approval
    assert cli("approval", "approve", change, *m(ws, "bob")).code == 0
    done = cli("incident", "playbook", "step", "INC-000001", "step-004", *m(ws, "carol"),
               "--change-id", change, "--json")  # fmt: skip
    assert done.code == 0, done.err
    assert done.json()["change_id"] == change
    replay = cli("approval", "show", change, *w(ws), "--json").json()
    assert replay["applied"] is True


def test_errors_do_not_echo_input(cli: Runner, ws: Path) -> None:
    for argv in (
        ("incident", "playbook", "attach", "INC-000001", f"x{SECRET}", *m(ws)),
        ("incident", "playbook", "step", "INC-000001", f"x{SECRET}", *m(ws)),
        ("playbook", "show", f"x{SECRET}", *w(ws)),
        ("playbook", "load", f"../{SECRET}.yaml", *m(ws)),
    ):
        out = cli(*argv)
        assert out.code == 1
        assert SECRET not in out.err
        assert SECRET not in out.out


def test_step_requires_attachment(cli: Runner, ws: Path) -> None:
    out = cli("incident", "playbook", "step", "INC-000001", "step-001", *m(ws))
    assert out.code == 1
    assert "no_playbook_attached" in out.err
