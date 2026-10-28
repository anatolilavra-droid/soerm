"""``incident``, ``task`` and ``approval`` commands: flows, exit codes, no hidden values."""

from pathlib import Path

import pytest

from tests.unit.cli.conftest import (
    Runner,
    add_asset,
    add_finding,
    assert_terminal_safe,
    current_hash,
)

SECRET = "hunter2-TOP-SECRET-token"


@pytest.fixture
def ws(cli: Runner, workspace: Path) -> Path:
    assert add_asset(cli, workspace).code == 0
    assert add_finding(cli, workspace).code == 0
    return workspace


def w(path: Path) -> list[str]:
    return ["--workspace", str(path)]


def m(path: Path, actor: str = "alice") -> list[str]:
    return [*w(path), "--actor", actor]


def new_incident(cli: Runner, ws: Path) -> str:
    out = cli("incident", "create", *m(ws), "--title", "Breach", "--severity", "high",
              "--owner", "ir", "--json")  # fmt: skip
    assert out.code == 0, out.err
    return str(out.json()["object_id"])


def test_mutations_require_actor_and_workspace(cli: Runner, ws: Path) -> None:
    assert cli("incident", "create", *w(ws), "--title", "t", "--severity", "low",
               "--owner", "o").code == 2  # fmt: skip
    assert cli("task", "create", "--title", "t", "--owner", "o").code == 2
    assert cli("approval", "approve", *w(ws), "CHG-000001").code == 2


def test_update_and_transition_require_expect_hash(cli: Runner, ws: Path) -> None:
    iid = new_incident(cli, ws)
    assert cli("incident", "update", iid, *m(ws), "--title", "x").code == 2
    assert cli("incident", "transition", iid, *m(ws), "--status", "triaged").code == 2


def test_read_commands_do_not_create_files(cli: Runner, tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    for argv in (("incident", "list"), ("task", "list"), ("approval", "list")):
        out = cli(*argv, *w(empty))
        assert out.code != 0
    assert list(empty.iterdir()) == []


def test_incident_lifecycle(cli: Runner, ws: Path) -> None:
    iid = new_incident(cli, ws)
    for target in ("triaged", "investigating", "contained", "remediated"):
        h = current_hash(cli, ws, "incident", iid)
        out = cli("incident", "transition", iid, *m(ws), "--expect-hash", h, "--status", target)
        assert out.code == 0, out.err
    h = current_hash(cli, ws, "incident", iid)
    no_reason = cli("incident", "transition", iid, *m(ws), "--expect-hash", h, "--status", "closed")
    assert no_reason.code == 1
    assert "reason" in no_reason.err
    closed = cli("incident", "transition", iid, *m(ws), "--expect-hash", h, "--status", "closed",
                 "--reason", "contained and verified")  # fmt: skip
    assert closed.code == 0, closed.err
    h = current_hash(cli, ws, "incident", iid)
    plain = cli("incident", "transition", iid, *m(ws), "--expect-hash", h,
                "--status", "investigating", "--reason", "again")  # fmt: skip
    assert plain.code == 1
    reopened = cli("incident", "transition", iid, *m(ws), "--expect-hash", h,
                   "--status", "investigating", "--reason", "again", "--reopen")  # fmt: skip
    assert reopened.code == 0, reopened.err
    shown = cli("incident", "show", iid, *w(ws), "--json").json()
    assert shown["status"] == "investigating"
    assert shown["closed_at"] is None


def test_stale_hash_is_a_conflict(cli: Runner, ws: Path) -> None:
    iid = new_incident(cli, ws)
    out = cli("incident", "update", iid, *m(ws), "--expect-hash", "0" * 64, "--title", "x")
    assert out.code == 1
    assert "conflict" in out.err


def test_note_link_timeline_and_redaction(cli: Runner, ws: Path) -> None:
    iid = new_incident(cli, ws)
    assert cli("incident", "link", iid, *m(ws), "--finding-id", "FND-000001").code == 0
    again = cli("incident", "link", iid, *m(ws), "--finding-id", "FND-000001")
    assert again.code == 1
    assert "already_linked" in again.err
    note = cli("incident", "note", iid, *m(ws), "--text", f"password={SECRET} seen")
    assert note.code == 0, note.err
    assert SECRET not in note.out
    assert SECRET not in note.err
    table = cli("incident", "timeline", iid, *w(ws))
    assert table.code == 0
    assert SECRET not in table.out
    assert "finding_linked" in table.out
    assert "seen" in table.out
    assert_terminal_safe(table.out)
    shown = cli("incident", "show", iid, *w(ws), "--json").json()
    assert shown["findings"] == ["FND-000001"]
    assert cli("incident", "list", *w(ws), "--status", "new", "--json").json()["incidents"]


def test_task_flow(cli: Runner, ws: Path) -> None:
    out = cli("task", "create", *m(ws), "--title", "Patch", "--owner", "ops",
              "--finding-id", "FND-000001", "--json")  # fmt: skip
    assert out.code == 0, out.err
    tid = out.json()["object_id"]
    assert cli("task", "create", *m(ws), "--title", "x", "--owner", "o").code == 1  # no parent
    for target in ("in_progress", "done"):
        h = current_hash(cli, ws, "task", tid)
        res = cli("task", "transition", tid, *m(ws), "--expect-hash", h, "--status", target)
        assert res.code == 0, res.err
    shown = cli("task", "show", tid, *w(ws), "--json").json()
    assert shown["status"] == "done"
    assert shown["completed_at"] is not None
    assert cli("task", "list", *w(ws), "--status", "done").code == 0


def test_task_cancel_and_reinstate(cli: Runner, ws: Path) -> None:
    tid = cli("task", "create", *m(ws), "--title", "T", "--owner", "o",
              "--finding-id", "FND-000001", "--json").json()["object_id"]  # fmt: skip
    h = current_hash(cli, ws, "task", tid)
    assert cli("task", "transition", tid, *m(ws), "--expect-hash", h,
               "--status", "cancelled").code == 0  # fmt: skip
    h = current_hash(cli, ws, "task", tid)
    bad = cli("task", "transition", tid, *m(ws), "--expect-hash", h, "--status", "done")
    assert bad.code == 1
    assert "cancelled_cannot_be_done" in bad.err
    ok = cli("task", "transition", tid, *m(ws), "--expect-hash", h, "--status", "open",
             "--reinstate")  # fmt: skip
    assert ok.code == 0, ok.err


def test_approval_flow_end_to_end(cli: Runner, ws: Path) -> None:
    h = current_hash(cli, ws, "finding", "FND-000001")
    direct = cli("finding", "update", "FND-000001", *m(ws), "--expect-hash", h,
                 "--status", "accepted_risk")  # fmt: skip
    assert direct.code == 4
    req = cli("approval", "request", "FND-000001", *m(ws), "--status", "accepted_risk",
              "--reason", f"token={SECRET} rotated", "--json")  # fmt: skip
    assert req.code == 0, req.err
    assert SECRET not in req.out
    cid = req.json()["object_id"]
    self_ok = cli("approval", "approve", cid, *m(ws, "alice"))
    assert self_ok.code == 1
    assert "self_approval" in self_ok.err
    assert cli("approval", "approve", cid, *m(ws, "bob")).code == 0
    again = cli("approval", "reject", cid, *m(ws, "carol"))
    assert again.code == 1
    shown = cli("approval", "show", cid, *w(ws), "--json").json()
    assert shown["status"] == "approved"
    assert shown["applied"] is False
    assert SECRET not in cli("approval", "show", cid, *w(ws)).out
    applied = cli("finding", "update", "FND-000001", *m(ws, "carol"), "--expect-hash", h,
                  "--status", "accepted_risk", "--change-id", cid)  # fmt: skip
    assert applied.code == 0, applied.err
    replay = cli("finding", "update", "FND-000001", *m(ws, "carol"), "--expect-hash",
                 current_hash(cli, ws, "finding", "FND-000001"), "--status", "accepted_risk",
                 "--change-id", cid)  # fmt: skip
    assert replay.code == 1
    listing = cli("approval", "list", *w(ws), "--status", "approved")
    assert listing.code == 0
    assert cid in listing.out
    assert "yes" in listing.out


def test_approval_expire_command(cli: Runner, ws: Path) -> None:
    out = cli("approval", "expire", *m(ws), "--json")
    assert out.code == 0
    assert out.json()["expired"] == []


def test_invalid_ids_do_not_echo_input(cli: Runner, ws: Path) -> None:
    for argv in (
        ("incident", "show", f"INC-{SECRET}"),
        ("task", "show", f"TSK-{SECRET}"),
        ("approval", "show", f"CHG-{SECRET}"),
    ):
        out = cli(*argv, *w(ws))
        assert out.code == 1
        assert SECRET not in out.err
        assert SECRET not in out.out


def test_config_validate_rejects_bad_approval_policy(cli: Runner, ws: Path) -> None:
    (ws / "soerm.yaml").write_text("version: 1\napprovals:\n  ttl_hours: 0\n", encoding="utf-8")
    out = cli("config", "validate", *w(ws))
    assert out.code == 1
    assert "approvals.ttl_hours" in out.err
    (ws / "soerm.yaml").write_text("version: 1\napprovals:\n  ttl_hours: 24\n", encoding="utf-8")
    assert cli("config", "validate", *w(ws)).code == 0
