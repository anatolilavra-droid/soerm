"""``soerm asset ...`` end to end."""

import json
from pathlib import Path

from tests.unit.cli.conftest import (
    Runner,
    add_asset,
    assert_terminal_safe,
    current_hash,
)
from tests.unit.services.helpers import SECRET

ASSET_KEYS = [
    "asset_id", "hash", "name", "owner", "environment", "business_criticality",
    "data_classification", "exposure", "tags", "created_at", "updated_at",
]  # fmt: skip


def test_add_prints_id_hash_and_the_audit_event(cli: Runner, workspace: Path) -> None:
    result = add_asset(cli, workspace, "--tag", "api", "--tag", "pci", actor="Alice")
    assert result.code == 0
    assert result.err == ""
    assert "created:" in result.out
    assert "AST-000001" in result.out
    assert "audit_action:     asset.create" in result.out
    assert "audit_actor:      alice" in result.out
    assert_terminal_safe(result.out)


def test_add_json(cli: Runner, workspace: Path) -> None:
    result = add_asset(cli, workspace, "--json")
    payload = result.json()
    assert list(payload) == [
        "result", "object_type", "object_id", "before_hash", "after_hash", "audit", "redaction",
    ]  # fmt: skip
    assert payload["object_id"] == "AST-000001"
    assert payload["before_hash"] is None
    audit = payload["audit"]
    assert isinstance(audit, dict)
    assert list(audit) == ["seq", "timestamp", "actor", "action", "entry_hash", "prev_hash"]
    assert (audit["seq"], audit["action"], audit["actor"]) == (1, "asset.create", "alice")
    assert audit["prev_hash"] == "0" * 64


def test_ids_are_assigned_by_the_system(cli: Runner, workspace: Path) -> None:
    add_asset(cli, workspace, "--json")
    second = add_asset(cli, workspace, "--json")
    assert second.json()["object_id"] == "AST-000002"
    assert cli("asset", "add", "--workspace", str(workspace), "--actor", "a", "--asset-id",
               "AST-000009").code == 2  # fmt: skip


def test_show_text_and_json(cli: Runner, workspace: Path) -> None:
    add_asset(cli, workspace, "--tag", "api", "--tag", "pci")
    text = cli("asset", "show", "--workspace", str(workspace), "AST-000001")
    assert text.code == 0
    assert "name:" in text.out
    assert "Billing API" in text.out
    assert "tags:" in text.out
    assert "api, pci" in text.out
    assert_terminal_safe(text.out)
    data = cli("asset", "show", "--workspace", str(workspace), "AST-000001", "--json").json()
    assert list(data) == ASSET_KEYS
    assert data["tags"] == ["api", "pci"]
    assert data["environment"] == "production"


def test_list_text_json_filter_and_sort(cli: Runner, workspace: Path) -> None:
    ws = str(workspace)
    add_asset(cli, workspace, "--json")
    cli("asset", "add", "--workspace", ws, "--actor", "a", "--name", "Alpha", "--owner", "o",
        "--environment", "staging", "--criticality", "low", "--classification", "public",
        "--exposure", "isolated")  # fmt: skip
    text = cli("asset", "list", "--workspace", ws)
    assert text.out.splitlines()[0].split() == [
        "ID", "NAME", "OWNER", "ENVIRONMENT", "CRITICALITY", "EXPOSURE",
    ]  # fmt: skip
    assert [line.split()[0] for line in text.out.splitlines()[1:]] == ["AST-000001", "AST-000002"]
    by_name = cli("asset", "list", "--workspace", ws, "--sort", "name", "--json").json()
    assert [a["name"] for a in by_name["assets"]] == ["Alpha", "Billing API"]
    staging = cli("asset", "list", "--workspace", ws, "--environment", "staging", "--json")
    assert [a["asset_id"] for a in staging.json()["assets"]] == ["AST-000002"]
    assert list(staging.json()["assets"][0]) == ASSET_KEYS
    empty = cli("asset", "list", "--workspace", ws, "--environment", "test")
    assert empty.code == 0
    assert len(empty.out.splitlines()) == 1  # header only


def test_update_with_the_hash_from_show(cli: Runner, workspace: Path) -> None:
    ws = str(workspace)
    add_asset(cli, workspace, "--tag", "old")
    first = current_hash(cli, workspace, "asset", "AST-000001")
    result = cli("asset", "update", "--workspace", ws, "--actor", "Bob", "AST-000001",
                 "--expect-hash", first, "--name", "Billing API v2", "--tag", "new",
                 "--exposure", "partner", "--json")  # fmt: skip
    assert result.code == 0
    payload = result.json()
    assert payload["before_hash"] == first
    assert payload["after_hash"] == current_hash(cli, workspace, "asset", "AST-000001")
    assert payload["audit"]["action"] == "asset.update"
    assert payload["audit"]["actor"] == "bob"
    shown = cli("asset", "show", "--workspace", ws, "AST-000001", "--json").json()
    assert (shown["name"], shown["exposure"], shown["tags"]) == (
        "Billing API v2",
        "partner",
        ["new"],
    )
    cleared = cli("asset", "update", "--workspace", ws, "--actor", "bob", "AST-000001",
                  "--expect-hash", str(payload["after_hash"]), "--clear-tags")  # fmt: skip
    assert cleared.code == 0
    assert cli("asset", "show", "--workspace", ws, "AST-000001", "--json").json()["tags"] == []


def test_update_with_a_stale_hash_is_a_conflict(cli: Runner, workspace: Path) -> None:
    ws = str(workspace)
    add_asset(cli, workspace)
    old = current_hash(cli, workspace, "asset", "AST-000001")
    base = ("asset", "update", "--workspace", ws, "--actor", "bob", "AST-000001")
    assert cli(*base, "--expect-hash", old, "--name", "First").code == 0
    stale = cli(*base, "--expect-hash", old, "--name", "Second")
    assert stale.code == 1
    assert stale.err.startswith("error[conflict]")
    shown = cli("asset", "show", "--workspace", ws, "AST-000001", "--json").json()
    assert shown["name"] == "First"


def test_update_without_changes_is_rejected(cli: Runner, workspace: Path) -> None:
    add_asset(cli, workspace)
    h = current_hash(cli, workspace, "asset", "AST-000001")
    result = cli("asset", "update", "--workspace", str(workspace), "--actor", "a", "AST-000001",
                 "--expect-hash", h)  # fmt: skip
    assert result.code == 1
    assert "no_changes" in result.err


def test_invalid_actor_is_rejected_without_echo_and_without_side_effects(
    cli: Runner, workspace: Path
) -> None:
    bad = f"Mallory {SECRET}!"
    result = add_asset(cli, workspace, actor=bad)
    assert result.code == 1
    assert result.err.startswith("error[invalid_input]")
    assert SECRET not in result.err + result.out
    assert "Mallory" not in result.err
    assert list(workspace.iterdir()) == []


def test_invalid_values_are_reported_by_field_not_by_value(cli: Runner, workspace: Path) -> None:
    result = cli("asset", "add", "--workspace", str(workspace), "--actor", "a",
                 "--name", SECRET * 10000,
                 "--owner", "o", "--environment", "test", "--criticality", "low",
                 "--classification", "public", "--exposure", "isolated")  # fmt: skip
    assert result.code == 1
    assert "name: input_too_large" in result.err
    assert SECRET not in result.err
    assert list(workspace.iterdir()) == []


def test_sql_looking_values_are_plain_data(cli: Runner, workspace: Path) -> None:
    nasty = "x'); DROP TABLE assets; --"
    result = cli("asset", "add", "--workspace", str(workspace), "--actor", "a", "--name", nasty,
                 "--owner", nasty, "--environment", "test", "--criticality", "low",
                 "--classification", "public", "--exposure", "isolated",
                 "--tag", nasty)  # fmt: skip
    assert result.code == 0
    shown = cli("asset", "show", "--workspace", str(workspace), "AST-000001", "--json").json()
    assert shown["name"] == nasty
    assert cli("asset", "show", "--workspace", str(workspace), "AST-000001' OR '1'='1").code == 1
    assert cli("asset", "list", "--workspace", str(workspace)).code == 0


def test_json_output_is_ascii_and_parseable(cli: Runner, workspace: Path) -> None:
    add_asset(cli, workspace, "--tag", "тег")
    out = cli("asset", "show", "--workspace", str(workspace), "AST-000001", "--json").out
    assert out.isascii()
    assert json.loads(out)["tags"] == ["тег"]
