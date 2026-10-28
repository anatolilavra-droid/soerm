"""Asset service: create, get, list, update, audit and failure behaviour."""
# ruff: noqa: RUF001
# (look-alike and full-width characters are deliberate test data)

from pathlib import Path

import pytest

from soerm.domain.enums import BusinessCriticality, DataClassification, Environment, Exposure
from soerm.services.assets import AssetSort, create_asset, get_asset, list_assets, update_asset
from soerm.services.errors import (
    ConflictServiceError,
    ConstraintViolationServiceError,
    InvalidInputError,
    NotFoundServiceError,
    ServiceError,
)
from soerm.services.workspace import Workspace
from soerm.storage.assets import AssetRepository
from soerm.storage.audit import verify_audit_chain
from soerm.storage.errors import StorageError
from tests.unit.services.helpers import (
    SECRET,
    audit_entries,
    make_asset,
    raw_execute,
    table_dump,
)

NASTY = 'O\'Brien "x"; DROP TABLE assets; --\nline two'


def test_create_assigns_ids_and_writes_audit(ws: Workspace) -> None:
    first = make_asset(ws)
    second = make_asset(ws, name="Other")
    assert (first.object_id, second.object_id) == ("AST-000001", "AST-000002")
    assert (first.before_hash, first.object_type) == (None, "asset")
    assert first.audit.action == "asset.create"
    assert first.audit.after_hash == first.after_hash
    entries = audit_entries(ws)
    assert [e.seq for e in entries] == [1, 2]
    assert entries[1].prev_hash == entries[0].entry_hash
    with ws.read() as session:
        assert verify_audit_chain(session.connection).seq == 2


def test_user_cannot_choose_the_id() -> None:
    with pytest.raises(TypeError):
        create_asset(  # type: ignore[call-arg]
            Workspace("/nonexistent"), asset_id="AST-000099", actor="a", name="n", owner="o",
            environment=Environment.TEST, business_criticality=BusinessCriticality.LOW,
            data_classification=DataClassification.PUBLIC, exposure=Exposure.ISOLATED,
        )  # fmt: skip


def test_get_returns_the_stored_asset(ws: Workspace) -> None:
    result = make_asset(ws)
    asset = get_asset(ws, "AST-000001")
    assert asset.digest() == result.after_hash
    assert (asset.name, asset.tags) == ("Billing API", ("api", "pci"))


@pytest.mark.parametrize("bad", ["AST-1", "ast-000001", "FND-000001", "x' OR '1'='1", "", "AST-%"])
def test_get_rejects_malformed_ids(ws: Workspace, bad: str) -> None:
    make_asset(ws)
    with pytest.raises(InvalidInputError):
        get_asset(ws, bad)


def test_get_unknown_asset_is_not_found(ws: Workspace) -> None:
    make_asset(ws)
    with pytest.raises(NotFoundServiceError) as excinfo:
        get_asset(ws, "AST-000042")
    assert excinfo.value.code == "not_found"


def test_reading_an_empty_workspace_does_not_create_anything(ws: Workspace, tmp_path: Path) -> None:
    with pytest.raises(NotFoundServiceError):
        get_asset(ws, "AST-000001")
    with pytest.raises(NotFoundServiceError):
        list_assets(ws)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "actor", ["", "   ", "Al!ce", "al ice", "alice;drop", "аlice", "a\nb", "x" * 500]
)
def test_invalid_actor_is_rejected_without_touching_the_workspace(
    ws: Workspace, tmp_path: Path, actor: str
) -> None:
    with pytest.raises(InvalidInputError) as excinfo:
        make_asset(ws, actor=actor)
    assert actor.strip() == "" or actor not in str(excinfo.value)
    assert list(tmp_path.iterdir()) == []


def test_actor_is_normalized(ws: Workspace) -> None:
    assert make_asset(ws, actor="  ＡＬＩＣＥ@Example.COM ").audit.actor == "alice@example.com"


def test_invalid_input_creates_nothing(ws: Workspace, tmp_path: Path) -> None:
    for overrides in ({"name": ""}, {"environment": "moon"}, {"tags": "not-a-list"}):
        with pytest.raises(InvalidInputError):
            make_asset(ws, **overrides)
    assert list(tmp_path.iterdir()) == []  # no database, no lock file


def test_rejected_input_never_appears_in_the_error(ws: Workspace) -> None:
    with pytest.raises(InvalidInputError) as excinfo:
        make_asset(ws, name=SECRET, environment=SECRET)
    text = str(excinfo.value) + repr(excinfo.value.to_dict())
    assert SECRET not in text
    assert "environment" in text


def test_quotes_newlines_and_sql_text_are_data(ws: Workspace) -> None:
    make_asset(ws, name=NASTY, owner="Robert'); DROP TABLE assets;--", tags=("a'b", 'c"d'))
    asset = get_asset(ws, "AST-000001")
    assert "DROP TABLE" in asset.name
    assert len(list_assets(ws)) == 1


def test_audit_holds_no_user_text(ws: Workspace) -> None:
    make_asset(ws, name=SECRET, owner=SECRET, tags=(SECRET,))
    asset = get_asset(ws, "AST-000001")
    update_asset(ws, "AST-000001", actor="bob", expected_hash=asset.digest(), name=SECRET + "2")
    dump = table_dump(ws, "audit_log").lower()
    assert SECRET.lower() not in dump


def test_list_filters_and_allowlisted_sort(ws: Workspace) -> None:
    make_asset(ws, name="Zeta", environment=Environment.PRODUCTION)
    make_asset(ws, name="Alpha", environment=Environment.STAGING)
    assert [a.name for a in list_assets(ws)] == ["Zeta", "Alpha"]
    assert [a.name for a in list_assets(ws, sort=AssetSort.NAME)] == ["Alpha", "Zeta"]
    assert [a.name for a in list_assets(ws, sort=AssetSort.CREATED_AT)] == ["Zeta", "Alpha"]
    assert [a.name for a in list_assets(ws, environment=Environment.STAGING)] == ["Alpha"]
    assert list_assets(ws, environment=Environment.TEST) == []


@pytest.mark.parametrize("bad", ["name; DROP TABLE assets", "name DESC", "", "NAME", 5])
def test_list_rejects_non_allowlisted_sort(ws: Workspace, bad: object) -> None:
    make_asset(ws)
    with pytest.raises(InvalidInputError):
        list_assets(ws, sort=bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", ["production' OR '1'='1", "prod", "", 5])
def test_list_rejects_non_allowlisted_filter(ws: Workspace, bad: object) -> None:
    make_asset(ws)
    with pytest.raises(InvalidInputError):
        list_assets(ws, environment=bad)  # type: ignore[arg-type]


def test_update_changes_fields_and_audits_both_hashes(ws: Workspace) -> None:
    created = make_asset(ws)
    result = update_asset(
        ws, "AST-000001", actor="Bob", expected_hash=created.after_hash,
        name="Billing API v2", exposure=Exposure.PARTNER, tags=("x",),
    )  # fmt: skip
    asset = get_asset(ws, "AST-000001")
    assert (asset.name, asset.exposure, asset.tags) == ("Billing API v2", Exposure.PARTNER, ("x",))
    assert asset.owner == "platform"
    assert asset.updated_at > asset.created_at
    assert result.before_hash == created.after_hash
    assert result.after_hash == asset.digest()
    assert result.audit.action == "asset.update"
    assert (result.audit.before_hash, result.audit.after_hash) == (
        created.after_hash,
        asset.digest(),
    )
    assert result.audit.actor == "bob"
    assert [e.seq for e in audit_entries(ws)] == [1, 2]


def test_update_can_clear_tags(ws: Workspace) -> None:
    created = make_asset(ws)
    update_asset(ws, "AST-000001", actor="bob", expected_hash=created.after_hash, tags=())
    assert get_asset(ws, "AST-000001").tags == ()


def test_stale_hash_is_a_conflict_and_writes_nothing(ws: Workspace) -> None:
    created = make_asset(ws)
    update_asset(ws, "AST-000001", actor="bob", expected_hash=created.after_hash, name="Changed")
    before = get_asset(ws, "AST-000001")
    with pytest.raises(ConflictServiceError) as excinfo:
        update_asset(ws, "AST-000001", actor="eve", expected_hash=created.after_hash, name="Evil")
    assert excinfo.value.code == "conflict"
    assert get_asset(ws, "AST-000001") == before
    assert [e.seq for e in audit_entries(ws)] == [1, 2]


def test_repository_level_hash_check_is_atomic(ws: Workspace) -> None:
    created = make_asset(ws)
    asset = get_asset(ws, "AST-000001")
    changed = asset.with_changes(name="Changed", updated_at=asset.updated_at.replace(year=2030))
    with pytest.raises(ConflictServiceError), ws.write() as session:
        AssetRepository(session.connection).update(
            changed, actor="eve", at=session.now, expected_before_hash="0" * 64
        )
    assert get_asset(ws, "AST-000001").digest() == created.after_hash


def test_update_requires_changes_and_a_valid_hash(ws: Workspace) -> None:
    created = make_asset(ws)
    with pytest.raises(InvalidInputError):
        update_asset(ws, "AST-000001", actor="bob", expected_hash=created.after_hash)
    with pytest.raises(InvalidInputError):  # same value: nothing would change
        update_asset(ws, "AST-000001", actor="bob", expected_hash=created.after_hash,
                     name="Billing API")  # fmt: skip
    for bad in ("", "ABC", "A" * 64, "g" * 64, None):
        with pytest.raises(InvalidInputError):
            update_asset(ws, "AST-000001", actor="bob", expected_hash=bad, name="x")  # type: ignore[arg-type]
    assert [e.seq for e in audit_entries(ws)] == [1]


def test_update_unknown_asset(ws: Workspace) -> None:
    make_asset(ws)
    with pytest.raises(NotFoundServiceError):
        update_asset(ws, "AST-000009", actor="bob", expected_hash="0" * 64, name="x")


def test_invalid_update_values_leave_everything_unchanged(ws: Workspace) -> None:
    created = make_asset(ws)
    with pytest.raises(InvalidInputError):
        update_asset(ws, "AST-000001", actor="bob", expected_hash=created.after_hash, name=" ")
    assert get_asset(ws, "AST-000001").digest() == created.after_hash
    assert [e.seq for e in audit_entries(ws)] == [1]


def test_failed_audit_rolls_back_the_asset_and_the_counter(
    ws: Workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_asset(ws)

    def boom(*args: object, **kwargs: object) -> None:
        raise StorageError("simulated")

    monkeypatch.setattr("soerm.storage.assets.append_audit", boom)
    with pytest.raises(ServiceError):
        make_asset(ws, name="Second")
    monkeypatch.undo()
    assert [a.asset_id for a in list_assets(ws)] == ["AST-000001"]
    assert make_asset(ws, name="Second").object_id == "AST-000002"  # the number was not consumed
    assert [e.seq for e in audit_entries(ws)] == [1, 2]


def test_failed_audit_rolls_back_an_update(ws: Workspace, monkeypatch: pytest.MonkeyPatch) -> None:
    created = make_asset(ws)

    def boom(*args: object, **kwargs: object) -> None:
        raise StorageError("simulated")

    monkeypatch.setattr("soerm.storage.assets.append_audit", boom)
    with pytest.raises(ServiceError):
        update_asset(ws, "AST-000001", actor="bob", expected_hash=created.after_hash, name="New")
    monkeypatch.undo()
    assert get_asset(ws, "AST-000001").digest() == created.after_hash


def test_identifier_collision_is_a_constraint_violation(ws: Workspace, tmp_path: Path) -> None:
    make_asset(ws)
    raw_execute(tmp_path, "UPDATE counters SET value = 0 WHERE prefix = 'AST'")  # tampering
    with pytest.raises(ConstraintViolationServiceError) as excinfo:
        make_asset(ws, name="Second")
    assert excinfo.value.code == "constraint_violation"
    assert [a.name for a in list_assets(ws)] == ["Billing API"]
    assert [e.seq for e in audit_entries(ws)] == [1]
