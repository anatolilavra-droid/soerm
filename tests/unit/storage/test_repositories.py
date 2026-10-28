"""Asset and finding repositories."""
# ruff: noqa: PT012  (the transaction context managers are the point of these blocks)

from datetime import timedelta

import pytest

from soerm.domain import (
    Asset,
    Environment,
    Finding,
    FindingStatus,
    InvalidIdentifierError,
    TechnicalSeverity,
    ValidationDomainError,
)
from soerm.storage.assets import AssetOrder, AssetRepository
from soerm.storage.audit import get_audit_head, list_audit_entries, verify_audit_chain
from soerm.storage.connection import SoermConnection
from soerm.storage.counters import CounterRepository
from soerm.storage.errors import ConstraintViolationError, NotFoundError, StorageError
from soerm.storage.findings import FindingOrder, FindingRepository
from soerm.storage.transactions import transaction
from tests.unit.domain.factories import SECRET, SHA_A, SHA_B, T0, T1, asset_data, finding_data
from tests.unit.storage.conftest import NOW

NASTY = 'O\'Brien "quoted"; DROP TABLE assets; --\nsecond line\t100% \\ back\\slash'


def asset(**overrides: object) -> Asset:
    return Asset(**asset_data(**overrides))


def finding(**overrides: object) -> Finding:
    return Finding(**finding_data(**overrides))


@pytest.fixture
def assets(conn: SoermConnection) -> AssetRepository:
    return AssetRepository(conn)


@pytest.fixture
def findings(conn: SoermConnection, assets: AssetRepository) -> FindingRepository:
    assets.add(asset(), actor="alice", at=NOW)
    return FindingRepository(conn)


# ---- assets -------------------------------------------------------------------------------


def test_asset_round_trip(assets: AssetRepository) -> None:
    original = asset()
    entry = assets.add(original, actor="alice", at=NOW)
    loaded = assets.get("AST-000001")
    assert loaded == original
    assert loaded is not None
    assert loaded.tags == ("api", "pci")
    assert entry.object_id == "AST-000001"
    assert entry.before_hash is None
    assert entry.after_hash == original.digest()
    assert assets.get("AST-999999") is None


def test_input_model_is_not_modified(assets: AssetRepository) -> None:
    original = asset(name="  Billing   API ")
    before = original.model_dump()
    assets.add(original, actor="alice", at=NOW)
    assert original.model_dump() == before
    assert original.name == "Billing API"


def test_duplicate_asset_is_rejected_without_side_effects(
    assets: AssetRepository, conn: SoermConnection
) -> None:
    assets.add(asset(), actor="alice", at=NOW)
    head = get_audit_head(conn)
    with pytest.raises(ConstraintViolationError) as excinfo:
        assets.add(asset(name="Other"), actor="alice", at=NOW)
    assert excinfo.value.details["kind"] == "unique"
    assert get_audit_head(conn) == head
    loaded = assets.get("AST-000001")
    assert loaded is not None
    assert loaded.name == "Billing API"


def test_quotes_newlines_and_sql_text_are_stored_as_data(
    assets: AssetRepository, conn: SoermConnection
) -> None:
    model = asset(name=NASTY, owner="Robert'); DROP TABLE assets;--", tags=["a'b", 'c"d', "e;f"])
    assets.add(model, actor="alice", at=NOW)
    loaded = assets.get("AST-000001")
    assert loaded == model
    assert loaded is not None
    assert "DROP TABLE" in loaded.name
    assert conn.execute("SELECT count(*) FROM assets").fetchone()[0] == 1  # table still there


@pytest.mark.parametrize(
    "asset_id", ["x' OR '1'='1", "AST-000001' --", "'; DROP TABLE assets; --", "", "%", "AST-%"]
)
def test_get_is_not_injectable(assets: AssetRepository, asset_id: str) -> None:
    assets.add(asset(), actor="alice", at=NOW)
    assert assets.get(asset_id) is None


def test_update_records_before_and_after_hashes(assets: AssetRepository) -> None:
    original = asset()
    assets.add(original, actor="alice", at=NOW)
    changed = original.with_changes(name="Billing API v2", updated_at=T1 + timedelta(hours=1))
    entry = assets.update(changed, actor="bob", at=NOW + timedelta(minutes=5))
    assert (entry.action, entry.actor) == ("asset.update", "bob")
    assert entry.before_hash == original.digest()
    assert entry.after_hash == changed.digest()
    assert assets.get("AST-000001") == changed


def test_update_rules(assets: AssetRepository) -> None:
    with pytest.raises(NotFoundError):
        assets.update(asset(), actor="alice", at=NOW)
    assets.add(asset(), actor="alice", at=NOW)
    with pytest.raises(StorageError) as excinfo:
        assets.update(asset(created_at=T0 - timedelta(days=1)), actor="alice", at=NOW)
    assert excinfo.value.details["reason"] == "immutable_field"


def test_unvalidated_models_are_not_trusted(assets: AssetRepository, conn: SoermConnection) -> None:
    bogus = Asset.model_construct(**{**asset_data(), "environment": "moon", "name": ""})
    with pytest.raises(ValidationDomainError):
        assets.add(bogus, actor="alice", at=NOW)
    with pytest.raises(StorageError):
        assets.add({"asset_id": "AST-000001"}, actor="alice", at=NOW)  # type: ignore[arg-type]
    assert get_audit_head(conn).seq == 0


def test_asset_listing_filters_and_order_allowlist(assets: AssetRepository) -> None:
    assets.add(asset(asset_id="AST-000001", name="Zeta", environment="production"),
               actor="alice", at=NOW)  # fmt: skip
    assets.add(asset(asset_id="AST-000002", name="Alpha", environment="staging",
                     created_at=T0 - timedelta(days=1)), actor="alice", at=NOW)  # fmt: skip
    assert [a.asset_id for a in assets.list()] == ["AST-000001", "AST-000002"]
    assert [a.name for a in assets.list(order=AssetOrder.NAME)] == ["Alpha", "Zeta"]
    assert [a.asset_id for a in assets.list(order=AssetOrder.CREATED_AT)] == [
        "AST-000002", "AST-000001",
    ]  # fmt: skip
    assert [a.asset_id for a in assets.list(environment=Environment.STAGING)] == ["AST-000002"]
    assert assets.list(environment=Environment.TEST) == []


@pytest.mark.parametrize(
    "bad", ["name; DROP TABLE assets", "name DESC", "1", "", None, "ID", "created_at--"]
)
def test_sort_order_must_come_from_the_allowlist(assets: AssetRepository, bad: object) -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        assets.list(order=bad)  # type: ignore[arg-type]
    assert "DROP" not in str(excinfo.value)


@pytest.mark.parametrize("bad", ["production' OR '1'='1", "prod", "", 5])
def test_environment_filter_is_an_allowlist(assets: AssetRepository, bad: object) -> None:
    with pytest.raises(ValidationDomainError):
        assets.list(environment=bad)  # type: ignore[arg-type]


def test_corrupt_rows_are_reported_not_trusted(
    assets: AssetRepository, conn: SoermConnection
) -> None:
    assets.add(asset(), actor="alice", at=NOW)
    with transaction(conn, write=True):
        conn.execute("UPDATE assets SET tags = '[1, 2]'")  # valid JSON array, invalid for the model
    with pytest.raises(StorageError) as excinfo:
        assets.get("AST-000001")
    assert excinfo.value.details["reason"] == "corrupt_row"


def test_repositories_inside_one_outer_transaction_with_counters(conn: SoermConnection) -> None:
    counters, assets = CounterRepository(conn), AssetRepository(conn)
    with transaction(conn, write=True):
        asset_id = counters.next_identifier("AST")
        assets.add(asset(asset_id=asset_id), actor="alice", at=NOW)
    assert asset_id == "AST-000001"
    with pytest.raises(RuntimeError), transaction(conn, write=True):
        counters.next_identifier("AST")
        raise RuntimeError
    assert counters.current("AST") == 1
    assert verify_audit_chain(conn).seq == 1


# ---- findings -----------------------------------------------------------------------------


def test_finding_round_trip_with_all_fields(
    findings: FindingRepository, conn: SoermConnection
) -> None:
    full = finding(
        description=NASTY, evidence="line1\n  indented 'quote'", cvss_version="4.0",
        cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        cvss_score=9.3, cvss_score_source="imported", business_priority="p1",
        risk_factors={"exploit_maturity": 0.5, "age_days": 30}, risk_formula_version="1",
        risk_config_hash=SHA_B, status="triaged", owner="Platform", sla_due_at=T1,
    )  # fmt: skip
    entry = findings.add(full, actor="alice", at=NOW)
    assert findings.get("FND-000001") == full
    assert entry.action == "finding.create"
    assert entry.after_hash == full.digest()
    assert findings.get_by_fingerprint(SHA_A) == full
    assert findings.get_by_fingerprint(SHA_B) is None
    assert conn.execute("SELECT count(*) FROM findings").fetchone()[0] == 1


def test_minimal_finding_round_trip(findings: FindingRepository) -> None:
    minimal = finding()
    findings.add(minimal, actor="alice", at=NOW)
    assert findings.get("FND-000001") == minimal


def test_finding_needs_an_existing_asset(
    findings: FindingRepository, conn: SoermConnection
) -> None:
    head = get_audit_head(conn)
    with pytest.raises(ConstraintViolationError) as excinfo:
        findings.add(finding(asset_id="AST-000099"), actor="alice", at=NOW)
    assert excinfo.value.details["kind"] == "foreign_key"
    assert get_audit_head(conn) == head
    assert conn.execute("SELECT count(*) FROM findings").fetchone()[0] == 0


def test_finding_uniqueness(findings: FindingRepository) -> None:
    findings.add(finding(), actor="alice", at=NOW)
    with pytest.raises(ConstraintViolationError):
        findings.add(finding(), actor="alice", at=NOW)  # same id
    with pytest.raises(ConstraintViolationError) as excinfo:
        findings.add(finding(finding_id="FND-000002"), actor="alice", at=NOW)  # same fingerprint
    assert excinfo.value.details["kind"] == "unique"


def test_asset_with_findings_cannot_be_deleted(
    findings: FindingRepository, conn: SoermConnection
) -> None:
    findings.add(finding(), actor="alice", at=NOW)
    with pytest.raises(ConstraintViolationError), transaction(conn, write=True):
        conn.execute("DELETE FROM assets")


def test_finding_update_and_immutable_fields(findings: FindingRepository) -> None:
    original = finding()
    findings.add(original, actor="alice", at=NOW)
    changed = original.with_changes(status="triaged", updated_at=T1 + timedelta(hours=1))
    entry = findings.update(changed, actor="bob", at=NOW)
    assert (entry.before_hash, entry.after_hash) == (original.digest(), changed.digest())
    assert findings.get("FND-000001") == changed
    for field, value in (("fingerprint", SHA_B), ("created_at", T0 - timedelta(days=1))):
        with pytest.raises(StorageError) as excinfo:
            findings.update(original.with_changes(**{field: value}), actor="bob", at=NOW)
        assert excinfo.value.details["reason"] == "immutable_field"
    with pytest.raises(NotFoundError):
        findings.update(finding(finding_id="FND-000009", fingerprint=SHA_B), actor="bob", at=NOW)


def test_finding_listing_filters_and_order(
    findings: FindingRepository, assets: AssetRepository
) -> None:
    assets.add(asset(asset_id="AST-000002"), actor="alice", at=NOW)
    first_seen = T0 + timedelta(minutes=1)
    findings.add(finding(finding_id="FND-000001", fingerprint="1" * 64, last_seen=first_seen),
                 actor="alice", at=NOW)  # fmt: skip
    findings.add(finding(finding_id="FND-000002", fingerprint="2" * 64, asset_id="AST-000002",
                         technical_severity="critical", status="triaged", last_seen=T1),
                 actor="alice", at=NOW)  # fmt: skip

    def ids(items: list[Finding]) -> list[str]:
        return [f.finding_id for f in items]

    assert ids(findings.list()) == ["FND-000001", "FND-000002"]
    assert ids(findings.list(order=FindingOrder.LAST_SEEN)) == ["FND-000002", "FND-000001"]
    assert ids(findings.list(status=FindingStatus.TRIAGED)) == ["FND-000002"]
    assert ids(findings.list(asset_id="AST-000002")) == ["FND-000002"]
    assert ids(findings.list(severity=TechnicalSeverity.CRITICAL)) == ["FND-000002"]
    assert ids(findings.list(status=FindingStatus.OPEN, asset_id="AST-000001")) == ["FND-000001"]


def test_finding_filters_cannot_inject_sql(findings: FindingRepository) -> None:
    findings.add(finding(), actor="alice", at=NOW)
    with pytest.raises(ValidationDomainError):
        findings.list(status="open' OR '1'='1")  # type: ignore[arg-type]
    with pytest.raises(ValidationDomainError):
        findings.list(severity="high; DROP TABLE findings")  # type: ignore[arg-type]
    with pytest.raises(ValidationDomainError):
        findings.list(order="last_seen; DROP TABLE findings")  # type: ignore[arg-type]
    with pytest.raises(InvalidIdentifierError):
        findings.list(asset_id="AST-000001' OR '1'='1")
    assert findings.get("FND-000001' OR '1'='1") is None
    assert findings.get_by_fingerprint("' OR '1'='1") is None
    assert len(findings.list()) == 1


def test_secret_text_never_reaches_audit_or_errors(
    findings: FindingRepository, conn: SoermConnection
) -> None:
    findings.add(finding(title=SECRET, description=SECRET, evidence=SECRET), actor="alice", at=NOW)
    with pytest.raises(ConstraintViolationError) as excinfo:
        findings.add(finding(title=SECRET, evidence=SECRET), actor="alice", at=NOW)
    assert SECRET not in str(excinfo.value) + repr(excinfo.value.to_dict())
    dump = repr([e.model_dump() for e in list_audit_entries(conn)])
    assert SECRET not in dump


def test_evidence_limit_holds_at_every_layer(
    findings: FindingRepository, conn: SoermConnection
) -> None:
    with pytest.raises(ValidationDomainError):
        finding(evidence="x" * 4097)
    over = Finding.model_construct(**{**finding_data(), "evidence": "x" * 4097})
    with pytest.raises(ValidationDomainError):
        findings.add(over, actor="alice", at=NOW)  # re-validated by the repository
    findings.add(finding(evidence="x" * 4096), actor="alice", at=NOW)
    with pytest.raises(ConstraintViolationError), transaction(conn, write=True):
        conn.execute("UPDATE findings SET evidence = ?", ("x" * 4097,))  # and by the schema
    loaded = findings.get("FND-000001")
    assert loaded is not None
    assert len(loaded.evidence) == 4096
