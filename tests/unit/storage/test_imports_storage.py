"""Import run and occurrence repositories."""

from datetime import UTC, datetime

import pytest

from soerm.domain.enums import ImportSource
from soerm.domain.import_run import ImportRun
from soerm.domain.provenance import Occurrence
from soerm.storage.connection import SoermConnection
from soerm.storage.counters import CounterRepository
from soerm.storage.errors import StorageError
from soerm.storage.imports import ImportRunRepository, OccurrenceRepository
from soerm.storage.transactions import transaction
from tests.unit.storage.conftest import NOW

SHA = "c" * 64


def make_run(run_id: str = "RUN-000001") -> ImportRun:
    return ImportRun(
        run_id=run_id,
        source=ImportSource.SARIF,
        file_sha256=SHA,
        source_path="in/a.sarif",
        imported_at=NOW,
        record_count=2,
    )


def test_run_round_trip_and_audit(conn: SoermConnection) -> None:
    repo = ImportRunRepository(conn)
    with transaction(conn, write=True):
        CounterRepository(conn).next_identifier("RUN")
        entry = repo.add(make_run(), actor="alice", at=NOW)
    assert (entry.action, entry.object_id, entry.before_hash) == ("import.run", "RUN-000001", None)
    assert entry.after_hash == make_run().digest()
    assert repo.get("RUN-000001") == make_run()
    assert repo.list() == [make_run()]
    assert repo.get("RUN-000002") is None


def test_run_rolls_back_with_its_transaction(conn: SoermConnection) -> None:
    repo = ImportRunRepository(conn)

    def fail() -> None:
        with transaction(conn, write=True):
            repo.add(make_run(), actor="alice", at=NOW)
            raise RuntimeError

    with pytest.raises(RuntimeError):
        fail()
    assert repo.list() == []


def test_occurrence_needs_a_write_transaction_and_existing_rows(conn: SoermConnection) -> None:
    occ = Occurrence(
        import_run_id="RUN-000001",
        file_sha256=SHA,
        source_path="in/a.sarif",
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        location="src/a.py:1",
    )
    with pytest.raises(StorageError):
        OccurrenceRepository(conn).add("FND-000001", occ)
    assert not OccurrenceRepository(conn).exists(
        "FND-000001", file_sha256=SHA, source_path="in/a.sarif", location="src/a.py:1"
    )
