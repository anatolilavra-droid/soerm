"""Asset repository. Every write also appends an audit entry in the same transaction."""

import json
import sqlite3
from datetime import datetime
from enum import StrEnum

from soerm.domain.asset import Asset
from soerm.domain.audit import AuditEntry
from soerm.domain.enums import Environment
from soerm.domain.hashing import canonical_json
from soerm.storage.audit import append_audit
from soerm.storage.codec import coerce_enum, to_db_timestamp
from soerm.storage.connection import SoermConnection
from soerm.storage.errors import ConflictError, NotFoundError, StorageError
from soerm.storage.transactions import transaction

__all__ = ["AssetOrder", "AssetRepository"]

_INSERT = (
    "INSERT INTO assets (asset_id, name, owner, environment, business_criticality,"
    " data_classification, exposure, tags, created_at, updated_at)"
    " VALUES (:asset_id, :name, :owner, :environment, :business_criticality,"
    " :data_classification, :exposure, :tags, :created_at, :updated_at)"
)
_UPDATE = (
    "UPDATE assets SET name = :name, owner = :owner, environment = :environment,"
    " business_criticality = :business_criticality, data_classification = :data_classification,"
    " exposure = :exposure, tags = :tags, updated_at = :updated_at WHERE asset_id = :asset_id"
)
_GET = "SELECT * FROM assets WHERE asset_id = :asset_id"
_LIST = (
    "SELECT * FROM assets WHERE (:environment IS NULL OR environment = :environment)"
    " ORDER BY CASE :order WHEN 'name' THEN name END,"
    " CASE :order WHEN 'created_at' THEN created_at END, asset_id"
)


class AssetOrder(StrEnum):
    """Allowed sort orders (the value is bound as a parameter, never spliced into SQL)."""

    ID = "id"
    NAME = "name"
    CREATED_AT = "created_at"


def _params(asset: Asset) -> dict[str, object]:
    return {
        "asset_id": asset.asset_id,
        "name": asset.name,
        "owner": asset.owner,
        "environment": asset.environment.value,
        "business_criticality": asset.business_criticality.value,
        "data_classification": asset.data_classification.value,
        "exposure": asset.exposure.value,
        "tags": canonical_json(list(asset.tags)),
        "created_at": to_db_timestamp(asset.created_at),
        "updated_at": to_db_timestamp(asset.updated_at),
    }


def _from_row(row: sqlite3.Row) -> Asset:
    try:
        return Asset(
            asset_id=row["asset_id"],
            name=row["name"],
            owner=row["owner"],
            environment=row["environment"],
            business_criticality=row["business_criticality"],
            data_classification=row["data_classification"],
            exposure=row["exposure"],
            tags=json.loads(row["tags"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
    except ValueError:
        raise StorageError("corrupt_row", object_type="asset") from None


def _checked(asset: object) -> Asset:
    """Re-validate the model (``model_construct`` bypasses validation); the input is not
    modified."""
    if not isinstance(asset, Asset):
        raise StorageError("invalid_model", object_type="asset")
    return asset.with_changes()


class AssetRepository:
    def __init__(self, connection: SoermConnection) -> None:
        self._connection = connection

    def add(self, asset: Asset, *, actor: str, at: datetime) -> AuditEntry:
        """Insert a new asset and its ``asset.create`` audit entry atomically."""
        model = _checked(asset)
        with transaction(self._connection, write=True) as conn:
            conn.execute(_INSERT, _params(model))
            return append_audit(
                conn,
                timestamp=at,
                actor=actor,
                action="asset.create",
                object_type="asset",
                object_id=model.asset_id,
                before_hash=None,
                after_hash=model.digest(),
            )

    def update(
        self,
        asset: Asset,
        *,
        actor: str,
        at: datetime,
        expected_before_hash: str | None = None,
    ) -> AuditEntry:
        """Replace the mutable fields of an existing asset and append ``asset.update``."""
        model = _checked(asset)
        with transaction(self._connection, write=True) as conn:
            row = conn.execute(_GET, {"asset_id": model.asset_id}).fetchone()
            if row is None:
                raise NotFoundError("asset")
            existing = _from_row(row)
            if expected_before_hash is not None and existing.digest() != expected_before_hash:
                raise ConflictError("asset")
            if existing.created_at != model.created_at:
                raise StorageError("immutable_field", field="created_at")
            conn.execute(_UPDATE, _params(model))
            return append_audit(
                conn,
                timestamp=at,
                actor=actor,
                action="asset.update",
                object_type="asset",
                object_id=model.asset_id,
                before_hash=existing.digest(),
                after_hash=model.digest(),
            )

    def get(self, asset_id: str) -> Asset | None:
        with transaction(self._connection, write=False) as conn:
            row = conn.execute(_GET, {"asset_id": asset_id}).fetchone()
        return None if row is None else _from_row(row)

    def list(
        self,
        *,
        environment: Environment | None = None,
        order: AssetOrder = AssetOrder.ID,
    ) -> list[Asset]:
        env = None if environment is None else coerce_enum(Environment, environment, "environment")
        with transaction(self._connection, write=False) as conn:
            rows = conn.execute(
                _LIST,
                {
                    "environment": None if env is None else env.value,
                    "order": coerce_enum(AssetOrder, order, "order").value,
                },
            ).fetchall()
        return [_from_row(row) for row in rows]
