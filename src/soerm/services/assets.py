"""Asset service: create, read, list and update assets.

Identifiers come from the storage counters; callers never choose them. Every mutation
appends an audit entry in the same transaction (identifiers and hashes only).
"""

from collections.abc import Sequence
from enum import StrEnum
from typing import Any

from soerm.domain.asset import Asset
from soerm.domain.enums import BusinessCriticality, DataClassification, Environment, Exposure
from soerm.domain.errors import DomainError
from soerm.domain.identifiers import check_identifier
from soerm.services.common import (
    PLACEHOLDER_TIME,
    MutationResult,
    require_actor,
    require_expected_hash,
)
from soerm.services.errors import (
    ConflictServiceError,
    InvalidInputError,
    NotFoundServiceError,
    to_service_error,
)
from soerm.services.redaction import FieldRedactor, load_redactor
from soerm.services.workspace import Workspace
from soerm.storage.assets import AssetOrder, AssetRepository
from soerm.storage.counters import CounterRepository

__all__ = ["AssetSort", "create_asset", "get_asset", "list_assets", "update_asset"]

_PLACEHOLDER_ID = "AST-000001"


class AssetSort(StrEnum):
    """Allowed sort orders for :func:`list_assets`."""

    ID = "id"
    NAME = "name"
    CREATED_AT = "created_at"


def _tag_tuple(tags: Sequence[str]) -> tuple[str, ...]:
    if isinstance(tags, str):  # a bare string would be split into one-character tags
        raise InvalidInputError("tags: tags_type")
    return tuple(tags)


def _redact_tags(redactor: FieldRedactor, tags: Sequence[str]) -> tuple[str, ...]:
    return tuple(redactor.field("tags", tag, "tag") for tag in _tag_tuple(tags))


def _asset_id(asset_id: object) -> str:
    try:
        return check_identifier("AST", asset_id, field="asset_id")
    except DomainError as exc:
        raise to_service_error(exc) from None


def create_asset(
    workspace: Workspace,
    *,
    actor: str,
    name: str,
    owner: str,
    environment: Environment,
    business_criticality: BusinessCriticality,
    data_classification: DataClassification,
    exposure: Exposure,
    tags: Sequence[str] = (),
) -> MutationResult:
    """Create an asset with a server-assigned id and write its ``asset.create`` audit entry."""
    actor = require_actor(actor)
    redactor = FieldRedactor(load_redactor(workspace.path))
    fields: dict[str, Any] = {
        "name": redactor.field("name", name, "name"),
        "owner": redactor.field("owner", owner, "name"),
        "environment": environment,
        "business_criticality": business_criticality,
        "data_classification": data_classification,
        "exposure": exposure,
        "tags": _redact_tags(redactor, tags),
    }
    try:  # fail before anything is created in the workspace
        Asset(
            asset_id=_PLACEHOLDER_ID,
            created_at=PLACEHOLDER_TIME,
            updated_at=PLACEHOLDER_TIME,
            **fields,
        )
    except DomainError as exc:
        raise to_service_error(exc) from None
    with workspace.write() as session:
        asset_id = CounterRepository(session.connection).next_identifier("AST")
        asset = Asset(
            asset_id=asset_id,
            created_at=session.now,
            updated_at=session.now,
            **fields,
        )
        entry = AssetRepository(session.connection).add(asset, actor=actor, at=session.now)
    return MutationResult("asset", asset_id, None, asset.digest(), entry, redactor.report())


def get_asset(workspace: Workspace, asset_id: str) -> Asset:
    asset_id = _asset_id(asset_id)
    with workspace.read() as session:
        asset = AssetRepository(session.connection).get(asset_id)
    if asset is None:
        raise NotFoundServiceError("object_not_found", object_type="asset")
    return asset


def list_assets(
    workspace: Workspace,
    *,
    environment: Environment | None = None,
    sort: AssetSort = AssetSort.ID,
) -> list[Asset]:
    """List assets; only the allowlisted filter and sort orders are accepted."""
    try:
        order = AssetOrder(AssetSort(sort).value)
        env = None if environment is None else Environment(environment)
    except ValueError:
        raise InvalidInputError("filter: invalid_enum") from None
    with workspace.read() as session:
        return AssetRepository(session.connection).list(environment=env, order=order)


def update_asset(
    workspace: Workspace,
    asset_id: str,
    *,
    actor: str,
    expected_hash: str,
    name: str | None = None,
    owner: str | None = None,
    environment: Environment | None = None,
    business_criticality: BusinessCriticality | None = None,
    data_classification: DataClassification | None = None,
    exposure: Exposure | None = None,
    tags: Sequence[str] | None = None,
) -> MutationResult:
    """Change fields of an asset, but only if it still has the hash the caller read.

    ``expected_hash`` is the ``hash`` shown by ``asset show``. A different stored hash is a
    ``conflict`` and nothing is written.
    """
    actor = require_actor(actor)
    asset_id = _asset_id(asset_id)
    expected = require_expected_hash(expected_hash)
    redactor = FieldRedactor(load_redactor(workspace.path))
    changes: dict[str, object] = {
        key: value
        for key, value in (
            ("name", redactor.optional("name", name, "name")),
            ("owner", redactor.optional("owner", owner, "name")),
            ("environment", environment),
            ("business_criticality", business_criticality),
            ("data_classification", data_classification),
            ("exposure", exposure),
            ("tags", None if tags is None else _redact_tags(redactor, tags)),
        )
        if value is not None
    }
    if not changes:
        raise InvalidInputError("no_changes")
    with workspace.write() as session:
        repo = AssetRepository(session.connection)
        current = repo.get(asset_id)
        if current is None:
            raise NotFoundServiceError("object_not_found", object_type="asset")
        before = current.digest()
        if before != expected:
            raise ConflictServiceError("hash_mismatch", object_type="asset")
        candidate = current.with_changes(**changes)
        if candidate == current:
            raise InvalidInputError("no_changes")
        updated = candidate.with_changes(updated_at=session.now)
        entry = repo.update(updated, actor=actor, at=session.now, expected_before_hash=expected)
    return MutationResult("asset", asset_id, before, updated.digest(), entry, redactor.report())
