"""Asset model."""

from typing import Self

from pydantic import model_validator

from soerm.domain.base import DomainModel
from soerm.domain.enums import BusinessCriticality, DataClassification, Environment, Exposure
from soerm.domain.errors import ValidationDomainError
from soerm.domain.identifiers import AssetId
from soerm.domain.text import Name, Tags
from soerm.domain.timestamps import UtcTimestamp

__all__ = ["Asset"]


class Asset(DomainModel):
    asset_id: AssetId
    name: Name
    owner: Name
    environment: Environment
    business_criticality: BusinessCriticality
    data_classification: DataClassification
    exposure: Exposure
    tags: Tags = ()
    created_at: UtcTimestamp
    updated_at: UtcTimestamp

    @model_validator(mode="after")
    def _check_timestamps(self) -> Self:
        if self.updated_at < self.created_at:
            raise ValidationDomainError.single("updated_at", "before_created_at")
        return self
