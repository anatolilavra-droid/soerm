"""Base class of all domain models and the conversion of validation errors."""

from typing import TYPE_CHECKING, Any, Self

from pydantic import BaseModel, ConfigDict, ValidationError

from soerm.domain.errors import ValidationDomainError, ValidationIssue
from soerm.domain.hashing import hash_canonical

__all__ = ["DomainModel", "translate_validation_error"]

# Names of model fields. Only these may appear in error locations; any other name could be
# a user-supplied key (an unexpected field, a mapping key) and is replaced by ``*``.
_KNOWN_FIELDS: set[str] = set()


def _location(loc: tuple[int | str, ...], error_type: str) -> str:
    text = ""
    last = len(loc) - 1
    for index, part in enumerate(loc):
        if isinstance(part, int):
            text += "[]"
            continue
        known = part in _KNOWN_FIELDS and not (error_type == "extra_forbidden" and index == last)
        text += ("." if text else "") + (part if known else "*")
    return text


def translate_validation_error(exc: ValidationError) -> ValidationDomainError:
    """Convert a Pydantic error into a domain error without any input values.

    Only field names (known fields), and rule codes are kept: Pydantic's own message, the
    offending input and its context are dropped, so secrets cannot leak through errors.
    """
    issues: list[ValidationIssue] = []
    error_class: type[ValidationDomainError] = ValidationDomainError
    for error in exc.errors(include_url=False, include_context=True):
        field = _location(error["loc"], error["type"])
        inner = (error.get("ctx") or {}).get("error")
        if isinstance(inner, ValidationDomainError):
            if error_class is ValidationDomainError:
                error_class = type(inner)
            issues.extend(
                ValidationIssue(".".join(part for part in (field, item.field) if part), item.code)
                for item in inner.issues
            )
        else:
            issues.append(ValidationIssue(field, error["type"]))
    return error_class(issues)


class DomainModel(BaseModel):
    """Immutable, strict-about-extras model whose errors never echo the input.

    ``model_construct`` skips validation. It is an untrusted internal escape hatch: instances
    built that way must never be trusted or persisted without re-validation (the audit chain
    check, for one, recomputes hashes instead of relying on them).
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        hide_input_in_errors=True,
        validate_default=True,
    )

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs: Any) -> None:
        super().__pydantic_init_subclass__(**kwargs)
        _KNOWN_FIELDS.update(cls.model_fields)

    if not TYPE_CHECKING:
        # At type-check time the plugin-generated typed ``__init__`` stays in effect.

        def __init__(self, /, **data: Any) -> None:
            try:
                super().__init__(**data)
            except ValidationError as exc:
                raise translate_validation_error(exc) from None

        @classmethod
        def model_validate(cls, obj: Any, **kwargs: Any) -> Self:
            try:
                return super().model_validate(obj, **kwargs)
            except ValidationError as exc:
                raise translate_validation_error(exc) from None

        @classmethod
        def model_validate_json(cls, json_data: Any, **kwargs: Any) -> Self:
            try:
                return super().model_validate_json(json_data, **kwargs)
            except ValidationError as exc:
                raise translate_validation_error(exc) from None

    def with_changes(self, **changes: Any) -> Self:
        """Return a validated copy with some fields replaced."""
        data: dict[str, Any] = {name: getattr(self, name) for name in type(self).model_fields}
        data.update(changes)
        return type(self)(**data)

    def canonical_dict(self) -> dict[str, Any]:
        """JSON-compatible dict (timestamps as ``...Z`` strings, enums as values)."""
        return self.model_dump(mode="json")

    def digest(self) -> str:
        """SHA-256 of the canonical JSON of the model."""
        return hash_canonical(self.canonical_dict())
