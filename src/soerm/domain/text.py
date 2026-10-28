"""Safe normalization of user-supplied strings and the string types built on it."""

import unicodedata
from collections.abc import Callable
from typing import Annotated

from pydantic import AfterValidator, BeforeValidator

from soerm.domain.errors import ValidationDomainError

__all__ = [
    "EVIDENCE_MAX_BYTES",
    "Actor",
    "Criterion",
    "Evidence",
    "LongText",
    "Name",
    "Reason",
    "Tags",
    "Title",
    "actor_key",
    "normalize_actor",
    "normalize_tag",
    "normalize_text",
    "utf8_length",
]

EVIDENCE_MAX_BYTES = 4096
MAX_TAGS = 32
_MAX_TAG_LENGTH = 64
_ACTOR_MAX_LENGTH = 128
_ACTOR_FIRST = frozenset("abcdefghijklmnopqrstuvwxyz0123456789")
_ACTOR_REST = _ACTOR_FIRST | frozenset("._@+-")

# Invisible or direction-changing characters are removed (they can hide or reorder text).
_STRIPPED = frozenset("­؜​‎‏‪‫‬‭‮⁠⁦⁧⁨⁩﻿")


def _violation(code: str) -> ValidationDomainError:
    return ValidationDomainError.single("", code)


def normalize_text(value: object, *, multiline: bool = False) -> str:
    """Normalize a user-supplied string.

    NFC normalization; control characters and exotic spaces become plain spaces; invisible
    and bidirectional control characters are removed; lone surrogates are rejected. Single-line
    text additionally has its whitespace collapsed; multi-line text keeps ``\\n`` and
    indentation, drops trailing spaces and surrounding blank lines.
    """
    if not isinstance(value, str):
        raise _violation("string_type")
    text = unicodedata.normalize("NFC", value)
    if multiline:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
    chars: list[str] = []
    for char in text:
        if char in _STRIPPED:
            continue
        category = unicodedata.category(char)
        if category == "Cs":
            raise _violation("invalid_character")
        if char == "\n" and multiline:
            chars.append(char)
        elif category in {"Cc", "Zl", "Zp", "Zs"}:
            chars.append(" ")
        else:
            chars.append(char)
    cleaned = "".join(chars)
    if multiline:
        return "\n".join(line.rstrip() for line in cleaned.split("\n")).strip("\n")
    return " ".join(cleaned.split())


def utf8_length(text: str) -> int:
    """Length of ``text`` in UTF-8 bytes."""
    return len(text.encode("utf-8", errors="strict"))


def _required_line(value: object) -> str:
    text = normalize_text(value)
    if not text:
        raise _violation("empty_text")
    return text


def _optional_block(value: object) -> str:
    return normalize_text(value, multiline=True)


def _max_length(limit: int) -> Callable[[str], str]:
    def check(text: str) -> str:
        if len(text) > limit:
            raise _violation("text_too_long")
        return text

    return check


def _max_bytes(limit: int) -> Callable[[str], str]:
    def check(text: str) -> str:
        if utf8_length(text) > limit:
            raise _violation("text_too_large")
        return text

    return check


Name = Annotated[str, BeforeValidator(_required_line), AfterValidator(_max_length(200))]
Title = Annotated[str, BeforeValidator(_required_line), AfterValidator(_max_length(300))]
Reason = Annotated[str, BeforeValidator(_required_line), AfterValidator(_max_length(500))]
Criterion = Annotated[str, BeforeValidator(_required_line), AfterValidator(_max_length(500))]
LongText = Annotated[str, BeforeValidator(_optional_block), AfterValidator(_max_length(8000))]
# Redaction happens in the service layer before validation (M4); this type only enforces the
# byte limit as a last backstop.
Evidence = Annotated[
    str, BeforeValidator(_optional_block), AfterValidator(_max_bytes(EVIDENCE_MAX_BYTES))
]


def normalize_actor(value: object) -> str:
    """Normalize an actor identifier: NFKC + casefold, then ASCII ``[a-z0-9._@+-]`` only.

    NFKC folds full-width and compatibility characters; the ASCII restriction rules out
    look-alike letters from other scripts, so two spellings of one actor compare equal.
    """
    text = unicodedata.normalize("NFKC", normalize_text(value)).casefold()
    if (
        not text
        or len(text) > _ACTOR_MAX_LENGTH
        or text[0] not in _ACTOR_FIRST
        or any(char not in _ACTOR_REST for char in text)
    ):
        raise _violation("invalid_actor")
    return text


def actor_key(value: object) -> str:
    """Comparison key of an actor (identical to its normalized form)."""
    return normalize_actor(value)


Actor = Annotated[str, BeforeValidator(normalize_actor)]


def normalize_tag(value: object) -> str:
    """Normalize one tag: single-line, casefolded, whitespace replaced by ``-``."""
    text = _required_line(value).casefold().replace(" ", "-")
    if len(text) > _MAX_TAG_LENGTH:
        raise _violation("text_too_long")
    return text


def _normalize_tags(value: object) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, (list, tuple, set, frozenset)):
        raise _violation("tags_type")
    if len(value) > MAX_TAGS * 4:
        raise _violation("too_many_tags")
    unique = {normalize_tag(item) for item in value}
    if len(unique) > MAX_TAGS:
        raise _violation("too_many_tags")
    return tuple(sorted(unique))


Tags = Annotated[tuple[str, ...], BeforeValidator(_normalize_tags)]
