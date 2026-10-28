"""Argument parser that never echoes user-supplied values.

``argparse`` normally copies offending values into its messages (``invalid choice: 'x'``,
``unrecognized arguments: x``). Values may be secrets, so :class:`SafeArgumentParser`
raises :class:`CliUsageError` with a message built only from option names.
"""

import argparse
import re
from typing import NoReturn

__all__ = ["CliUsageError", "SafeArgumentParser", "safe_usage_message"]

_REQUIRED = re.compile(r"the following arguments are required: [A-Za-z0-9_,/ -]+")
_ONE_OF = re.compile(r"one of the arguments [A-Za-z0-9_/ -]+ is required")
_NAMED = re.compile(r"argument ([A-Za-z0-9_/ ,{}.-]+?): (.*)", re.DOTALL)


class CliUsageError(Exception):
    """A command-line usage error; ``message`` is safe to print."""

    def __init__(self, message: str, usage: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.usage = usage


def safe_usage_message(message: str) -> str:
    """Reduce an ``argparse`` message to text that contains no user-supplied value."""
    if _REQUIRED.fullmatch(message) or _ONE_OF.fullmatch(message):
        return message
    named = _NAMED.fullmatch(message)
    if named is not None:
        name, rest = named.groups()
        if rest == "expected one argument":
            return f"expected a value for argument {name}"
        if rest.startswith("not allowed with argument "):
            return f"argument {name} cannot be combined with another option"
        return f"invalid value for argument {name}"
    if message.startswith("unrecognized arguments"):
        return "unrecognized arguments"
    return "invalid command line"


class SafeArgumentParser(argparse.ArgumentParser):
    """``ArgumentParser`` whose errors are exceptions with sanitized messages."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]

    def error(self, message: str) -> NoReturn:
        raise CliUsageError(safe_usage_message(message), self.format_usage().rstrip())
