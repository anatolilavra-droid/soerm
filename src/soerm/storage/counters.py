"""Sequential identifiers (``AST-000001``, ...) from the ``counters`` table.

The increment and the read are one ``UPDATE ... RETURNING`` statement and must run inside a
write transaction (``BEGIN IMMEDIATE``). Consequences:

* two processes can never obtain the same number;
* if the surrounding transaction rolls back, the counter rolls back with it, so a failed
  operation does not consume a number;
* numbers are never reused and never chosen by the user. Gaps are allowed and are not
  repaired: they appear when a number was handed out in a transaction that committed but
  whose object was later removed or never created by the caller (for example a crash between
  two separate committed steps).
"""

from soerm.domain.errors import InvalidIdentifierError, ValidationDomainError
from soerm.domain.identifiers import PREFIXES, format_identifier
from soerm.storage.connection import SoermConnection
from soerm.storage.errors import StorageError
from soerm.storage.transactions import require_write_transaction, transaction

__all__ = ["CounterRepository"]

_NEXT = "UPDATE counters SET value = value + 1 WHERE prefix = :prefix RETURNING value"
_CURRENT = "SELECT value FROM counters WHERE prefix = :prefix"


def _check_prefix(prefix: object) -> str:
    if not isinstance(prefix, str) or prefix not in PREFIXES:
        raise InvalidIdentifierError.single("prefix", "invalid_identifier")
    return prefix


class CounterRepository:
    def __init__(self, connection: SoermConnection) -> None:
        self._connection = connection

    def next_identifier(self, prefix: str) -> str:
        """Allocate the next identifier for ``prefix``. Needs an active write transaction."""
        require_write_transaction(self._connection)
        checked = _check_prefix(prefix)
        rows = self._connection.execute(_NEXT, {"prefix": checked}).fetchall()
        if len(rows) != 1:
            raise StorageError("counter_missing", prefix=checked)
        try:
            return format_identifier(checked, rows[0][0])
        except ValidationDomainError:
            raise StorageError("counter_exhausted", prefix=checked) from None

    def current(self, prefix: str) -> int:
        """Last number handed out for ``prefix`` (0 if none)."""
        checked = _check_prefix(prefix)
        with transaction(self._connection, write=False) as conn:
            row = conn.execute(_CURRENT, {"prefix": checked}).fetchone()
        if row is None:
            raise StorageError("counter_missing", prefix=checked)
        return int(row[0])
