"""Safe local importers (M5): read, check and normalize files; never write to the database.

``safe_file`` is the only module that touches the filesystem. The parsers work on text that
has already been read and size-limited, and return :class:`~soerm.domain.imports.ParseResult`.
"""

from soerm.importers.csv_import import parse_csv
from soerm.importers.generic_json import parse_generic_json
from soerm.importers.safe_file import SafeFile, read_workspace_file
from soerm.importers.sarif import parse_sarif

__all__ = ["SafeFile", "parse_csv", "parse_generic_json", "parse_sarif", "read_workspace_file"]
