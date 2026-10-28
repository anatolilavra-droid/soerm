"""Shared helpers for the import tests."""

import json
from pathlib import Path
from typing import Any

from soerm.domain.enums import ImportSource
from soerm.services.imports import ImportPreview, preview_import
from soerm.services.workspace import Workspace

SECRET = "Zq7-hidden-Value-31"


def put(root: Path, name: str, content: str | bytes) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def config(root: Path, text: str) -> None:
    put(root, "soerm.yaml", "version: 1\n" + text)


def sarif(results: list[Any] | None = None, **overrides: Any) -> str:
    document: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "scanner",
                        "rules": [
                            {
                                "id": "R1",
                                "name": "sql-injection",
                                "shortDescription": {"text": "SQL injection"},
                                "fullDescription": {"text": "Tainted data reaches a query"},
                            }
                        ],
                    }
                },
                "results": results if results is not None else [result()],
            }
        ],
    }
    document.update(overrides)
    return json.dumps(document)


def result(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "ruleId": "R1",
        "level": "error",
        "message": {"text": "user input flows into a query"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app/db.py"},
                    "region": {"startLine": 12, "startColumn": 5},
                }
            }
        ],
    }
    data.update(overrides)
    return data


JSON_MAPPING = """\
format: generic_json
records_path: items[]
fields:
  title: name
  description: detail.text
  evidence: detail.evidence
  owner: owner
  severity: sev
  cvss_score: cvss.score
  cvss_vector: cvss.vector
  location: where
"""

CSV_MAPPING = """\
format: csv
delimiter: ","
has_header: true
columns:
  title: title
  description: description
  asset_reference: asset
  evidence: evidence
  severity: severity
"""


def run(root: Path, path: str, fmt: ImportSource, mapping: str | None = None) -> ImportPreview:
    return preview_import(Workspace(root), path, fmt=fmt, mapping_path=mapping)


def tree(root: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()
    }
